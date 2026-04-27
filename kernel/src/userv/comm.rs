/*! Kernel-userspace service communication.
 */

use core::mem;

use crate::errorcode::ErrorCode;
use crate::grant::GrantKernelData;
use crate::process::Error;
use crate::processbuffer::{
    ReadOnlyProcessBuffer,
    ReadOnlyProcessBufferRef,
    ReadableProcessBuffer,
    WriteableProcessBuffer,
};
use crate::userv::data::{
    Deserialize,
    Serialize,
};

/// Userspace service-compatible argument representation.
pub enum Argument<'a> {
    /// A single 32-bit unsigned integer.
    U32(u32),
    /// A sequence of bytes.
    ///
    /// A buffer of data to provide to a userspace service.
    /// The bytes in the slice are copied into the target userspace service's memory.
    Bytes(&'a [u8]),
}

/// Usercall argument format.
#[derive(Clone, Copy)]
pub enum UsercallArguments<'a, 'b> {
    /// Short-format call arguments requiring only up to two words.
    Short(usize, usize),
    /// Arguments requiring more than two words.
    Extended(Option<usize>, Option<usize>, &'a [&'b dyn Serialize]),
}

/// Provides access to userspace services, `userv`s.
///
/// Exposes an asynchronous call interface to userspace services.
/// An operation delivers results to the caller with a callback to the provided [`UserspaceServiceClient`].
pub trait UserspaceServiceAccess {
    /// Invoke a userspace service.
    ///
    /// Trigger a userspace service operation.
    /// This operation is an asynchronous process, delivering results to the `caller`
    /// (most likely to be the caller of this function).
    fn usercall(
        &self,
        caller: &'static dyn UserspaceServiceClient,
        role_id: usize,
        operation_id: usize,
        args: UsercallArguments,
    ) -> Result<(), Error>;
}

/// Client receiving results of "usercalls": userspace service calls.
pub trait UserspaceServiceClient {
    /// Callback signalling completion of a usercall.
    ///
    /// Provides the client with the results of a usercall operation.
    /// The role ID accompanies the results to allow an implementor creating a composite facility
    /// (e.g., encrypting and hashing roles)
    /// to support and discern multiple roles.
    fn usercall_done<'r, 'grant>(
        &self,
        role_id: usize,
        operation_id: usize,
        args: Result<ReturnValueReader<'r, 'grant>, usize>,
    );
}

/// Put arguments into a userspace service's process buffers.
pub fn place_arguments(
    operation_id: usize,
    k_grant_data: &GrantKernelData,
    usercall_args: UsercallArguments
) -> Result<(usize, usize, usize), Error>
{
    match usercall_args {
        UsercallArguments::Short(arg1, arg2) =>
            Ok((operation_id, arg1, arg2)),

        UsercallArguments::Extended(opt_arg1, opt_arg2, ext_args) => {
            // Retrieve ALLOWed buffers one at a time,
            // placing an argument into each buffer.
            let it = ext_args.iter()
                .enumerate()
                .map(|(allow_no, arg)| (k_grant_data.get_readwrite_processbuffer(allow_no), arg));
            for (res_allow_buffer, usercall_arg) in it {
                let allow_buffer = res_allow_buffer?;
                usercall_arg.try_serialize(allow_buffer)
                    .map_err(|_empty| Error::KernelError)?;
            }

            Ok((operation_id,
                opt_arg1.unwrap_or(0),
                opt_arg2.unwrap_or(0)))
        },
    }
}

/// Reader for userspace service return values.
///
/// Structured interpreter for userspace service return values.
/// Provides the two `usize` values returned directly from the userspace service,
/// as well as functions to parse the data in the userspace service's process buffers.
/// Use [`ReturnValueReader::buffer_n_as_value()`] to retrieve values of a supported type.
/// Use [`ReturnValueReader::buffer_n()`] to access the buffer.
pub struct ReturnValueReader<'r, 'grant> {
    // Values returned directly through the command syscall.
    direct_rvals: (usize, usize),
    // Kernel-managed grant data for the userspace service
    // permitting access to allow'd buffers containing returned data.
    userv_k_grant_data: &'r GrantKernelData<'grant>,
}

impl<'r, 'grant> ReturnValueReader<'r, 'grant> {
    /// Create a new instance.
    pub fn new(
        rval1: usize,
        rval2: usize,
        userv_k_grant_data: &'r GrantKernelData<'grant>,
    ) -> ReturnValueReader<'r, 'grant>
    {
        ReturnValueReader {
            direct_rvals: (rval1, rval2),
            userv_k_grant_data,
        }
    }

    /// Returns the pair of direct return values from the userspace service.
    pub fn direct_rvals(&self) -> (usize, usize) {
        self.direct_rvals
    }

    /// Returns access to the nth read-only process buffer.
    ///
    /// Provides access to the userspace service's entire nth process buffer.
    /// Returns `Some(_)` if the userspace service has `allow`ed the buffer and its length is greater than zero.
    pub fn buffer_n(&self, idx: usize) -> Option<ReadOnlyProcessBufferRef<'_>> {
        self.userv_k_grant_data
            .get_readonly_processbuffer(idx)
            .ok()
            .filter(|pbuf| pbuf.len() > 0)
    }

    /// Interprets and returns the value stored in the nth read-only process buffer.
    ///
    /// Interprets the bytes in the userspace service's nth read-only process buffer and returns that value.
    /// Returns `None` if the userspace service has not `allow`ed its nth read-only process buffer.
    /// Returns `Some(Err(())` if the userspace service is returning data but the interpretation failed.
    /// Returns `Some(Ok(T))` upon successful interpretation.
    pub fn buffer_n_as_value<T: Deserialize>(&self, idx: usize) -> Option<Result<T, ()>> {
        let ro_pbuf = self.buffer_n(idx)?;
        Some(T::try_deserialize(ro_pbuf))
    }
}
