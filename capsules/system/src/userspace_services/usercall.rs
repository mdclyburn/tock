/*! Userspace service invocation and data-handling.

Structures and interfaces for calling userspace services and copying data to and from them.
 */

use kernel::errorcode::ErrorCode;
use kernel::grant::GrantKernelData;
use kernel::process::Error;
use kernel::processbuffer::{
    ReadOnlyProcessBufferRef,
    ReadableProcessBuffer,
};

use crate::userspace_services::{
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

/// Usercall argument data.
///
/// Usercalls arguments have two formats:
/// a shorter format using up to two words of data
/// and a longer format that serializes data into buffers.
/// The `Short` variant passes two words of data directly through [`schedule_upcall()`](kernel::grant::GrantKernelData::schedule_upcall())'s arguments.
/// In addition to passing the same two words as the `Short` variant,
/// the `Extended` variant passes additional arguments by serializing them into one or more buffers.
/// The additional arguments provided in the slice must support the [`Serialize`] trait.
#[derive(Clone, Copy)]
pub enum Arguments<'arg, 'slice> {
    /// Short-format call arguments requiring only up to two words.
    Short(usize, usize),
    /// Arguments using up to two words and one or more buffers.
    Extended(usize, usize, &'slice [&'arg dyn Serialize]),
}

/// Provides call access to userspace services.
///
/// Exposes an asynchronous call interface to userspace services ("usercalls").
/// The userspace service's operation result returns to the caller through a callback to `caller`.
pub trait UserspaceServiceAccess {
    /// Invoke a userspace service.
    ///
    /// Trigger a userspace service operation.
    /// This operation is an asynchronous process, delivering results to the `caller`.
    /// The caller must provide a &'static `caller`
    /// (most likely to itself)
    /// to receive the usercall result.
    fn usercall(
        &self,
        caller: &'static dyn UserspaceServiceClient,
        role_id: usize,
        operation_id: usize,
        args: Arguments,
    ) -> Result<(), ErrorCode>;
}

/// Client receiving the result of a usercall.
pub trait UserspaceServiceClient {
    /// Callback signalling completion of a usercall.
    ///
    /// Provides the client with the results of a usercall operation.
    /// The client accesses data the userspace service returns with the
    /// [`ReturnReader`] `args`.
    fn usercall_done<'r, 'grant>(
        &self,
        args: Result<ReturnReader<'r, 'grant>, ErrorCode>,
    );
}

/// Put arguments into a userspace service's process buffers.
///
/// Prepares arguments for an upcall to the userspace service by
/// constructing the argument tuple for the call to [`schedule_upcall()`](kernel::grant::GrantKernelData::schedule_upcall())
/// and serializing arguments into buffers when using [`Arguments::Extended`].
/// Returns `Result::Ok` containing the upcall tuple upon success.
pub fn place_arguments(
    operation_id: usize,
    userv_kdata: &GrantKernelData,
    usercall_args: Arguments
) -> Result<(usize, usize, usize), Error>
{
    match usercall_args {
        Arguments::Short(arg1, arg2) =>
            Ok((operation_id, arg1, arg2)),

        Arguments::Extended(arg1, arg2, ext_args) => {
            // Retrieve ALLOWed buffers one at a time,
            // placing an argument into each buffer.
            let it = ext_args.iter()
                .enumerate()
                .map(|(allow_no, arg)| (userv_kdata.get_readwrite_processbuffer(allow_no), arg));
            for (res_allow_buffer, usercall_arg) in it {
                let allow_buffer = res_allow_buffer?;
                usercall_arg.try_serialize(allow_buffer)
                    .map_err(|_empty| Error::KernelError)?;
            }

            Ok((operation_id, arg1, arg2))
        },
    }
}

/// Reader for userspace service return values.
///
/// This an interpreter for userspace service return results.
/// It provides the two `usize` values returned directly from the userspace service
/// as well as functions to parse the data in the userspace service's process buffers.
/// Use [`buffer_n()`](ReturnReader::buffer_n()) to access an argument buffer.
/// Use [`buffer_n_as_value()`](ReturnReader::buffer_n_as_value()) to parse a buffer as a value supporting [`Deserialize`].
pub struct ReturnReader<'r, 'grant> {
    // Values returned directly through the command syscall.
    direct_rvals: (usize, usize),
    // Kernel-managed grant data for the userspace service
    // permitting access to allow'd buffers containing returned data.
    userv_k_grant_data: &'r GrantKernelData<'grant>,
}

impl<'r, 'grant> ReturnReader<'r, 'grant> {
    /// Create a new instance.
    pub fn new(
        rval1: usize,
        rval2: usize,
        userv_k_grant_data: &'r GrantKernelData<'grant>,
    ) -> ReturnReader<'r, 'grant>
    {
        ReturnReader {
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

    /// Deserializes and returns the value stored in the nth read-only process buffer.
    ///
    /// Interprets the bytes in the userspace service's nth read-only process buffer and returns that value.
    /// Returns `None` if the userspace service has not `allow`ed its nth read-only process buffer.
    /// Returns `Some(Err(())` if the userspace service is returning data but the interpretation failed.
    /// Returns `Some(Ok(T))` upon successful deserialization.
    pub fn buffer_n_as_value<T: Deserialize>(&self, idx: usize) -> Option<Result<T, ErrorCode>> {
        let ro_pbuf = self.buffer_n(idx)?;
        Some(T::try_deserialize(ro_pbuf))
    }
}
