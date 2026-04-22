/*! Kernel-userspace service communication.
 */

use core::mem;

use crate::errorcode::ErrorCode;
use crate::grant::GrantKernelData;
use crate::process::Error;
use crate::processbuffer::{
    ReadableProcessBuffer,
    WriteableProcessBuffer,
};
use crate::userv::tl::{
    ArgumentReader,
};

/// Userspace service-compatible argument representation.
pub enum Argument<'a> {
    /// A single 32-bit unsigned integer.
    U32(u32),
    /// A sequence of bytes, copied.
    Bytes(&'a [u8]),
}

/// Usercall argument format.
#[derive(Clone, Copy)]
pub enum UsercallArguments<'a, 'b> {
    /// Short-format call arguments requiring only up to two words.
    Short(usize, usize),
    /// Arguments requiring more than two words.
    Extended(Option<usize>, Option<usize>, &'a [Argument<'b>]),
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
    fn usercall_done<'a>(
        &self,
        role_id: usize,
        operation_id: usize,
        args: Result<&ArgumentReader<'a>, usize>);
}

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
                match usercall_arg {
                    Argument::U32(val) => {
                        if allow_buffer.len() < mem::size_of::<u32>() {
                            return Err(Error::OutOfMemory);
                        } else {
                            allow_buffer.mut_enter(
                                |pbuf| pbuf[0..mem::size_of::<u32>()]
                                    .copy_from_slice(&val.to_ne_bytes()))?;
                        }
                    },

                    Argument::Bytes(arg_src_buffer) => {
                        if allow_buffer.len() < arg_src_buffer.len() {
                            return Err(Error::OutOfMemory);
                        } else {
                            allow_buffer.mut_enter(
                                |pbuf| pbuf[0..arg_src_buffer.len()]
                                    .copy_from_slice(arg_src_buffer))?;
                        }
                    },
                }
            }

            Ok((operation_id,
                opt_arg1.unwrap_or(0),
                opt_arg2.unwrap_or(0)))
        },
    }
}
