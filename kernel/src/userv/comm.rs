/*! Kernel-userspace service communication.
 */

use crate::errorcode::ErrorCode;
use crate::process::Error;
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
pub enum UsercallArguments<'a, 'b> {
    /// Short-format call arguments requiring only up to two words.
    Short(usize, usize),
    /// Arguments requiring more than two words.
    Extended(&'a [Argument<'b>]),
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
