/*! Kernel-userspace service communication.
 */

use crate::process::Error;
use crate::userv::tl::{
    Argument,
    ArgumentReader,
};

/// Provides access to userspace services, `userv`s.
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
        args: &[Argument],
    ) -> Result<(), Error>;
}

/// Client receiving results of "usercalls": userspace service calls.
pub trait UserspaceServiceClient {
    /// Callback signalling completion of a usercall.
    fn usercall_done<'a>(&self, args: &ArgumentReader<'a>);
}
