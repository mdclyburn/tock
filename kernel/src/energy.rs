/*! Energy accounting.
 */

use crate::process::FunctionCall;
use crate::syscall::{
    Syscall,
    SyscallReturn
};

/// Track energy usage by driver calls.
pub trait DriverEnergyAccounting {
    /// Perform accounting updates based on the provided syscall information.
    fn on_command(&self, invocation: &Syscall, outcome: &SyscallReturn);

    /// Perform accounting updates based on an upcall.
    fn on_upcall(&self, call: &FunctionCall);

    /// Returns the accounted total.
    fn total_accounted(&self) -> u64;
}
