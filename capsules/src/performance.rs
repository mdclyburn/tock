/*! Performance-tracking support capsule.

Currently, this capsule's only purpose is to provide applications with the information necessary to make calls to performance-tracking code.
 */

use kernel::errorcode::ErrorCode;
use kernel::process::ProcessId;
use kernel::syscall::{
    CommandReturn,
    SyscallDriver
};

use perf;

pub const DRIVER_NUM: usize = crate::driver::NUM::Performance as usize;

pub struct PerformanceSupport;

impl PerformanceSupport {
    pub fn new() -> PerformanceSupport {
        PerformanceSupport
    }
}

impl SyscallDriver for PerformanceSupport {
    fn command(&self, command_no: usize, _r2: usize, _r3: usize, _pid: ProcessId) -> CommandReturn {
        match command_no {
            0 => CommandReturn::success(),
            1 => CommandReturn::success_u32(perf::account_ffi as usize as u32),
            2 => CommandReturn::success_u32(perf::freeze_ffi as usize as u32),
            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, _pid: ProcessId) -> Result<(), kernel::process::Error> {
        Ok(())
    }
}
