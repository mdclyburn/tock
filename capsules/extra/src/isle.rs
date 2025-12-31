/*! ISLE network isolation layer.
 */

use kernel::errorcode::ErrorCode;
use kernel::grant::{
    AllowRoCount,
    AllowRwCount,
    Grant,
    UpcallCount,
};
use kernel::hil::symmetric_encryption::AES128CCM;
use kernel::process::{
    Error,
    ProcessId,
};
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};

pub const DRIVER_NO: usize = capsules_core::driver::NUM::Isle as usize;

pub struct Isle<'a> {
    crypt: &'a dyn AES128CCM<'a>,
    app_data: Grant<(), UpcallCount<0>, AllowRoCount<1>, AllowRwCount<1>>,
}

impl<'a> Isle<'a> {
    pub fn new(
        crypt: &'a dyn AES128CCM<'a>,
        grant_data: Grant<(), UpcallCount<0>, AllowRoCount<1>, AllowRwCount<1>>,
    ) -> Isle<'a> {
        Isle {
            crypt,
            app_data: grant_data,
        }
    }
}

impl<'a> SyscallDriver for Isle<'a> {
    fn command(
        &self,
        command_no: usize,
        r2: usize,
        r3: usize,
        _pid: ProcessId,
    ) -> CommandReturn {
        match (command_no, r2, r3) {
            (0, _r2, _r3) => CommandReturn::success(),

            _ => CommandReturn::failure(ErrorCode::NOSUPPORT),
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> Result<(), Error> {
        self.app_data.enter(
            pid,
            |_grant_data, _kernel_grant_data| {  })
    }
}
