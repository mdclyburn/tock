/*! Energy accounting information.
 */

use kernel::energy::DriverEnergyAccounting;
use kernel::errorcode::ErrorCode;
use kernel::process::ProcessId;
use kernel::syscall::{CommandReturn, SyscallDriver};

pub const DRIVER_NUM: usize = crate::driver::NUM::Energy as usize;

pub struct AccountingData {
    accounting: &'static dyn DriverEnergyAccounting,
}

impl AccountingData {
    pub fn new(accounting: &'static dyn DriverEnergyAccounting) -> AccountingData {
        AccountingData {
            accounting,
        }
    }
}

impl SyscallDriver for AccountingData {
    fn command(&self,
               command_no: usize,
               r2: usize,
               r3: usize,
               pid: ProcessId) -> CommandReturn
    {
        match command_no {
            0 => CommandReturn::success(),

            1 => {
                let (_r2, _r3) = (r2, r3);
                CommandReturn::success_u64(self.accounting.total_accounted())
            },

            _ => CommandReturn::failure(ErrorCode::INVAL)
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> Result<(), kernel::process::Error> {
        Ok(())
    }
}
