use kernel::ProcessId;
use kernel::grant::{
    AllowRoCount,
    AllowRwCount,
    Grant,
    UpcallCount,
};
use kernel::hil::spi::SpiMasterDevice;
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
    SyscallReturn,
};

pub const DRIVER_NUM: usize = crate::driver::NUM::Ism as usize;

pub struct AppData {
    awaiting_rx: bool,
}

impl Default for AppData {
    fn default() -> AppData {
        AppData {
            awaiting_rx: false,
        }
    }
}

/// RFM69 ISM radio driver.
pub struct RFM69 {
    grants: Grant<AppData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>,
    spi: &'static dyn SpiMasterDevice,
}

impl RFM69 {
    /// Create a new instance of the driver.
    pub fn new(
        grants: Grant<AppData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>,
        spi: &'static dyn SpiMasterDevice,
    ) -> RFM69
    {
        RFM69 {
            grants,
            spi,
        }
    }
}

impl SyscallDriver for RFM69 {
    fn allocate_grant(&self, pid: ProcessId) -> Result<(), kernel::process::Error> {
        self.grants.enter(pid, |_, _| {  })
    }
}
