/*! ISLE network isolation layer.
 */

use core::default::Default;

use kernel::errorcode::ErrorCode;
use kernel::grant::{
    AllowRoCount,
    AllowRwCount,
    Grant,
    UpcallCount,
};
use kernel::hil::symmetric_encryption::{
    AES128CCM,
    CCMClient,
};
use kernel::process::{
    Error,
    ProcessId,
};
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};
use kernel::utilities::cells::MapCell;

pub const DRIVER_NO: usize = capsules_core::driver::NUM::Isle as usize;

pub struct AppData;

impl Default for AppData {
    fn default() -> AppData {
        AppData
    }
}

const IP6_ADDR_LEN: usize = 16;

pub struct Isle<'a> {
    crypt: &'a dyn AES128CCM<'a>,
    app_data: Grant<AppData, UpcallCount<0>, AllowRoCount<1>, AllowRwCount<1>>,
    mleid_address: MapCell<[u8; IP6_ADDR_LEN]>,
}

impl<'a> Isle<'a> {
    pub fn new(
        crypt: &'a dyn AES128CCM<'a>,
        grant_data: Grant<AppData, UpcallCount<0>, AllowRoCount<1>, AllowRwCount<1>>,
    ) -> Isle<'a> {
        Isle {
            crypt,
            app_data: grant_data,
            mleid_address: MapCell::empty(),
        }
    }
}

impl<'a> SyscallDriver for Isle<'a> {
    fn command(
        &self,
        command_no: usize,
        r2: usize,
        r3: usize,
        pid: ProcessId,
    ) -> CommandReturn {
        match (command_no, r2, r3) {
            (0, _r2, _r3) => CommandReturn::success(),

            // Translate CoAP message to Group OSCORE.
            (1, _arg0, _arg1) => {
                CommandReturn::failure(ErrorCode::NOSUPPORT)
            },

            // Set lower half of IP address.
            (10, block01, block23) => {
                self.mleid_address.map(|addr| {
                    addr[00] = ((block01 >> 00) & 0xFF) as u8;
                    addr[01] = ((block01 >> 08) & 0xFF) as u8;
                    addr[02] = ((block01 >> 16) & 0xFF) as u8;
                    addr[03] = ((block01 >> 24) & 0xFF) as u8;

                    addr[04] = ((block23 >> 00) & 0xFF) as u8;
                    addr[05] = ((block23 >> 08) & 0xFF) as u8;
                    addr[06] = ((block23 >> 16) & 0xFF) as u8;
                    addr[07] = ((block23 >> 24) & 0xFF) as u8;
                });
                CommandReturn::success()
            },

            // Set upper half of IP address.
            (20, block45, block67) => {
                self.mleid_address.map(|addr| {
                    addr[08] = ((block45 >> 00) & 0xFF) as u8;
                    addr[09] = ((block45 >> 08) & 0xFF) as u8;
                    addr[10] = ((block45 >> 16) & 0xFF) as u8;
                    addr[11] = ((block45 >> 24) & 0xFF) as u8;

                    addr[12] = ((block67 >> 00) & 0xFF) as u8;
                    addr[13] = ((block67 >> 08) & 0xFF) as u8;
                    addr[14] = ((block67 >> 16) & 0xFF) as u8;
                    addr[15] = ((block67 >> 24) & 0xFF) as u8;
                });
                CommandReturn::success()
            },

            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> Result<(), Error> {
        self.app_data.enter(
            pid,
            |_grant_data, _kernel_grant_data| {  })
    }
}

impl<'a> CCMClient for Isle<'a> {
    fn crypt_done(
        &self,
        buffer: &'static mut [u8],
        op_result: Result<(), ErrorCode>,
        tag_is_valid: bool,
    )
    {
        unimplemented!()
    }
}
