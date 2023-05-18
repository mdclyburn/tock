use kernel::errorcode::ErrorCode;
use kernel::hil;
use kernel::hil::symmetric_encryption::AES128;
use kernel::process::ProcessId;
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
    SyscallReturn,
};
use kernel::utilities::cells::TakeCell;

pub const DRIVER_NUM: usize = crate::driver::NUM::Aes as usize;

pub struct DummyAES {
    aes: &'static AES128<'static>,
    src_buffer: TakeCell<'static, [u8]>,
    dst_buffer: TakeCell<'static, [u8]>,
}

impl DummyAES {
    pub fn new(aes: &'static AES128<'static>,
               src_buffer: &'static mut [u8],
               dst_buffer: &'static mut [u8]) -> DummyAES
    {
        DummyAES {
            aes,
            src_buffer: TakeCell::new(src_buffer),
            dst_buffer: TakeCell::new(dst_buffer),
        }
    }

    pub fn configure(&'static self) {
        // self.aes.enable();
        self.aes.set_client(self);
    }
}

impl hil::symmetric_encryption::Client<'static> for DummyAES {
    fn crypt_done(&'static self, source: Option<&'static mut [u8]>, dest: &'static mut [u8]) {
        self.src_buffer.put(source);
        self.dst_buffer.put(Some(dest));
        // kernel::debug!("done encrypting");
        self.aes.disable();
    }
}

impl SyscallDriver for DummyAES {
    fn allocate_grant(&self, pid: ProcessId) -> Result<(), kernel::process::Error> {
        Ok(())
    }

    fn command(&self, command_no: usize, r2: usize, r3: usize, pid: ProcessId) -> CommandReturn {
        match (command_no, r2, r3) {
            (0, _, _) => CommandReturn::success(),

            (1, _, _) => {
                if let Some(src_buffer) = self.src_buffer.take() {
                    if let Some(dst_buffer) = self.dst_buffer.take() {
                        self.aes.enable();
                        self.aes.set_key(&[0xFE, 0xA8, 0x23, 0x4A]);
                        self.aes.set_iv(&[0xFE, 0xEE, 0xEA, 0x1C]);
                        self.aes.start_message();

                        let buffer_len = dst_buffer.len();
                        let ret = self.aes.crypt(Some(src_buffer), dst_buffer, 0, buffer_len);

                        if let Some((result, opt_src_buffer, dst_buffer)) = ret {
                            self.src_buffer.put(opt_src_buffer);
                            self.dst_buffer.put(Some(dst_buffer));

                            CommandReturn::failure(ErrorCode::FAIL)
                        } else {
                            CommandReturn::success()
                        }
                    } else {
                        CommandReturn::failure(ErrorCode::BUSY)
                    }
                } else {
                    CommandReturn::failure(ErrorCode::BUSY)
                }
            }

            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }
}
