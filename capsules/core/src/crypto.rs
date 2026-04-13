/*! Cryptographic `userv` capsule.
 */

use core::cell::Cell;

use kernel::crypto::config::{
    AAD_LEN_MAX,
    CKEY_LEN_MAX,
    MESSAGE_LEN_MAX,
    NONCE_LEN_MAX,
    TAG_LEN_MAX,
};
use kernel::crypto::provider::{
    AEADProvider,
    AEADProviderClient,
};
use kernel::errorcode::ErrorCode;
use kernel::grant::{
    AllowRoCount,
    AllowRwCount,
    Grant,
    UpcallCount,
};
use kernel::process::{
    Error,
    ProcessId,
};
use kernel::processbuffer::{
    ReadableProcessBuffer,
};
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};

use kernel::userv::tl::{
    Argument,
    ArgumentBuilder,
};
use kernel::utilities::cells::OptionalCell;

pub const DRIVER_NO: usize = crate::driver::NUM::UservCrypto as usize;

#[derive(Debug, Default)]
pub struct ServiceData;

/// Cryptograpphy userspace service provider kernel counterpart.
pub struct UservCrypto {
    /// Flag indicating idle/busy state of the userspace service.
    ///
    /// In this iteration the userspace service handles a single request at a time.
    /// Subsequent requests that arrive while the userspace service is busy
    /// will receive the equivalent of a busy error.
    userv_busy: Cell<bool>,
    /// Process ID of the application implementing the userspace service.
    userv_pid: OptionalCell<ProcessId>,
    userv_data: Grant<ServiceData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>,
    /// The current entity using the userspace service.
    client: OptionalCell<&'static dyn AEADProviderClient>,
}

const ALLOW_RW_NO_ARG_BUFFER: usize = 0;

const SUBSCRIBE_NO_INVOKE: usize = 0;

impl UservCrypto {
    pub fn new(grant_data: Grant<ServiceData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>) -> UservCrypto {
        UservCrypto {
            userv_busy: Cell::new(false),
            userv_pid: OptionalCell::empty(),
            userv_data: grant_data,
            client: OptionalCell::empty(),
        }
    }

    pub fn acquire(&self, caller: &'static dyn AEADProviderClient) -> Result<(), ErrorCode> {
        if self.client.is_some() {
            Err(ErrorCode::BUSY)
        } else {
            self.client.set(caller);
            Ok(())
        }
    }
}

const PADDING_LEN: usize = 8;

/// Encryption interface for kernel-internal entities (even on behalf of userspace requests).
impl AEADProvider for UservCrypto {
    fn padding_size(&self) -> usize { PADDING_LEN }

    fn encrypt(
        &self,
        ckey: &[u8; CKEY_LEN_MAX],
        nonce: &'static mut [u8; NONCE_LEN_MAX],
        in_plaintext: &'static mut [u8; MESSAGE_LEN_MAX],
        in_aad: &'static mut [u8; AAD_LEN_MAX],
        out_ciphertext: &'static mut [u8; MESSAGE_LEN_MAX],
        out_tag: &'static mut [u8; TAG_LEN_MAX],
        message_len: usize,
        aad_len: usize,
    ) -> Result<(), (ErrorCode, (&'static mut [u8; NONCE_LEN_MAX],
                                 &'static mut [u8; MESSAGE_LEN_MAX],
                                 &'static mut [u8; AAD_LEN_MAX],
                                 &'static mut [u8; MESSAGE_LEN_MAX],
                                 &'static mut [u8; TAG_LEN_MAX]))> {
        // Make sure no other operation is active and then mark the service busy.
        // There is a "gentleman's agreement" in place here that no entity will call this function
        // unless they have correctly acquire()d the service.
        //
        // By altering this interface or providing an entirely new one
        // that takes the client as an argument, we can avoid this issue.
        // That client (AEADProviderClient) can be a capsule performing an operation on behalf of an application
        // or just another kernel entity with an interest in the operation for its own purposes.
        if self.userv_busy.get() {
            Err((ErrorCode::BUSY,
                (nonce,
                 in_plaintext,
                 in_aad,
                 out_ciphertext,
                 out_tag)))
        } else {
            // Mark the service as busy.
            self.userv_busy.set(true);

            // Build arguments for service call.
            self.userv_data.enter(
                self.userv_pid.unwrap_or_panic(),
                |_ad, kad| {
                    let pbuf = kad.get_readwrite_processbuffer(ALLOW_RW_NO_ARG_BUFFER)
                        .unwrap();

                    let mut builder = ArgumentBuilder::new(&pbuf)
                        .unwrap();
                    builder.place(Argument::Bytes(ckey));
                    builder.place(Argument::Bytes(nonce));
                    builder.place(Argument::U32(message_len as u32)); // ENG: Hmm...
                    builder.place(Argument::Buffer(in_plaintext));
                    builder.place(Argument::Buffer(in_aad));
                    builder.place(Argument::Buffer(out_ciphertext));
                    builder.place(Argument::Buffer(out_tag));
                    // Length of the AAD is communicated through slice length.

                    // Make the upcall to the service.
                    let _upcall_result = kad.schedule_upcall(
                        SUBSCRIBE_NO_INVOKE,
                        builder.as_upcall_arguments())
                        .unwrap();
                })
                .unwrap();


            Ok(())
        }
    }

    fn decrypt(
        &self,
        ckey: &[u8; CKEY_LEN_MAX],
        nonce: &'static mut [u8; NONCE_LEN_MAX],
        in_ciphertext: &'static mut [u8; MESSAGE_LEN_MAX],
        in_aad: &'static mut [u8; AAD_LEN_MAX],
        expected_tag: &'static mut [u8; TAG_LEN_MAX],
        out_plaintext: &'static mut [u8; MESSAGE_LEN_MAX],
        message_len: usize,
        aad_len: usize,
    ) -> Result<(), (ErrorCode, (&'static mut [u8; NONCE_LEN_MAX],
                                 &'static mut [u8; MESSAGE_LEN_MAX],
                                 &'static mut [u8; AAD_LEN_MAX],
                                 &'static mut [u8; MESSAGE_LEN_MAX],
                                 &'static mut [u8; TAG_LEN_MAX]))>
    {
        unimplemented!()
    }

    /// Set the client.
    ///
    /// Do not use this function; it will panic.
    /// Instead, use the `UservCrypto::acquire()` function to exclusively use the service.
    fn set_client(&self, client: &'static dyn AEADProviderClient) {
        panic!()
    }
}

const COMMAND_CHECK: usize = 0x00;

const COMMAND_USERV_ENCRYPT_SUCCESS: usize = 0x1000_0000;
const COMMAND_USERV_ENCRYPT_FAIL: usize    = 0x1000_1000;

impl SyscallDriver for UservCrypto {
    fn command(
        &self,
        command_no: usize,
        r2: usize,
        r3: usize,
        pid: ProcessId,
    ) -> CommandReturn
    {
        match (command_no, r2, r3) {
            (COMMAND_CHECK, _r2, _r3) => CommandReturn::success(),

            (COMMAND_USERV_ENCRYPT_SUCCESS, _r2, _r3) => unimplemented!(),

            (COMMAND_USERV_ENCRYPT_FAIL, _r2, _r3) => unimplemented!(),

            (_unrecognized_command_no, _r2, _r3) => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> Result<(), Error> {
        self.userv_data.enter(pid, |_ad, _kad| {  })
    }
}
