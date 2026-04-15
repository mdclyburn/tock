/*! Userspace service-kernel intermediation.
 */

use core::cell::Cell;
use core::ptr;

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
    AEADTuple,
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
    ShortId,
};
use kernel::processbuffer::{
    ReadableProcessBuffer,
};
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};
use kernel::userv::comm::{
    Client,
};
use kernel::userv::tl::{
    Argument,
    ArgumentBuilder,
    ArgumentReader,
};
use kernel::utilities::cells::OptionalCell;

pub const DRIVER_NO: usize = crate::driver::NUM::UservRegistry as usize;

#[derive(Default)]
pub struct UserspaceServiceGrant {
    client: Option<&'static dyn Client>,
}

/// Userspace service entry.
#[derive(Clone, Copy, Debug)]
struct Service {
    /// Identifier for the functionality the userspace service implements.
    userv_id: usize,
    /// The process ID of the application implementing the userspace service instance running now.
    current_pid: ProcessId,
}

const ALLOW_RW_NO_ARGS: usize = 0;

const SUBSCRIBE_NO_INVOKE: usize = 0;

pub struct Registry {
    /// Userspace services running on the system.
    userv_ents: [OptionalCell<Service>; 5],
    userv_data: Grant<UserspaceServiceGrant, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>,
}

impl Registry {
    pub fn new(grant_data: Grant<UserspaceServiceGrant, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>) -> Registry {
        Registry {
            userv_ents: [
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
                OptionalCell::empty(),
            ],
            userv_data: grant_data,
        }
    }

    /// Run code with a particular service.
    ///
    /// Idenfifies the `Service` requested by the caller and runs the provided function.
    /// Returns an Error if the service is not in the registry.
    pub fn with_service<F, T>(&self, target_userv_id: usize, f: F) -> Result<T, Error>
    where
        F: FnOnce(Service) -> T
    {
        for userv_ent in self.userv_ents.iter() {
            if userv_ent.is_some() {
                let userv_id = userv_ent.map(|s| s.userv_id)
                    .unwrap(); // Earlier if-statement check guarantees a service is present.
                if userv_id == target_userv_id {
                    return Ok(userv_ent.map(f).unwrap());
                }
            }
        }

        Err(Error::NoSuchApp)
    }

    /// Locate the entry for the service fulfilling the given role ID.
    fn find(&self, userv_role_id: usize) -> Option<&OptionalCell<Service>> {
        for userv_ent in self.userv_ents.iter() {
            if userv_ent.is_some() {
                let is_userv_match = userv_ent.map(|s| s.userv_id == userv_role_id)
                    .unwrap();
                if is_userv_match {
                    return Some(userv_ent);
                }
            }
        }

        None
    }

    /// Register a userspace service.
    ///
    /// Adds a userspace service entry.
    /// Replaces an existing entry if the application short ID matches.
    fn register(&self, pid: ProcessId, userv_role_id: usize) -> Result<(), Error> {
        let new_service = Service {
            userv_id: userv_role_id,
            current_pid: pid,
        };

        // See if this is replacing an older (crashed) instance of the same application.
        if let Some(userv_ent) = self.find(userv_role_id) {
            // Make sure it isn't replacing an existing application.
            let can_replace = userv_ent
                .map(|s| pid.short_app_id() == s.current_pid.short_app_id())
                .unwrap(); // Previous find must not turn up an empty OptionalCell.
            if can_replace {
                // New instance of the userspace service replaces its older entry.
                userv_ent.set(new_service);
                Ok(())
            } else {
                // A userspace service that is not the registering one already fulfills the role.
                Err(Error::AlreadyInUse)
            }
        } else {
            // The userspace service is fulfilling an unfilled role.
            // Place service entry in an empty slot.
            self.userv_ents.iter()
                .find(|ent| ent.is_none())
                .unwrap() // Registered service count must not exceed max count.
                .set(new_service);
            Ok(())
        }
    }

    /// Invoke a userspace service.
    ///
    /// Trigger a userspace service operation.
    /// This operation is an asynchronous process, delivering results to the `caller`
    /// (most likely to be the caller of this function).
    pub fn usercall(
        &self,
        caller: &'static dyn Client,
        userv_role_id: usize,
        args: &[Argument],
    ) -> Result<(), Error>
    {
        self.with_service(
            userv_role_id,
            |userv| {
                self.userv_data.enter(
                    userv.current_pid,
                    |ad, kad| {
                        if !ad.client.is_none() {
                            return Err(Error::AlreadyInUse);
                        }

                        // Build the arguments buffer.
                        let pbuf = kad
                            .get_readwrite_processbuffer(ALLOW_RW_NO_ARGS)
                            .unwrap(); // Userspace service should have shared the buffer upon registration.
                        let mut arg_builder = ArgumentBuilder::new(&pbuf)?;
                        for arg in args.iter() {
                            arg_builder.place(arg)?;
                        }

                        // Send an upcall to the userspace service.
                        kad.schedule_upcall(
                            SUBSCRIBE_NO_INVOKE,
                            arg_builder.as_upcall_arguments())
                            .map_err(|_upcall_error| Error::KernelError)?;

                        // The caller is now the client of the userspace service.
                        ad.client.insert(caller);

                        Ok(())
                    })
                    .flatten()
            })
            .flatten()
    }
}

const COMMAND_CHECK: usize    = 0x00;
const COMMAND_REGISTER: usize = 0x10;

impl SyscallDriver for Registry {
    fn command(
        &self,
        command_no: usize,
        r2: usize,
        r3: usize,
        pid: ProcessId
    ) -> CommandReturn
    {
        match (command_no, r2, r3) {
            (COMMAND_CHECK, _r2, _r3) => CommandReturn::success(),

            // Application is registering as a userspace service.
            // Check that it has shared its buffer with the capsule.
            (COMMAND_REGISTER, role_id, _r3) => {
                // Check buffer data.
                let res_buffer_check = self.userv_data.enter(
                    pid,
                    |_ad, kad| {
                        kad.get_readwrite_processbuffer(ALLOW_RW_NO_ARGS)
                            .map(|pbuf| pbuf.ptr() != ptr::null() && pbuf.len() > 0)
                    })
                    .flatten()
                    .map_err(|err| ErrorCode::FAIL)
                    .and_then(|is_valid_pbuf| if is_valid_pbuf { Ok(()) } else { Err(ErrorCode::NOMEM) })
                    .into();

                // Register the service.
                self.register(pid, role_id)
                    .map_err(|err| ErrorCode::ALREADY)
                    .and(res_buffer_check)
                    .into()
            },

            _unhandled => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> Result<(), Error> {
        self.userv_data.enter(pid, |_ad, _kad| {  })
    }
}

#[derive(Copy, Clone, Default)]
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
    /// Client-provided buffers.
    client_buffers: OptionalCell<AEADTuple>,
}

const ALLOW_RW_NO_ARG_BUFFER: usize = 0;

impl UservCrypto {
    pub fn new(grant_data: Grant<ServiceData, UpcallCount<1>, AllowRoCount<0>, AllowRwCount<1>>) -> UservCrypto {
        UservCrypto {
            userv_busy: Cell::new(false),
            userv_pid: OptionalCell::empty(),
            userv_data: grant_data,
            client: OptionalCell::empty(),
            client_buffers: OptionalCell::empty(),
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
                    // builder.place(Argument::Bytes(ckey));
                    // builder.place(Argument::Bytes(nonce));
                    // builder.place(Argument::U32(message_len as u32)); // ENG: Hmm...
                    // builder.place(Argument::Buffer(in_plaintext));
                    // builder.place(Argument::Buffer(in_aad));
                    // builder.place(Argument::Buffer(out_ciphertext));
                    // builder.place(Argument::Buffer(out_tag));
                    // Length of the AAD is communicated through slice length.

                    // Make the upcall to the service.
                    let _upcall_result = kad.schedule_upcall(
                        SUBSCRIBE_NO_INVOKE,
                        builder.as_upcall_arguments())
                        .unwrap();
                })
                .unwrap();

            // Take ownership of the buffers.
            self.client_buffers.set((
                nonce,
                in_plaintext,
                in_aad,
                out_ciphertext,
                out_tag,
            ));


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

const COMMAND_USERV_ENCRYPT_SUCCESS: usize = 0x1000_0000;
const COMMAND_USERV_ENCRYPT_FAIL: usize    = 0x1000_1000;

impl SyscallDriver for UservCrypto {
    fn command(
        &self,
        command_no: usize,
        r2: usize,
        r3: usize,
        caller_pid: ProcessId,
    ) -> CommandReturn
    {
        match (command_no, r2, r3) {
            (COMMAND_CHECK, _r2, _r3) => CommandReturn::success(),

            (COMMAND_USERV_ENCRYPT_SUCCESS, _r2, _r3) => {
                let caller_is_userv = self.userv_pid.map_or(
                    false,
                    |userv_pid| caller_pid == userv_pid);
                if !caller_is_userv {
                    CommandReturn::failure(ErrorCode::NOSUPPORT)
                } else {
                    // The userv operation is complete and the data is in its buffers.
                    //
                    // Copy the resulting data back to the client's buffers.
                    let enter_res = self.userv_data.enter(
                        self.userv_pid.unwrap_or_panic(), // The userv capsule must track the userv PID upon its startup.
                        |_ad, kad| {
                            let arg_pbuffer = kad.get_readwrite_processbuffer(ALLOW_RW_NO_ARG_BUFFER)?;
                            let arg_reader = ArgumentReader::new(&arg_pbuffer);

                            // NEXT: copy results into the client's buffers.
                            unimplemented!();

                            Ok::<_, Error>(())
                        });

                    // Call client to notify that the encryption operation is complete.
                    if enter_res.is_ok() {
                        // Done with the client's buffers.
                        // Extract them for to pass back.
                        let (nonce, pt, aad, ct, tag) = self.client_buffers
                            .take()
                            .unwrap();

                        // The client is no longer the client.
                        // This workflow will prevent deadlocks.
                        let client = self.client.take().unwrap();
                        client.encrypt_done(nonce, pt, ct, aad, tag);

                        CommandReturn::success()
                    } else {
                        return CommandReturn::failure(ErrorCode::FAIL)
                    }
                }
            },

            (COMMAND_USERV_ENCRYPT_FAIL, _r2, _r3) => unimplemented!(),

            (_unrecognized_command_no, _r2, _r3) => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> Result<(), Error> {
        self.userv_data.enter(pid, |_ad, _kad| {  })
    }
}
