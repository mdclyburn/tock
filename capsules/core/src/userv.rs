/*! Userspace service-kernel intermediation.
 */

use core::cell::Cell;
use core::ptr;

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
    UserspaceServiceAccess,
    UserspaceServiceClient,
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
    /// The client the service is acting on behalf of currently and the operation ID.
    client: Option<(usize, &'static dyn UserspaceServiceClient)>,
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
        caller: &'static dyn UserspaceServiceClient,
        userv_role_id: usize,
        operation_id: usize,
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
                            arg_builder.as_upcall_arguments(operation_id))
                            .map_err(|_upcall_error| Error::KernelError)?;

                        // The caller is now the client of the userspace service.
                        ad.client.insert((operation_id, caller));

                        Ok(())
                    })
                    .flatten()
            })
            .flatten()
    }
}

const COMMAND_CHECK: usize        = 0x00;
const COMMAND_REGISTER: usize     = 0x10;
const COMMAND_USERV_RETURN: usize = 0x11;

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

            // A userspace operation has completed a previously-requested operation.
            // Retrieve the result and send it to client.
            (COMMAND_USERV_RETURN, _r2, _r3) => {
                let role_id = self.userv_ents.iter()
                    .find(|ent| ent.map_or(false, |s| s.current_pid == pid))
                    .map(|ent| ent.unwrap_or_panic().userv_id)
                    .unwrap();
                self.userv_data.enter(
                    pid,
                    |ad, kad| {
                        // Provide the client with the data sent from the userspace service.
                        let pbuf = kad.get_readwrite_processbuffer(ALLOW_RW_NO_ARGS)?;
                        let arg_reader = ArgumentReader::new(&pbuf)?;
                        ad.client.map(|(op, c)| c.usercall_done(role_id, op, &arg_reader));

                        // The client is no longer the client,
                        // even in the event of an unsuccessful operation.
                        ad.client = None;

                        Ok(())
                    })
                    .flatten()
                    .map_err(|_perr| ErrorCode::FAIL)
                    .into()
            },

            _unhandled => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> Result<(), Error> {
        self.userv_data.enter(pid, |_ad, _kad| {  })
    }
}

impl UserspaceServiceAccess for Registry {
    fn usercall(
        &self,
        caller: &'static dyn UserspaceServiceClient,
        role_id: usize,
        operation_id: usize,
        args: &[Argument<'_>],
    ) -> Result<(), Error>
    {
        Registry::usercall(self, caller, role_id, operation_id, args)
    }
}
