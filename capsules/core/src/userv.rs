/*! Userspace service-kernel intermediation.
 */

use kernel::debug;
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
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};
use kernel::userv;
use kernel::userv::comm::{
    ReturnValueReader,
    UserspaceServiceAccess,
    UserspaceServiceClient,
    UsercallArguments,
};
use kernel::utilities::cells::OptionalCell;

pub const DRIVER_NO: usize = crate::driver::NUM::UservRegistry as usize;

#[derive(Default)]
/// Grant containing context for userspace service process.
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

const SUBSCRIBE_NO_INVOKE_USERCALL: usize = 0;

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
    fn with_service<F, T>(&self, target_userv_id: usize, f: F) -> Result<T, Error>
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

    fn find_by_pid(&self, userv_pid: ProcessId) -> Option<usize> {
        self.userv_ents.iter()
            .find(|ent| ent.map_or(false, |s| s.current_pid == userv_pid))
            .map(|ent| ent.unwrap_or_panic().userv_id)
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
                debug!("[usreg] {} re-registered for service role 0x{:x}",
                       pid.short_app_id(),
                       userv_role_id);
                Ok(())
            } else {
                // A userspace service that is not the registering one already fulfills the role.
                debug!("[usreg] {} cannot register for filled service role 0x{:x}",
                       pid.short_app_id(),
                       userv_role_id);
                Err(Error::AlreadyInUse)
            }
        } else {
            // The userspace service is fulfilling an unfilled role.
            // Place service entry in an empty slot.
            self.userv_ents.iter()
                .find(|ent| ent.is_none())
                .unwrap() // Registered service count must not exceed max count.
                .set(new_service);
                debug!("[usreg] {} registered for service role 0x{:x}",
                       pid.short_app_id(),
                       userv_role_id);
            Ok(())
        }
    }

    /// Invoke a userspace service with extended call arguments.
    pub fn usercall(
        &self,
        caller: &'static dyn UserspaceServiceClient,
        userv_role_id: usize,
        operation_id: usize,
        args: UsercallArguments,
    ) -> Result<(), Error>
    {
        debug!("[usreg] usercall: (role: 0x{:x}, op: {})", userv_role_id, operation_id);
        self.with_service(
            userv_role_id,
            |userv| {
                debug!("[usreg] found userspace service for {:x}", userv_role_id);
                self.userv_data.enter(
                    userv.current_pid,
                    |ad, kad| {
                        // Userspace service is already busy with another operation.
                        if ad.client.is_some() {
                            return Err(Error::AlreadyInUse);
                        }

                        let upcall_args = userv::comm::place_arguments(operation_id, kad, args)?;

                        // Send an upcall to the userspace service.
                        debug!("[usreg] invoking userspace service");
                        kad.schedule_upcall(SUBSCRIBE_NO_INVOKE_USERCALL, upcall_args)
                            .map_err(|_upcall_error| Error::KernelError)?;

                        // The caller is now the client of the userspace service.
                        let _none = ad.client.insert((operation_id, caller));

                        Ok(())
                    })
                    .flatten()
            })
            .flatten()
    }
}

const COMMAND_CHECK: usize                = 0x00;
const COMMAND_REGISTER: usize             = 0x10;
const COMMAND_USERV_RETURN_SUCCESS: usize = 0x11;
const COMMAND_USERV_RETURN_FAILURE: usize = 0x12;

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
                // Register the service.
                self.register(pid, role_id)
                    .map_err(|err| err.into())
                    .into()
            },

            // A userspace operation has completed a previously-requested operation.
            // Retrieve the result and send it to client.
            (COMMAND_USERV_RETURN_SUCCESS, rv1, rv2) => {
                let role_id = self.find_by_pid(pid).unwrap();
                self.userv_data.enter(
                    pid,
                    |ad, kad| {
                        // Provide the client with the data sent from the userspace service.
                        // Use the userspace service's read-only allow buffers to return results.
                        let rv_reader = ReturnValueReader::new(rv1, rv2, kad);
                        ad.client.map(|(op, c)| c.usercall_done(role_id, op, Ok(rv_reader)));

                        // The client is no longer the client,
                        // even in the event of an unsuccessful operation.
                        ad.client = None;

                        Ok(())
                    })
                    .flatten()
                    .map_err(|_perr| ErrorCode::FAIL)
                    .into()
            },

            (COMMAND_USERV_RETURN_FAILURE, errno, _r3) => {
                let role_id = self.find_by_pid(pid).unwrap();
                self.userv_data.enter(
                    pid,
                    |ad, _kad| {
                        // Inform the client that the operation completed in failure.
                        ad.client.map(|(op, c)| c.usercall_done(role_id, op, Err(errno)));
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
        args: UsercallArguments,
    ) -> Result<(), Error>
    {
        Registry::usercall(self, caller, role_id, operation_id, args)
    }
}
