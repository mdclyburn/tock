/*! Userspace service-kernel intermediation.
 */

use core::array;

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
use kernel::utilities::cells::OptionalCell;

use crate::ipc::userspace_services::comm;
use crate::ipc::userspace_services::{
    ReturnValueReader,
    UserspaceServiceAccess,
    UserspaceServiceClient,
    UsercallArguments,
};

pub const DRIVER_NUM: usize = capsules_core::driver::NUM::UserspaceServices as usize;

/// Outstanding usercall tracking.
#[derive(Clone, Copy)]
struct PendingUsercall {
    /// Operation ID of the usercall the service is currently executing.
    operation_id: usize,
    /// The callback client to notify upon the operation's completion.
    client: &'static dyn UserspaceServiceClient,
}

#[derive(Default)]
/// Grant containing context for userspace service process.
pub struct UserspaceServiceGrant {
    /// The current operation the userspace service is executing.
    current_op: Option<PendingUsercall>,
}

/// Userspace service entry.
#[derive(Clone, Copy, Debug)]
struct Service {
    /// Identifier for the functionality the userspace service implements.
    userv_id: usize,
    /// The process ID of the application implementing the userspace service instance running now.
    current_pid: ProcessId,
}

/// Userspace services registry.
///
/// A registry that tracks running userspace services and calls to them.
/// Userspace services interact with its `SyscallDriver` implementation
/// to announce their availability and to respond to invocations.
/// The type mediates calls and returns between userspace services and kernel-level code using them
/// with its `UserspaceServiceAccess` implementation.
/// Userspace services execute a single usercall at a time in this implementation.
///
/// It supports up to `N` userspace services.
pub struct Registry<const N: usize> {
    /// Userspace services running on the system.
    userv_ents: [OptionalCell<Service>; N],
    userv_data: Grant<UserspaceServiceGrant, UpcallCount<1>, AllowRoCount<1>, AllowRwCount<3>>,
}

impl<const N: usize> Registry<N> {
    pub fn new(grant_data: Grant<UserspaceServiceGrant, UpcallCount<1>, AllowRoCount<1>, AllowRwCount<3>>) -> Registry<N> {
        Registry {
            userv_ents: array::from_fn(|_| OptionalCell::empty()),
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
                debug!("[userv-registry] {} re-registered for service role 0x{:x}",
                       pid.short_app_id(),
                       userv_role_id);
                Ok(())
            } else {
                // A userspace service that is not the registering one already fulfills the role.
                debug!("[userv-registry] {} cannot register for filled service role 0x{:x}",
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
            debug!("[userv-registry] {}-{} registered for service role 0x{:x}",
                   pid.id(),
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
        debug!("[userv-registry] usercall: (role: 0x{:x}, op: {})", userv_role_id, operation_id);
        self.with_service(
            userv_role_id,
            |userv| {
                debug!("[userv-registry] found userspace service for {:x}", userv_role_id);
                self.userv_data.enter(
                    userv.current_pid,
                    |ad, kad| {
                        // Userspace service is already busy with another operation.
                        if ad.current_op.is_some() {
                            return Err(Error::AlreadyInUse);
                        }

                        let upcall_args = comm::place_arguments(operation_id, kad, args)?;

                        // Send an upcall to the userspace service.
                        debug!("[userv-registry] invoking userspace service");
                        kad.schedule_upcall(upcall::INVOKE_USERCALL, upcall_args)
                            .map_err(|_upcall_error| Error::KernelError)?;

                        // The caller is now the client of the userspace service.
                        let _none = ad.current_op.insert(
                            PendingUsercall {
                                operation_id,
                                client: caller,
                            });

                        Ok(())
                    })
                    .flatten()
            })
            .flatten()
    }
}

/// Syscall driver command numbers.
mod command {
    /// Driver available check.
    pub const CHECK: usize                   = 0x00;
    /// Userspace service registration.
    pub const REGISTER_SERVICE: usize        = 0x10;
    /// Usercall success return.
    pub const USERCALL_RETURN_SUCCESS: usize = 0x11;
    /// Usercall failure return.
    pub const USERCALL_RETURN_FAILURE: usize = 0x12;
}

/// Syscall driver upcall numbers.
mod upcall {
    /// Invoke a userspace service.
    pub const INVOKE_USERCALL: usize = 0x00;
}

impl<const N: usize> SyscallDriver for Registry<N> {
    fn command(
        &self,
        command_no: usize,
        r2: usize,
        r3: usize,
        pid: ProcessId
    ) -> CommandReturn
    {
        match (command_no, r2, r3) {
            (command::CHECK, _r2, _r3) => CommandReturn::success(),

            // Application is registering as a userspace service.
            // Check that it has shared its buffer with the capsule.
            (command::REGISTER_SERVICE, role_id, _r3) => {
                // Register the service.
                self.register(pid, role_id)
                    .map_err(|err| err.into())
                    .into()
            },

            // A userspace operation has completed a previously-requested operation.
            // Retrieve the result and send it to client.
            (command::USERCALL_RETURN_SUCCESS, rv1, rv2) => {
                let role_id = self.find_by_pid(pid).unwrap();
                self.userv_data.enter(
                    pid,
                    |ad, kad| {
                        // Provide the client with the data sent from the userspace service.
                        // Use the userspace service's read-only allow buffers to return results.
                        let rv_reader = ReturnValueReader::new(rv1, rv2, kad);
                        ad.current_op.map(|op| op.client.usercall_done(role_id, op.operation_id, Ok(rv_reader)));

                        // The client is no longer the client,
                        // even in the event of an unsuccessful operation.
                        ad.current_op = None;

                        Ok(())
                    })
                    .flatten()
                    .map_err(|_perr| ErrorCode::FAIL)
                    .into()
            },

            (command::USERCALL_RETURN_FAILURE, errno, _r3) => {
                let role_id = self.find_by_pid(pid).unwrap();
                debug!("[userv-registry] userv 0x{:x} reported failure: {}", role_id, errno);
                self.userv_data.enter(
                    pid,
                    |ad, _kad| {
                        // Inform the client that the operation completed in failure.
                        // Map the error number back into an ErrorCode.
                        let ec = match errno {
                            1 => ErrorCode::FAIL,
                            2 => ErrorCode::BUSY,
                            3 => ErrorCode::ALREADY,
                            4 => ErrorCode::OFF,
                            5 => ErrorCode::RESERVE,
                            6 => ErrorCode::INVAL,
                            7 => ErrorCode::SIZE,
                            8 => ErrorCode::CANCEL,
                            9 => ErrorCode::NOMEM,
                            10 => ErrorCode::NOSUPPORT,
                            11 => ErrorCode::NODEVICE,
                            12 => ErrorCode::UNINSTALLED,
                            13 => ErrorCode::NOACK,

                            _ => ErrorCode::FAIL,
                        };
                        ad.current_op.map(|op| op.client.usercall_done(
                            role_id,
                            op.operation_id,
                            Err(ec)));
                        ad.current_op = None;

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

impl<const N: usize> UserspaceServiceAccess for Registry<N> {
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
