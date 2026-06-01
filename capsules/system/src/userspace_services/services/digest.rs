/*! Hashing as a userspace service.
 */

use kernel::errorcode::{
    self,
    ErrorCode,
};
use kernel::grant::{
    Grant,
    AllowRoCount,
    AllowRwCount,
    UpcallCount,
};
use kernel::hil::digest::{
    Client,
    ClientData,
    ClientHash,
    ClientVerify,
    Digest,
    DigestData,
    DigestHash,
    DigestVerify,
};
use kernel::process::{
    Error,
    ProcessId,
};
use kernel::processbuffer::{
    ReadableProcessBuffer,
    WriteableProcessBuffer,
};
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};
use kernel::utilities::cells::{
    OptionalCell,
    TakeCell,
};
use kernel::utilities::leasable_buffer::{
    SubSlice,
    SubSliceMut,
};

use crate::userspace_services::{
    Bytes,
    ReturnReader,
    Role,
    Serialize,
    Arguments,
    UserspaceServiceAccess,
    UserspaceServiceClient,
};

mod ops {
    pub const ADD_DATA: usize   = 0x02;
    pub const CLEAR_DATA: usize = 0x11;
    pub const RUN: usize        = 0x01;
    pub const VERIFY: usize     = 0x03;
}

const ROLE_ID: usize = Role::Digest as usize;

enum Operation<const L: usize> {
    AddData(SubSlice<'static, u8>),
    AddMutData(SubSliceMut<'static, u8>),
    Run(&'static mut [u8; L]),
    Verify(&'static mut [u8; L]),
}

const RETURN_HASHDONE_HASH_BUFFER_IDX: usize = 0;

/// Hashing userspace service interface.
pub struct ServiceInterface<const L: usize> {
    /// Self-reference to avoid needing &'static self in HILs.
    this: OptionalCell<&'static dyn UserspaceServiceClient>,
    /// Userspace service access interface.
    userv_access: &'static dyn UserspaceServiceAccess,

    // Clients.
    /// Client using the userspace service for input data addition.
    data_client: OptionalCell<&'static dyn ClientData<L>>,
    /// Client using the userspace service for hash calculation.
    hash_client: OptionalCell<&'static dyn ClientHash<L>>,
    /// Client using the userspace service for hash verification.
    verify_client: OptionalCell<&'static dyn ClientVerify<L>>,

    /// The userspace service's current operation.
    current_op: OptionalCell<Operation<L>>,
}

impl<const L: usize> ServiceInterface<L> {
    /// Create a new instance of the service interface.
    pub fn new(userv_access: &'static dyn UserspaceServiceAccess) -> ServiceInterface<L> {
        ServiceInterface {
            this: OptionalCell::empty(),
            userv_access,
            data_client: OptionalCell::empty(),
            hash_client: OptionalCell::empty(),
            verify_client: OptionalCell::empty(),
            current_op: OptionalCell::empty(),
        }
    }

    /// Initialize internal state necessary before use.
    pub fn init(&'static self) {
        self.this.set(self)
    }
}

impl<const L: usize> UserspaceServiceClient for ServiceInterface<L> {
    fn usercall_done<'r, 'grant>(
        &self,
        return_data: Result<ReturnReader<'r, 'grant>, ErrorCode>,
    )
    {
        kernel::debug!("[digest-serv-int] usercall is done");
        if let Some(op) = self.current_op.take() {
            match op {
                // Provide the client with its buffer back.
                Operation::AddData(data_slice) => {
                    self.data_client.map(
                        |c| c.add_data_done(
                            return_data
                                .map(|_reader| ()),
                            data_slice));
                },

                Operation::AddMutData(data_slice) => {
                    self.data_client.map(
                        |c| c.add_mut_data_done(
                            return_data
                                .map(|_reader| ()),
                            data_slice));
                },

                // Copy the resulting hash into the caller's provided buffer and return it.
                Operation::Run(hash) => {
                    match return_data {
                        Ok(reader) => {
                            if let Some(hash_output_pbuf) = reader.buffer_n(RETURN_HASHDONE_HASH_BUFFER_IDX) {
                                // Copy bytes.
                                // The run function ensures that the caller's buffer is L bytes long.
                                let copy_hash_res = hash_output_pbuf.enter(
                                    |hash_output_pslice| hash_output_pslice[0..L]
                                        .copy_to_slice(hash));

                                self.hash_client.map(|c| c.hash_done(
                                    copy_hash_res.map_err(|kerr| kerr.into()),
                                    hash));
                            } else {
                                // Userspace service did not provide hash output buffer.
                            }
                        },

                        Err(_eval) => {
                            self.hash_client.map(|c| c.hash_done(Err(ErrorCode::FAIL), hash));
                        },
                    }
                },

                // Provide the digest output buffer back to the client along with the comparison result.
                Operation::Verify(digest_buffer) => {
                    let verify_result = return_data
                        .map(|reader| reader.direct_rvals().0 == 1);
                    self.verify_client.map(|c| c.verification_done(verify_result, digest_buffer));
                },
            }
        } else {
            // This ServiceInterface called usercall()
            // but did not place an Operation variant into self.current_op.
        }
    }
}

impl<'a: 'static, const L: usize> Digest<'a, L> for ServiceInterface<L> {
    fn set_client(&'a self, client: &'a dyn Client<L>) {
        self.data_client.set(client);
        self.hash_client.set(client);
        self.verify_client.set(client);
    }
}

impl<'a: 'static, const L: usize> DigestData<'a, L> for ServiceInterface<L> {
    fn set_data_client(&'a self, client: &'a dyn ClientData<L>) {
        self.data_client.set(client)
    }

    fn add_data(&self, data: SubSlice<'static, u8>)
                -> Result<(), (ErrorCode, SubSlice<'static, u8>)> {
        if self.current_op.is_some() {
            Err((ErrorCode::BUSY, data))
        } else {
            if let Some(this) = self.this.get() {
                let usercall_args: [&dyn Serialize; _] = [
                    &Bytes(data.as_slice()),
                ];

                let usercall_result = self.userv_access.usercall(
                    this,
                    ROLE_ID,
                    ops::ADD_DATA,
                    Arguments::Extended(
                        0,
                        0,
                        &usercall_args));
                if let Err(ec) = usercall_result {
                    Err((ec, data))
                } else {
                    self.current_op.set(Operation::AddData(data));
                    Ok(())
                }
            } else {
                Err((ErrorCode::NODEVICE, data))
            }
        }
    }

    fn add_mut_data(&self, data: SubSliceMut<'static, u8>)
                    -> Result<(), (ErrorCode, SubSliceMut<'static, u8>)> {
        if self.current_op.is_some() {
            Err((ErrorCode::BUSY, data))
        } else {
            if let Some(this) = self.this.get() {
                let usercall_args: [&dyn Serialize; _] = [
                    &Bytes(data.as_slice()),
                ];

                let usercall_result = self.userv_access.usercall(
                    this,
                    ROLE_ID,
                    ops::ADD_DATA,
                    Arguments::Extended(
                        data.len(),
                        0,
                        &usercall_args));
                if let Err(kerr) = usercall_result {
                    Err((kerr.into(), data))
                } else {
                    self.current_op.set(Operation::AddMutData(data));
                    Ok(())
                }
            } else {
                Err((ErrorCode::NODEVICE, data))
            }
        }
    }

    fn clear_data(&self) {
        if let Some(this) = self.this.get() {
            // No return type means no error-handling for the operation or the usercall.
            let _usercall_result = self.userv_access.usercall(
                this,
                ROLE_ID,
                ops::CLEAR_DATA,
                Arguments::Short(0, 0));
        }
    }
}

impl<'a: 'static, const L: usize> DigestHash<'a, L> for ServiceInterface<L> {
    fn set_hash_client(&'a self, client: &'a dyn ClientHash<L>) {
        self.hash_client.set(client)
    }

    fn run(&'a self, hash: &'static mut [u8; L])
           -> Result<(), (ErrorCode, &'static mut [u8; L])> {
        if self.current_op.is_some() {
            Err((ErrorCode::BUSY, hash))
        } else {
            if let Some(this) = self.this.get() {
                let usercall_result = self.userv_access.usercall(
                    this,
                    ROLE_ID,
                    ops::RUN,
                    Arguments::Short(0, 0));
                if let Err(kerr) = usercall_result {
                    Err((kerr.into(), hash))
                } else {
                    self.current_op.set(Operation::Run(hash));
                    Ok(())
                }
            } else {
                Err((ErrorCode::NODEVICE, hash))
            }
        }
    }
}

impl<'a: 'static, const L: usize> DigestVerify<'a, L> for ServiceInterface<L> {
    fn set_verify_client(&'a self, client: &'a dyn ClientVerify<L>) {
        self.verify_client.set(client)
    }

    fn verify(
        &'a self,
        expected_digest_buffer: &'static mut [u8; L]
    ) -> Result<(), (ErrorCode, &'static mut [u8; L])>
    {
        if self.current_op.is_some() {
            Err((ErrorCode::BUSY, expected_digest_buffer))
        } else {
            if let Some(this) = self.this.get() {
                let usercall_res = self.userv_access.usercall(
                    this,
                    ROLE_ID,
                    ops::VERIFY,
                    Arguments::Extended(
                        0,
                        0,
                        &[&Bytes(expected_digest_buffer)]
                    ),
                );

                if let Err(kerr) = usercall_res {
                    Err((kerr.into(), expected_digest_buffer))
                } else {
                    self.current_op.set(Operation::Verify(expected_digest_buffer));
                    Ok(())
                }
            } else {
                Err((ErrorCode::NODEVICE, expected_digest_buffer))
            }
        }
    }
}

pub const DRIVER_NUM: usize = capsules_core::driver::NUM::Sha as usize;

#[derive(Default)]
pub struct AppData;

pub type DriverGrant = Grant<AppData, UpcallCount<3>, AllowRoCount<1>, AllowRwCount<1>>;

pub struct Driver<const L: usize> {
    app_data: DriverGrant,
    digest_provider: &'static dyn Digest<'static, L>,
    data_buffer: TakeCell<'static, [u8]>,
    hash_buffer: TakeCell<'static, [u8; L]>,
    pending_for: OptionalCell<ProcessId>,
}

impl<const L: usize> Driver<L> {
    pub fn new(
        grant: DriverGrant,
        digest_provider: &'static dyn Digest<'static, L>,
        data_buffer: &'static mut [u8],
        hash_buffer: &'static mut [u8; L],
    ) -> Driver<L>
    {
        Driver {
            app_data: grant,
            digest_provider,
            data_buffer: TakeCell::new(data_buffer),
            hash_buffer: TakeCell::new(hash_buffer),
            pending_for: OptionalCell::empty(),
        }
    }
}

/// Allow buffer numbers.
mod allow {
    /// Read-only allows.
    pub mod ro {
        /// Input data for digest calculation.
        pub const DATA: usize = 0;
    }

    /// Read-write allows.
    pub mod rw {
        /// Digest calculation output.
        pub const HASH: usize = 0;
    }
}

/// Driver command numbers.
mod command {
    /// Add data to the digest calculation.
    pub const ADD: usize    = 0x02;
    /// Calculate the digest of accumulated data.
    pub const RUN: usize    = 0x01;
    /// Calculate the digest of accumulated data and compare it to an existing digest.
    pub const VERIFY: usize = 0x03;
}

/// Upcall numbers.
mod upcall {
    /// Digest calculation is complete.
    pub const RUN_DONE: usize    = 0x00;
    /// Data digest verification is complete.
    pub const VERIFY_DONE: usize = 0x01;
    /// Data addition is complete.
    pub const ADD_DONE: usize    = 0x02;
}

impl<const L: usize> SyscallDriver for Driver<L> {
    fn allocate_grant(&self, pid: ProcessId) -> Result<(), Error> {
        self.app_data.enter(pid, |_ad, _kad| {  })
    }

    fn command(
        &self,
        command_no: usize,
        r2: usize,
        r3: usize,
        pid: ProcessId
    ) -> CommandReturn
    {
        match (command_no, r2, r3) {
            (0, _r2, _r3) => CommandReturn::success(),

            // Add the data in the allow'd RO slice to the input data.
            (command::ADD, _r2, _r3) => {
                if let Some(data_buffer) = self.data_buffer.take() {
                    self.app_data.enter(
                        pid,
                        |_ad, kad| {
                            let input_data_pbuf = kad.get_readonly_processbuffer(allow::ro::DATA)?;
                            if input_data_pbuf.len() > data_buffer.len() {
                                Err(ErrorCode::SIZE)
                            } else {
                                input_data_pbuf.enter(|buf| buf.copy_to_slice(&mut data_buffer[0..input_data_pbuf.len()]))?;
                                let mut input_data_slice = SubSliceMut::new(data_buffer);
                                input_data_slice.slice(0..input_data_pbuf.len());
                                if let Err((ec, buf)) = self.digest_provider.add_mut_data(SubSliceMut::new(data_buffer)) {
                                    self.data_buffer.put(Some(buf.take()));
                                    Err(ec)
                                } else {
                                    self.pending_for.set(pid);
                                    Ok(())
                                }
                            }
                        })
                        .map_err(|kerr| kerr.into())
                        .flatten()
                        .into()
                } else {
                    CommandReturn::failure(ErrorCode::BUSY)
                }
            },

            // Trigger the start of a digest calculation on the accumulated data.
            (command::RUN, _r2, _r3) => {
                if let Some(hash_buffer) = self.hash_buffer.take() {
                    if let Err((ec, buf)) = self.digest_provider.run(hash_buffer) {
                        self.hash_buffer.put(Some(buf));
                        Err(ec).into()
                    } else {
                        self.pending_for.set(pid);
                        CommandReturn::success()
                    }
                } else {
                    Err(ErrorCode::BUSY).into()
                }
            },

            // Check the data against the provided hash.
            (command::VERIFY, _r2, _r3) => {
                if let Some(hash_buffer) = self.hash_buffer.take() {
                    if let Err((ec, buf)) = self.digest_provider.verify(hash_buffer) {
                        self.hash_buffer.put(Some(buf));
                        Err(ec).into()
                    } else {
                        self.pending_for.set(pid);
                        CommandReturn::success()
                    }
                } else {
                    Err(ErrorCode::BUSY).into()
                }
            },

            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }
}

impl<'a, const L: usize> ClientData<L> for Driver<L> {
    fn add_data_done(
        &self,
        _result: Result<(), ErrorCode>,
        _data_buffer: SubSlice<'static, u8>,
    )
    {
        // This type does not call DigestHash::add_data()
        // and so should never receive this callback.
    }

    fn add_mut_data_done(
        &self,
        result: Result<(), ErrorCode>,
        data_buffer: SubSliceMut<'static, u8>,
    )
    {
        kernel::debug!("[digest-driver] add data finished {:?}", result);
        self.pending_for.map(
            |pid| {
                self.data_buffer.put(Some(data_buffer.take()));
                let _enter_res = self.app_data.enter(
                    pid,
                    |_ad, kad| {
                        kernel::debug!("[digest-driver] sending add data finished upcall");
                        let _res = kad.schedule_upcall(
                            upcall::ADD_DONE,
                            (errorcode::into_statuscode(result), 0, 0));
                    });
            });
        self.pending_for.clear();
    }
}

impl<'a, const L: usize> ClientHash<L> for Driver<L> {
    fn hash_done(
        &self,
        hash_result: Result<(), ErrorCode>,
        hash_buffer: &'static mut [u8; L],
    )
    {
        self.pending_for.map(
            |pid| {
                let _enter_res = self.app_data.enter(
                    pid,
                    |_ad, kad| {
                        // Copy the resulting digest to the application's RW buffer.
                        let digest_copy_res = kad
                            .get_readwrite_processbuffer(allow::rw::HASH)
                            .map_err(|kerr| kerr.into())
                            .and_then(
                                |app_hash_pbuf| {
                                    // Check RW-allow buffer's length and copy the digest to it.
                                    if app_hash_pbuf.len() >= L {
                                        app_hash_pbuf.mut_enter(
                                            |app_hash_buf| app_hash_buf[0..L].copy_from_slice(hash_buffer))?;
                                        Ok(())
                                    } else {
                                        Err(ErrorCode::NOMEM)
                                    }
                                });
                        self.hash_buffer.put(Some(hash_buffer));

                        let _upcall_res = kad.schedule_upcall(
                            upcall::RUN_DONE,
                            (errorcode::into_statuscode(hash_result.and(digest_copy_res)), 0, 0));
                    });
            });
        self.pending_for.clear();
    }
}

impl<'a, const L: usize> ClientVerify<L> for Driver<L> {
    fn verification_done(
        &self,
        verification_result: Result<bool, ErrorCode>,
        hash_buffer: &'static mut [u8; L],
    )
    {
        self.pending_for.map(
            |pid| {
                self.hash_buffer.put(Some(hash_buffer));
                let _enter_res = self.app_data.enter(
                    pid,
                    |_ad, kad| {
                        let (is_match, status_arg) = match verification_result {
                            Ok(is_match) => (is_match, Ok(())),
                            Err(ec) => (false, Err(ec)),
                        };
                        let _res = kad.schedule_upcall(
                            upcall::VERIFY_DONE,
                            (errorcode::into_statuscode(status_arg), is_match as usize, 0));
                    });
            });
        self.pending_for.clear();
    }
}
