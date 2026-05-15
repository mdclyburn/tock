/*! Hashing userspace service.
 */

use kernel::ErrorCode;
use kernel::grant::{
    Grant,
    AllowRoCount,
    AllowRwCount,
    UpcallCount,
};
use kernel::hil::hasher::{
    Client,
    Hasher,
};
use kernel::process::{
    Error,
    ProcessId,
};
use kernel::processbuffer::ReadableProcessBuffer;
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};
use kernel::utilities::cells::{
    OptionalCell,
    TakeCell,
};
use kernel::utilities::leasable_buffer::SubSlice;
use kernel::utilities::leasable_buffer::SubSliceMut;

use crate::ipc::userspace_services::{
    Bytes,
    ReturnValueReader,
    Role,
    Serialize,
    UsercallArguments,
    UserspaceServiceAccess,
    UserspaceServiceClient,
};

mod ops {
    pub const ADD_DATA: usize   = 0x10;
    pub const CLEAR_DATA: usize = 0x11;
    pub const RUN: usize        = 0x20;
}

const ROLE_ID: usize = Role::Hasher as usize;

enum Operation<const L: usize> {
    AddData(SubSlice<'static, u8>),
    AddMutData(SubSliceMut<'static, u8>),
    Run(&'static mut [u8; L]),
}

const RETURN_HASHDONE_HASH_BUFFER_IDX: usize = 0;

pub struct ServiceInterface<const L: usize> {
    /// Self-reference to avoid needing &'static self in HILs.
    this: OptionalCell<&'static dyn UserspaceServiceClient>,
    /// Userspace service access interface.
    userv_access: &'static dyn UserspaceServiceAccess,
    /// Client using the hashing userspace service through this entity.
    client: OptionalCell<&'static dyn Client<L>>,
    /// The userspace service's current operation.
    current_op: OptionalCell<Operation<L>>,
}

impl<const L: usize> ServiceInterface<L> {
    pub fn new(userv_access: &'static dyn UserspaceServiceAccess) -> ServiceInterface<L> {
        ServiceInterface {
            this: OptionalCell::empty(),
            userv_access,
            client: OptionalCell::empty(),
            current_op: OptionalCell::empty(),
        }
    }

    pub fn init(&'static self) {
        self.this.set(self)
    }
}

impl<const L: usize> UserspaceServiceClient for ServiceInterface<L> {
    fn usercall_done<'r, 'grant>(
        &self,
        _role_id: usize,
        _operation_id: usize,
        return_data: Result<ReturnValueReader<'r, 'grant>, usize>,
    )
    {
        if let Some(op) = self.current_op.take() {
            match op {
                // Provide the client with its buffer back.
                Operation::AddData(data_slice) => {
                    self.client.map(
                        |c| c.add_data_done(
                            return_data
                                .map(|_reader| ())
                                // TODO: how to translate an arbitrary usize into an ErrorCode?
                                // Without this, error codes from the userspace service do not get to the caller.
                                .map_err(|_val| ErrorCode::FAIL),
                            data_slice));
                },

                Operation::AddMutData(data_slice) => {
                    self.client.map(
                        |c| c.add_mut_data_done(
                            return_data
                                .map(|_reader| ())
                                .map_err(|_val| ErrorCode::FAIL),
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

                                self.client.map(|c| c.hash_done(
                                    copy_hash_res.map_err(|kerr| kerr.into()),
                                    hash));
                            } else {
                                // Userspace service did not provide hash output buffer.
                            }
                        },

                        Err(_eval) => {
                            self.client.map(|c| c.hash_done(Err(ErrorCode::FAIL), hash));
                        },
                    }
                },
            }
        } else {
            // This ServiceInterface called usercall()
            // but did not place an Operation variant into self.current_op.
        }
    }
}

impl<'a: 'static, const L: usize> Hasher<'a, L> for ServiceInterface<L> {
    fn set_client(&'a self, client: &'a dyn Client<L>) {
        self.client.set(client)
    }

    fn add_data(&self, data: SubSlice<'static, u8>)
                -> Result<usize, (ErrorCode, SubSlice<'static, u8>)> {
        if data.len() != L {
            Err((ErrorCode::SIZE, data))
        } else if self.current_op.is_some() {
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
                    UsercallArguments::Extended(
                        None,
                        None,
                        &usercall_args));
                if let Err(kerr) = usercall_result {
                    Err((kerr.into(), data))
                } else {
                    self.current_op.set(Operation::AddData(data));
                    Ok(L)
                }
            } else {
                Err((ErrorCode::NODEVICE, data))
            }
        }
    }

    fn add_mut_data(&self, data: SubSliceMut<'static, u8>)
                    -> Result<usize, (ErrorCode, SubSliceMut<'static, u8>)> {
        if data.len() != L {
            Err((ErrorCode::SIZE, data))
        } else if self.current_op.is_some() {
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
                    UsercallArguments::Extended(
                        None,
                        None,
                        &usercall_args));
                if let Err(kerr) = usercall_result {
                    Err((kerr.into(), data))
                } else {
                    self.current_op.set(Operation::AddMutData(data));
                    Ok(L)
                }
            } else {
                Err((ErrorCode::NODEVICE, data))
            }
        }
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
                    UsercallArguments::Short(0, 0));
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

    fn clear_data(&self) {
        if let Some(this) = self.this.get() {
            // No return type means no error-handling for the operation or the usercall.
            let _usercall_result = self.userv_access.usercall(
                this,
                ROLE_ID,
                ops::CLEAR_DATA,
                UsercallArguments::Short(0, 0));
        }
    }
}

#[derive(Default)]
pub struct AppData;

pub type DriverGrant = Grant<AppData, UpcallCount<2>, AllowRoCount<1>, AllowRwCount<1>>;

pub struct Driver<const L: usize> {
    app_data: DriverGrant,
    data_buffer: TakeCell<'static, [u8; L]>,
    hash_buffer: TakeCell<'static, [u8; L]>,
}

impl<const L: usize> Driver<L> {
    pub fn new(
        grant: DriverGrant,
        data_buffer: &'static mut [u8; L],
        hash_buffer: &'static mut [u8; L],
    ) -> Driver<L>
    {
        Driver {
            app_data: grant,
            data_buffer: TakeCell::new(data_buffer),
            hash_buffer: TakeCell::new(hash_buffer),
        }
    }
}

const ALLOW_RO_NO_DATA: usize = 0;
const ALLOW_RW_NO_HASH: usize = 0;

const COMMAND_ADD: usize = 0x10;
const COMMAND_RUN: usize = 0x20;

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
            (COMMAND_ADD, _r2, _r3) => {
                if let Some(data_buffer) = self.data_buffer.take() {
                    self.app_data.enter(
                        pid,
                        |_ad, kad| {
                            let input_data_pbuf = kad.get_readonly_processbuffer(ALLOW_RO_NO_DATA)?;
                            if input_data_pbuf.len() < L {
                                Err(ErrorCode::NOMEM)
                            } else if input_data_pbuf.len() > L {
                                Err(ErrorCode::SIZE)
                            } else {
                                input_data_pbuf.enter(|buf| buf.copy_to_slice(data_buffer))?;
                                Ok(())
                            }
                        })
                        .map_err(|kerr| kerr.into())
                        .flatten()
                        .into()
                } else {
                    CommandReturn::failure(ErrorCode::BUSY)
                }
            },

            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }
}

impl<const L: usize> Client<L> for Driver<L> {
    fn add_data_done(&self, result: Result<(), ErrorCode>, data: SubSlice<'static, u8>) {
        unimplemented!()
    }

    fn add_mut_data_done(&self, result: Result<(), ErrorCode>, data: SubSliceMut<'static, u8>) {
        unimplemented!()
    }

    fn hash_done(&self, result: Result<(), ErrorCode>, hash: &'static mut [u8; L]) {
        unimplemented!()
    }
}
