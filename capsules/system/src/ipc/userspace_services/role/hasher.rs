/*! Hashing userspace service.
 */

use kernel::ErrorCode;
use kernel::hil::hasher::{
    Client,
    Hasher,
};
use kernel::utilities::cells::OptionalCell;
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
    pub const ADD_DATA: usize = 0x10;
    pub const RUN: usize =      0x20;
}

const ROLE_ID: usize = Role::Hasher as usize;

pub struct ServiceInterface<const L: usize> {
    /// Self-reference to avoid needing &'static self in HILs.
    this: OptionalCell<&'static dyn UserspaceServiceClient>,
    /// Userspace service access interface.
    userv_access: &'static dyn UserspaceServiceAccess,
    /// Client using the hashing userspace service through this entity.
    client: OptionalCell<&'static dyn Client<L>>,
}

impl<const L: usize> ServiceInterface<L> {
    pub fn new(userv_access: &'static dyn UserspaceServiceAccess) -> ServiceInterface<L> {
        ServiceInterface {
            this: OptionalCell::empty(),
            userv_access,
            client: OptionalCell::empty(),
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
        operation_id: usize,
        _return_data: Result<ReturnValueReader<'r, 'grant>, usize>,
    )
    {
        match operation_id {
            ops::ADD_DATA => unimplemented!(),

            ops::RUN => unimplemented!(),

            // An unknown operation ID passed to this call.
            _ => {  },
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
        } else {
            let usercall_args: [&dyn Serialize; _] = [
                &Bytes(data.as_slice()),
            ];

            self.this.map(|this| self.userv_access.usercall(
                this,
                ROLE_ID,
                ops::ADD_DATA,
                UsercallArguments::Extended(
                    None,
                    None,
                    &usercall_args)));

            Ok(L)
        }
    }

    fn add_mut_data(&self, _data: SubSliceMut<'static, u8>)
                    -> Result<usize, (ErrorCode, SubSliceMut<'static, u8>)> {
        unimplemented!()
    }

    fn run(&'a self, _hash: &'static mut [u8; L])
           -> Result<(), (ErrorCode, &'static mut [u8; L])> {
        unimplemented!()
    }

    fn clear_data(&self) {
        unimplemented!()
    }
}
