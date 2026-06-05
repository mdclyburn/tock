/*! Userspace service grant types.
 */

use kernel::grant::{
    AllowRoCount,
    AllowRwCount,
    Grant,
    UpcallCount,
};
use crate::userspace_services::usercall::UserspaceServiceClient;

/// Registry's grant type.
pub type RegistryGrant = Grant<UserspaceServiceGrant, UpcallCount<1>, AllowRoCount<3>, AllowRwCount<5>>;

/// Userspace service state.
#[derive(Clone, Copy, Default)]
pub enum ServiceState {
    #[default]
    /// The userspace service is not busy.
    Idle,
    /// The userspace service is busy and executing an operation for a client.
    Pending(&'static dyn UserspaceServiceClient),
}

#[derive(Default)]
/// Grant containing context for userspace service process.
pub struct UserspaceServiceGrant {
    /// The current operational state of the userspace service.
    pub op_state: ServiceState,
}
