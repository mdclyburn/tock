/*! Userspace service service interfaces.

Service interfaces bridge a HIL client to the userspace service application through the registry,
preventing the HIL client from needing code to interact with the registry.
 */

pub mod digest;

/// Service function identifier.
///
/// Identifies the userspace service by its function.
/// The Role identifies the kind of userspace service to address in a usercall.
#[derive(Debug, PartialEq)]
pub enum Role {
    Digest               = 0x11,
}
