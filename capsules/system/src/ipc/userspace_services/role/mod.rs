/*! Service roles.
 */

pub mod digest;

#[derive(Debug, PartialEq)]
pub enum Role {
    Digest               = 0x11,
}
