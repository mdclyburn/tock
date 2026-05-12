/*! Service roles.
 */

pub mod hasher;

#[derive(Debug, PartialEq)]
pub enum Role {
    Hasher               = 0x11,
}
