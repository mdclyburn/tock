/*! Userspace services interfaces.
 */

pub mod comm;
pub mod tl;

pub mod role {
    pub mod crypto {
        pub const ID: usize = 0xA0;

        pub const OP_ENCRYPT: usize = 0x10;
        pub const OP_DECRYPT: usize = 0x20;
    }
}
