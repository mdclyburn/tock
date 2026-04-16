/*! Cryptography userspace service helpers.
 */

use crate::crypto::config::{
    AAD_LEN_MAX,
    CKEY_LEN_MAX,
    MESSAGE_LEN_MAX,
    NONCE_LEN_MAX,
    TAG_LEN_MAX,
};
use crate::crypto::provider::{
    AEADProvider,
    AEADProviderClient,
    AEADTuple,
};
use crate::errorcode::ErrorCode;
use crate::userv::tl::{
    Argument,
    ArgumentReader,
};
use crate::process::Error;
use crate::userv::comm::{
    UserspaceServiceAccess,
    UserspaceServiceClient,
};
use crate::utilities::cells::OptionalCell;

/// Cryptography userspace service role ID.
pub const ROLE_ID: usize = 0xA0;

/// Cryptographic operations.
pub mod ops {
    pub const ENCRYPT: usize = 0x10;
    pub const DECRYPT: usize = 0x20;
}

/// Plaintext buffer padding byte length.
pub const PADDING_LEN: usize = 8;

/// Encrypt a plaintext buffer with a userspace service.
pub fn encrypt(
    uservs: &'static dyn UserspaceServiceAccess,
    caller: &'static dyn UserspaceServiceClient,
    ckey: &[u8; CKEY_LEN_MAX],
    nonce: &[u8; NONCE_LEN_MAX],
    in_plaintext: &[u8; MESSAGE_LEN_MAX],
    in_aad: &[u8; AAD_LEN_MAX],
    out_ciphertext: &[u8; MESSAGE_LEN_MAX],
    out_tag: &[u8; TAG_LEN_MAX],
    message_len: usize,
    aad_len: usize,
) -> Result<(), Error>
{
    let encrypt_args = [
        Argument::Bytes(ckey),
        Argument::Bytes(nonce),
        Argument::U32(message_len as u32), // ENG: Hmm...
        Argument::Buffer(in_plaintext),
        Argument::Buffer(in_aad),
        Argument::Buffer(out_ciphertext),
        Argument::Buffer(out_tag),
    ];

    uservs.usercall(
        caller,
        ROLE_ID,
        ops::ENCRYPT,
        &encrypt_args)
}

/// Decrypt a plaintext buffer with a userspace service.
pub fn decrypt(
    uservs: &'static dyn UserspaceServiceAccess,
    caller: &'static dyn UserspaceServiceClient,
    ckey: &[u8; CKEY_LEN_MAX],
    nonce: &[u8; NONCE_LEN_MAX],
    in_ciphertext: &[u8; MESSAGE_LEN_MAX],
    in_aad: &[u8; AAD_LEN_MAX],
    expected_tag: &[u8; TAG_LEN_MAX],
    out_plaintext: &[u8; MESSAGE_LEN_MAX],
    message_len: usize,
    aad_len: usize,
) -> Result<(), Error>
{
    let decrypt_args = [
        Argument::Bytes(ckey),
        Argument::Bytes(nonce),
        Argument::Buffer(in_ciphertext),
        Argument::Buffer(in_aad),
        Argument::Buffer(out_plaintext),
        Argument::Buffer(expected_tag),
        Argument::U32(message_len as u32), // ENG: Hmm...
    ];

    uservs.usercall(
        caller,
        ROLE_ID,
        ops::DECRYPT,
        &decrypt_args)
}
