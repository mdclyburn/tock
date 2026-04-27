/*! Cryptography providers.
 *
 * Interfaces providing cryptographic algorithm implementations that may be
 * either hardware- or software-based, promoting cryptographic agility.
 * Using these traits makes it simple to transparently switch algorithms.
 *
 * Trait objects backing these interfaces may either operate synchronously
 * or asynchronously, meaning that calling code (i.e., clients) must ensure
 * that receiving a callback from a provider will not cause a race condition
 * in the caller's code.
 */

use crate::crypto::config::{
    AAD_LEN_MAX,
    CKEY_LEN_MAX,
    MESSAGE_LEN_MAX,
    NONCE_LEN_MAX,
    TAG_LEN_MAX,
};
use crate::errorcode::ErrorCode;

pub type AEADTuple = (
    &'static mut [u8; NONCE_LEN_MAX],
    &'static mut [u8; MESSAGE_LEN_MAX],
    &'static mut [u8; AAD_LEN_MAX],
    &'static mut [u8; MESSAGE_LEN_MAX],
    &'static mut [u8; TAG_LEN_MAX]
);

/// Provider of authenticated encryption with authenticated additional data.
pub trait AEADProvider {
    /// Returns the block size the provider requires in plaintext.
    fn padding_size(&self) -> usize;

    /// Encrypt a message.
    fn encrypt(
        &self,
        ckey: &[u8; CKEY_LEN_MAX],
        nonce: &'static mut [u8; NONCE_LEN_MAX],
        in_plaintext: &'static mut [u8; MESSAGE_LEN_MAX],
        in_aad: &'static mut [u8; AAD_LEN_MAX],
        out_ciphertext: &'static mut [u8; MESSAGE_LEN_MAX],
        out_tag: &'static mut [u8; TAG_LEN_MAX],
        message_len: usize,
        aad_len: usize,
    ) -> Result<(), (ErrorCode, (&'static mut [u8; NONCE_LEN_MAX],
                                 &'static mut [u8; MESSAGE_LEN_MAX],
                                 &'static mut [u8; AAD_LEN_MAX],
                                 &'static mut [u8; MESSAGE_LEN_MAX],
                                 &'static mut [u8; TAG_LEN_MAX]))>;

    /// Decrypt a message.
    fn decrypt(
        &self,
        ckey: &[u8; CKEY_LEN_MAX],
        nonce: &'static mut [u8; NONCE_LEN_MAX],
        in_ciphertext: &'static mut [u8; MESSAGE_LEN_MAX],
        in_aad: &'static mut [u8; AAD_LEN_MAX],
        expected_tag: &'static mut [u8; TAG_LEN_MAX],
        out_plaintext: &'static mut [u8; MESSAGE_LEN_MAX],
        message_len: usize,
        aad_len: usize,
    ) -> Result<(), (ErrorCode, (&'static mut [u8; NONCE_LEN_MAX],
                                 &'static mut [u8; MESSAGE_LEN_MAX],
                                 &'static mut [u8; AAD_LEN_MAX],
                                 &'static mut [u8; MESSAGE_LEN_MAX],
                                 &'static mut [u8; TAG_LEN_MAX]))>;

    /// Set the client.
    fn set_client(
        &self,
        client: &'static dyn AEADProviderClient,
    );
}

pub trait AEADProviderClient {
    fn encrypt_done(
        &self,
        nonce_buffer: &'static mut [u8; NONCE_LEN_MAX],
        plaintext_buffer: &'static mut [u8; MESSAGE_LEN_MAX],
        ciphertext_buffer: &'static mut [u8; MESSAGE_LEN_MAX],
        aad_buffer: &'static mut [u8; AAD_LEN_MAX],
        tag_buffer: &'static mut [u8; TAG_LEN_MAX],
    );

    fn decrypt_done(
        &'static self,
        nonce_buffer: &'static mut [u8; NONCE_LEN_MAX],
        plaintext_buffer: &'static mut [u8; MESSAGE_LEN_MAX],
        ciphertext_buffer: &'static mut [u8; MESSAGE_LEN_MAX],
        aad_buffer: &'static mut [u8; AAD_LEN_MAX],
        tag_buffer: &'static mut [u8; TAG_LEN_MAX],
        tag_matches: bool,
    );
}
