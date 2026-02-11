/*! Configuration values for cryptographic operations.
 */

/// Maximum length for a cipher key.
pub const CKEY_LEN_MAX: usize = 16;

/// Maximum length of the plaintext and ciphertext buffers.
pub const MESSAGE_LEN_MAX: usize = 80;

/// Maximum length of the authenticated associated data (AAD) buffer.
pub const AAD_LEN_MAX: usize = 32;

/// Maximum length of the message authentication code tag buffer (<= 16).
pub const TAG_LEN_MAX: usize = 8;

/// Maximum length of the nonce buffer.
pub const NONCE_LEN_MAX: usize = 16;
