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

/// Cryptography userspace service provider kernel counterpart.
pub struct Mediator {
    userv_access: &'static dyn UserspaceServiceAccess,
    /// The user using the cryptography userspace service through this construct.
    client: &'static dyn AEADProviderClient,
    /// Client-provided buffers.
    crypt_buffers: OptionalCell<AEADTuple>,
}

impl Mediator {
    pub fn new(
        userv_access: &'static dyn UserspaceServiceAccess,
        client: &'static dyn AEADProviderClient,
        crypt_buffers: AEADTuple,
    ) -> Mediator
    {
        Mediator {
            userv_access,
            client,
            crypt_buffers: OptionalCell::new(crypt_buffers),
        }
    }
}

const PADDING_LEN: usize = 8;

/// Encryption interface for kernel-internal entities (even on behalf of userspace requests).
impl AEADProvider for Mediator {
    fn padding_size(&self) -> usize { PADDING_LEN }

    fn encrypt(
        &'static self,
        ckey: &[u8; CKEY_LEN_MAX],
        nonce: &'static mut [u8; NONCE_LEN_MAX],
        in_plaintext: &'static mut [u8; MESSAGE_LEN_MAX],
        in_aad: &'static mut [u8; AAD_LEN_MAX],
        out_ciphertext: &'static mut [u8; MESSAGE_LEN_MAX],
        out_tag: &'static mut [u8; TAG_LEN_MAX],
        message_len: usize,
        aad_len: usize,
    ) -> Result<(), (ErrorCode, AEADTuple)> {
        let encrypt_args = [
            Argument::Bytes(ckey),
            Argument::Bytes(nonce),
            Argument::U32(message_len as u32), // ENG: Hmm...
            Argument::Buffer(in_plaintext),
            Argument::Buffer(in_aad),
            Argument::Buffer(out_ciphertext),
            Argument::Buffer(out_tag),
        ];

        // Send request via the userspace service capsule.
        let invoke_res = self.userv_access.usercall(
            self,
            ROLE_ID,
            ops::ENCRYPT,
            &encrypt_args);

        if invoke_res.is_ok() {
            // Take ownership of the buffers.
            self.crypt_buffers.set((
                nonce,
                in_plaintext,
                in_aad,
                out_ciphertext,
                out_tag,
            ));

            Ok(())
        } else {
            Err((ErrorCode::FAIL,
                 (nonce,
                  in_plaintext,
                  in_aad,
                  out_ciphertext,
                  out_tag)))
        }
    }

    fn decrypt(
        &'static self,
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
                                 &'static mut [u8; TAG_LEN_MAX]))>
    {
        unimplemented!()
    }

    /// Set the client.
    ///
    /// Do not use this function; it has no effect.
    /// The client is set with the creation of the `Mediator`.
    fn set_client(&self, client: &'static dyn AEADProviderClient) {  }
}

impl UserspaceServiceClient for Mediator {
    fn usercall_done(&self, args: &ArgumentReader) {
        // Use the AEAD client interface to send result to the original caller.

    }
}
