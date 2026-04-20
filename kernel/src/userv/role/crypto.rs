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
use crate::process::Error;
use crate::userv::comm::{
    Argument,
    UsercallArguments,
    UserspaceServiceAccess,
    UserspaceServiceClient,
};
use crate::userv::tl::ArgumentReader;
use crate::utilities::cells::OptionalCell;

/// Cryptography userspace service role ID.
pub const ROLE_ID: usize = 0xA0;

/// Cryptographic operations.
pub mod ops {
    pub const ENCRYPT: usize = 0x10;
    pub const DECRYPT: usize = 0x20;
}

// TODO: padding length should come from the userspace service.
/// Plaintext buffer padding byte length.
pub const PADDING_LEN: usize = 8;

pub struct ServiceInterface {
    userv_access: &'static dyn UserspaceServiceAccess,
    /// The client for the cryptographic userspace service through this entity.
    client: OptionalCell<&'static dyn AEADProviderClient>,
    /// Client-provided buffers.
    aead_buffers: OptionalCell<AEADTuple>,
}

impl ServiceInterface {
    pub fn new(
        userv_access: &'static dyn UserspaceServiceAccess,
    ) -> ServiceInterface
    {
        ServiceInterface {
            userv_access,
            client: OptionalCell::empty(),
            aead_buffers: OptionalCell::empty(),
        }
    }
}

impl AEADProvider for ServiceInterface {
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
            UsercallArguments::Extended(&encrypt_args));

        if invoke_res.is_ok() {
            // Take ownership of the buffers while the request is outstanding.
            // This is the expectation of a typical, hardware-backed provider.
            self.aead_buffers.set((
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
    fn set_client(&self, client: &'static dyn AEADProviderClient) {
        self.client.set(client)
    }
}

impl UserspaceServiceClient for ServiceInterface {
    fn usercall_done<'a>(&self, _role_id: usize, operation_id: usize, args: &ArgumentReader<'a>) {
        let (nonce_buf, pt_buf, aad_buf, ct_buf, tag_buf) = self.aead_buffers.take()
        // Should have always taken ownership of AEAD buffers on call to encrypt/decrypt,
        // and should only get one callback from the userspace service.
            .unwrap();
        match operation_id {
            ops::ENCRYPT => {
                self.client.map(
                    |client| {
                        client.encrypt_done(
                            nonce_buf,
                            pt_buf,
                            ct_buf,
                            aad_buf,
                            tag_buf)
                    });
            },

            ops::DECRYPT => {
                self.client.map(
                    |client| {
                        client.decrypt_done(
                            nonce_buf,
                            ct_buf,
                            pt_buf,
                            aad_buf,
                            tag_buf,
                            true) // TODO: tag_matches should come from userspace service as return argument.
                    });
            },

            // Ignore unknown operation codes.
            _ => {  }
        };
    }
}

/// Encrypt a plaintext buffer with a userspace service.
pub fn encrypt(
    uservs: &'static dyn UserspaceServiceAccess,
    caller: &'static dyn UserspaceServiceClient,
    ckey: &[u8; CKEY_LEN_MAX],
    nonce: &'static mut [u8; NONCE_LEN_MAX],
    in_plaintext: &'static mut [u8; MESSAGE_LEN_MAX],
    in_aad: &'static mut [u8; AAD_LEN_MAX],
    out_ciphertext: &'static mut [u8; MESSAGE_LEN_MAX],
    out_tag: &'static mut [u8; TAG_LEN_MAX],
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
        UsercallArguments::Extended(&encrypt_args))
}
