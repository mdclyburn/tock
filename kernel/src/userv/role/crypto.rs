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
use crate::processbuffer::{
    ReadableProcessBuffer,
};
use crate::userv::comm::{
    ReturnValueReader,
    UsercallArguments,
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

// TODO: padding length should come from the userspace service.
/// Plaintext buffer padding byte length.
pub const PADDING_LEN: usize = 8;

/// Cryptographic userspace service access provider.
pub struct ServiceInterface {
    /// Self-reference to avoid needing &'static self in HILs.
    self_userv_client: OptionalCell<&'static dyn UserspaceServiceClient>,
    /// Userspace service access interface.
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
            self_userv_client: OptionalCell::empty(),
            userv_access,
            client: OptionalCell::empty(),
            aead_buffers: OptionalCell::empty(),
        }
    }

    pub fn init(&'static self) {
        self.self_userv_client.set(self)
    }
}

impl AEADProvider for ServiceInterface {
    fn padding_size(&self) -> usize { PADDING_LEN }

    fn encrypt(
        &self,
        ckey: &[u8; CKEY_LEN_MAX],
        nonce: &'static mut [u8; NONCE_LEN_MAX],
        in_plaintext: &'static mut [u8; MESSAGE_LEN_MAX],
        in_aad: &'static mut [u8; AAD_LEN_MAX],
        out_ciphertext: &'static mut [u8; MESSAGE_LEN_MAX],
        out_tag: &'static mut [u8; TAG_LEN_MAX],
        message_len: usize,
        _aad_len: usize,
    ) -> Result<(), (ErrorCode, AEADTuple)> {
        use crate::userv::data::{Bytes, Serialize};

        let encrypt_args: [&dyn Serialize; 4] = [
            &Bytes(ckey),
            &Bytes(nonce),
            &Bytes(in_plaintext),
            &Bytes(in_aad),
        ];

        // Send request via the userspace service capsule.
        if let Some(userv_client) = self.self_userv_client.get() {
                let invoke_res = self.userv_access.usercall(
                    userv_client,
                    ROLE_ID,
                    ops::ENCRYPT,
                    UsercallArguments::Extended(Some(message_len), None, &encrypt_args));

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
        } else {
            Err((ErrorCode::FAIL,
                 (nonce,
                  in_plaintext,
                  in_aad,
                  out_ciphertext,
                  out_tag)))
        }
    }

    #[allow(unused_variables)]
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
    fn usercall_done<'r, 'grant>(
        &self,
        _role_id: usize,
        operation_id: usize,
        args: Result<ReturnValueReader<'r, 'grant>, usize>,
    ) {
        let (nonce_buf, pt_buf, aad_buf, ct_buf, tag_buf) = self.aead_buffers.take()
        // Should have always taken ownership of AEAD buffers on call to encrypt/decrypt,
        // and should only get one callback from the userspace service.
            .unwrap();

        if let Ok(args) = args {
            match operation_id {
                ops::ENCRYPT => {
                    // Copy the ciphertext and the AAD into their respective buffers.
                    let userv_ret = (
                        args.buffer_n(0),
                        args.buffer_n(1));
                    if let (Some(ct), Some(aad)) = userv_ret {
                        let _r = ct.enter(|ro_buf| ro_buf.copy_to_slice(&mut ct_buf[0..ct.len()]));
                        let _r = aad.enter(|ro_buf| ro_buf.copy_to_slice(&mut aad_buf[0..aad.len()]));

                        // Provide the client with the resulting ciphertext and AAD.
                        self.client.map(
                            |client| {
                                client.encrypt_done(
                                    nonce_buf,
                                    pt_buf,
                                    ct_buf,
                                    aad_buf,
                                    tag_buf)
                            });
                    } else {
                        // What happens if the userspace service does not abide by the expected return format?
                        unimplemented!();
                    }
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
        } else {
            // Encrypt/decrypt operation failed.
            unimplemented!();
        }
    }
}
