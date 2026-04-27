/*! ISLE network isolation layer.
 */

use core::default::Default;


pub use kernel::crypto::config::{
    AAD_LEN_MAX,
    CKEY_LEN_MAX,
    MESSAGE_LEN_MAX,
    NONCE_LEN_MAX,
    TAG_LEN_MAX,
};
use kernel::crypto::provider::{
    AEADProvider,
    AEADProviderClient,
};
use kernel::debug;
use kernel::errorcode::ErrorCode;
use kernel::grant::{
    AllowRoCount,
    AllowRwCount,
    Grant,
    UpcallCount,
};
use kernel::process::{
    Error,
    ProcessId,
};
use kernel::processbuffer::{
    ReadableProcessBuffer,
    WriteableProcessBuffer,
};
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};
use kernel::utilities::cells::{
    OptionalCell,
    TakeCell,
};

pub const DRIVER_NO: usize = capsules_core::driver::NUM::Isle as usize;

/// Length of the interface identifier, the lower half of the IP address.
const IID_LEN: usize = 8;
/// Length of the sender ID; lower 64 bits of the IP address.
const SENDER_ID_LEN: usize = IID_LEN;
/// Length of the partial IV in bytes; uses the sender sequence no.
const PARTIAL_IV_LEN: usize = 4;

/// Allow buffer number for input messages.
const ALLOW_RO_NO_IN_BUFFER: usize = 0;
/// Allow buffer number of the received message.
const ALLOW_RO_NO_RECV_SRC_HOST: usize = 1;
/// Allow buffer number for output message.
const ALLOW_RW_NO_OUT_BUFFER: usize = 0;
/// Allow buffer number for the partial IV.
const ALLOW_RW_NO_RECV_PARTIAL_IV: usize = 1;

/// Upcall number for indicating completed processing of a message.
const UPCALL_OUT_MESSAGE_READY: usize = 0;

pub trait ISLEConfigurationProvider {
    fn init_context(&self, context: &mut [Realm]);
}

const ISLE_REALM_ID_OFFSET: usize = 6;
const ISLE_REALM_ID_LEN: usize = 2;
const ISLE_REALM_ADDR_OFFSET: usize = 0;
const ISLE_REALM_ADDR_LEN: usize = 6;
const ISLE_REALMS_MAX: usize = 2;

const ISLE_NULL_REALM_ID: [u8; ISLE_REALM_ID_LEN] = [0xFF; ISLE_REALM_ID_LEN];

pub struct Realm {
    // Structure of bytes:
    // <- LSB -- -- -- -- -- -- -- MSB ->
    //    [ 0  1  2  3  4  5  7  6   ]
    //
    // Ordering for reconstructing address (MSB first):
    //    [ 7  6  5  4  3  2  1  0   ]
    iid: [u8; IID_LEN],
    master_secret: [u8; 16],
    master_salt: [u8; 8],
    message_key: [u8; 16],
    hash_key: [u8; 16],
    sender_seq_no: u32,
}

impl Realm {
    /// Initialize Group OSCORE group parameters.
    pub fn init(
        &mut self,
        realm_id: u16,
        host_network_no: &[u8; 6],
        master_secret: &[u8; 16],
        master_salt: &[u8; 8],
    )
    {
        // Set the IID, composed of...
        // ... the realm ID (upper 16 bits)...
        self.iid[ISLE_REALM_ID_OFFSET..ISLE_REALM_ID_OFFSET+ISLE_REALM_ID_LEN]
            .copy_from_slice(&realm_id.to_le_bytes());
        // ... and the host network number (lower 48 bits).
        self.iid[ISLE_REALM_ADDR_OFFSET..ISLE_REALM_ADDR_OFFSET+ISLE_REALM_ADDR_LEN]
            .copy_from_slice(host_network_no);

        self.master_secret.copy_from_slice(master_secret);
        self.master_salt.copy_from_slice(master_salt);
    }

    fn is_null(&self) -> bool {
        self.iid[ISLE_REALM_ID_OFFSET..ISLE_REALM_ID_OFFSET+ISLE_REALM_ID_LEN]
            == ISLE_NULL_REALM_ID
    }

    fn realm_id(&self) -> u16 {
        self.iid[ISLE_REALM_ID_OFFSET] as u16
            | (self.iid[ISLE_REALM_ID_OFFSET+1] as u16) << 8
    }
}

impl Default for Realm {
    fn default() -> Realm {
        Realm {
            master_secret: [0x00; 16],
            master_salt: [0x00; 8],
            message_key: [0x00; 16],
            hash_key: [0x00; 16],
            iid: [
                0xFF, 0xFF, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            sender_seq_no: 0,
        }
    }
}

pub struct AppData {
    initialized: bool,
    realm_ctxs: [Realm; ISLE_REALMS_MAX],
}

impl AppData {
    fn get_realm(&self, realm_id: u16) -> Result<&Realm, Error> {
        let realm_id = realm_id.to_le_bytes();
        for realm in &self.realm_ctxs {
            if realm.iid[ISLE_REALM_ID_OFFSET..ISLE_REALM_ID_OFFSET+ISLE_REALM_ID_LEN] == realm_id {
                return Ok(realm);
            }
        }

        Err(Error::AddressOutOfBounds)
    }

    fn get_realm_mut(&mut self, realm_id: u16) -> Result<&mut Realm, Error> {
        let realm_id = realm_id.to_le_bytes();
        for realm in &mut self.realm_ctxs {
            if realm.iid[ISLE_REALM_ID_OFFSET..ISLE_REALM_ID_OFFSET+ISLE_REALM_ID_LEN] == realm_id {
                return Ok(realm);
            }
        }

        Err(Error::AddressOutOfBounds)
    }
}

impl Default for AppData {
    fn default() -> AppData {
        AppData {
            initialized: false,
            realm_ctxs: [
                Realm::default(),
                Realm::default(),
            ],
        }
    }
}

#[derive(Clone, Copy)]
struct PendingState {
    pid: ProcessId,
    message_len: u8,
}

// Fixed AAD data.
// Excludes the sender ID (address) and the partial IV (pIV).
const AAD_PREFIX: [u8; 11] = [
    // Array, 4 items.
    0b1000_0000 | 0b0000_0100,
    // Item 1, OSCORE version.
	1,
	// Item 2, Algorithms, array, 4 items.
    0b0100_0000 | 4,
    0b0000_0000 | 10,  // AEAD alg.: AES-CCM-16-64-128 => integer, 10.
    0b0000_0000 | 10,  // Group enc. alg.: AES-CCM-16-64-128 => integer, 10.
    0b0011_1001,       // Sig. alg.: EdDSA => -8 -> 2-byte unsigned integer extension, 7.
    0,
    7,
    0b0011_1001, // Pairwise key agreement: ECDG-SS + HKDF-256 => -27 -> 2-byte unsigned integer extension, 26.
    0,
    26,
];
const AAD_SENDER_ID_OFFSET: usize = AAD_PREFIX.len();
const AAD_PARTIAL_IV_OFFSET: usize = AAD_SENDER_ID_OFFSET + SENDER_ID_LEN;

/// Network-level isolation packet filter for applications.
pub struct Isle {
    config_provider: &'static dyn ISLEConfigurationProvider,
    aead: &'static dyn AEADProvider,
    app_data: Grant<AppData, UpcallCount<1>, AllowRoCount<2>, AllowRwCount<2>>,
    // TODO: move this to the application's grant data.
    // Initialize this in allocate_grant() with the application's IP6 address.
    pending_for: OptionalCell<PendingState>,

    // AEAD buffers.
    pt_buffer: TakeCell<'static, [u8; MESSAGE_LEN_MAX]>,
    ct_buffer: TakeCell<'static, [u8; MESSAGE_LEN_MAX]>,
    aad_buffer: TakeCell<'static, [u8; AAD_LEN_MAX]>,
    tag_buffer: TakeCell<'static, [u8; TAG_LEN_MAX]>,
    nonce_buffer: TakeCell<'static, [u8; NONCE_LEN_MAX]>,
}

impl Isle {
    /// Create a new instance.
    pub fn new(
        config_provider: &'static dyn ISLEConfigurationProvider,
        grant_data: Grant<AppData, UpcallCount<1>, AllowRoCount<2>, AllowRwCount<2>>,
        aead: &'static dyn AEADProvider,
        pt_buffer: &'static mut [u8; MESSAGE_LEN_MAX],
        ct_buffer: &'static mut [u8; MESSAGE_LEN_MAX],
        aad_buffer: &'static mut [u8; AAD_LEN_MAX],
        tag_buffer: &'static mut [u8; TAG_LEN_MAX],
        nonce_buffer: &'static mut [u8; NONCE_LEN_MAX],
    ) -> Isle {
        Isle {
            config_provider,
            aead,
            app_data: grant_data,
            pending_for: OptionalCell::empty(),

            pt_buffer: TakeCell::new(pt_buffer),
            ct_buffer: TakeCell::new(ct_buffer),
            aad_buffer: TakeCell::new(aad_buffer),
            tag_buffer: TakeCell::new(tag_buffer),
            nonce_buffer: TakeCell::new(nonce_buffer),
        }
    }

    /// Ensure the application's realm data in its grant is set up.
    fn check_init_realms(&self, pid: ProcessId) -> Result<(), Error> {
        if !self.app_data.enter(pid, |ad, _kad| ad.initialized)? {
            self.allocate_grant(pid)
        } else {
            Ok(())
        }
    }

    /// Perform prerequisite setup for encryption or decryption of ISLE message.
    fn prepare_crypt_op(
        &self,
        pid: ProcessId,
        realm_id: u16,
        is_send: bool,
    ) -> Result<usize, Error>
    {
        // Construct the AAD.
        let aad_len = self.build_aad(pid, realm_id, is_send)?;

        // Construct the nonce.
        // debug!("[isle] constructing nonce");
        self.app_data.enter(
            pid,
            |ad, _kad| {
                self.nonce_buffer.map_or(Err(Error::AlreadyInUse), |buf| {
                    if is_send {
                        let realm = ad.get_realm(realm_id)?;
                        let iid_bytes = &realm.iid;

                        // buf[0..realm.iid.len()]
                        //     .copy_from_slice(iid_bytes);
                        buf[0..ISLE_REALM_ID_LEN]
                            .copy_from_slice(&realm.realm_id().to_be_bytes());
                        buf[ISLE_REALM_ID_LEN..ISLE_REALM_ID_LEN+ISLE_REALM_ADDR_LEN]
                            .copy_from_slice(&iid_bytes[ISLE_REALM_ADDR_OFFSET..ISLE_REALM_ADDR_OFFSET+ISLE_REALM_ADDR_LEN]);

                        buf[iid_bytes.len()..iid_bytes.len()+realm.sender_seq_no.to_le_bytes().len()]
                            .copy_from_slice(&realm.sender_seq_no.to_le_bytes());
                    } else {
                        self.app_data.enter(
                            pid,
                            |_ad, kad| {
                                kad.get_readonly_processbuffer(ALLOW_RO_NO_RECV_SRC_HOST)?
                                    .enter(|b| b.copy_to_slice(&mut buf[0..b.len()]))?;
                                kad.get_readwrite_processbuffer(ALLOW_RW_NO_RECV_PARTIAL_IV)?
                                    .enter(|b| b.copy_to_slice(&mut buf[IID_LEN..IID_LEN+b.len()]))?;

                                Ok::<_, Error>(())
                            })
                            .flatten()?;
                    }

                    Ok(())
                })
            })??;

        // Copy the message into the capsule buffer.
        // Assign the right buffer depending on if this is a send or receive.
        // debug!("[isle] copying payload to capsule buffer");
        let (src_buffer, _dst_buffer) = if is_send {
            (&self.pt_buffer, &self.ct_buffer)
        } else {
            (&self.ct_buffer, &self.pt_buffer)
        };
        src_buffer.map_or(
            Err(Error::AlreadyInUse),
            |src_buf| {
                self.app_data.enter(
                    pid,
                    |_ad, kad| {
                        // When sending a message, the entire buffer has the message.
                        // When receiving a message, the last TAG_LEN_MAX bytes are the authentication tag bytes.
                        if is_send {
                            kad.get_readonly_processbuffer(ALLOW_RO_NO_IN_BUFFER)?
                                .enter(|pbuf| pbuf.copy_to_slice(&mut src_buf[0..pbuf.len()]))?;
                        } else {
                            kad.get_readonly_processbuffer(ALLOW_RO_NO_IN_BUFFER)?
                                .enter(
                                    |pbuf| {
                                        pbuf.get(0..(pbuf.len() - TAG_LEN_MAX))
                                            // ASSUME: the network stack allow'd an amount of bytes > TAG_LEN_MAX.
                                            // The new size buffer will always be greater with subtraction,
                                            // and Rust will panic on underflow.
                                            .unwrap()
                                            .copy_to_slice(&mut src_buf[0..(pbuf.len() - TAG_LEN_MAX)]);

                                        // Copy the rest of the bytes (tag).
                                        self.tag_buffer.map(
                                            |tag_buf| {
                                                pbuf.get((pbuf.len() - TAG_LEN_MAX)..pbuf.len())
                                                    .unwrap()
                                                    .copy_to_slice(tag_buf);
                                            }).unwrap(); // TODO: a panic here means the capsule is not taking ownership of buffers properly.
                                    })?;
                        }

                        Ok::<(), kernel::process::Error>(())
                    })
                    .flatten()
            })?;

        // debug!("[isle] prepare_crypt_op() done (AAD len.: {} B)", aad_len);

        Ok(aad_len)
    }

    /// Construct the AAD in the internal AAD buffer.
    fn build_aad(
        &self,
        pid: ProcessId,
        realm_id: u16,
        is_send: bool
    ) -> Result<usize, Error>
    {
        // debug!("[isle] constructing the AAD");
        self.aad_buffer.map_or(
            Err(Error::AlreadyInUse),
            |aad_buffer| {
                // Get this into the AAD buffer.
                aad_buffer[0..AAD_PREFIX.len()].copy_from_slice(&AAD_PREFIX);

                // Copy the...
                // - sender ID (in this implementation, the IID).
                // - partial IV (i.e., the sender sequence no.).
                if is_send {
                    // These values come from this device.
                    self.app_data.enter(
                        pid,
                        |ad, kad| {
                            // debug!("[isle] realm ID = {:x}", realm_id);
                            let realm = ad.get_realm(realm_id)?;
                            // debug!("[isle] copying IID to capsule AAD buffer");
                            let mut sender_id = [0u8; 8];
                            sender_id[0] = realm.iid[7];
                            sender_id[1] = realm.iid[6];
                            sender_id[2..8].copy_from_slice(&realm.iid[0..6]);
                            aad_buffer[AAD_SENDER_ID_OFFSET..AAD_SENDER_ID_OFFSET+realm.iid.len()]
                                .copy_from_slice(&sender_id);
                            let piv_buffer = realm.sender_seq_no.to_le_bytes();
                            aad_buffer[AAD_PARTIAL_IV_OFFSET..AAD_PARTIAL_IV_OFFSET+PARTIAL_IV_LEN]
                                .copy_from_slice(&piv_buffer);
                            // Give the pIV to the network stack as well, which will place it into the packet.
                            // kad.get_readwrite_processbuffer(ALLOW_RW_NO_RECV_PARTIAL_IV)?
                            //     .mut_enter(
                            //         |b| {
                            //             debug!("{} vs. {}", b.len(), piv_buffer.len());
                            //             b.copy_from_slice(&piv_buffer);
                            //     })?;
                            kad.get_readwrite_processbuffer(ALLOW_RW_NO_RECV_PARTIAL_IV)?
                                .mut_enter(|b| b.copy_from_slice(&piv_buffer))?;

                            // debug!("AAD:");
                            // let (aad_chunks, aad_rem) = aad_buffer.as_chunks::<4>();
                            // for chunk in aad_chunks {
                            //     debug!("{:02x} {:02x} {:02x} {:02x}",
                            //            chunk[0], chunk[1],
                            //            chunk[2], chunk[3]);
                            // }
                            // for x in aad_rem {
                            //     debug!("{:02x}", x);
                            // }

                            // Return the length of the AAD.
                            // debug!("[isle] done copying, length of AAD = {}", AAD_PARTIAL_IV_OFFSET + PARTIAL_IV_LEN);
                            Ok(AAD_PARTIAL_IV_OFFSET + PARTIAL_IV_LEN)
                        })
                } else {
                    // These values come from the sender.
                    // The Isle layer in the network stack will provide this value.
                    self.app_data.enter(
                        pid,
                        |_ad, kad| {
                            kad.get_readonly_processbuffer(ALLOW_RO_NO_RECV_SRC_HOST)?
                                .enter(|b| b.copy_to_slice(&mut aad_buffer[AAD_SENDER_ID_OFFSET..AAD_SENDER_ID_OFFSET+SENDER_ID_LEN]))?;

                            kad.get_readwrite_processbuffer(ALLOW_RW_NO_RECV_PARTIAL_IV)?
                                .enter(|b| b.copy_to_slice(&mut aad_buffer[AAD_PARTIAL_IV_OFFSET..AAD_PARTIAL_IV_OFFSET+PARTIAL_IV_LEN]))?;

                            // debug!("AAD:");
                            // let (aad_chunks, aad_rem) = aad_buffer.as_chunks::<4>();
                            // for chunk in aad_chunks {
                            //     debug!("{:02x} {:02x} {:02x} {:02x}",
                            //            chunk[0], chunk[1],
                            //            chunk[2], chunk[3]);
                            // }
                            // for x in aad_rem {
                            //     debug!("{:02x}", x);
                            // }


                            // Return the length of the AAD.
                            Ok(AAD_PARTIAL_IV_OFFSET + PARTIAL_IV_LEN)
                        })
                }
            })
            .flatten()
    }

    /// Encrypt a message for transmission over the network.
    fn encrypt_send(
        &self,
        pid: ProcessId,
        realm_id: u16,
        aad_len: usize,
    ) -> Result<usize, Error>
    {
        // Set up pending state here so that there cannot be a race between
        // setting up the pending state and completing the encryption operation.
        // debug!("[isle] setting up pending state");
        let (raw_message_len, message_len) = self.app_data.enter(
            pid,
            |_ad, kad| {
                let padding_size = self.aead.padding_size();
                kad.get_readonly_processbuffer(ALLOW_RO_NO_IN_BUFFER)
                    .map(|b| (b.len(), b.len() + (padding_size - b.len() % padding_size)))
            })
            .flatten()?;
        debug!("[isle] encrypting {} B message ({} B padded)", raw_message_len, message_len);
        self.pending_for.set(PendingState {
            pid,
            message_len: message_len as u8,
        });

        // Get the key from the application's grant data.
        debug!("[isle] fetching ckey");
        let mut ckey = [0u8; CKEY_LEN_MAX];
        self.app_data.enter(
            pid,
            |ad, _kad| {
                let realm = ad.get_realm(realm_id)?;
                ckey.copy_from_slice(&realm.message_key);

                Ok(())
            })??;

        // Perform the encryption.
        // debug!("[isle] calling encryption provider");
        let encrypt_result = self.aead.encrypt(
            &ckey,
            self.nonce_buffer.take().ok_or(Error::AlreadyInUse)?,
            self.pt_buffer.take().ok_or(Error::AlreadyInUse)?,
            self.aad_buffer.take().ok_or(Error::AlreadyInUse)?,
            self.ct_buffer.take().ok_or(Error::AlreadyInUse)?,
            self.tag_buffer.take().ok_or(Error::AlreadyInUse)?,
            message_len,
            aad_len);

        if let Err((_ec, (nonce_buf, pt_buf, aad_buf, ct_buf, tag_buf))) = encrypt_result {
            debug!("[isle] encryption provider failed");
            self.nonce_buffer.put(Some(nonce_buf));
            self.pt_buffer.put(Some(pt_buf));
            self.aad_buffer.put(Some(aad_buf));
            self.ct_buffer.put(Some(ct_buf));
            self.tag_buffer.put(Some(tag_buf));

            self.pending_for.clear();

            Err(Error::KernelError)
        } else {
            // Increment the SSN.
            self.app_data.enter(
                pid,
                |ad, _kad| {
                    let realm = ad.get_realm_mut(realm_id)?;
                    realm.sender_seq_no += 1;

                    Ok(())
                })??;

            Ok(message_len)
        }
    }

    /// Decrypt a message that was received over the network.
    ///
    /// Performs a check that the HMAC tag matches the expected value
    /// and then triggers a decryption operation on the ciphertext.
    fn decrypt_recv(
        &self,
        pid: ProcessId,
        realm_id: u16,
        aad_len: usize,
    ) -> Result<(), Error>
    {
        let message_len = self.app_data.enter(
            pid,
            |_ad, kad| {
                kad.get_readonly_processbuffer(ALLOW_RO_NO_IN_BUFFER)
                    .map(|b| b.len() - TAG_LEN_MAX)
            })
            .flatten()?;

        // Set up the pending state.
        // See the note in encrypt_send().
        self.pending_for.set(PendingState {
            pid,
            message_len: message_len as u8,
        });

        // Get the key from the application's grant data.
        let mut ckey = [0u8; CKEY_LEN_MAX];
        self.app_data.enter(
            pid,
            |ad, _kad| {
                let realm = ad.get_realm(realm_id)?;
                ckey.copy_from_slice(&realm.message_key);

                Ok::<_, Error>(())
            })??;

        // Perform the decryption.
        let decrypt_result = self.aead.decrypt(
            &ckey,
            self.nonce_buffer.take().ok_or(Error::AlreadyInUse)?,
            self.ct_buffer.take().ok_or(Error::AlreadyInUse)?,
            self.aad_buffer.take().ok_or(Error::AlreadyInUse)?,
            self.tag_buffer.take().ok_or(Error::AlreadyInUse)?,
            self.pt_buffer.take().ok_or(Error::AlreadyInUse)?,
            message_len,
            aad_len);

        if let Err((_ec, (nonce_buf, pt_buf, aad_buf, ct_buf, tag_buf))) = decrypt_result {
            self.nonce_buffer.put(Some(nonce_buf));
            self.pt_buffer.put(Some(pt_buf));
            self.aad_buffer.put(Some(aad_buf));
            self.ct_buffer.put(Some(ct_buf));
            self.tag_buffer.put(Some(tag_buf));

            self.pending_for.clear();

            Err(Error::KernelError)
        } else {
            // debug!("[isle] started decrypting payload");
            Ok(())
        }
    }
}

const COMMAND_CHECK: usize   = 0x00;
const COMMAND_ENCRYPT: usize = 0x01;
const COMMAND_DECRYPT: usize = 0x02;
const COMMAND_QUERY: usize   = 0x0A;

impl SyscallDriver for Isle {
    fn command(
        &self,
        command_no: usize,
        r2: usize,
        r3: usize,
        pid: ProcessId,
    ) -> CommandReturn {
        // Make sure the application's Isle grant is initialized.
        if let Err(_kerr) = self.check_init_realms(pid) {
            CommandReturn::failure(ErrorCode::FAIL)
        } else {
            match (command_no, r2, r3) {
                (COMMAND_CHECK, _r2, _r3) => CommandReturn::success(),

                // Translate CoAP message to Group OSCORE.
                (COMMAND_ENCRYPT, dst_host_lower, _dst_host_upper) => {
                    // debug!("[isle] application wants to send to {:x} {:x}", dst_host_lower, dst_host_upper);
                    // Get the application's provided buffers' lengths.
                    let app_buffer_lens_res = self.app_data.enter(
                        pid,
                        |_ad, kad| {
                            (kad.get_readonly_processbuffer(ALLOW_RO_NO_IN_BUFFER).map(|b| b.len()),
                             kad.get_readwrite_processbuffer(ALLOW_RW_NO_OUT_BUFFER).map(|b| b.len()))
                        });

                    match app_buffer_lens_res {
                        // Check that the buffers are appropriately sized.
                        // The application's ciphertext buffer must both
                        // be at least as long as the plaintext buffer
                        // and fit the AEAD provider's padding requirements.
                        Ok((Ok(pt_buffer_len), Ok(ct_buffer_len))) => {
                            let pad = self.aead.padding_size();
                            let padding_byte_count = pad - (pt_buffer_len % pad);

                            // debug!("[isle] {} >= {} + {} ?",
                            //        ct_buffer_len,
                            //        pt_buffer_len,
                            //        padding_byte_count);
                            if ct_buffer_len >= pt_buffer_len + padding_byte_count {
                                // Numbers from the network stack are big-endian.
                                // So, the realm ID is actually in the lower two bytes.
                                let realm_id = ((dst_host_lower & 0xFFFF) as u16).swap_bytes();
                                let operation_res = self.prepare_crypt_op(pid, realm_id, true)
                                    .and_then(|aad_len| self.encrypt_send(pid, realm_id, aad_len));
                                match operation_res {
                                    Ok(_msg_len) => CommandReturn::success(),

                                    Err(kerr) => CommandReturn::failure(ErrorCode::from(kerr)),
                                }
                            } else {
                                CommandReturn::failure(ErrorCode::NOMEM)
                            }
                        },

                        // Either or both of the buffers were inaccessible from the grant operation.
                        // It does not matter why the operation could not get the buffer lengths,
                        // if the application is around, we will return NOMEM.
                        _ => CommandReturn::failure(ErrorCode::NOMEM),
                    }
                },

                // Translate a received message from Group OSCORE to CoAP.
                // TODO: use the source IID in processing the packet.
                (COMMAND_DECRYPT, src_host_lower, _src_host_upper) => {
                    // Get the application's buffers' lengths.
                    let app_buffer_lens_res = self.app_data.enter(
                        pid,
                        |_ad, kad| {
                            (kad.get_readonly_processbuffer(ALLOW_RO_NO_IN_BUFFER).map(|b| b.len()),
                             kad.get_readwrite_processbuffer(ALLOW_RW_NO_OUT_BUFFER).map(|b| b.len()))
                        });

                    // Check that buffers are appropriately sized.
                    // The application's plaintext buffer must be at least the size of the ciphertext buffer.
                    match app_buffer_lens_res {
                        Ok((Ok(ct_buffer_len), Ok(pt_buffer_len))) => {
                            if pt_buffer_len < ct_buffer_len {
                                CommandReturn::failure(ErrorCode::NOMEM)
                            } else {
                                let realm_id = ((src_host_lower & 0xFFFF) as u16).swap_bytes();
                                // debug!("Received packet in realm {:X}", realm_id);
                                let operation_res = self.prepare_crypt_op(pid, realm_id, false)
                                    .and_then(|aad_len| self.decrypt_recv(pid, realm_id, aad_len));
                                match operation_res {
                                    Ok(()) => CommandReturn::success(),
                                    Err(kerr) => {
                                        // debug!("Failed to start decrypt: {:?}", kerr);
                                        CommandReturn::failure(ErrorCode::from(kerr))
                                    }
                                }
                            }
                        },

                        _ => {
                            // debug!("[isle] application did not provide buffers");
                            CommandReturn::failure(ErrorCode::NOMEM)
                        },
                    }
                },

                // Retrieve application-accessible realm data.
                (COMMAND_QUERY, realm_idx, data_id) => {
                    const REALM_ID: usize = 0;
                    const IID: usize = 1;

                    self.app_data.enter(
                        pid,
                        |ad, _kad| {
                            if let Some(realm) = ad.realm_ctxs.get(realm_idx) {
                                if realm.is_null() {
                                    CommandReturn::failure(ErrorCode::NODEVICE)
                                } else {
                                    match data_id {
                                        REALM_ID => CommandReturn::success_u32(realm.realm_id() as u32),
                                        IID => CommandReturn::success_u64(
                                            (realm.iid[0] as u64)
                                                | (realm.iid[1] as u64) <<  8
                                                | (realm.iid[2] as u64) << 16
                                                | (realm.iid[3] as u64) << 24
                                                | (realm.iid[4] as u64) << 32
                                                | (realm.iid[5] as u64) << 40),
                                        _ => CommandReturn::failure(ErrorCode::INVAL),
                                    }
                                }
                            } else {
                                CommandReturn::failure(ErrorCode::NODEVICE)
                            }
                        })
                        .unwrap_or(CommandReturn::failure(ErrorCode::FAIL))
                },

                _ => CommandReturn::failure(ErrorCode::INVAL),
            }
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> Result<(), Error> {
        self.app_data.enter(pid, |ad, _kad| {
            // Get the context provider to set Group OSCORE parameters.
            self.config_provider.init_context(&mut ad.realm_ctxs);

            for ctx in &mut ad.realm_ctxs {
                // 0xFFFF means this is not an active context.
                if ctx.is_null() {
                    continue;
                }

                // Build input for key derivation.
                // Input:
                //  8 B <= salt
                // 16 B <= secret
                //  2 B <= key length
                //  8 B <= sender ID <= IP6 IID
                //  2 B <= group ID
                //  2 B <= encryption algorithm ID
                //  3 B <= "key"
                //  2 B <= key length (yes, again)
                let mut kd_input: [u8; 43] = [0; 43];
                kd_input[0..8].copy_from_slice(&ctx.master_salt);
                kd_input[8..24].copy_from_slice(&ctx.master_secret);
                // ENG: these are commented out for debugging to ensure the sender and receiver derive the same key.
                // This does not change the amount of computational work that goes into key derivation, though.
                // kd_input[24..26].copy_from_slice(&CKEY_LEN_BITS.to_be_bytes());
                // kd_input[26..28].copy_from_slice(&ctx.iid[ISLE_REALM_ID_OFFSET..ISLE_REALM_ID_OFFSET+ISLE_REALM_ID_LEN]);
                // kd_input[28..34].copy_from_slice(&ctx.iid[ISLE_REALM_ADDR_OFFSET..ISLE_REALM_ADDR_OFFSET+ISLE_REALM_ADDR_LEN]);
                // kd_input[34..36].copy_from_slice(&ctx.iid[ISLE_REALM_ID_OFFSET..ISLE_REALM_ID_OFFSET+ISLE_REALM_ID_LEN]);
                // // ENG: specific encryption algorithm ID intentionally not filled in.
                // kd_input[36..38].copy_from_slice(&[00, 00]);
                // kd_input[38..41].copy_from_slice(&['k' as u8, 'e' as u8, 'y' as u8]);
                // kd_input[41..43].copy_from_slice(&CKEY_LEN_BITS.to_be_bytes());

                // Derive the encryption key.
                use kernel::crypto::alg::ascon;
                let mut crypt_buffer: [u8; 32] = [0; 32];
                ascon::hash256(&[], &kd_input, &mut crypt_buffer).unwrap();
                // Save it in the application's grant.
                ctx.message_key.copy_from_slice(&crypt_buffer[..16]);

                // Derive the MAC key.
                // TODO: how does OSCORE dictate that this happen?
                for b in &mut crypt_buffer[0..16] { *b ^= ctx.master_salt[0]; }
                ctx.hash_key.copy_from_slice(&crypt_buffer[0..16]);
            }

            ad.initialized = true;
        })
    }
}

impl AEADProviderClient for Isle {
    fn encrypt_done(
        &self,
        nonce_buffer: &'static mut [u8; NONCE_LEN_MAX],
        plaintext_buffer: &'static mut [u8; MESSAGE_LEN_MAX],
        ciphertext_buffer: &'static mut [u8; MESSAGE_LEN_MAX],
        aad_buffer: &'static mut [u8; AAD_LEN_MAX],
        tag_buffer: &'static mut [u8; TAG_LEN_MAX],
    )
    {
        self.pending_for.map(|current_state| {
            let _enter_result = self.app_data.enter(
                current_state.pid,
                |_ad, kad| {
                    // debug!("[isle] writing result back to application buffers");
                    // Copy the ciphertext and tag to the application's buffer.
                    // Use the const-defined HMAC tag length.
                    let write_res = kad.get_readwrite_processbuffer(ALLOW_RW_NO_OUT_BUFFER)
                        .map(|out_procbuf| {
                            out_procbuf.mut_enter(|out_buf| {
                                out_buf.get(0..current_state.message_len as usize)
                                    .unwrap()
                                    .copy_from_slice(&ciphertext_buffer[0..current_state.message_len as usize]);
                                out_buf.get(current_state.message_len as usize..(current_state.message_len as usize + TAG_LEN_MAX))
                                    .unwrap()
                                    .copy_from_slice(&tag_buffer[0..TAG_LEN_MAX]);
                            })
                        }).flatten();

                    if write_res.is_ok() {
                        // Notify the application layer that this payload is ready to send.
                        // The total length includes the length of the HMAC tag.
                        let total_len = current_state.message_len as usize + TAG_LEN_MAX;
                        let _upcall_result = kad.schedule_upcall(
                            UPCALL_OUT_MESSAGE_READY,
                            (0, total_len as usize, 0))
                            .map_err(|e| debug!("[isle] message ready upcall error: {:?}", e));
                    } else {
                        // debug!("[isle] failed to write data back to application buffer");
                    }
                });
        });

        // Reset capsule state.
        // These buffers belongs back with the capsule.
        self.nonce_buffer.put(Some(nonce_buffer));
        self.pt_buffer.put(Some(plaintext_buffer));
        self.aad_buffer.put(Some(aad_buffer));
        self.ct_buffer.put(Some(ciphertext_buffer));
        self.tag_buffer.put(Some(tag_buffer));

        self.pending_for.clear();
    }

    fn decrypt_done(
        &self,
        nonce_buffer: &'static mut [u8; NONCE_LEN_MAX],
        ciphertext_buffer: &'static mut [u8; MESSAGE_LEN_MAX],
        plaintext_buffer: &'static mut [u8; MESSAGE_LEN_MAX],
        aad_buffer: &'static mut [u8; AAD_LEN_MAX],
        tag_buffer: &'static mut [u8; TAG_LEN_MAX],
        tag_matches: bool,
    )
    {
        if !tag_matches {
            // The tag does not match.
            // The message is malformed or an intermediary has tampered with it.
            // debug!("[isle] message not authenticated; dropping");
            let _enter_result = self.app_data.enter(
                // A failed unwrap() here means that the capsule is not tracking state correctly.
                self.pending_for.map(|current_state| current_state.pid).unwrap(),
                |_ad, kad| {
                    let _upcall_result = kad.schedule_upcall(
                        UPCALL_OUT_MESSAGE_READY,
                        (1, 0, 0));
                });
        } else {
            // The tag matches, so the plaintext is authentic.
            // Give the application the payload data in the plaintext buffer.
            let (pid, msg_len) = self.pending_for.map(|p| (p.pid, p.message_len as usize))
                .unwrap();
            let copy_result: Result<_, _> = self.app_data.enter(
                pid,
                |_ad, kad| {
                    kad.get_readwrite_processbuffer(ALLOW_RW_NO_OUT_BUFFER)?
                        .mut_enter(
                            |app_out_buffer| {
                                app_out_buffer.get(0..msg_len)
                                    .map(|s| s.copy_from_slice(&plaintext_buffer[0..msg_len]))
                                    .ok_or(kernel::process::Error::AddressOutOfBounds)
                            })
                });
            if copy_result.is_err() {
                // debug!("[isle] error copying back to application buffer");
            }
        }

        // Put buffers back.
        self.nonce_buffer.put(Some(nonce_buffer));
        self.pt_buffer.put(Some(plaintext_buffer));
        self.aad_buffer.put(Some(aad_buffer));
        self.ct_buffer.put(Some(ciphertext_buffer));
        self.tag_buffer.put(Some(tag_buffer));

        self.pending_for.clear();
    }
}
