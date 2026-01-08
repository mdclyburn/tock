/*! ISLE network isolation layer.
 */

use core::default::Default;

use kernel::debug;
use kernel::errorcode::ErrorCode;
use kernel::grant::{
    AllowRoCount,
    AllowRwCount,
    Grant,
    UpcallCount,
};
use kernel::hil::symmetric_encryption;
use kernel::hil::symmetric_encryption::{
    AES128,
    AES128CBC,
};
use kernel::process::{
    Error,
    ProcessId,
};
use kernel::processbuffer::{
    ReadOnlyProcessBufferRef,
    ReadableProcessBuffer,
    WriteableProcessBuffer,
};
use kernel::syscall::{
    CommandReturn,
    SyscallDriver,
};
use kernel::utilities::cells::{
    MapCell,
    OptionalCell,
    TakeCell,
};

pub const DRIVER_NO: usize = capsules_core::driver::NUM::Isle as usize;

const KEY_SIZE: u16 = 256;

pub trait ISLEConfigurationProvider {
    fn init_context(&self, context: &mut [GroupOSCOREContext]);
}

pub struct GroupOSCOREContext {
    group_id: u16,
    master_secret: [u8; 16],
    master_salt: [u8; 8],
    message_key: [u8; 16],
    hash_key: [u8; 16],
    sender_seq_no: u32,
}

impl GroupOSCOREContext {
    /// Initialize Group OSCORE group parameters.
    pub fn init(
        &mut self,
        group_id: u16,
        master_secret: &[u8; 16],
        master_salt: &[u8; 8],
    )
    {
        self.group_id = group_id;
        self.master_secret.copy_from_slice(master_secret);
        self.master_salt.copy_from_slice(master_salt);
    }
}

impl Default for GroupOSCOREContext {
    fn default() -> GroupOSCOREContext {
        GroupOSCOREContext {
            group_id: 0xFFFF,
            master_secret: [0x00; 16],
            master_salt: [0x00; 8],
            message_key: [0x00; 16],
            hash_key: [0x00; 16],
            sender_seq_no: 0,
        }
    }
}

pub struct AppData {
    group_oscore_ctxs: [GroupOSCOREContext; 2],
}

impl Default for AppData {
    fn default() -> AppData {
        AppData {
            group_oscore_ctxs: [
                GroupOSCOREContext::default(),
                GroupOSCOREContext::default(),
            ],
        }
    }
}

#[derive(Clone, Copy)]
struct PendingState {
    pid: ProcessId,
    ctx_no: u8,
    aad_len: u8,
    ciphertext_len: u8,
}

const IP6_ADDR_LEN: usize = 16;

const ALLOW_NO_IN_BUFFER: usize = 0;
const ALLOW_NO_OUT_BUFFER: usize = 0;
const UPCALL_OUT_MESSAGE_READY: usize = 0;

const HMAC_TAG_LEN: usize = 8;

pub trait Crypto: AES128<'static> + AES128CBC {  }
impl<T: AES128<'static> + AES128CBC> Crypto for T {  }

pub struct Isle {
    config_provider: &'static dyn ISLEConfigurationProvider,
    crypt: &'static dyn Crypto,
    crypt_buffer: TakeCell<'static, [u8]>,
    app_data: Grant<AppData, UpcallCount<1>, AllowRoCount<1>, AllowRwCount<1>>,
    mleid_address: MapCell<[u8; IP6_ADDR_LEN]>,
    pending_for: OptionalCell<PendingState>,
}

impl Isle {
    pub fn new(
        config_provider: &'static dyn ISLEConfigurationProvider,
        crypt: &'static dyn Crypto,
        crypt_buffer: &'static mut [u8; 128],
        grant_data: Grant<AppData, UpcallCount<1>, AllowRoCount<1>, AllowRwCount<1>>,
    ) -> Isle {
        Isle {
            config_provider,
            crypt,
            crypt_buffer: TakeCell::new(crypt_buffer),
            app_data: grant_data,
            mleid_address: MapCell::empty(),
            pending_for: OptionalCell::empty(),
        }
    }

    fn encrypt_send(
        &self,
        group_oscore_context: &GroupOSCOREContext,
        payload_buffer: &ReadOnlyProcessBufferRef,
        message_len: usize,
        aad_len: usize,
    ) -> Result<usize, ErrorCode>
    {
        // Set the mode, key, and IV encryption parameters.
        self.crypt.set_mode_aes128cbc(true)?;
        self.crypt.set_key(&group_oscore_context.message_key)?;
        self.crypt_buffer.map_or(Err(ErrorCode::BUSY), |buf| {
            self.mleid_address.map_or(Err(ErrorCode::OFF), |addr| {
                buf[0..8].copy_from_slice(&addr[0..8]);
                buf[8..12].copy_from_slice(&[
                    (group_oscore_context.sender_seq_no & 0xFF) as u8,
                    ((group_oscore_context.sender_seq_no >> 8) & 0xFF) as u8,
                    ((group_oscore_context.sender_seq_no >> 16) & 0xFF) as u8,
                    ((group_oscore_context.sender_seq_no >> 24) & 0xFF) as u8]);
                buf[13..16].copy_from_slice(&[0u8; 4]);
                self.crypt.set_iv(&buf[0..16])
            })
        })?;

        // Copy the message into the capsule buffer.
        self.crypt_buffer.map(|buf| {
            payload_buffer.enter(|pbuf| {
                // The message first.
                (&pbuf[0..message_len])
                    .copy_to_slice(&mut buf[0..message_len]);
                // AAD starts right after the message.
                // We move it to the end of the capsule's buffer and do not encrypt it.
                // It will later be used for HMAC tag calculation.
                //
                // This assumes that the AAD won't be overwritten between now and the HMAC calculation.
                // The padding and encryption are the only intermediate operations on the buffer.
                // Messages will be less than 64 bytes due to application layer payload size constraints.
                let crypt_buffer_len = buf.len();
                (&pbuf[message_len..message_len+aad_len])
                    .copy_to_slice(&mut buf[crypt_buffer_len - aad_len..]);
            })
        });

        // Encrypt the payload.
        let padded_len = self.crypt_buffer.map_or(
            Err(ErrorCode::BUSY),
            |buf| {
                pad_plaintext(
                    buf,
                    message_len,
                    symmetric_encryption::AES128_BLOCK_SIZE)
            })?;
        if let Some((ec, _src_buf, dst_buf)) = self.crypt.crypt(
            None,
            // TODO: get rid of unwrap.
            self.crypt_buffer.take().unwrap(),
            0,
            padded_len)
        {
            self.crypt_buffer.put(Some(dst_buf));
            ec.map(|_x| 0)
        } else {
            debug!("Started encrypting payload.");
            Ok(padded_len)
        }
    }
}

impl SyscallDriver for Isle {
    fn command(
        &self,
        command_no: usize,
        r2: usize,
        r3: usize,
        pid: ProcessId,
    ) -> CommandReturn {
        match (command_no, r2, r3) {
            (0, _r2, _r3) => CommandReturn::success(),

            // Translate CoAP message to Group OSCORE.
            (1, msg_len, aad_len) => {
                debug!("Mapping CoAP to Group OSCORE.");
                let res = self.app_data.enter(pid, |ad, kad| {
                    // TODO: Dynamically choose the right context.
                    let ctx_no: u8 = 0;
                    let group_oscore_ctx = &ad.group_oscore_ctxs[ctx_no as usize];

                    let (res_in_buf, res_out_buf) = (
                        kad.get_readonly_processbuffer(ALLOW_NO_IN_BUFFER),
                        kad.get_readwrite_processbuffer(ALLOW_NO_OUT_BUFFER));
                    match (res_in_buf, res_out_buf) {
                        (Ok(in_buffer), Ok(_out_buffer)) =>
                            self.encrypt_send(
                                group_oscore_ctx,
                                &in_buffer,
                                msg_len,
                                aad_len)
                            .map(|ciphertext_len| (ciphertext_len, ctx_no)),

                        _ => Err(ErrorCode::FAIL)
                    }
                })
                    .map_err(|_e| ErrorCode::FAIL)
                    .flatten();

                match res {
                    Ok((ciphertext_len, ctx_no)) => {
                        self.pending_for.set(PendingState {
                            pid,
                            ctx_no,
                            aad_len: aad_len as u8,
                            ciphertext_len: ciphertext_len as u8,
                        });
                        CommandReturn::success()
                    },
                    Err(_ec) => CommandReturn::failure(ErrorCode::FAIL),
                }
            },

            // Set lower half of IP address.
            (10, block01, block23) => {
                debug!("Set lower half of IP6 address.");
                self.mleid_address.map(|addr| {
                    addr[00] = ((block01 >> 00) & 0xFF) as u8;
                    addr[01] = ((block01 >> 08) & 0xFF) as u8;
                    addr[02] = ((block01 >> 16) & 0xFF) as u8;
                    addr[03] = ((block01 >> 24) & 0xFF) as u8;

                    addr[04] = ((block23 >> 00) & 0xFF) as u8;
                    addr[05] = ((block23 >> 08) & 0xFF) as u8;
                    addr[06] = ((block23 >> 16) & 0xFF) as u8;
                    addr[07] = ((block23 >> 24) & 0xFF) as u8;
                });
                CommandReturn::success()
            },

            // Set upper half of IP address.
            (20, block45, block67) => {
                debug!("Set upper half of IP6 address.");
                self.mleid_address.map(|addr| {
                    addr[08] = ((block45 >> 00) & 0xFF) as u8;
                    addr[09] = ((block45 >> 08) & 0xFF) as u8;
                    addr[10] = ((block45 >> 16) & 0xFF) as u8;
                    addr[11] = ((block45 >> 24) & 0xFF) as u8;

                    addr[12] = ((block67 >> 00) & 0xFF) as u8;
                    addr[13] = ((block67 >> 08) & 0xFF) as u8;
                    addr[14] = ((block67 >> 16) & 0xFF) as u8;
                    addr[15] = ((block67 >> 24) & 0xFF) as u8;
                });
                CommandReturn::success()
            },

            _ => CommandReturn::failure(ErrorCode::INVAL),
        }
    }

    fn allocate_grant(&self, pid: ProcessId) -> Result<(), Error> {
        self.app_data.enter(pid, |ad, _kad| {
            // Get the context provider to set Group OSCORE parameters.
            self.config_provider.init_context(&mut ad.group_oscore_ctxs);

            for ctx in &mut ad.group_oscore_ctxs {
                // Assume 0xFFFF means this is not an active context.
                if ctx.group_id == 0xFFFF {
                    continue;
                }

                // Build input for key derivation.
                // Input:
                //  8 B <= salt
                // 16 B <= secret
                //  2 B <= key length
                //  8 B <= sender ID <= IP6 host number
                //  2 B <= group ID
                //  2 B <= encryption algorithm ID
                //  3 B <= "key"
                //  2 B <= key length (yes, again)
                let mut kd_input: [u8; 43] = [0; 43];
                kd_input[0..8].copy_from_slice(&ctx.master_salt);
                kd_input[8..24].copy_from_slice(&ctx.master_secret);
                kd_input[24..26].copy_from_slice(&[(KEY_SIZE & 0xFF) as u8, (KEY_SIZE >> 8) as u8]);
                self.mleid_address.map(|addr| kd_input[26..34].copy_from_slice(&addr[8..16]));
                kd_input[34..36].copy_from_slice(&[
                    (ctx.group_id & 0xFF) as u8,
                    (ctx.group_id >> 8) as u8,
                ]);
                // ENG: specific encryption algorithm ID intentionally not filled in.
                kd_input[36..38].copy_from_slice(&[00, 00]);
                kd_input[38..41].copy_from_slice(&['k' as u8, 'e' as u8, 'y' as u8]);
                kd_input[41..43].copy_from_slice(&[(KEY_SIZE & 0xFF) as u8, (KEY_SIZE >> 8) as u8]);

                // Derive the encryption key.
                use kernel::crypto_sw::ascon;
                let mut crypt_buffer: [u8; 32] = [0; 32];
                ascon::hash256(&kd_input, &mut crypt_buffer).unwrap();
                // Save it in the application's grant.
                ctx.message_key.copy_from_slice(&crypt_buffer[..16]);

                // Derive the MAC key.
                // TODO: how does OSCORE dictate that this happen?
                for b in &mut crypt_buffer[0..16] { *b ^= ctx.master_salt[0]; }
                ctx.hash_key.copy_from_slice(&crypt_buffer[0..16]);
            }
        })
    }
}

impl symmetric_encryption::Client<'static> for Isle {
    fn crypt_done(
        &self,
        _plaintext_buffer: Option<&'static mut [u8]>,
        ciphertext_buffer: &'static mut [u8],
    )
    {
        debug!("Payload encryption done.");
        self.pending_for.map(|pending_state| {
            self.app_data.enter(pending_state.pid, |ad, kad| {
                // Build the input to the HMAC by reusing the ciphertext in the capsule's buffer.
                let (mut aad_src_offset, mut aad_dst_offset) = (
                    pending_state.ciphertext_len as usize,
                    ciphertext_buffer.len() - pending_state.aad_len as usize,
                );
                let mut ssn_marker_run = 0;
                while aad_dst_offset < ciphertext_buffer.len() {
                    // Fill in the SSN if we just finished copying its space.
                    if ssn_marker_run == 4 {
                        let ssn = ad.group_oscore_ctxs[pending_state.ctx_no as usize].sender_seq_no;
                        ciphertext_buffer[aad_dst_offset-4] = (ssn & 0xFF) as u8;
                        ciphertext_buffer[aad_dst_offset-3] = (ssn >> 1) as u8;
                        ciphertext_buffer[aad_dst_offset-2] = (ssn >> 2) as u8;
                        ciphertext_buffer[aad_dst_offset-1] = (ssn >> 3) as u8;
                        ad.group_oscore_ctxs[pending_state.ctx_no as usize].sender_seq_no += 1;
                    }

                    ciphertext_buffer[aad_src_offset] = ciphertext_buffer[aad_dst_offset];

                    // Check for the SSN marker.
                    if ciphertext_buffer[aad_src_offset] == 0xFE {
                        ssn_marker_run += 1;
                    }

                    aad_src_offset += 1;
                    aad_dst_offset += 1;
                }

                // Compute the HMAC.
                use kernel::crypto_sw::ascon;
                let mut hmac = [0u8; 32];
                ascon::hash256(
                    &ciphertext_buffer[0..pending_state.ciphertext_len as usize + pending_state.aad_len as usize],
                    &mut hmac)
                    .unwrap();

                // Copy the ciphertext and HMAC tag back to the application's buffer.
                // Use the const-defined HMAC tag length.
                let write_res = kad.get_readwrite_processbuffer(ALLOW_NO_OUT_BUFFER)
                    .map(|out_pbuf| {
                        out_pbuf.mut_enter(|out_buf| {
                            out_buf.get(0..pending_state.ciphertext_len as usize)
                                .unwrap()
                                .copy_from_slice(&ciphertext_buffer[0..pending_state.ciphertext_len as usize]);
                            out_buf.get(pending_state.ciphertext_len as usize..(pending_state.ciphertext_len + 8) as usize)
                                .unwrap()
                                .copy_from_slice(&hmac[0..HMAC_TAG_LEN]);
                        })
                    }).flatten();

                // Notify the application layer that this payload is ready to send.
                let total_len = pending_state.ciphertext_len as usize + HMAC_TAG_LEN;
                let _ = kad.schedule_upcall(
                    UPCALL_OUT_MESSAGE_READY,
                    (if write_res.is_ok() { 0 } else { 1 }, total_len as usize, 0))
                    .map_err(|e| debug!("[isle] message ready upcall error: {:?}", e));

                // Reset capsule state.
                // This buffer belongs back with the capsule.
                self.crypt_buffer.put(Some(ciphertext_buffer));
                self.pending_for.clear();

                if let Err(e) = write_res {
                    debug!("Error completing message protection: {:?}", e);
                }
            }).unwrap();
        });
    }
}

fn pad_plaintext(
    buffer: &mut [u8],
    payload_len: usize,
    block_size: usize
) -> Result<usize, ErrorCode>
{
    let mut padded_len = 0;
    while padded_len < payload_len {
        padded_len += block_size;
        if block_size > buffer.len() {
            return Err(ErrorCode::NOMEM)
        }
    }

    for b in &mut buffer[payload_len..] {
        *b = 0;
    }

    Ok(padded_len)
}
