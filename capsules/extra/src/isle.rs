/*! ISLE network isolation layer.
 */

use core::default::Default;

use kernel::errorcode::ErrorCode;
use kernel::grant::{
    AllowRoCount,
    AllowRwCount,
    Grant,
    UpcallCount,
};
use kernel::hil::symmetric_encryption::{
    AES128CCM,
    CCMClient,
};
use kernel::process::{
    Error,
    ProcessId,
};
use kernel::processbuffer::{
    ReadOnlyProcessBufferRef,
    ReadableProcessBuffer,
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
    sig_enc_key: [u8; 16],
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
            sig_enc_key: [0x00; 16],
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

const IP6_ADDR_LEN: usize = 16;
const ALLOW_NO_IN_BUFFER: usize = 0;
const ALLOW_NO_OUT_BUFFER: usize = 0;

pub struct Isle<'a> {
    config_provider: &'static dyn ISLEConfigurationProvider,
    crypt: &'a dyn AES128CCM<'a>,
    crypt_buffer: TakeCell<'static, [u8]>,
    app_data: Grant<AppData, UpcallCount<0>, AllowRoCount<1>, AllowRwCount<1>>,
    mleid_address: MapCell<[u8; IP6_ADDR_LEN]>,
    pending_for: OptionalCell<(ProcessId, (usize, usize))>,
}

impl<'a> Isle<'a> {
    pub fn new(
        config_provider: &'static dyn ISLEConfigurationProvider,
        crypt: &'a dyn AES128CCM<'a>,
        crypt_buffer: &'static mut [u8; 128],
        grant_data: Grant<AppData, UpcallCount<0>, AllowRoCount<1>, AllowRwCount<1>>,
    ) -> Isle<'a> {
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
    ) -> Result<(), ErrorCode>
    {
        // Set the key.
        self.crypt.set_key(&group_oscore_context.message_key)?;

        // Construct the nonce.
        self.crypt_buffer.map_or(Err(ErrorCode::BUSY), |buf| {
            // Use the least significant 7 bytes of the sender ID (IP6 host number).
            let sender_id_len = 7;
            buf[0] = sender_id_len;
            self.mleid_address.map(|addr| buf[1..1+7].copy_from_slice(&addr[9..16]));
            // Use four bytes from the SSN and pad with a zero byte.
            let ssn = &group_oscore_context.sender_seq_no;
            buf[8] = (*ssn & 0xFF) as u8;
            buf[9] =  (*ssn >>  8) as u8;
            buf[10] = (*ssn >> 16) as u8;
            buf[11] = (*ssn >> 24) as u8;
            buf[12] = 0u8;
            // Set the nonce.
            self.crypt.set_nonce(&buf[..13])
        })?;

        // Copy the payload into the capsule buffer.
        // AAD starts right after the message.
        let aad_offset = message_len;
        self.crypt_buffer.map(|buf| payload_buffer.enter(|pbuf| pbuf.copy_to_slice(&mut buf[0..pbuf.len()])));
        // self.crypt_buffer.map(|buf| buf[0..payload_buffer.len()].copy_from_slice(&payload_buffer));

        // Encrypt the payload.
        if let Err((ec, buf)) = self.crypt.crypt(
            // TODO: get rid of unwrap.
            self.crypt_buffer.take().unwrap(),
            aad_offset as usize,
            0,
            64,
            4,
            true,
            true)
        {
            self.crypt_buffer.put(Some(buf));
            Err(ec)
        } else {
            Ok(())
        }
    }
}

impl<'a> SyscallDriver for Isle<'a> {
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
                let mut crypt_key: [u8; 16] = [0; 16];
                let res = self.app_data.enter(pid, |ad, kad| {
                    // TODO: Dynamically choose the right context.
                    let group_oscore_ctx = &ad.group_oscore_ctxs[0];

                    let (res_in_buf, res_out_buf) = (
                        kad.get_readonly_processbuffer(ALLOW_NO_IN_BUFFER),
                        kad.get_readwrite_processbuffer(ALLOW_NO_OUT_BUFFER));
                    match (res_in_buf, res_out_buf) {
                        (Ok(in_buffer), Ok(out_buffer)) =>
                            self.encrypt_send(
                                group_oscore_ctx,
                                &in_buffer,
                                msg_len),

                        _ => Err(ErrorCode::FAIL)
                    }
                })
                    .map_err(|_e| ErrorCode::FAIL)
                    .flatten();

                match res {
                    Ok(()) => {
                        self.pending_for.set((pid, (msg_len, aad_len)));
                        CommandReturn::success()
                    },
                    Err(ec) => CommandReturn::failure(ErrorCode::FAIL),
                }
            },

            // Set lower half of IP address.
            (10, block01, block23) => {
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
        self.app_data.enter(pid, |ad, kad| {
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

impl<'a> CCMClient for Isle<'a> {
    fn crypt_done(
        &self,
        _buffer: &'static mut [u8],
        _op_result: Result<(), ErrorCode>,
        _tag_is_valid: bool,
    )
    {
        self.pending_for.map(|(pid, (msg_len, aad_len))| {
            self.app_data.enter(pid, |ad, kad| {
                // Encryption is done.
                // Generate the MAC and then the payload is ready.
            }).unwrap();
        });
    }
}
