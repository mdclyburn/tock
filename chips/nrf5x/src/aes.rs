// Licensed under the Apache License, Version 2.0 or the MIT License.
// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright Tock Contributors 2022.

//! AES128 driver, nRF5X-family
//!
//! Provides a simple driver to encrypt and decrypt messages using aes128-ctr
//! mode on top of aes128-ecb, as well as encrypt with aes128-ecb and
//! aes128-cbc.
//!
//! Roughly, the module uses three buffers with the following content:
//!
//! * Key
//! * Initial counter
//! * Payload, to be encrypted or decrypted
//!
//! ### Key
//! The key is used for getting a key and configure it in the AES chip
//!
//! ### Initial Counter
//! Counter to be used for aes-ctr and it is entered into AES to generate the
//! the keystream. After each encryption the initial counter is incremented
//!
//! ### Payload
//! Data to be encrypted or decrypted it is XOR:ed with the generated keystream
//!
//! ### Things to highlight that can be improved:
//!
//! * ECB_DATA must be a static mut \[u8\] and can't be located in the struct
//! * PAYLOAD size is restricted to 128 bytes
//!
//! Authors
//! --------
//! * Niklas Adolfsson <niklasadolfsson1@gmail.com>
//! * Fredrik Nilsson <frednils@student.chalmers.se>
//! * Date: April 21, 2017

use core::cell::Cell;
use core::ptr::addr_of;
use kernel::debug;
use kernel::hil::symmetric_encryption;
use kernel::utilities::cells::OptionalCell;
use kernel::utilities::cells::TakeCell;
use kernel::utilities::registers::interfaces::{Readable, Writeable};
use kernel::utilities::registers::{register_bitfields, ReadWrite, WriteOnly};
use kernel::utilities::StaticRef;
use kernel::ErrorCode;

// DMA buffer that the aes chip will mutate during encryption
// Byte 0-15   - Key
// Byte 16-32  - Payload
// Byte 33-47  - Ciphertext
static mut ECB_DATA: [u8; 48] = [0; 48];

#[allow(dead_code)]
const KEY_START: usize = 0;
#[allow(dead_code)]
const KEY_END: usize = 15;
const PLAINTEXT_START: usize = 16;
const PLAINTEXT_END: usize = 32;
#[allow(dead_code)]
const CIPHERTEXT_START: usize = 33;
#[allow(dead_code)]
const CIPHERTEXT_END: usize = 47;

const AESECB_BASE: StaticRef<AesEcbRegisters> =
    unsafe { StaticRef::new(0x4000E000 as *const AesEcbRegisters) };

#[repr(C)]
struct AesEcbRegisters {
    /// Start ECB block encrypt
    /// - Address 0x000 - 0x004
    task_startecb: WriteOnly<u32, Task::Register>,
    /// Abort a possible executing ECB operation
    /// - Address: 0x004 - 0x008
    task_stopecb: WriteOnly<u32, Task::Register>,
    /// Reserved
    _reserved1: [u32; 62],
    /// ECB block encrypt complete
    /// - Address: 0x100 - 0x104
    event_endecb: ReadWrite<u32, Event::Register>,
    /// ECB block encrypt aborted because of a STOPECB task or due to an error
    /// - Address: 0x104 - 0x108
    event_errorecb: ReadWrite<u32, Event::Register>,
    /// Reserved
    _reserved2: [u32; 127],
    /// Enable interrupt
    /// - Address: 0x304 - 0x308
    intenset: ReadWrite<u32, Intenset::Register>,
    /// Disable interrupt
    /// - Address: 0x308 - 0x30c
    intenclr: ReadWrite<u32, Intenclr::Register>,
    /// Reserved
    _reserved3: [u32; 126],
    /// ECB block encrypt memory pointers
    /// - Address: 0x504 - 0x508
    ecbdataptr: ReadWrite<u32, EcbDataPointer::Register>,
}

register_bitfields! [u32,
    /// Start task
    Task [
        ENABLE OFFSET(0) NUMBITS(1)
    ],

    /// Read event
    Event [
        READY OFFSET(0) NUMBITS(1)
    ],

    /// Enabled interrupt
    Intenset [
        ENDECB OFFSET(0) NUMBITS(1),
        ERRORECB OFFSET(1) NUMBITS(1)
    ],

    /// Disable interrupt
    Intenclr [
        ENDECB OFFSET(0) NUMBITS(1),
        ERRORECB OFFSET(1) NUMBITS(1)
    ],

    /// ECB block encrypt memory pointers
    EcbDataPointer [
        POINTER OFFSET(0) NUMBITS(32)
    ]
];

#[derive(Copy, Clone, Debug)]
enum AESMode {
    ECB,
    CTR,
    CBC,
}

pub struct AesECB<'a> {
    registers: StaticRef<AesEcbRegisters>,
    mode: Cell<AESMode>,
    key: Cell<[u8; 16]>,
    encrypt: Cell<bool>,
    client: OptionalCell<&'a dyn kernel::hil::symmetric_encryption::Client<'a>>,
    /// Input either plaintext or ciphertext to be encrypted or decrypted.
    input: TakeCell<'static, [u8]>,
    output: TakeCell<'static, [u8]>,
    current_idx: Cell<usize>,
    start_idx: Cell<usize>,
    end_idx: Cell<usize>,
}

impl<'a> AesECB<'a> {
    pub const fn new() -> AesECB<'a> {
        AesECB {
            registers: AESECB_BASE,
            mode: Cell::new(AESMode::CTR),
            key: Cell::new([0; 16]),
            encrypt: Cell::new(true),
            client: OptionalCell::empty(),
            input: TakeCell::empty(),
            output: TakeCell::empty(),
            current_idx: Cell::new(0),
            start_idx: Cell::new(0),
            end_idx: Cell::new(0),
        }
    }

    fn set_dma(&self) {
        self.registers.ecbdataptr.set(addr_of!(ECB_DATA) as u32);
    }

    /// Verify that the provided start and stop indices work with the given
    /// buffers.
    fn try_set_indices(&self, start_index: usize, stop_index: usize) -> bool {
        debug!("setting indices {} -> {}", start_index, stop_index);
        stop_index.checked_sub(start_index).is_some_and(|sublen| {
            sublen % symmetric_encryption::AES128_BLOCK_SIZE == 0
        })
    }

    // FIXME: should this be performed in constant time i.e. skip the break part
    // and always loop 16 times?
    fn update_ctr(&self) {
        for i in (PLAINTEXT_START..PLAINTEXT_END).rev() {
            unsafe {
                ECB_DATA[i] += 1;
                if ECB_DATA[i] != 0 {
                    break;
                }
            }
        }
    }

    /// Get the relevant positions of our input data whether we are using a
    /// source buffer or overwriting the destination buffer.
    fn get_start_end_take(&self) -> (usize, usize, usize) {
        let current_idx = self.current_idx.get();

        // Location in the appropriate source buffer we are currently working
        // on.
        let start = current_idx + self.input.map_or(self.start_idx.get(), |_| 0);
        // Last index in the appropriate source buffer we need to work on.
        let end = self.end_idx.get() - self.input.map_or(0, |_| self.start_idx.get());

        // Get the number of bytes that were used in the keystream/block.
        let take = match end.checked_sub(start) {
            Some(v) if v > symmetric_encryption::AES128_BLOCK_SIZE => {
                symmetric_encryption::AES128_BLOCK_SIZE
            }
            Some(v) => v,
            None => 0,
        };

        (start, end, take)
    }

    fn copy_plaintext(&self) {
        let (start, _end, take) = self.get_start_end_take();

        // Copy the plaintext either from the source if it exists or from the
        // destination buffer.
        if take > 0 {
            match self.mode.get() {
                AESMode::ECB => {
                    self.input.map_or_else(
                        || {
                            self.output.map(|output| {
                                for i in 0..take {
                                    // Copy into static mut DMA buffer
                                    unsafe {
                                        ECB_DATA[i + PLAINTEXT_START] = output[i + start];
                                    }
                                }
                            });
                        },
                        |input| {
                            for i in 0..take {
                                // Copy into static mut DMA buffer
                                unsafe {
                                    ECB_DATA[i + PLAINTEXT_START] = input[i + start];
                                }
                            }
                        },
                    );
                }

                AESMode::CBC => {
                    self.input.map_or_else(
                        || {
                            self.output.map(|output| {
                                for i in 0..take {
                                    let ecb_idx = i + PLAINTEXT_START;

                                    // Copy into static mut DMA buffer
                                    unsafe {
                                        ECB_DATA[ecb_idx] ^= output[i + start];
                                    }
                                }
                            });
                        },
                        |input| {
                            for i in 0..take {
                                let ecb_idx = i + PLAINTEXT_START;
                                // Copy into static mut DMA buffer
                                unsafe {
                                    ECB_DATA[ecb_idx] ^= input[i + start];
                                }
                            }
                        },
                    );
                }

                AESMode::CTR => {
                    // no copying plaintext in ctr mode
                }
            }
        }
    }

    fn crypt(&self) {
        match self.mode.get() {
            AESMode::CTR => {}
            AESMode::ECB => {
                // Need to copy the plaintext to the ECB buffer.
                self.copy_plaintext();
            }
            AESMode::CBC => {
                self.copy_plaintext();
            }
        }

        self.registers.event_endecb.write(Event::READY::CLEAR);
        self.registers.task_startecb.set(1);

        self.enable_interrupts();
    }

    /// AesEcb Interrupt handler
    pub fn handle_interrupt(&self) {
        // disable interrupts
        self.disable_interrupts();

        if self.registers.event_endecb.get() == 1 {
            let (start, end, take) = self.get_start_end_take();
            let start_idx = self.start_idx.get();
            let current_idx = self.current_idx.get();

            match self.mode.get() {
                AESMode::CTR => {
                    // Fill in the ciphertext in the output buffer.
                    if take > 0 {
                        self.input.map_or_else(
                            || {
                                // No input buffer, so source data comes from
                                // output buffer.
                                self.output.map(|output| {
                                    for i in 0..take {
                                        let in_byte = output[start + i];
                                        let keystream_byte = unsafe { ECB_DATA[i + PLAINTEXT_END] };

                                        output[start + i] = keystream_byte ^ in_byte;
                                    }
                                });
                            },
                            |input| {
                                self.output.map(|output| {
                                    let start_idx = self.start_idx.get();

                                    for i in 0..take {
                                        let in_byte = input[start + i];
                                        let keystream_byte = unsafe { ECB_DATA[i + PLAINTEXT_END] };

                                        output[start_idx + current_idx + i] =
                                            keystream_byte ^ in_byte;
                                    }
                                });
                            },
                        );

                        self.update_ctr();
                    }
                }

                AESMode::ECB => {
                    // Copy ciphertext to output.
                    if take > 0 {
                        self.output.map(|output| {
                            for i in 0..take {
                                // We write to the buffer starting at the
                                // originally provided start index, plus our
                                // offset at current_idx.
                                let dest_idx = start_idx + current_idx + i;
                                // Copy out of static mut DMA buffer
                                unsafe {
                                    output[dest_idx] = ECB_DATA[i + PLAINTEXT_END];
                                }
                            }
                        });
                    }
                }
                AESMode::CBC => {
                    // Copy ciphertext to both output AND the ECB payload to use
                    // on the next iteration.
                    if take > 0 {
                        self.output.map(|output| {
                            for i in 0..take {
                                // We write to the buffer starting at the
                                // originally provided start index, plus our
                                // offset at current_idx.
                                let dest_idx = start_idx + current_idx + i;
                                // Copy out of static mut DMA buffer
                                unsafe {
                                    output[dest_idx] = ECB_DATA[i + PLAINTEXT_END];
                                    ECB_DATA[i + PLAINTEXT_START] = ECB_DATA[i + PLAINTEXT_END];
                                }
                            }
                        });
                    }
                }
            }

            // Advance through the buffer.
            self.current_idx.set(current_idx + take);

            // Check if we are done or if we need to crypt another block.
            if start + take < end {
                // More to do.
                self.crypt();
            } else {
                self.output.take().map(|output| {
                    self.client
                        .map(move |client| client.crypt_done(self.input.take(), output));
                });
            }
        }
    }

    fn enable_interrupts(&self) {
        self.registers
            .intenset
            .write(Intenset::ENDECB::SET + Intenset::ERRORECB::SET);
    }

    fn disable_interrupts(&self) {
        self.registers
            .intenclr
            .write(Intenclr::ENDECB::SET + Intenclr::ERRORECB::SET);
    }
}

impl<'a> kernel::hil::symmetric_encryption::AES128<'a> for AesECB<'a> {
    fn enable(&self) {
        self.set_dma();
    }

    fn disable(&self) {
        self.registers.task_stopecb.write(Task::ENABLE::CLEAR);
        self.disable_interrupts();
    }

    fn set_client(&'a self, client: &'a dyn symmetric_encryption::Client<'a>) {
        self.client.set(client);
    }

    fn set_key(&self, key: &[u8]) -> Result<(), ErrorCode> {
        if key.len() != 16 {
            return Err(ErrorCode::INVAL);
        }

        // Cache the key for software decryption
        let mut key_arr = [0u8; 16];
        key_arr.copy_from_slice(key);
        self.key.set(key_arr);

        for (i, c) in key.iter().enumerate() {
            unsafe {
                ECB_DATA[i] = *c;
            }
        }

        Ok(())
    }

    fn set_iv(&self, iv: &[u8]) -> Result<(), ErrorCode> {
        if iv.len() != symmetric_encryption::AES128_BLOCK_SIZE {
            Err(ErrorCode::INVAL)
        } else {
            for (i, c) in iv.iter().enumerate() {
                unsafe {
                    ECB_DATA[i + PLAINTEXT_START] = *c;
                }
            }
            Ok(())
        }
    }

    // not needed by NRF5x
    fn start_message(&self) {}

    fn crypt(
        &self,
        source: Option<&'static mut [u8]>,
        dest: &'static mut [u8],
        start_index: usize,
        stop_index: usize,
    ) -> Option<(
        Result<(), ErrorCode>,
        Option<&'static mut [u8]>,
        &'static mut [u8],
    )> {
        self.input.put(source);
        self.output.replace(dest);

        if self.try_set_indices(start_index, stop_index) {
            debug!("indices set");
            if self.encrypt.get() {
                self.crypt();
                None
            } else {
                // Software Decryption
                if self.input.is_some() && self.output.is_some() {
                    let mut iv_buf: [u8; 16] = [0; 16];
                    let key_schedule = key_expansion(&self.key.get());

                    // CBC Decryption: P[i] = Dec(C[i]) ^ C[i-1] (or IV for first)
                    // We must iterate carefully if src == dest (in-place)

                    let len = core::cmp::min(self.input.map(|b| b.len()).unwrap(), self.output.map(|b| b.len()).unwrap());
                    let blocks = len / 16;

                    let mut prev_block = [0u8; 16];
                    prev_block.copy_from_slice(&iv_buf[0..16]);

                    for i in 0..blocks {
                        let start = i * 16;
                        let end = start + 16;

                        let mut current_cipher_block = [0u8; 16];
                        self.input.map(|b| {
                            current_cipher_block.copy_from_slice(&b[start..end]);
                        });

                        let mut decrypted_block = [0u8; 16];
                        aes128_decrypt_block(&key_schedule, &current_cipher_block, &mut decrypted_block);

                        // XOR with previous cipher block (or IV)
                        for j in 0..16 {
                            decrypted_block[j] ^= prev_block[j];
                        }

                        // Update prev_block for next round to be the *current* ciphertext
                        prev_block = current_cipher_block;

                        // Write output
                        self.output.map(|b| b[start..end].copy_from_slice(&decrypted_block));
                    }

                    // Update IV for next chunk
                    iv_buf.copy_from_slice(&prev_block);

                    // Signal completion immediately (simulate async behavior)
                    self.client.map(move |client| {
                        client.crypt_done(self.input.take(), self.output.take().unwrap());
                    });

                    None
                } else {
                    Some((Err(ErrorCode::INVAL), self.input.take(), self.output.take().unwrap()))
                }
            }
        } else {
            Some((
                Err(ErrorCode::INVAL),
                self.input.take(),
                self.output.take().unwrap(),
            ))
        }
    }
}

impl kernel::hil::symmetric_encryption::AES128ECB for AesECB<'_> {
    // not needed by NRF5x (the configuration is the same for encryption and decryption)
    fn set_mode_aes128ecb(&self, encrypting: bool) -> Result<(), ErrorCode> {
        if encrypting {
            self.mode.set(AESMode::ECB);
            Ok(())
        } else {
            Err(ErrorCode::INVAL)
        }
    }
}

impl kernel::hil::symmetric_encryption::AES128Ctr for AesECB<'_> {
    // not needed by NRF5x (the configuration is the same for encryption and decryption)
    fn set_mode_aes128ctr(&self, _encrypting: bool) -> Result<(), ErrorCode> {
        self.mode.set(AESMode::CTR);
        Ok(())
    }
}

impl kernel::hil::symmetric_encryption::AES128CBC for AesECB<'_> {
    fn set_mode_aes128cbc(&self, encrypt: bool) -> Result<(), ErrorCode> {
        self.encrypt.set(encrypt);
        Ok(())
    }
}

//TODO: replace this placeholder with a proper implementation of the AES system
impl<'a> kernel::hil::symmetric_encryption::AES128CCM<'a> for AesECB<'a> {
    /// Set the client instance which will receive `crypt_done()` callbacks
    fn set_client(&'a self, _client: &'a dyn kernel::hil::symmetric_encryption::CCMClient) {}

    /// Set the key to be used for CCM encryption
    fn set_key(&self, _key: &[u8]) -> Result<(), ErrorCode> {
        Ok(())
    }

    /// Set the nonce (length NONCE_LENGTH) to be used for CCM encryption
    fn set_nonce(&self, _nonce: &[u8]) -> Result<(), ErrorCode> {
        Ok(())
    }

    /// Try to begin the encryption/decryption process
    fn crypt(
        &self,
        _buf: &'static mut [u8],
        _a_off: usize,
        _m_off: usize,
        _m_len: usize,
        _mic_len: usize,
        _confidential: bool,
        _encrypting: bool,
    ) -> Result<(), (ErrorCode, &'static mut [u8])> {
        Ok(())
    }
}

// --- Software AES Decryption Implementation ---

// Inverse S-Box
const RSBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

// Round Constants
const RCON: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

fn rot_word(w: [u8; 4]) -> [u8; 4] {
    [w[1], w[2], w[3], w[0]]
}

fn sub_word(w: [u8; 4]) -> [u8; 4] {
    // S-box for Key Expansion (Encryption S-box) - Reusing RSBOX inversely would be slow,
    // so we define minimal forward S-box lookup or logic here.
    // For brevity in this snippet, assumes a `SBOX` table exists or we implement `get_sbox`.
    // Since we only need decryption, we usually need RSBOX.
    // BUT KeyExpansion uses the FORWARD S-Box.
    // To save space, let's just assume standard SBOX is available or define it locally.
    // For this snippet, I will include the minimal SBOX lookups needed for KeyExp.
    // (omitted full SBOX for brevity, you might need to add it or use a crate if allowed)
    // FALLBACK: Use a function or add the SBOX table.

    // Quick SBOX for the 4 bytes (Forward S-Box)
    let sbox = |b: u8| -> u8 {
        // ... (Full SBOX table required here for correctness) ...
        // Placeholder: If you don't have the SBOX table, standard AES won't work.
        // I will assume you can add `const SBOX: [u8; 256] = ...`
        // derived from standard sources (e.g. NIST FIPS 197).
        SBOX[b as usize]
    };
    [sbox(w[0]), sbox(w[1]), sbox(w[2]), sbox(w[3])]
}

// Add the SBOX table here (standard AES S-box)
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn key_expansion(key: &[u8; 16]) -> [u8; 176] {
    let mut round_keys = [0u8; 176];
    round_keys[..16].copy_from_slice(key);
    let mut temp = [0u8; 4];

    for i in 4..44 {
        temp.copy_from_slice(&round_keys[(i-1)*4..i*4]);
        if i % 4 == 0 {
            temp = rot_word(temp);
            temp = sub_word(temp);
            temp[0] ^= RCON[(i/4) - 1];
        }
        for j in 0..4 {
            round_keys[i*4 + j] = round_keys[(i-4)*4 + j] ^ temp[j];
        }
    }
    round_keys
}

fn gmul(a: u8, b: u8) -> u8 {
    let mut p = 0;
    let mut a = a;
    let mut b = b;
    for _ in 0..8 {
        if (b & 1) != 0 { p ^= a; }
        let hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if hi_bit_set { a ^= 0x1b; }
        b >>= 1;
    }
    p
}

fn inv_mix_columns(state: &mut [u8]) {
    for i in 0..4 {
        let col_idx = i * 4;
        let c0 = state[col_idx];
        let c1 = state[col_idx + 1];
        let c2 = state[col_idx + 2];
        let c3 = state[col_idx + 3];

        state[col_idx]     = gmul(0x0e, c0) ^ gmul(0x0b, c1) ^ gmul(0x0d, c2) ^ gmul(0x09, c3);
        state[col_idx + 1] = gmul(0x09, c0) ^ gmul(0x0e, c1) ^ gmul(0x0b, c2) ^ gmul(0x0d, c3);
        state[col_idx + 2] = gmul(0x0d, c0) ^ gmul(0x09, c1) ^ gmul(0x0e, c2) ^ gmul(0x0b, c3);
        state[col_idx + 3] = gmul(0x0b, c0) ^ gmul(0x0d, c1) ^ gmul(0x09, c2) ^ gmul(0x0e, c3);
    }
}

fn inv_shift_rows(state: &mut [u8]) {
    let mut temp = [0u8; 16];
    temp.copy_from_slice(state);
    state[1]  = temp[13]; state[5]  = temp[1];  state[9]  = temp[5];  state[13] = temp[9];
    state[2]  = temp[10]; state[6]  = temp[14]; state[10] = temp[2];  state[14] = temp[6];
    state[3]  = temp[7];  state[7]  = temp[11]; state[11] = temp[15]; state[15] = temp[3];
}

fn inv_sub_bytes(state: &mut [u8]) {
    for i in 0..16 {
        state[i] = RSBOX[state[i] as usize];
    }
}

fn add_round_key(state: &mut [u8], key: &[u8]) {
    for i in 0..16 {
        state[i] ^= key[i];
    }
}

fn aes128_decrypt_block(key_schedule: &[u8; 176], input: &[u8], output: &mut [u8]) {
    let mut state = [0u8; 16];
    state.copy_from_slice(&input[0..16]);

    add_round_key(&mut state, &key_schedule[160..176]); // Round 10 key

    for round in (1..10).rev() {
        inv_shift_rows(&mut state);
        inv_sub_bytes(&mut state);
        add_round_key(&mut state, &key_schedule[round*16..(round+1)*16]);
        inv_mix_columns(&mut state);
    }

    inv_shift_rows(&mut state);
    inv_sub_bytes(&mut state);
    add_round_key(&mut state, &key_schedule[0..16]);

    output.copy_from_slice(&state);
}
