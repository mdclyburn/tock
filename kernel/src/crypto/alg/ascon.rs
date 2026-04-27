/*! Ascon cryptographic algorithms.
 */

use core::convert::TryInto;

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
};
use crate::errorcode::ErrorCode;
use crate::hil::hasher::CryptographicHasher;
use crate::utilities::cells::OptionalCell;

pub struct AsconHash256;

impl CryptographicHasher for AsconHash256 {
    fn hash(&self, hkey: &[u8], in_data: &[u8], out_hash: &mut [u8])
            -> Result<(), ErrorCode>
    {
        hash256(hkey, in_data, out_hash)
    }
}

/// Ascon-Hash256 with Key support.
///
/// Computes the 256-bit hash of `input` keyed with `hkey` and writes it to `output`.
///
/// # Parameters
/// * `input`: The message data to hash.
/// * `hkey`: The key to use for the hash. Must be a multiple of 8 bytes in length.
/// * `output`: The buffer to write the 32-byte hash result into.
///
/// Derived from MIT-licensed implementation found at:
/// <https://github.com/RustCrypto/hashes/blob/master/ascon-hash256/src/lib.rs>
pub fn hash256(hkey: &[u8], input: &[u8], output: &mut [u8]) -> Result<(), ErrorCode> {
    let args_are_viable =
        output.len() == 32
        && hkey.len() % 8 == 0;
    if !args_are_viable {
        return Err(ErrorCode::INVAL);
    }

    // Initialize state with Ascon-Hash256 IV
    // IV constants: 0x9b1e5494e934d681, 0x4bc3a01e333751d2, 0xae65396c6b34b81a, 0x3c7fd4a4d56a4db3, 0x1a5c464906c5976d
    let mut x = [
        0x9b1e5494e934d681,
        0x4bc3a01e333751d2,
        0xae65396c6b34b81a,
        0x3c7fd4a4d56a4db3,
        0x1a5c464906c5976d,
    ];

    // --- Absorb Key Phase ---
    // The key is absorbed first, acting as a prefix to the message.
    // Since hkey is a multiple of 8 bytes (the rate), we process it in full blocks.
    for chunk in hkey.chunks_exact(8) {
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        x[0] ^= u64::from_le_bytes(word);

        permute_12(&mut x);
    }

    // --- Absorb Message Phase ---
    let mut chunks = input.chunks_exact(8);
    for chunk in chunks.by_ref() {
        // Absorb 64-bit block into state[0]
        let mut word = [0u8; 8];
        word.copy_from_slice(chunk);
        x[0] ^= u64::from_le_bytes(word);

        permute_12(&mut x);
    }

    // --- Absorb Last Block (Padding) ---
    // Pad(n) = 0x01 << (8 * n) xored into the state
    let rem = chunks.remainder();
    let mut last = [0u8; 8];
    last[..rem.len()].copy_from_slice(rem);

    x[0] ^= u64::from_le_bytes(last);
    x[0] ^= 1_u64 << (rem.len() * 8);

    permute_12(&mut x);

    // --- Squeeze Phase ---
    // Extract 32 bytes (4 words)
    let mut out_chunks = output.chunks_exact_mut(8);
    let mut i = 0;
    for chunk in out_chunks.by_ref() {
        chunk.copy_from_slice(&x[0].to_le_bytes());

        i += 1;
        if i < 4 {
            permute_12(&mut x);
        }
    }

    Ok(())
}

/// Ascon permutation (12 rounds)
/// Optimized bitsliced implementation suitable for ARM M4
#[inline(always)]
fn permute_12(x: &mut [u64; 5]) {
    // Round constants for 12 rounds (0xf0 .. 0x4b)
    const RC: [u64; 12] = [
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
    ];

    for &rc in &RC {
        // 1. Addition of Constants
        x[2] ^= rc;

        // 2. Substitution Layer (S-box)
        x[0] ^= x[4];
        x[4] ^= x[3];
        x[2] ^= x[1];

        // t = !x
        let t0 = !x[0];
        let t1 = !x[1];
        let t2 = !x[2];
        let t3 = !x[3];
        let t4 = !x[4];

        // t &= x_rotated
        let t0 = t0 & x[1];
        let t1 = t1 & x[2];
        let t2 = t2 & x[3];
        let t3 = t3 & x[4];
        let t4 = t4 & x[0];

        x[0] ^= t1;
        x[1] ^= t2;
        x[2] ^= t3;
        x[3] ^= t4;
        x[4] ^= t0;

        x[1] ^= x[0];
        x[0] ^= x[4];
        x[3] ^= x[2];
        x[2] = !x[2];

        // 3. Linear Diffusion Layer
        // Sigma functions: rotations and XORs
        x[0] ^= x[0].rotate_right(19) ^ x[0].rotate_right(28);
        x[1] ^= x[1].rotate_right(61) ^ x[1].rotate_right(39);
        x[2] ^= x[2].rotate_right(1) ^ x[2].rotate_right(6);
        x[3] ^= x[3].rotate_right(10) ^ x[3].rotate_right(17);
        x[4] ^= x[4].rotate_right(7) ^ x[4].rotate_right(41);
    }
}

/// Ascon-128 Constants (Ascon v1.2 / NIST SP 800-232)
const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 16;
const RATE: usize = 8; // 64 bits (8 bytes)

// Initialization Vector for Ascon-128:
// k=128, r=64, a=12, b=6 -> IV = 0x80400c0600000000
const IV: u64 = 0x80400c0600000000;

// Round Constants for the permutation (indices 0..11)
const ROUND_CONSTANTS: [u64; 12] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b,
];

/// Ascon Internal State (320 bits / 5 words)
#[derive(Clone, Copy)]
struct AsconState {
    x: [u64; 5],
}

impl AsconState {
    /// Initialize the state with Key and Nonce
    #[inline(always)]
    fn new(key: &[u8], nonce: &[u8]) -> Self {
        let k0 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_be_bytes(key[8..16].try_into().unwrap());
        let n0 = u64::from_be_bytes(nonce[0..8].try_into().unwrap());
        let n1 = u64::from_be_bytes(nonce[8..16].try_into().unwrap());

        let mut s = AsconState {
            x: [IV, k0, k1, n0, n1],
        };

        // Initialization Phase: p12
        s.permute(12);

        // XOR Key into last 128 bits of state
        s.x[3] ^= k0;
        s.x[4] ^= k1;

        s
    }

    /// Ascon Permutation (p^a or p^b)
    /// Optimized loop for compactness.
    fn permute(&mut self, rounds: usize) {
        let start = 12 - rounds;
        for i in start..12 {
            // 1. Constant Addition Layer
            self.x[2] ^= ROUND_CONSTANTS[i];

            // 2. Substitution Layer (S-box)
            let mut x0 = self.x[0];
            let mut x1 = self.x[1];
            let mut x2 = self.x[2];
            let mut x3 = self.x[3];
            let mut x4 = self.x[4];

            x0 ^= x4; x4 ^= x3; x2 ^= x1;
            let t0 = x0 ^ (!x1 & x2);
            let t1 = x1 ^ (!x2 & x3);
            let t2 = x2 ^ (!x3 & x4);
            let t3 = x3 ^ (!x4 & x0);
            let t4 = x4 ^ (!x0 & x1);
            x0 = t0 ^ t4; x1 = t1 ^ t0; x2 = t2 ^ t1; x3 = t3 ^ t2; x4 = t4 ^ t3;
            x1 ^= x0; x0 ^= x4; x3 ^= x2; x2 = !x2;

            self.x[0] = x0; self.x[1] = x1; self.x[2] = x2; self.x[3] = x3; self.x[4] = x4;

            // 3. Linear Diffusion Layer
            self.x[0] ^= self.x[0].rotate_right(19) ^ self.x[0].rotate_right(28);
            self.x[1] ^= self.x[1].rotate_right(61) ^ self.x[1].rotate_right(39);
            self.x[2] ^= self.x[2].rotate_right(1) ^ self.x[2].rotate_right(6);
            self.x[3] ^= self.x[3].rotate_right(10) ^ self.x[3].rotate_right(17);
            self.x[4] ^= self.x[4].rotate_right(7) ^ self.x[4].rotate_right(41);
        }
    }

    /// Absorb Associated Data
    fn process_aad(&mut self, aad: &[u8]) {
        if !aad.is_empty() {
            let mut iter = aad.chunks_exact(RATE);
            for chunk in iter.by_ref() {
                self.x[0] ^= u64::from_be_bytes(chunk.try_into().unwrap());
                self.permute(6); // p6
            }
            // Padding
            let rem = iter.remainder();
            let mut padded = [0u8; 8];
            padded[..rem.len()].copy_from_slice(rem);
            padded[rem.len()] = 0x80;
            self.x[0] ^= u64::from_be_bytes(padded);
            self.permute(6); // p6

            // Domain Separation for AAD
            self.x[4] ^= 1;
        }
    }

    /// Finalize and generate Tag
    fn finalize(&mut self, key: &[u8], out_tag: &mut [u8]) {
        let k0 = u64::from_be_bytes(key[0..8].try_into().unwrap());
        let k1 = u64::from_be_bytes(key[8..16].try_into().unwrap());

        // Finalization: XOR Key into state
        self.x[1] ^= k0;
        self.x[2] ^= k1;

        // p12
        self.permute(12);

        // XOR Key into last 128 bits
        self.x[3] ^= k0;
        self.x[4] ^= k1;

        // Output Tag
        crate::debug!("Tag: {:X} {:X}", self.x[3], self.x[4]);
        let mut tag_bytes = [0u8; 16];
        tag_bytes[0..8].copy_from_slice(&self.x[3].to_be_bytes());
        tag_bytes[8..16].copy_from_slice(&self.x[4].to_be_bytes());

        out_tag.copy_from_slice(&tag_bytes[..out_tag.len()]);
    }
}

const CT_BLOCK_SIZE: usize = 8;

/// Ascon-128 Encryption
///
/// Ascon-128 encryption.
/// Based on MIT-licensed implementation found at:
/// <https://github.com/RustCrypto/AEADs/blob/master/ascon-aead128/src/lib.rs>
pub fn encrypt(
    ckey: &[u8],
    nonce: &[u8],
    in_plaintext: &[u8],
    in_aad: &[u8],
    out_ciphertext: &mut [u8],
    out_tag: &mut [u8],
    msg_len: usize,
    aad_len: usize,
) -> Result<(), ()> {
    if ckey.len() != KEY_LEN || nonce.len() != NONCE_LEN {
        return Err(());
    }

    if in_plaintext.len() % CT_BLOCK_SIZE != 0 {
        return Err(());
    }

    if out_ciphertext.len() < msg_len {
        return Err(());
    }

    let in_plaintext = &in_plaintext[0..msg_len];
    let in_aad = &in_aad[0..aad_len];
    let out_ciphertext = &mut out_ciphertext[0..msg_len];

    let mut state = AsconState::new(ckey, nonce);

    // 1. Process Associated Data
    state.process_aad(in_aad);

    // 2. Process Plaintext
    let mut iter = in_plaintext.chunks_exact(RATE);
    let mut out_iter = out_ciphertext.chunks_exact_mut(RATE);

    for (p_chunk, c_chunk) in iter.by_ref().zip(out_iter.by_ref()) {
        state.x[0] ^= u64::from_be_bytes(p_chunk.try_into().unwrap());
        c_chunk.copy_from_slice(&state.x[0].to_be_bytes());
        state.permute(6); // p6
    }

    // 3. Process Last Block (Padding)
    let rem_p = iter.remainder();
    let rem_c = out_iter.into_remainder();

    let mut padded = [0u8; 8];
    padded[..rem_p.len()].copy_from_slice(rem_p);
    padded[rem_p.len()] = 0x80;

    state.x[0] ^= u64::from_be_bytes(padded);

    // Output partial ciphertext
    let c_bytes = state.x[0].to_be_bytes();
    rem_c.copy_from_slice(&c_bytes[..rem_p.len()]);

    // Note: No p6 after the last absorbed block, go directly to Finalization.

    // 4. Final
    // 4. Finalization
    state.finalize(ckey, out_tag);

    // {
    //     let (chunks, _rem) = ckey.as_chunks::<8>();
    //     crate::debug!("Cipher key:");
    //     for chunk in chunks {
    //         crate::debug!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
    //                       chunk[0], chunk[1], chunk[2], chunk[3],
    //                       chunk[4], chunk[5], chunk[6], chunk[7]);
    //     }

    //     let (chunks, _rem) = nonce.as_chunks::<8>();
    //     crate::debug!("Nonce:");
    //     for chunk in chunks {
    //         crate::debug!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
    //                       chunk[0], chunk[1], chunk[2], chunk[3],
    //                       chunk[4], chunk[5], chunk[6], chunk[7]);
    //     }

    //     let (chunks, _rem) = out_ciphertext.as_chunks::<8>();
    //     crate::debug!("Ciphertext:");
    //     for chunk in chunks {
    //         crate::debug!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
    //                       chunk[0], chunk[1], chunk[2], chunk[3],
    //                       chunk[4], chunk[5], chunk[6], chunk[7]);
    //     }
    // }

    Ok(())
}

/// Decrypt using Ascon-128 AEAD.
pub fn decrypt(
    ckey: &[u8],
    nonce: &[u8],
    in_ciphertext: &[u8],
    in_aad: &[u8],
    in_expected_tag: &[u8],
    out_plaintext: &mut [u8],
    msg_len: usize,
    aad_len: usize,
) -> Result<bool, ()> {
    if ckey.len() != KEY_LEN || nonce.len() != NONCE_LEN {
        return Err(());
    }

    let in_ciphertext = &in_ciphertext[0..msg_len];
    let in_aad = &in_aad[0..aad_len];
    if out_plaintext.len() < in_ciphertext.len() {
        return Err(());
    }

    // {
    //     let (chunks, _rem) = ckey.as_chunks::<8>();
    //     crate::debug!("Cipher key:");
    //     for chunk in chunks {
    //         crate::debug!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
    //                       chunk[0], chunk[1], chunk[2], chunk[3],
    //                       chunk[4], chunk[5], chunk[6], chunk[7]);
    //     }

    //     let (chunks, _rem) = nonce.as_chunks::<8>();
    //     crate::debug!("Nonce:");
    //     for chunk in chunks {
    //         crate::debug!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
    //                       chunk[0], chunk[1], chunk[2], chunk[3],
    //                       chunk[4], chunk[5], chunk[6], chunk[7]);
    //     }

    //     let (chunks, _rem) = in_ciphertext.as_chunks::<8>();
    //     crate::debug!("Ciphertext:");
    //     for chunk in chunks {
    //         crate::debug!("{:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x} {:02x}",
    //                       chunk[0], chunk[1], chunk[2], chunk[3],
    //                       chunk[4], chunk[5], chunk[6], chunk[7]);
    //     }
    // }

    let mut state = AsconState::new(ckey, nonce);

    // 1. Process Associated Data
    state.process_aad(in_aad);

    // 2. Process Ciphertext
    let mut iter = in_ciphertext.chunks_exact(RATE);
    let mut out_iter = out_plaintext.chunks_exact_mut(RATE);

    for (c_chunk, p_chunk) in iter.by_ref().zip(out_iter.by_ref()) {
        let c_block = u64::from_be_bytes(c_chunk.try_into().unwrap());
        let p_block = state.x[0] ^ c_block;
        p_chunk.copy_from_slice(&p_block.to_be_bytes());

        state.x[0] = c_block; // Update state with Ciphertext
        state.permute(6); // p6
    }

    // 3. Process Last Block (Padding)
    let rem_c = iter.remainder();
    let rem_p = out_iter.into_remainder();

    // For the last block: P_last = S[0]_len ^ C_last
    // We need to absorb C_last properly.
    // The state update is S[0] ^= P_padded.
    // We reconstruct P_padded.

    let s0_bytes = state.x[0].to_be_bytes();
    let mut p_padded = [0u8; 8]; // Reconstructed Plaintext padded

    // XOR partial ciphertext with state to get plaintext
    for i in 0..rem_c.len() {
        rem_p[i] = s0_bytes[i] ^ rem_c[i];
        p_padded[i] = rem_p[i];
    }
    // Apply Padding to P
    p_padded[rem_c.len()] = 0x80;

    // Update state: S[0] ^= P_padded
    state.x[0] ^= u64::from_be_bytes(p_padded);

    // 4. Finalization
    let mut out_tag = [0u8; TAG_LEN_MAX];
    state.finalize(ckey, &mut out_tag);

    // 5. Verification
    // Constant-time comparison is recommended for security,
    // but standard `==` is used here for compactness as requested.
    // In production, use `subtle::ConstantTimeEq`.
    let valid = &out_tag[0..in_expected_tag.len()] == in_expected_tag;
    // crate::debug!("Tag: {:X} {:X} {:X} {:X} {:X} {:X} {:X} {:X}",
    //                out_tag[0],
    //                out_tag[1],
    //                out_tag[2],
    //                out_tag[3],
    //                out_tag[4],
    //                out_tag[5],
    //                out_tag[6],
    //                out_tag[7]);

    Ok(valid)
}

pub struct Ascon128 {
    client: OptionalCell<&'static dyn AEADProviderClient>,
}

impl Ascon128 {
    pub fn new() -> Ascon128 {
        Ascon128 {
            client: OptionalCell::empty(),
        }
    }
}

impl AEADProvider for Ascon128 {
    fn padding_size(&self) -> usize { CT_BLOCK_SIZE }

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
                                 &'static mut [u8; TAG_LEN_MAX]))>
    {
        if self.client.is_none() {
            Err((ErrorCode::INVAL,
                 (nonce,
                  in_plaintext,
                  in_aad,
                  out_ciphertext,
                  out_tag)))
        } else {
            let encrypt_result = encrypt(
                ckey,
                nonce,
                in_plaintext,
                in_aad,
                out_ciphertext,
                out_tag,
                message_len,
                aad_len);
            // crate::debug!("Tag: {:X} {:X} {:X} {:X} {:X} {:X} {:X} {:X}",
            //        out_tag[0],
            //        out_tag[1],
            //        out_tag[2],
            //        out_tag[3],
            //        out_tag[4],
            //        out_tag[5],
            //        out_tag[6],
            //        out_tag[7]);
            if encrypt_result.is_ok() {
                self.client.map(|client| {
                    client.encrypt_done(
                        nonce,
                        in_plaintext,
                        out_ciphertext,
                        in_aad,
                        out_tag);
                });

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
    }

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
        aad_len: usize
    ) -> Result<(), (ErrorCode, (&'static mut [u8; NONCE_LEN_MAX],
                                 &'static mut [u8; MESSAGE_LEN_MAX],
                                 &'static mut [u8; AAD_LEN_MAX],
                                 &'static mut [u8; MESSAGE_LEN_MAX],
                                 &'static mut [u8; TAG_LEN_MAX]))>
    {
        if self.client.is_none() {
            Err((ErrorCode::INVAL,
                 (nonce,
                  out_plaintext,
                  in_aad,
                  in_ciphertext,
                  expected_tag)))
        } else {
            let decrypt_result = decrypt(
                ckey,
                nonce,
                in_ciphertext,
                in_aad,
                expected_tag,
                out_plaintext,
                message_len,
                aad_len);
            if let Ok(tag_matches) = decrypt_result {
                self.client.map(|client| {
                    client.decrypt_done(
                        nonce,
                        out_plaintext,
                        in_ciphertext,
                        in_aad,
                        expected_tag,
                        tag_matches);
                });

                Ok(())
            } else {
                Err((ErrorCode::FAIL,
                         (nonce,
                          out_plaintext,
                          in_aad,
                          in_ciphertext,
                          expected_tag)))
            }
        }
    }

    /// Set the client.
    fn set_client(&self, client: &'static dyn AEADProviderClient) {
        self.client.set(client)
    }
}
