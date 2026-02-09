/*! Ascon cryptographic algorithms.
 */

use crate::errorcode::ErrorCode;

use crate::hil::hasher::CryptographicHasher;

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
