// Ownership proof module
// Proves knowledge of a private key corresponding to a public key

use poseidon::poseidon;
use std::ecdsa_secp256k1;

global NUM_LIMBS: u32 = 2;
global BYTES_PER_LIMB: u32 = 16;

pub fn verify_ecdsa(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    pre_hash: [u8; 32],
    signature: [u8; 64],
) -> bool {
    ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, pre_hash)
}

/// Decompose a 256-bit value into limbs of specified bit width
/// Returns an array of Field elements representing the limbs
fn decompose_coordinate(value: [u8; 32]) -> [Field; NUM_LIMBS] {
    let mut limbs: [Field; NUM_LIMBS] = [0; NUM_LIMBS];

    // Process value byte by byte into limbs
    // Each limb is limb_bits wide
    for i in 0..NUM_LIMBS {
        let start_byte = (i as u32) * BYTES_PER_LIMB;
        let mut limb: u128 = 0;

        for j in 0..BYTES_PER_LIMB {
            limb |= (value[start_byte + j] as u128) << (8 * j) as u128;
        }

        // could be from be bytes
        limbs[i] = limb as Field;
    }

    limbs
}

/// Compute public key hash from x and y coordinates
/// Uses Poseidon hash with 5 inputs (2 limbs for x, 2 limbs for y, nonce)
pub fn compute_ownership(pk_x: [u8; 32], pk_y: [u8; 32], nonce: Field) -> Field {
    // Decompose x coordinate into 2 limbs of 64 bits each
    let x_limbs: [Field; NUM_LIMBS] = decompose_coordinate(pk_x);

    // Decompose y coordinate into 2 limbs of 64 bits each
    let y_limbs: [Field; NUM_LIMBS] = decompose_coordinate(pk_y);

    // Combine into 5-element array for Poseidon hash
    let mut pk_limbs: [Field; NUM_LIMBS * 2 + 1] = [0; NUM_LIMBS * 2 + 1];
    for i in 0..NUM_LIMBS {
        pk_limbs[i] = x_limbs[i];
        pk_limbs[i + NUM_LIMBS] = y_limbs[i];
    }

    pk_limbs[NUM_LIMBS * 2] = nonce;

    // Hash using Poseidon
    poseidon::bn254::hash_5(pk_limbs)
}
