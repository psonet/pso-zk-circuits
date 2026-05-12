// Full Proof Circuit in Noir
// Implements both:
// 1. Ownership proof: Prove knowledge of secp256k1 private key
// 2. Inclusion proof: Prove membership in Merkle tree

use pso_circuit_core::ownership;
use pso_circuit_core::inclusion;

/// Main circuit function
///
/// Private inputs:
/// - nonce: Field - random nonce used for ownership generation
/// - pk_x_bytes: [u8; 32] - Public key x-coordinate (bytes, needed for ECDSA)
/// - pk_y_bytes: [u8; 32] - Public key y-coordinate (bytes, needed for ECDSA)
/// - signature: [u8; 64] - ECDSA signature over ownership hash (private to prevent linkability)
/// - merkle_path_siblings: [Field; 8] - Sibling hashes along the Merkle path
/// - merkle_path_indices: [u8; 8] - Position indicators (1 = current is left)
///
/// Public inputs:
/// - expected_ownership: Field - Expected ownership hash
/// - nft_hash: Field - Entity hash to prove inclusion for
/// - expected_merkle_root: Field - Expected Merkle root
///
/// NOTE: secp256k1 scalar multiplication is extremely expensive in circuits.
/// For efficiency, we compute pk = private_key * G off-circuit and verify
/// the relationship using ECDSA signature verification.
pub fn main(
    // Private inputs (witness values)
    nonce: Field, // random nonce used for ownership generation
    pk_x_bytes: [u8; 32], // public_key_x
    pk_y_bytes: [u8; 32], // public_key_y
    signature: [u8; 64], // ECDSA signature over ownership hash
    merkle_path_siblings: [Field; 8], // Sibling hashes (padded to MAX_DEPTH)
    merkle_path_indices: [u8; 8], // Position indicators (1 = current is left)
    // Public inputs
    expected_ownership: pub Field, // Expected ownership hash
    nft_hash: pub Field, // Entity hash to prove inclusion for
    expected_merkle_root: pub Field, // Expected merkle root
) {

    // ============================================
    // Part 1: Ownership Proof
    // ============================================
    // Compute ownership from the public key coordinates and given nonce
    let computed_ownership = ownership::compute_ownership(pk_x_bytes, pk_y_bytes, nonce);
    let computed_ownership_bytes = computed_ownership.to_le_bytes();

    let verify_signature = ownership::verify_ecdsa(
        pk_x_bytes,
        pk_y_bytes,
        computed_ownership_bytes,
        signature,
    );

    // Verify the computed computed_ownership matches the expected value
    assert(verify_signature, "signature_verification_failed: ownership proof failed");
    assert(computed_ownership == expected_ownership, "ownership mismatch: ownership proof failed");

    // ============================================
    // Part 2: Merkle Inclusion Proof
    // ============================================
    // Compute merkle root from nft_hash and path
    let computed_merkle_root = inclusion::compute_merkle_root(
        nft_hash,
        merkle_path_siblings,
        merkle_path_indices,
    );

    // Verify the computed merkle root matches the expected value
    assert(
        computed_merkle_root == expected_merkle_root,
        "merkle_root mismatch: inclusion proof failed",
    );
}

// ============================================
// Tests
// ============================================

#[test]
fn test_verify_signature() {
    let pk_x: [u8; 32] = [
        027, 132, 197, 086, 123, 018, 100, 064, 153, 093, 062, 213, 170, 186, 005, 101, 215, 030,
        024, 052, 096, 072, 025, 255, 156, 023, 245, 233, 213, 221, 007, 143,
    ];

    let pk_y: [u8; 32] = [
        112, 190, 175, 143, 088, 139, 084, 021, 007, 254, 214, 166, 066, 197, 171, 066, 223, 223,
        129, 032, 167, 246, 057, 222, 081, 034, 212, 122, 105, 168, 232, 209,
    ];

    let signature: [u8; 64] = [
        196, 092, 228, 067, 044, 069, 204, 194, 182, 191, 222, 178, 051, 186, 103, 123, 245, 196,
        200, 007, 175, 050, 186, 184, 004, 014, 159, 114, 003, 181, 251, 135, 010, 238, 077, 041,
        148, 025, 048, 172, 083, 195, 059, 206, 064, 235, 043, 105, 189, 253, 103, 037, 030, 074,
        011, 017, 238, 245, 103, 195, 152, 156, 023, 023,
    ];
    let pre_hash = [
        062, 203, 247, 237, 084, 033, 185, 116, 187, 250, 103, 242, 011, 062, 180, 090, 132, 002,
        237, 030, 081, 019, 158, 235, 129, 202, 040, 045, 008, 131, 128, 021,
    ];

    let result = ownership::verify_ecdsa(pk_x, pk_y, pre_hash, signature);

    assert_eq(result, true);
}

#[test]
fn test_ownership_proof() {
    let pk_x: [u8; 32] = [
        027, 132, 197, 086, 123, 018, 100, 064, 153, 093, 062, 213, 170, 186, 005, 101, 215, 030,
        024, 052, 096, 072, 025, 255, 156, 023, 245, 233, 213, 221, 007, 143,
    ];

    let pk_y: [u8; 32] = [
        112, 190, 175, 143, 088, 139, 084, 021, 007, 254, 214, 166, 066, 197, 171, 066, 223, 223,
        129, 032, 167, 246, 057, 222, 081, 034, 212, 122, 105, 168, 232, 209,
    ];

    let nonce = 10 as Field;

    let hash = ownership::compute_ownership(pk_x, pk_y, nonce);

    let expected_hash: [u8; 32] = [
        053, 057, 009, 094, 242, 155, 154, 030, 243, 045, 186, 110, 019, 080, 044, 154, 007, 227,
        084, 114, 172, 238, 138, 180, 029, 242, 101, 231, 013, 166, 161, 035,
    ];

    let generated_hash: [u8; 32] = hash.to_le_bytes();

    println(expected_hash);
    println(generated_hash);

    assert_eq(generated_hash, expected_hash);
}

#[test]
fn test_merkle_inclusion() {
    let leaf: Field = 0;

    let siblings: [Field; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    let indices: [u8; 8] = [0, 1, 0, 1, 0, 1, 0, 1];

    let expected_merkle_tree_root = [
        104, 057, 009, 238, 038, 094, 110, 105, 035, 161, 094, 225, 051, 038, 244, 246, 031, 175,
        154, 035, 222, 125, 171, 102, 037, 145, 234, 128, 202, 151, 032, 009,
    ];

    let root = inclusion::compute_merkle_root(leaf, siblings, indices);

    let generated_root: [u8; 32] = root.to_le_bytes();

    println(expected_merkle_tree_root);
    println(generated_root);

    assert_eq(expected_merkle_tree_root, generated_root);
}

#[test]
fn test_main_integration() {
    let nonce: Field = 0x0f7b7c58e1ab64a311eca2df3647bfd8c884fdff87860cd2f29aaf2b2dc07412;
    let pk_x_bytes: [u8; 32] = [113, 199, 168, 094, 051, 172, 010, 187, 125, 073, 250, 151, 169, 236, 205, 210, 166, 156, 004, 243, 167, 010, 236, 097, 121, 129, 199, 179, 190, 168, 111, 243];
    let pk_y_bytes: [u8; 32] = [050, 173, 025, 050, 174, 254, 076, 162, 124, 156, 102, 071, 050, 023, 079, 019, 235, 012, 246, 064, 062, 024, 200, 119, 085, 204, 058, 210, 168, 230, 147, 155];
    let signature: [u8; 64] = [110, 177, 082, 044, 203, 057, 178, 066, 242, 095, 038, 057, 144, 136, 163, 080, 105, 071, 246, 208, 214, 068, 237, 072, 048, 245, 216, 059, 133, 170, 133, 087, 013, 118, 167, 069, 029, 210, 026, 219, 074, 064, 216, 078, 050, 008, 014, 216, 233, 234, 208, 219, 179, 030, 079, 170, 049, 215, 179, 101, 119, 189, 193, 198];
    let merkle_path_siblings: [Field; 8] = [0x0ce327cab7c74139547cef2dbb177da2ab18c4d647fc7f476c1e01dbe578d3a5, 0x16af99c01af8ea4e041a16aac16b012605021ff1e58076060d8f28aa1e063966, 0x11ebfbb7d4e3c8071bfeaa03128b84f7874700de3f40ee1c71547436f53d8121, 0x2d9cd6f6810bde9477712b614ee1cdd773ce8654f26964cc4e8322fa8308ee07, 0x10517b24a8c69ed1021f214d665390e73c3197fe8924659e16aa077f505defc7, 0x14243042b7f3a44367fc3cad1aa04c2bdc76f45720bedd414ca14a206904a737, 0, 0];
    let merkle_path_indices: [u8; 8] = [1, 0, 1, 1, 1, 0, 0, 0];
    let expected_ownership: Field = 0x0073dc1cde6a39a3702454be621a9d423847cce63908959f6ecb62665a417a80;
    let nft_hash: Field = 0x150efc9fd34352c7ff152ae98094fe65336d40fae58b3206d0ae7ee5b022f383;
    let expected_merkle_root: Field = 0x233035d8b0cd55f53dde625be8f12be17c7159d8ec63161f1ade89beec22b983;

    main(nonce, pk_x_bytes, pk_y_bytes, signature, merkle_path_siblings, merkle_path_indices, expected_ownership, nft_hash, expected_merkle_root);
}
