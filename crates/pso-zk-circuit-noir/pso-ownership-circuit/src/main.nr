// Ownership-only Proof Circuit
// Proves knowledge of secp256k1 private key without Merkle inclusion.

use pso_circuit_core::ownership;

/// Main circuit function for ownership-only proof.
///
/// Private inputs:
/// - nonce: Field - random nonce used for ownership generation
/// - pk_x_bytes: [u8; 32] - Public key x-coordinate (bytes, needed for ECDSA)
/// - pk_y_bytes: [u8; 32] - Public key y-coordinate (bytes, needed for ECDSA)
/// - signature: [u8; 64] - ECDSA signature over ownership hash
///
/// Public inputs:
/// - expected_ownership: Field - Expected ownership hash
pub fn main(
    // Private inputs (witness values)
    nonce: Field,
    pk_x_bytes: [u8; 32],
    pk_y_bytes: [u8; 32],
    signature: [u8; 64],
    // Public inputs
    expected_ownership: pub Field,
) {
    // Compute ownership from the public key coordinates and given nonce
    let computed_ownership = ownership::compute_ownership(pk_x_bytes, pk_y_bytes, nonce);
    let computed_ownership_bytes = computed_ownership.to_le_bytes();

    let verify_signature = ownership::verify_ecdsa(
        pk_x_bytes,
        pk_y_bytes,
        computed_ownership_bytes,
        signature,
    );

    // Verify the computed ownership matches the expected value
    assert(verify_signature, "signature_verification_failed: ownership proof failed");
    assert(computed_ownership == expected_ownership, "ownership mismatch: ownership proof failed");
}

// ============================================
// Tests
// ============================================

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

    // Compute ownership hash
    let hash = ownership::compute_ownership(pk_x, pk_y, nonce);

    let expected_hash: [u8; 32] = [
        053, 057, 009, 094, 242, 155, 154, 030, 243, 045, 186, 110, 019, 080, 044, 154, 007, 227,
        084, 114, 172, 238, 138, 180, 029, 242, 101, 231, 013, 166, 161, 035,
    ];

    let generated_hash: [u8; 32] = hash.to_le_bytes();
    assert_eq(generated_hash, expected_hash);
}

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
