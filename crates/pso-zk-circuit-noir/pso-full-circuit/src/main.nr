// Full Proof Circuit.
//
// Composes the same §4.2 ownership constraint as `pso-ownership-circuit`
// with a Merkle-inclusion check. There is intentionally one ownership
// implementation across the codebase — `pso_circuit_core::ownership::verify_ownership_per_su`
// — so the ECDSA semantics, the Poseidon5 owner derivation, and the
// `Poseidon2(nft_hash, nonce)` signature payload are identical
// whether the proof is standalone (`pso-ownership-circuit`), folded
// via recursion (`pso-recursive-aggregation-circuit-n*`), or composed
// with inclusion here.

use pso_circuit_core::inclusion;
use pso_circuit_core::ownership;

pub fn main(
    // Private witness.
    pk_x_bytes: [u8; 32],
    pk_y_bytes: [u8; 32],
    signature: [u8; 64],
    nonce: Field,
    merkle_path_siblings: [Field; 8],
    merkle_path_indices: [u8; 8],
    // Public — same `(owner, nft_hash)` prefix as the standalone
    // ownership circuit, plus the Merkle root the inclusion check
    // resolves to.
    owner: pub Field,
    nft_hash: pub Field,
    expected_merkle_root: pub Field,
) {
    // Part 1: §4.2 ownership proof — owner commitment + ECDSA over
    // Poseidon2(nft_hash, nonce). Same code path the standalone
    // ownership circuit uses.
    ownership::verify_ownership_per_su(
        pk_x_bytes,
        pk_y_bytes,
        signature,
        nonce,
        owner,
        nft_hash,
    );

    // Part 2: Merkle inclusion against the same `nft_hash`.
    let computed_merkle_root = inclusion::compute_merkle_root(
        nft_hash,
        merkle_path_siblings,
        merkle_path_indices,
    );
    assert(
        computed_merkle_root == expected_merkle_root,
        "merkle_root mismatch: inclusion proof failed",
    );
}

// ============================================
// Tests
// ============================================

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
    assert_eq(expected_merkle_tree_root, generated_root);
}

#[test]
fn test_compute_ownership_known_vector() {
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
    let expected: [u8; 32] = [
        053, 057, 009, 094, 242, 155, 154, 030, 243, 045, 186, 110, 019, 080, 044, 154, 007, 227,
        084, 114, 172, 238, 138, 180, 029, 242, 101, 231, 013, 166, 161, 035,
    ];
    let generated: [u8; 32] = hash.to_le_bytes();
    assert_eq(generated, expected);
}
