// Full Proof Circuit.
//
// Composes the same sec.4.2 ownership constraint as `pso-ownership-circuit`
// with a Merkle-inclusion check. There is intentionally one ownership
// implementation across the codebase --
// `pso_circuit_core::ownership::verify_ownership_per_su` -- so the
// Grumpkin Schnorr semantics, the Poseidon3 owner derivation, and the
// `Poseidon3(nft_hash, nonce, binding_hash)` signature payload are
// identical whether the proof is standalone (`pso-ownership-circuit`),
// flat-aggregated (`pso-flat-aggregation-circuit-n*`), or composed with
// inclusion here.

use pso_circuit_core::inclusion;
use pso_circuit_core::ownership;
use std::embedded_curve_ops::EmbeddedCurvePoint;

pub fn main(
    // Private witness.
    pk: EmbeddedCurvePoint,
    signature: [u8; 64],
    nonce: Field,
    // Depth-32 Merkle inclusion path for the perpetual TD commitment
    // tree (single Incremental Merkle Tree, Poseidon2/BN254). Raised
    // from depth 8 -> 32 so one perpetual IMT can hold the full TD set.
    merkle_path_siblings: [Field; 32],
    merkle_path_indices: [u8; 32],
    // Public -- same `(owner, nft_hash, binding_hash)` prefix as the
    // standalone ownership circuit, plus the Merkle root the inclusion
    // check resolves to.
    owner: pub Field,
    nft_hash: pub Field,
    binding_hash: pub Field,
    expected_merkle_root: pub Field,
) {
    // Part 1: sec.4.2 ownership proof -- owner commitment + Grumpkin
    // Schnorr over Poseidon3(nft_hash, nonce, binding_hash). Same code
    // path the standalone ownership circuit uses.
    ownership::verify_ownership_per_su(pk, signature, nonce, owner, nft_hash, binding_hash);

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
    // Depth-32 inclusion path. Siblings 1..=32, alternating indices.
    let leaf: Field = 0;
    let siblings: [Field; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28, 29, 30, 31, 32,
    ];
    let indices: [u8; 32] = [
        0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
        0, 1,
    ];

    // Expected depth-32 root, regenerated for the perpetual TD IMT.
    let expected_merkle_tree_root = [
        043, 108, 118, 231, 172, 210, 186, 020, 105, 042, 248, 048, 006, 224, 235, 252, 135, 249,
        040, 176, 095, 208, 238, 223, 227, 144, 061, 058, 149, 122, 059, 022,
    ];

    let root = inclusion::compute_merkle_root(leaf, siblings, indices);
    let generated_root: [u8; 32] = root.to_le_bytes();
    assert_eq(expected_merkle_tree_root, generated_root);
}
