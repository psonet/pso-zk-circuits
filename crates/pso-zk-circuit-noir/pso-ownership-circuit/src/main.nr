// Single-NFT ownership proof circuit, per the privacy-preserving L2
// architecture §4.2.
//
// Used by wallets to prove ownership of one Spending Unit (or, with
// different inputs, one Tribute Draft). The recursive aggregation
// circuit (`pso-recursive-aggregation-circuit-n*`) verifies N copies
// of this circuit in-circuit via Noir recursion.
//
// ## Public-input layout
//
// `[owner, nft_hash]`
//
// The on-chain verifier supplies these from the NFT's stored
// `derivedOwner` field and the entity hash reconstructed from the
// NFT's other fields (see `pso_protocol::nft::compute_*_hash`).

use pso_circuit_core::ownership;

pub fn main(
    // Private inputs.
    //
    // For SU ownership: `pk_x_bytes` / `pk_y_bytes` are the per-SU
    // `shared_pk` coordinates derived via App. A; `nonce` is the
    // `su_nonce` extracted from the decrypted SRA receipt;
    // `signature` is ECDSA over Poseidon2(nft_hash, nonce) under
    // `shared_sk`.
    //
    // For TD ownership: same shape, but with the wallet-rolled
    // per-TD keypair and `tribute_draft_nonce`.
    pk_x_bytes: [u8; 32],
    pk_y_bytes: [u8; 32],
    signature: [u8; 64],
    nonce: Field,
    // Public inputs — order matters: the recursive aggregation
    // circuit reads them in this order from each inner proof.
    owner: pub Field,
    nft_hash: pub Field,
) {
    ownership::verify_ownership_per_su(
        pk_x_bytes,
        pk_y_bytes,
        signature,
        nonce,
        owner,
        nft_hash,
    );
}

// ============================================
// Tests
// ============================================

#[test]
fn test_compute_ownership_matches_known_vector() {
    // Sanity-check: the off-chain `pso_protocol::ownership::compute_ownership`
    // produces the same Poseidon5 commitment for these inputs. This
    // test pins the byte-decomposition convention.
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
    assert_eq(generated_hash, expected_hash);
}
