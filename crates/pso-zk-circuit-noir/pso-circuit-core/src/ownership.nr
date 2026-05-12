// Ownership proof helpers, per the privacy-preserving L2 architecture
// (PDF §2.2.3, §2.2.4, §4.2).
//
// Two layers:
//
//   1. Building blocks — `decompose_coordinate`, `compute_ownership`,
//      `verify_ecdsa`. Pure helpers; reusable from any circuit.
//
//   2. `verify_ownership_per_su` — the §4.2 ownership-proof
//      constraint set, factored out so both the standalone
//      `pso-ownership-circuit` and any future composite circuit
//      (e.g. tribute-draft ownership proof) can call it without
//      duplication.

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

/// Decompose a 32-byte SEC1 coordinate into two 128-bit Fr limbs, by
/// reading each 16-byte half as little-endian u128. Matches the
/// off-circuit decomposition the wallet uses (see
/// `pso_protocol::ownership::compute_ownership` in pso-protocol).
fn decompose_coordinate(value: [u8; 32]) -> [Field; NUM_LIMBS] {
    let mut limbs: [Field; NUM_LIMBS] = [0; NUM_LIMBS];

    for i in 0..NUM_LIMBS {
        let start_byte = (i as u32) * BYTES_PER_LIMB;
        let mut limb: u128 = 0;
        for j in 0..BYTES_PER_LIMB {
            limb |= (value[start_byte + j] as u128) << (8 * j) as u128;
        }
        limbs[i] = limb as Field;
    }

    limbs
}

/// Compute the Poseidon5 owner commitment from a SEC1 (x, y) public
/// key and a nonce — `Poseidon5(x_lo, x_hi, y_lo, y_hi, nonce)`.
/// See PDF §2.2.3.
pub fn compute_ownership(pk_x: [u8; 32], pk_y: [u8; 32], nonce: Field) -> Field {
    let x_limbs: [Field; NUM_LIMBS] = decompose_coordinate(pk_x);
    let y_limbs: [Field; NUM_LIMBS] = decompose_coordinate(pk_y);

    let mut pk_limbs: [Field; NUM_LIMBS * 2 + 1] = [0; NUM_LIMBS * 2 + 1];
    for i in 0..NUM_LIMBS {
        pk_limbs[i] = x_limbs[i];
        pk_limbs[i + NUM_LIMBS] = y_limbs[i];
    }
    pk_limbs[NUM_LIMBS * 2] = nonce;

    poseidon::bn254::hash_5(pk_limbs)
}

/// `verify_ownership_per_su` — single-shot ownership-proof constraint
/// per §4.2 of the privacy-preserving L2 architecture.
///
/// ## Constraints
///
/// 1. `owner == Poseidon5(decompose(pk_x), decompose(pk_y), nonce)`
///    — proves the prover knows a `(pk, nonce)` pair whose Poseidon
///    commitment equals the claimed `owner`.
/// 2. `ECDSA-verify((pk_x, pk_y), signature, Poseidon2(nft_hash, nonce).to_le_bytes())`
///    — proves the prover knows the `secret_key` matching `pk` and
///    has signed a per-NFT message that binds the proof to a specific
///    `(nft_hash, nonce)` pair (impossible to replay across NFTs).
///
/// ## Inputs
///
/// All private to the prover except `owner` and `nft_hash`, which are
/// public so the verifier (on-chain or otherwise) can supply the
/// expected values:
///
/// - `pk_x` / `pk_y`: 32-byte SEC1 coordinates of the public key
///   matching the secret key that signed. For SUs this is the
///   wallet's per-SU `shared_pk`; for TDs this is a fresh per-TD
///   public key.
/// - `signature`: 64-byte secp256k1 ECDSA signature.
/// - `nonce`: per-NFT nonce — for SUs this is `su_nonce` derived from
///   the SRA receipt; for TDs this is a fresh `tribute_draft_nonce`.
/// - `owner` (public): claimed Poseidon5 commitment. The verifier
///   supplies this from the NFT's on-chain `derivedOwner` field.
/// - `nft_hash` (public): per-NFT entity hash. The verifier
///   reconstructs this from the NFT's on-chain data (see
///   `pso_protocol::nft::compute_*_hash`).
///
/// Used by `pso-ownership-circuit` for SU ownership and (with
/// different inputs) for the post-mint TD ownership proof. The
/// recursive aggregation circuit verifies N copies of this circuit
/// in-circuit via `bb_proof_verification::verify_honk_proof_non_zk`.
pub fn verify_ownership_per_su(
    pk_x: [u8; 32],
    pk_y: [u8; 32],
    signature: [u8; 64],
    nonce: Field,
    owner: Field,
    nft_hash: Field,
) {
    // (1) Owner commitment.
    let computed_owner = compute_ownership(pk_x, pk_y, nonce);
    assert(
        computed_owner == owner,
        "owner mismatch: computed Poseidon5(pk, nonce) != public owner",
    );

    // (2) Signature binding: ECDSA over Poseidon2(nft_hash, nonce).to_le_bytes().
    //
    //     Signing the Poseidon2 commitment (rather than the raw
    //     `nft_hash` or the `owner`) binds the proof to BOTH the NFT
    //     data AND the per-NFT nonce. A replay attempt that swapped
    //     either component would produce a different pre-hash and
    //     fail signature verification.
    let pre_hash_fr = poseidon::bn254::hash_2([nft_hash, nonce]);
    let pre_hash_bytes: [u8; 32] = pre_hash_fr.to_le_bytes();

    let signature_ok = verify_ecdsa(pk_x, pk_y, pre_hash_bytes, signature);
    assert(
        signature_ok,
        "signature mismatch: ECDSA over Poseidon2(nft_hash, nonce) failed",
    );
}
