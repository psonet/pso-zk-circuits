// Spending Unit ownership aggregation module.
//
// Proves, in a single circuit, that the prover owns N distinct
// `derivedOwner` Poseidon hashes under one secp256k1 keypair, AND
// signs an EVM-side binding hash that pins the proof to a specific
// (caller, tributeDraftId, chainid) tuple.
//
// Used by the on-chain `TributeDraft` contract to gate aggregation of
// N Spending Units into a single Tribute Draft under the
// privacy-preserving L2 architecture (see PDF section 5).
// UltraHonkKeccak requires fixed circuit shape, so N is compile-time;
// the `pso-zk-canonical` table ships separately-compiled tiers
// (N = 1, 2, 4, 6, 8, 16, 32, 64).
//
// ## Public-input layout
//
// The circuit's public inputs, in order:
//   [0..N)     derived_owners[i] : Field   -- per-SU Poseidon-derived owner
//   [N]        binding_hash      : Field   -- Poseidon(sender, tdid_low,
//                                              tdid_high, chainid), fed
//                                              from the on-chain
//                                              `0x0202` Poseidon precompile
//
// The contract recomputes `binding_hash` itself from `msg.sender`,
// `tributeDraftId` (split into two 128-bit limbs to fit BN254 Fr), and
// `block.chainid`, then asserts the proof's public-input prefix matches
// the expected vector byte-for-byte before calling `zk_verify`. Without
// this binding the proof would be replayable from a public mempool.

use poseidon::poseidon;
use crate::ownership;

/// Verify SU-ownership aggregation. See module docs for full layout.
///
/// Generic over `N` (tier size) so a single source compiles to multiple
/// fixed-shape circuits. Per-tier bin crates supply `N` as a `global`.
pub fn verify<let N: u32>(
    pk_x_bytes: [u8; 32],
    pk_y_bytes: [u8; 32],
    nonces: [Field; N],
    signature: [u8; 64],
    derived_owners: [Field; N],
    binding_hash: Field,
) {
    // Per-SU Poseidon ownership: either the claimed derived_owners[i]
    // equals Poseidon(pk_x, pk_y, nonces[i]) under one shared keypair,
    // OR the slot is unused (derived_owners[i] == 0). Padding scheme:
    // the on-chain TributeDraft contract picks the smallest tier
    // `tier_n >= n_su` and zeroes out unused slots [n_su..tier_n);
    // the wallet sets the same slots to zero in its witness so the
    // constraint below trivializes for them.
    //
    // The check `(computed - derived_owners[i]) * derived_owners[i] == 0`
    // resolves to:
    //   - derived_owners[i] == 0  -> product is 0, no ownership check.
    //   - derived_owners[i] != 0  -> must have computed == derived_owners[i].
    //
    // Padding-into-collision risk: a legitimate SU whose derivedOwner
    // happens to equal zero would be indistinguishable from padding,
    // but Poseidon's preimage resistance makes such a hit ~2^-254 per
    // SU, well below any practical concern.
    for i in 0..N {
        let computed = ownership::compute_ownership(pk_x_bytes, pk_y_bytes, nonces[i]);
        assert(
            (computed - derived_owners[i]) * derived_owners[i] == 0,
            "su_ownership mismatch: aggregation proof failed",
        );
    }

    // Binding signature: ECDSA over the EVM-supplied binding_hash bytes.
    // The wallet signed the same value off-chain so the proof is
    // non-replayable across (caller, tributeDraftId, chainid) tuples.
    let pre_hash: [u8; 32] = binding_hash.to_le_bytes();
    let ok = ownership::verify_ecdsa(pk_x_bytes, pk_y_bytes, pre_hash, signature);
    assert(ok, "signature_verification_failed: binding_hash signature invalid");
}
