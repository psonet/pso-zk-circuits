// Recursive SU-ownership aggregation.
//
// One Noir circuit, parameterised over a compile-time tier size `N`,
// that verifies N copies of the per-SU ownership proof in-circuit via
// `bb_proof_verification::verify_honk_proof_non_zk`. Folds N
// individual UltraHonk proofs into one recursive proof the on-chain
// `TributeDraft.submit` verifies with a single `zk_verify` call.
//
// ## Public-input layout
//
// `[ owner_0, nft_hash_0, owner_1, nft_hash_1, ..., owner_{N-1},
//   nft_hash_{N-1}, inner_vk_hash ]`
//
// — `2 * N` interleaved (owner, nft_hash) pairs followed by the
// inner circuit's VK hash. The contract reads the per-slot pairs
// directly against the on-chain SU set (each slot's `owner` is the
// SU's `derivedOwner`; each slot's `nft_hash` is the SU's entity
// hash reconstructed via `pso_protocol::nft::compute_spending_unit_hash`).
// The contract MUST assert that `inner_vk_hash` equals the canonical
// `pso-ownership-circuit` VK hash; otherwise the recursive proof
// could be made over a different (compromised) inner circuit.
//
// Padding: when the wallet aggregates fewer than `N` real SUs, the
// excess slots are filled with sentinel inputs that produce
// trivially-true ownership proofs. Per the privacy spec, the
// contract zeroes both `owner_i` and `nft_hash_i` for padded slots
// and the wallet supplies a matching trivial inner proof. The
// recursive circuit verifies each inner proof unconditionally —
// the padded inputs must still be valid public inputs for some
// well-formed inner proof. (A natural implementation: the wallet
// generates an inner proof with `owner = 0, nft_hash = 0` and a
// signature over Poseidon2(0, 0); since Poseidon5 of any
// `(pk, nonce)` collision-resists with `owner == 0`, the wallet
// proves with a synthetic `nonce` that yields owner=0 — practically
// infeasible, so the spec uses a "padding proof" pre-generated and
// re-used across tiers.)

use bb_proof_verification::{
    verify_honk_proof_non_zk, UltraHonkProof, UltraHonkVerificationKey,
};

/// Per-slot public-input width — `(owner, nft_hash)` per SU.
global INNER_PUBLIC_INPUT_LEN: u32 = 2;

/// Verify N inner SU-ownership proofs under a shared verification
/// key. The aggregating prover supplies the inner VK + N proofs as
/// private witness data; the public-input vector mirrors the
/// per-slot inner public inputs plus the inner VK hash, so the
/// on-chain verifier can pin the proof to a specific inner circuit.
///
/// Generic over `N` so a single source compiles to multiple
/// fixed-shape recursive circuits — `pso-recursive-aggregation-circuit-n*`
/// passes its compile-time tier `N`.
pub fn verify<let N: u32>(
    inner_vk: UltraHonkVerificationKey,
    inner_proofs: [UltraHonkProof; N],
    inner_vk_hash: Field,
    // `2 * N + 1` flat: 2 per slot + 1 for inner_vk_hash.
    public_inputs: [Field; 2 * N + 1],
) {
    // Pin the inner-VK hash to the publicly-exposed value. The
    // verifier (on-chain or otherwise) compares this against the
    // canonical `pso-ownership-circuit` vk_hash and rejects the
    // recursive proof if it doesn't match — that's the trust
    // anchor that keeps the recursion bound to a specific inner
    // circuit.
    assert(
        public_inputs[2 * N] == inner_vk_hash,
        "inner_vk_hash mismatch: prover claimed a vk_hash that doesn't match the value exposed publicly",
    );

    // Verify each inner proof in-circuit against the same VK.
    // `verify_honk_proof_non_zk` internally checks that
    // `hash(inner_vk) == inner_vk_hash`, so a prover that lies
    // about the VK is caught here.
    for i in 0..N {
        let slot_inputs: [Field; INNER_PUBLIC_INPUT_LEN] = [
            public_inputs[2 * i],
            public_inputs[2 * i + 1],
        ];
        verify_honk_proof_non_zk(inner_vk, inner_proofs[i], slot_inputs, inner_vk_hash);
    }
}
