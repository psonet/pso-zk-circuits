// Recursive SU-ownership aggregation circuit, tier N = 6.
//
// Verifies N copies of `pso-ownership-circuit`'s ownership proof
// in-circuit via Noir recursion. One of 8 tier sizes the wallet
// picks based on the number of SUs being aggregated into a
// TributeDraft. See `pso_circuit_core::recursion` for the
// constraint set and the public-input layout, and
// `docs/aggregation-redesign.md` in psonet/pso-integration for
// the design rationale.

use bb_proof_verification::{UltraHonkProof, UltraHonkVerificationKey};
use pso_circuit_core::recursion;

global N: u32 = 6;

pub fn main(
    // Private witness — the inner circuit's VK and the N inner
    // proofs. Both are supplied by the aggregating wallet; the
    // recursive verifier doesn't need them at the public-input
    // boundary because the inner VK is pinned via `inner_vk_hash`
    // (public) and each proof is structurally verified in-circuit.
    inner_vk: UltraHonkVerificationKey,
    inner_proofs: [UltraHonkProof; N],
    inner_vk_hash: Field,
    // Public inputs — `2 * N` interleaved `(owner_i, nft_hash_i)`
    // pairs followed by the inner VK hash. The on-chain
    // TributeDraft.submit reads each pair against the loaded SU
    // and asserts the inner_vk_hash equals the canonical
    // pso-ownership-circuit vk_hash.
    public_inputs: pub [Field; 2 * N + 1],
) {
    recursion::verify(inner_vk, inner_proofs, inner_vk_hash, public_inputs);
}
