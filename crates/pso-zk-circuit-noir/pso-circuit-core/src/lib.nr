// Shared library for ZK proof circuits.
// Modules:
// - `ownership`: §4.2 single-NFT ownership proof helpers — Poseidon5
//   owner commitment + ECDSA over Poseidon2(nft_hash, nonce).
// - `inclusion`: Merkle inclusion path verification.
// - `recursion`: helper for the `pso-recursive-aggregation-circuit-n*`
//   tier bins to fold N inner ownership proofs into one recursive
//   proof via the bb_proof_verification primitive.

pub mod ownership;
pub mod inclusion;
pub mod recursion;
