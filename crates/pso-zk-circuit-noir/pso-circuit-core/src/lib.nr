// Shared library for ZK proof circuits.
// Modules:
// - `ownership`: single (pk, nonce) -> Poseidon ownership hash + ECDSA.
// - `inclusion`: Merkle inclusion path verification.
// - `aggregation`: N-SU ownership aggregation under one keypair, used
//   by the per-tier `pso-su-ownership-aggregation-circuit-n*` bins.

pub mod ownership;
pub mod inclusion;
pub mod aggregation;
