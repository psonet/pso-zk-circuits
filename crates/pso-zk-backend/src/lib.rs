//! Noir proving backend for the canonical PSO circuits.
//!
//! Layering: the circuit *seams* live in the core `pso-protocol`
//! ([`Circuit`](pso_protocol::protocol::zk::Circuit) with its prove-side
//! `witness_inputs` and verify-side `public_inputs`, plus
//! [`CircuitId`](pso_protocol::protocol::zk::CircuitId) /
//! [`CircuitSuite`](pso_protocol::protocol::zk::CircuitSuite)). This crate is
//! **generic over any circuit** implementing those seams — it does not depend on
//! the concrete `pso-zk-canonical` (only its tests/benches do). It adds the
//! noir-toolchain coupling that can't be published (acir/acvm via git, native
//! barretenberg): a shared ACVM witness-solving core ([`witness`]) and the
//! [`barretenberg`] UltraHonkKeccak prover/verifier (FFI, on-device).
//!
//! Both consume [`witness::solved_witness`] (the ACVM-solved witness) and
//! [`witness::public_inputs`], and implement the core
//! [`ProofGenerator`](pso_protocol::protocol::zk::ProofGenerator) /
//! [`ProofVerifier`](pso_protocol::protocol::zk::ProofVerifier) seams.

pub mod barretenberg;
pub mod witness;
