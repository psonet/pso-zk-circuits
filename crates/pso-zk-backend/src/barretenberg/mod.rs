//! Barretenberg backend (feature `barretenberg`): UltraHonkKeccak proving and
//! verification over the canonical circuits, via `barretenberg-rs`'s FFI
//! (`libbb-external`) — no `bb` subprocess, so it runs on-device.
//!
//! Mirrors the reference `pso-zk-circuit-noir` backend: keccak oracle hash for
//! on-chain (EVM) verification ([`settings_ultra_honk_keccak`]) and an optional
//! **low-memory mode** ([`configure_memory`]) that file-backs barretenberg's
//! polynomials (~2× slower, much less RAM — for proving on constrained
//! devices). Bytecode and witness are handed to bb **uncompressed** (the
//! committed bytecode and `WitnessStack::serialize()` are gzipped; bb wants raw
//! msgpack).
//!
//! Thin shell: [`witness::solved_witness`](crate::witness::solved_witness)
//! produces the ACVM-solved witness, this hands it to `circuit_prove` with the
//! circuit's committed bytecode + VK ([`CircuitId`](pso_zk_canonical::CircuitId));
//! verification re-derives the public inputs from the claim and calls
//! `circuit_verify`. Pinned to `barretenberg-rs` =5.0.0-nightly.20260522,
//! matching the `bb` that writes the committed VKs (`-t evm-no-zk`).

use std::io::Read;
use std::sync::{Mutex, MutexGuard};

use barretenberg_rs::api::BarretenbergApi;
use barretenberg_rs::backends::FfiBackend;
use barretenberg_rs::generated_types::{CircuitInput, ProofSystemSettings};
use base64::Engine;
use flate2::read::GzDecoder;

use pso_protocol::error::Error;
use pso_protocol::protocol::zk::{Circuit, CircuitId, CircuitSuite, ProofGenerator, ProofVerifier};

use crate::witness;

mod srs;

/// Barretenberg's CRS factory, low-memory globals, and prover are **process-
/// global** C++ state, and the API is not reentrant — so every bb operation
/// (SRS init through prove/verify) must be serialized. This lock makes the
/// backend safe to call from multiple threads: concurrent callers block here
/// instead of racing the global CRS. Poison is recovered (a panicked prior call
/// leaves the global state to be reset by the next `setup_srs` anyway).
static BB_LOCK: Mutex<()> = Mutex::new(());

fn bb_lock() -> MutexGuard<'static, ()> {
    BB_LOCK.lock().unwrap_or_else(|poison| poison.into_inner())
}

/// Pre-initialize bb's (one-shot, process-global) CRS to `num_points` G1 points.
/// Call once at startup with the largest circuit's size when a process proves
/// circuits of *different* sizes (e.g. several aggregation tiers) — otherwise
/// the first, smaller circuit fixes the CRS and larger ones fail. For our
/// canonical set the max is the n64 tier (`(1 << 20) + 1`). Single-circuit
/// callers can skip this; the first prove sizes the CRS to its circuit.
pub fn preinit_srs(num_points: u32) -> Result<(), Error> {
    let _bb = bb_lock();
    let mut api = Barretenberg::api()?;
    srs::ensure_srs(&mut api, num_points)
}

/// UltraHonkKeccak proof, as bb's field encoding (`Vec<Vec<u8>>`). The public
/// inputs are not carried here — verification re-derives them from the claim.
#[derive(Clone, Debug)]
pub struct Proof {
    /// The proof fields.
    pub proof: Vec<Vec<u8>>,
}

/// UltraHonk + keccak oracle settings (EVM/on-chain verification), matching how
/// the committed VKs are generated (`bb write_vk -t evm-no-zk`).
fn settings_ultra_honk_keccak(disable_zk: bool) -> ProofSystemSettings {
    ProofSystemSettings {
        ipa_accumulation: false,
        oracle_hash_type: "keccak".to_string(),
        disable_zk,
        optimized_solidity_verifier: false,
    }
}

/// Toggle barretenberg's low-memory mode (file-backed polynomial storage): much
/// less RAM at ~2× proving time, for constrained devices. Sets the env vars bb
/// reads (`BB_SLOW_LOW_MEMORY` / `BB_STORAGE_BUDGET`) before prove/VK ops.
fn configure_memory(enabled: bool, max_storage_usage: Option<u64>) {
    std::env::set_var("BB_SLOW_LOW_MEMORY", if enabled { "1" } else { "0" });
    if let Some(budget) = max_storage_usage {
        std::env::set_var("BB_STORAGE_BUDGET", budget.to_string());
    }
}

/// Base64-decode then gunzip a circuit's committed bytecode into the raw ACIR
/// buffer bb's FFI consumes.
fn acir_buffer_uncompressed<C: CircuitId>() -> Result<Vec<u8>, Error> {
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(C::BYTECODE_B64)
        .map_err(|e| Error::Proof(format!("acir bytecode base64: {e}")))?;
    let mut raw = Vec::new();
    GzDecoder::new(compressed.as_slice())
        .read_to_end(&mut raw)
        .map_err(|e| Error::Proof(format!("acir decompress: {e}")))?;
    Ok(raw)
}

/// The barretenberg prover/verifier. Carries the proof-mode knobs the reference
/// exposes: `disable_zk` (off by default — keep ZK for secret-bearing witnesses)
/// and `low_memory` (+ optional storage budget) for on-device proving.
#[derive(Clone, Copy, Debug)]
pub struct Barretenberg {
    /// Disable zero-knowledge blinding (faster, but not ZK — only for
    /// public-input-only statements). Default `false`.
    pub disable_zk: bool,
    /// File-back polynomial memory: less RAM, ~2× slower.
    pub low_memory: bool,
    /// Optional storage budget (bytes) for low-memory mode.
    pub max_storage_usage: Option<u64>,
}

#[allow(clippy::derivable_impls)] // manual impl documents the security-critical disable_zk = false default
impl Default for Barretenberg {
    fn default() -> Self {
        // Zero-knowledge ON: the ownership/full witnesses carry a secret key, so
        // the proof must not leak it. `disable_zk = true` is faster but not ZK —
        // opt into it only for public-input-only statements.
        Self {
            disable_zk: false,
            low_memory: false,
            max_storage_usage: None,
        }
    }
}

impl Barretenberg {
    fn api() -> Result<BarretenbergApi<FfiBackend>, Error> {
        let backend = FfiBackend::new().map_err(|e| Error::Proof(format!("bb init: {e}")))?;
        Ok(BarretenbergApi::new(backend))
    }
}

impl<S, C> ProofGenerator<S, C> for Barretenberg
where
    S: CircuitSuite,
    C: Circuit<S> + CircuitId,
{
    type Proof = Proof;

    fn generate(
        &self,
        witness: &C::Witness,
        public: &C::PublicInputs,
    ) -> Result<Self::Proof, Error> {
        // Pure (ACVM solve + decode) — no bb global state, so outside the lock.
        let solved = witness::solved_witness::<S, C>(witness, public)?;
        let acir = acir_buffer_uncompressed::<C>()?;
        let settings = settings_ultra_honk_keccak(self.disable_zk);

        // Everything below touches bb's process-global CRS / memory / prover.
        let _bb = bb_lock();
        configure_memory(self.low_memory, self.max_storage_usage);
        let mut api = Self::api()?;
        srs::ensure_srs_for(&mut api, &acir, &settings)?;
        let circuit = CircuitInput {
            name: C::LABEL.to_string(),
            bytecode: acir,
            verification_key: C::VK_BYTES.to_vec(),
        };
        let response = api
            .circuit_prove(circuit, &solved, settings)
            .map_err(|e| Error::Proof(format!("bb prove: {e}")))?;
        Ok(Proof {
            proof: response.proof,
        })
    }
}

impl<S, C> ProofVerifier<S, C> for Barretenberg
where
    S: CircuitSuite,
    C: Circuit<S> + CircuitId,
{
    type Proof = Proof;

    fn verify(&self, public: &C::PublicInputs, proof: &Self::Proof) -> Result<bool, Error> {
        let public_inputs = witness::public_inputs::<S, C>(public);
        let acir = acir_buffer_uncompressed::<C>()?;
        let settings = settings_ultra_honk_keccak(self.disable_zk);

        // bb's global CRS / prover — serialize against concurrent prove/verify.
        let _bb = bb_lock();
        let mut api = Self::api()?;
        srs::ensure_srs_for(&mut api, &acir, &settings)?;
        let response = api
            .circuit_verify(C::VK_BYTES, public_inputs, proof.proof.clone(), settings)
            .map_err(|e| Error::Proof(format!("bb verify: {e}")))?;
        Ok(response.verified)
    }
}
