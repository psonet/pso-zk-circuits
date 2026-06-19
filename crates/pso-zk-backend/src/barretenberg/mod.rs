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

use std::future::Future;
use std::io::Read;
use std::pin::Pin;
use std::sync::{mpsc, OnceLock};
use std::task::{Context, Poll};
use std::thread;

use barretenberg_rs::api::BarretenbergApi;
use barretenberg_rs::backends::FfiBackend;
use barretenberg_rs::generated_types::{CircuitInput, ProofSystemSettings};
use base64::Engine;
use flate2::read::GzDecoder;

use pso_protocol::error::Error;
use pso_protocol::protocol::zk::{Circuit, CircuitId, CircuitSuite, ProofGenerator, ProofVerifier};

use crate::witness;

mod srs;

/// Barretenberg's CRS factory, its internal `parallel_for` thread pool, and its
/// slab allocators are **process-global** C++ state, and the C API is not built
/// for concurrent top-level calls (`barretenberg-rs`'s `FfiBackend` is documented
/// "not thread-safe … synchronize externally"; only the one-shot `SrsInitSrs`
/// command writes the CRS, prove/verify read it). So every bb operation is
/// funneled through a single long-lived **`bb-worker` thread** that runs them
/// strictly one at a time.
///
/// Why a worker thread and not a `Mutex`: a guard held across the (CPU-bound,
/// multi-hundred-ms) FFI call blocks the *OS thread*, so on an async runtime
/// concurrent callers park executor worker threads and starve unrelated tasks.
/// With the worker, a caller hands off a [`Job`] and waits on a `oneshot`: sync
/// callers block on `recv()` (e.g. on-device proving — single-threaded anyway),
/// async callers `.await` (their executor thread is freed while bb works).
///
/// This serializes but costs almost no throughput: each bb op already saturates
/// the cores via bb's internal `parallel_for`, so one-at-a-time is the right
/// shape — concurrent ops would only thrash the shared pool. (Parallel verify
/// throughput needs separate processes; bb globals can't be made per-instance.)
/// The worker also keeps bb's globals warm — a CRS sized by
/// [`preinit_srs`](Barretenberg::preinit_srs) stays initialized for every later job.
enum Job {
    Preinit {
        num_points: u32,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Prove {
        acir: Vec<u8>,
        solved: Vec<u8>,
        vk_bytes: Vec<u8>,
        label: String,
        settings: ProofSystemSettings,
        low_memory: bool,
        max_storage_usage: Option<u64>,
        reply: oneshot::Sender<Result<Proof, Error>>,
    },
    Verify {
        acir: Vec<u8>,
        vk_bytes: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
        proof: Vec<Vec<u8>>,
        settings: ProofSystemSettings,
        reply: oneshot::Sender<Result<bool, Error>>,
    },
    /// Like [`Job::Verify`] but the CRS must already be sized (skips `ensure_srs`).
    VerifyCombined {
        vk_bytes: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
        proof: Vec<Vec<u8>>,
        settings: ProofSystemSettings,
        reply: oneshot::Sender<Result<bool, Error>>,
    },
}

impl Job {
    /// Run this job on the worker thread and send its reply. Exactly one bb
    /// operation against the process-global CRS / prover. A dropped `reply`
    /// (caller gave up) is ignored.
    ///
    /// The ops below hold no generics: the caller did the pure prep (ACVM solve,
    /// acir decode, blob parse — none of which touch bb globals) and passed
    /// plain bytes, exactly as the old lock kept that work outside the critical
    /// section.
    fn run(self) {
        match self {
            Job::Preinit { num_points, reply } => {
                let _ = reply.send(Self::preinit(num_points));
            }
            Job::Prove {
                acir,
                solved,
                vk_bytes,
                label,
                settings,
                low_memory,
                max_storage_usage,
                reply,
            } => {
                let _ = reply.send(Self::prove(
                    acir,
                    solved,
                    vk_bytes,
                    label,
                    settings,
                    low_memory,
                    max_storage_usage,
                ));
            }
            Job::Verify {
                acir,
                vk_bytes,
                public_inputs,
                proof,
                settings,
                reply,
            } => {
                let _ = reply.send(Self::verify(acir, vk_bytes, public_inputs, proof, settings));
            }
            Job::VerifyCombined {
                vk_bytes,
                public_inputs,
                proof,
                settings,
                reply,
            } => {
                let _ = reply.send(Self::verify_combined(
                    vk_bytes,
                    public_inputs,
                    proof,
                    settings,
                ));
            }
        }
    }

    fn preinit(num_points: u32) -> Result<(), Error> {
        let mut api = Barretenberg::api()?;
        srs::ensure_srs(&mut api, num_points)
    }

    #[allow(clippy::too_many_arguments)]
    fn prove(
        acir: Vec<u8>,
        solved: Vec<u8>,
        vk_bytes: Vec<u8>,
        label: String,
        settings: ProofSystemSettings,
        low_memory: bool,
        max_storage_usage: Option<u64>,
    ) -> Result<Proof, Error> {
        configure_memory(low_memory, max_storage_usage);
        let mut api = Barretenberg::api()?;
        srs::ensure_srs_for(&mut api, &acir, &settings)?;
        let circuit = CircuitInput {
            name: label,
            bytecode: acir,
            verification_key: vk_bytes,
        };
        let response = api
            .circuit_prove(circuit, &solved, settings)
            .map_err(|e| Error::Proof(format!("bb prove: {e}")))?;
        Ok(Proof {
            proof: response.proof,
        })
    }

    fn verify(
        acir: Vec<u8>,
        vk_bytes: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
        proof: Vec<Vec<u8>>,
        settings: ProofSystemSettings,
    ) -> Result<bool, Error> {
        let mut api = Barretenberg::api()?;
        srs::ensure_srs_for(&mut api, &acir, &settings)?;
        let response = api
            .circuit_verify(&vk_bytes, public_inputs, proof, settings)
            .map_err(|e| Error::Proof(format!("bb verify: {e}")))?;
        Ok(response.verified)
    }

    fn verify_combined(
        vk_bytes: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
        proof: Vec<Vec<u8>>,
        settings: ProofSystemSettings,
    ) -> Result<bool, Error> {
        let mut api = Barretenberg::api()?;
        let response = api
            .circuit_verify(&vk_bytes, public_inputs, proof, settings)
            .map_err(|e| Error::Proof(format!("bb raw verify: {e}")))?;
        Ok(response.verified)
    }
}

/// The single `bb-worker` thread and the `mpsc` queue feeding it. bb's
/// process-global state must be touched one operation at a time (see [`Job`]);
/// this owns the thread that does so. There is exactly one per process — reach
/// it through [`Worker::global`].
struct Worker {
    tx: mpsc::Sender<Job>,
}

impl Worker {
    /// The process-global worker, spawned on first use.
    fn global() -> &'static Worker {
        static WORKER: OnceLock<Worker> = OnceLock::new();
        WORKER.get_or_init(Worker::spawn)
    }

    /// Spawn the `bb-worker` thread and return the handle to its queue. The
    /// thread runs one [`Job`] at a time until the last `Sender` drops (process
    /// teardown).
    fn spawn() -> Worker {
        let (tx, rx) = mpsc::channel::<Job>();
        thread::Builder::new()
            .name("bb-worker".to_string())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    job.run();
                }
            })
            .expect("spawn bb-worker thread");
        Worker { tx }
    }

    /// Queue a job and hand back its reply channel. The closure embeds the
    /// `oneshot::Sender` into the chosen [`Job`] variant. If the worker is gone
    /// the send drops the sender, so the receiver resolves to an error —
    /// surfaced by both [`BbReply`] seams as [`Worker::gone`].
    fn submit<T>(&self, make_job: impl FnOnce(oneshot::Sender<T>) -> Job) -> oneshot::Receiver<T> {
        let (tx, rx) = oneshot::channel();
        let _ = self.tx.send(make_job(tx));
        rx
    }

    /// The error surfaced when the worker is unreachable / the reply was dropped.
    fn gone() -> Error {
        Error::Proof("bb-worker thread unavailable".to_string())
    }
}

/// The handle for a job queued on the `bb-worker`. The worker replies over a
/// `oneshot`, and this wraps the receiver so the **same** handle drives both
/// seams: [`recv`](BbReply::recv) blocks the calling thread (the sync traits)
/// and the [`Future`] impl `.await`s it (the `Async*` traits). This is the named
/// future the async traits expose as their associated `Future` type — no boxing,
/// and `Send` whenever `T: Send`.
///
/// A caller-side prep failure (malformed input, before any job was queued) is
/// carried inline and surfaced identically by both seams, so the async methods
/// stay infallible-to-construct (`-> BbReply<T>`, not `-> Result<…>`).
pub struct BbReply<T> {
    inner: Result<oneshot::Receiver<Result<T, Error>>, Option<Error>>,
}

impl<T> BbReply<T> {
    /// Pending on the worker's reply.
    fn pending(rx: oneshot::Receiver<Result<T, Error>>) -> Self {
        Self { inner: Ok(rx) }
    }

    /// Build from a prep `Result`: `Ok(rx)` pends on the worker; `Err(e)`
    /// resolves immediately to that prep error.
    fn from_prep(prep: Result<oneshot::Receiver<Result<T, Error>>, Error>) -> Self {
        Self {
            inner: prep.map_err(Some),
        }
    }

    /// Block the calling thread until the worker replies (the sync seam). The
    /// `Async*` traits' sync counterparts are exactly `self.…_async(…).recv()`.
    pub fn recv(self) -> Result<T, Error> {
        match self.inner {
            Ok(rx) => rx.recv().map_err(|_| Worker::gone())?,
            Err(prep_err) => Err(prep_err.unwrap_or_else(Worker::gone)),
        }
    }
}

// `Receiver<T>: Unpin` (oneshot), so `BbReply<T>` is `Unpin` and `get_mut`/
// `Pin::new` need no projection.
impl<T> Future for BbReply<T> {
    type Output = Result<T, Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut self.get_mut().inner {
            Ok(rx) => match Pin::new(rx).poll(cx) {
                Poll::Ready(Ok(result)) => Poll::Ready(result),
                Poll::Ready(Err(_)) => Poll::Ready(Err(Worker::gone())),
                Poll::Pending => Poll::Pending,
            },
            Err(prep_err) => Poll::Ready(Err(prep_err.take().unwrap_or_else(Worker::gone))),
        }
    }
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

    /// Pre-initialize bb's (one-shot, process-global) CRS to `num_points` G1
    /// points. Call once at startup with the largest circuit's size when a
    /// process proves circuits of *different* sizes (e.g. several aggregation
    /// tiers) — otherwise the first, smaller circuit fixes the CRS and larger
    /// ones fail. For our canonical set the max is the n64 tier
    /// (`(1 << 20) + 1`). Single-circuit callers can skip this; the first prove
    /// sizes the CRS to its circuit.
    ///
    /// An associated function, not a method: the CRS is process-global and
    /// shared by every [`Barretenberg`] instance and operation, so it depends on
    /// no instance state (`disable_zk` / `low_memory` are irrelevant here).
    pub fn preinit_srs(num_points: u32) -> Result<(), Error> {
        Self::preinit_srs_async(num_points).recv()
    }

    /// `async` analogue of [`preinit_srs`](Self::preinit_srs) — `.await` the
    /// worker instead of blocking the calling (executor) thread. Returns the
    /// [`BbReply`] future directly.
    pub fn preinit_srs_async(num_points: u32) -> BbReply<()> {
        BbReply::pending(Worker::global().submit(|reply| Job::Preinit { num_points, reply }))
    }
}

// ---- prove / verify: the async traits are canonical; sync derives from them --

/// Async counterpart of [`ProofGenerator`]. Exposes a **named** associated
/// future ([`BbReply`]) rather than an `async fn`, so the bound is explicitly
/// `+ Send` (usable from a multi-thread runtime) with no boxing — the
/// "GAT-style" async trait. The sync [`ProofGenerator`] impl is just
/// `generate_async(…).recv()`.
pub trait AsyncProofGenerator<S, C>
where
    S: CircuitSuite,
    C: Circuit<S> + CircuitId,
{
    /// The proof type, matching the sync [`ProofGenerator::Proof`].
    type Proof;
    /// The future [`generate_async`](Self::generate_async) returns.
    type Future: Future<Output = Result<Self::Proof, Error>> + Send;
    /// Queue a proof and return its reply future. Caller-side prep (witness
    /// solve, acir decode) runs eagerly, before the future is returned.
    fn generate_async(&self, witness: &C::Witness, public: &C::PublicInputs) -> Self::Future;
}

/// Async counterpart of [`ProofVerifier`]; see [`AsyncProofGenerator`].
pub trait AsyncProofVerifier<S, C>
where
    S: CircuitSuite,
    C: Circuit<S> + CircuitId,
{
    /// The proof type, matching the sync [`ProofVerifier::Proof`].
    type Proof;
    /// The future [`verify_async`](Self::verify_async) returns.
    type Future: Future<Output = Result<bool, Error>> + Send;
    /// Queue a verification and return its reply future.
    fn verify_async(&self, public: &C::PublicInputs, proof: &Self::Proof) -> Self::Future;
}

impl Barretenberg {
    /// Pure prep (ACVM solve + acir decode — no bb global state) then queue the
    /// prove job, on the calling thread, exactly as the old lock kept it outside
    /// the critical section. `Err` is a prep failure; `Ok` pends on the worker.
    fn submit_prove<S, C>(
        &self,
        witness: &C::Witness,
        public: &C::PublicInputs,
    ) -> Result<oneshot::Receiver<Result<Proof, Error>>, Error>
    where
        S: CircuitSuite,
        C: Circuit<S> + CircuitId,
    {
        let solved = witness::solved_witness::<S, C>(witness, public)?;
        let acir = acir_buffer_uncompressed::<C>()?;
        let settings = settings_ultra_honk_keccak(self.disable_zk);
        Ok(Worker::global().submit(|reply| Job::Prove {
            acir,
            solved,
            vk_bytes: C::VK_BYTES.to_vec(),
            label: C::LABEL.to_string(),
            settings,
            low_memory: self.low_memory,
            max_storage_usage: self.max_storage_usage,
            reply,
        }))
    }

    /// Pure prep (public-input reshape + acir decode) then queue the verify job.
    fn submit_verify<S, C>(
        &self,
        public: &C::PublicInputs,
        proof: &Proof,
    ) -> Result<oneshot::Receiver<Result<bool, Error>>, Error>
    where
        S: CircuitSuite,
        C: Circuit<S> + CircuitId,
    {
        let public_inputs = witness::public_inputs::<S, C>(public);
        let acir = acir_buffer_uncompressed::<C>()?;
        let settings = settings_ultra_honk_keccak(self.disable_zk);
        Ok(Worker::global().submit(|reply| Job::Verify {
            acir,
            vk_bytes: C::VK_BYTES.to_vec(),
            public_inputs,
            proof: proof.proof.clone(),
            settings,
            reply,
        }))
    }
}

impl<S, C> AsyncProofGenerator<S, C> for Barretenberg
where
    S: CircuitSuite,
    C: Circuit<S> + CircuitId,
{
    type Proof = Proof;
    type Future = BbReply<Proof>;

    fn generate_async(&self, witness: &C::Witness, public: &C::PublicInputs) -> BbReply<Proof> {
        BbReply::from_prep(self.submit_prove::<S, C>(witness, public))
    }
}

impl<S, C> AsyncProofVerifier<S, C> for Barretenberg
where
    S: CircuitSuite,
    C: Circuit<S> + CircuitId,
{
    type Proof = Proof;
    type Future = BbReply<bool>;

    fn verify_async(&self, public: &C::PublicInputs, proof: &Proof) -> BbReply<bool> {
        BbReply::from_prep(self.submit_verify::<S, C>(public, proof))
    }
}

// Sync seams, derived from the async ones. `ProofGenerator` / `ProofVerifier`
// are foreign (`pso_protocol`) traits, so coherence forbids a blanket
// `impl<T: Async…> Sync… for T` (no local type in the impl header). They're
// therefore implemented directly on `Barretenberg` — and because the concrete
// `Future` is known to be [`BbReply`], each is a one-line blocking `recv()` over
// its async counterpart (no executor needed on the hot proving path).
impl<S, C> ProofGenerator<S, C> for Barretenberg
where
    S: CircuitSuite,
    C: Circuit<S> + CircuitId,
{
    type Proof = Proof;

    fn generate(&self, witness: &C::Witness, public: &C::PublicInputs) -> Result<Proof, Error> {
        <Self as AsyncProofGenerator<S, C>>::generate_async(self, witness, public).recv()
    }
}

impl<S, C> ProofVerifier<S, C> for Barretenberg
where
    S: CircuitSuite,
    C: Circuit<S> + CircuitId,
{
    type Proof = Proof;

    fn verify(&self, public: &C::PublicInputs, proof: &Proof) -> Result<bool, Error> {
        <Self as AsyncProofVerifier<S, C>>::verify_async(self, public, proof).recv()
    }
}

/// Verify an UltraHonkKeccak proof against a raw verification key — without a
/// compile-time [`Circuit`] type.
///
/// Where [`ProofVerifier`] needs the concrete circuit type `C` (to supply
/// `C::VK_BYTES` and reshape a typed `C::PublicInputs` into field words), this
/// takes the verification key and the proof as opaque bytes. That makes it the
/// right seam for a circuit-agnostic consumer such as the chain's `zk_verify`
/// precompile, which only has a `vk_bytes` looked up at runtime from the
/// canonical registry plus the proof the caller submitted — and must stay
/// decoupled from every circuit's public-input layout.
pub trait RawVerifier {
    /// Verify the self-describing EVM "combined" proof against `vk_bytes`.
    ///
    /// `combined_proof` is the byte layout the on-chain verifier consumes:
    ///
    /// ```text
    /// [4B BE num_public_inputs][32B × num_public_inputs][proof fields …]
    /// ```
    ///
    /// i.e. a big-endian `u32` count, then that many 32-byte public-input
    /// words, then the proof as concatenated 32-byte field elements. The split
    /// is recovered from the header alone — no VK introspection needed.
    ///
    /// The global bb CRS must already be initialized (see
    /// [`preinit_srs`](Barretenberg::preinit_srs));
    /// this neither sizes nor fetches it. Returns `Ok(false)` for a
    /// well-formed-but-invalid proof and `Err` only for a malformed blob or an
    /// FFI failure.
    fn verify_combined(&self, vk_bytes: &[u8], combined_proof: &[u8]) -> Result<bool, Error>;
}

impl Barretenberg {
    /// Parse the combined-proof blob (pure — no bb global state) and queue the
    /// raw-verify job. Shared by [`RawVerifier::verify_combined`] and
    /// [`Barretenberg::verify_combined_async`].
    fn submit_verify_combined(
        &self,
        vk_bytes: &[u8],
        combined_proof: &[u8],
    ) -> Result<oneshot::Receiver<Result<bool, Error>>, Error> {
        // Header: big-endian u32 public-input count.
        let header = combined_proof
            .get(..4)
            .ok_or_else(|| Error::Proof("combined proof shorter than 4-byte header".into()))?;
        let num_public = u32::from_be_bytes(header.try_into().expect("4 bytes")) as usize;

        // [4 .. 4 + 32·N] public-input words.
        let pub_end = 4 + num_public * 32;
        let pub_bytes = combined_proof
            .get(4..pub_end)
            .ok_or_else(|| Error::Proof("combined proof truncated in public inputs".into()))?;
        let public_inputs: Vec<Vec<u8>> = pub_bytes.chunks_exact(32).map(<[u8]>::to_vec).collect();

        // Remainder is the proof, as 32-byte field words.
        let proof_bytes = &combined_proof[pub_end..];
        if !proof_bytes.len().is_multiple_of(32) {
            return Err(Error::Proof(
                "combined proof: proof section not a multiple of 32 bytes".into(),
            ));
        }
        let proof: Vec<Vec<u8>> = proof_bytes.chunks_exact(32).map(<[u8]>::to_vec).collect();

        let settings = settings_ultra_honk_keccak(self.disable_zk);
        Ok(Worker::global().submit(|reply| Job::VerifyCombined {
            vk_bytes: vk_bytes.to_vec(),
            public_inputs,
            proof,
            settings,
            reply,
        }))
    }
}

/// Async counterpart of [`RawVerifier`] — the seam the chain's `zk_verify`
/// precompile wants from an async runtime: blob parsing runs eagerly, then the
/// bb verify is awaited off the executor thread. See [`AsyncProofGenerator`] for
/// the named-future rationale. Unlike the prove/verify seams, [`RawVerifier`] is
/// a **local** trait, so its sync form is a true blanket over every
/// `AsyncRawVerifier` (below) rather than a per-type delegation.
pub trait AsyncRawVerifier {
    /// The future [`verify_combined_async`](Self::verify_combined_async) returns.
    type Future: Future<Output = Result<bool, Error>> + Send;
    /// Queue a raw verification (see [`RawVerifier::verify_combined`] for the
    /// `combined_proof` layout); the CRS must already be initialized.
    fn verify_combined_async(&self, vk_bytes: &[u8], combined_proof: &[u8]) -> Self::Future;
}

impl AsyncRawVerifier for Barretenberg {
    type Future = BbReply<bool>;

    fn verify_combined_async(&self, vk_bytes: &[u8], combined_proof: &[u8]) -> BbReply<bool> {
        BbReply::from_prep(self.submit_verify_combined(vk_bytes, combined_proof))
    }
}

// `RawVerifier` is local, so — unlike the foreign prove/verify seams — its sync
// form is a real blanket: every `AsyncRawVerifier` is a `RawVerifier`. The
// blanket is generic over `T::Future` (which it can't name to call
// `BbReply::recv`), so it drives the future with a minimal current-thread
// `block_on` instead. The bb work still runs on the worker; this only parks the
// caller until the reply lands.
impl<T: AsyncRawVerifier> RawVerifier for T {
    fn verify_combined(&self, vk_bytes: &[u8], combined_proof: &[u8]) -> Result<bool, Error> {
        pollster::block_on(self.verify_combined_async(vk_bytes, combined_proof))
    }
}

#[cfg(test)]
mod raw_verifier_tests {
    use super::*;

    // These exercise `verify_combined`'s blob-parsing guards, which all return
    // before the FFI `circuit_verify` call — so they need neither a CRS nor a
    // real proof. A well-formed blob would reach bb and is covered by the
    // integration tests that stand up the SRS.

    #[test]
    fn rejects_header_shorter_than_4_bytes() {
        assert!(Barretenberg::default()
            .verify_combined(b"vk", &[0u8; 3])
            .is_err());
    }

    #[test]
    fn rejects_public_inputs_truncated() {
        // Header claims 2 public inputs (needs 64 bytes) but only 10 follow.
        let mut blob = 2u32.to_be_bytes().to_vec();
        blob.extend_from_slice(&[0u8; 10]);
        assert!(Barretenberg::default()
            .verify_combined(b"vk", &blob)
            .is_err());
    }

    #[test]
    fn rejects_proof_not_multiple_of_32() {
        // Zero public inputs, then a 33-byte proof section.
        let mut blob = 0u32.to_be_bytes().to_vec();
        blob.extend_from_slice(&[0u8; 33]);
        assert!(Barretenberg::default()
            .verify_combined(b"vk", &blob)
            .is_err());
    }
}
