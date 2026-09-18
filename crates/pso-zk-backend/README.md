# pso-zk-backend

The Noir **proving backend** for the canonical PSO circuits: a shared ACVM
witness-solving core plus a barretenberg (UltraHonkKeccak, FFI) prover/verifier.

> **Not published to crates.io** (`publish = false`). It depends on the noir
> toolchain (`acir` / `acvm` / `bn254_blackbox_solver`) via git tags that
> crates.io cannot resolve, and links a native C++ barretenberg via FFI. Consume
> it as a git / workspace dependency.

## A circuit-generic prover/verifier

The backend is **generic over any circuit** — it depends only on the
`pso-protocol` seams (`Circuit` with its prove-side `witness_inputs` /
verify-side `public_inputs`, `CircuitId`, `CircuitSuite`), **not** on the
concrete `pso-zk-canonical` (only the tests/benches pull that in). A single
[`Barretenberg`] value implements both core seams for every `C: Circuit<S>`:

- [`ProofGenerator<S, C>`](https://docs.rs/pso-protocol) — `generate(witness, public) -> Proof`
- [`ProofVerifier<S, C>`](https://docs.rs/pso-protocol) — `verify(public, proof) -> bool`

So the same backend proves/verifies ownership, every flat-aggregation tier
(n1–n64), the full proof, **or any circuit you define** that implements the
seams — you pick the circuit type at the call site via the `C` type parameter.

```rust
use pso_protocol::{PsoV1, Suite};
use pso_protocol::protocol::zk::{ProofGenerator, ProofVerifier};
use pso_zk_backend::barretenberg::Barretenberg;
use pso_zk_canonical::noir::ownership_proof::OwnershipProof;
use pso_zk_canonical::ownership::Provable;   // builds the witness from protocol data

// `witness` + `public` come from the circuit's witness builder, e.g.
// `nft.derive_ownership_witness(&mut rng, &signer, binding)?`.
let bb = Barretenberg::default();            // zero-knowledge ON (see below)

// The circuit is chosen by the `C` type parameter — here `OwnershipProof`.
let proof = ProofGenerator::<PsoV1, OwnershipProof>::generate(&bb, &witness, &public)?;
let ok    = ProofVerifier::<PsoV1, OwnershipProof>::verify(&bb, &public, &proof)?;
assert!(ok);
```

`Barretenberg::default()` keeps **zero-knowledge on** (`disable_zk = false`) — the
ownership/full witnesses carry a secret key, so the proof must not leak it. Opt
into the faster `disable_zk = true` path only for public-input-only statements:

```rust
let bb = Barretenberg { disable_zk: true, ..Default::default() };
```

`preinit_srs(num_points)` warms the structured reference string up front (e.g.
before a batch of proofs) so the first `generate` doesn't pay the download/load.

## The native barretenberg library (`libbb-external.a`)

The `barretenberg-rs` dependency links a **prebuilt static** `libbb-external.a`.
Its build script resolves it, in order:

1. **`BB_LIB_DIR`** — if set, links the `libbb-external.a` in that directory
   (use this to supply a locally-built or patched library).
2. Otherwise it **downloads a prebuilt** for the build `TARGET` triple. Supported
   out of the box (no manual barretenberg build needed):

   | Host / target triple | bb arch |
   | -------------------- | ------- |
   | `x86_64-unknown-linux-gnu` | `amd64-linux` |
   | `aarch64-unknown-linux-gnu` | `arm64-linux` |
   | `x86_64-apple-darwin` | `amd64-darwin` |
   | `aarch64-apple-darwin` | `arm64-darwin` |
   | `aarch64-apple-ios` | `arm64-ios` |
   | `aarch64-apple-ios-sim` | `arm64-ios-sim` |
   | `aarch64-linux-android` | `arm64-android` |
   | `x86_64-linux-android` | `x86_64-android` |

   `BARRETENBERG_VERSION` overrides which prebuilt version is fetched (defaults to
   the `barretenberg-rs` crate version — the `=5.0.0-nightly.…` pin).

A host build needs a C++ toolchain (cmake + clang) and network access (the
prebuilt download + a first-run SRS fetch).

## Building for iOS / Android

Because the prebuilt covers the mobile triples, cross-compiling is a target flag
— barretenberg-rs fetches the matching `libbb-external.a` automatically — plus
`--no-default-features`, which is **not** optional here:

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim \
                  aarch64-linux-android x86_64-linux-android

cargo build -p pso-zk-backend --no-default-features --target aarch64-apple-ios
cargo build -p pso-zk-backend --no-default-features --target aarch64-apple-ios-sim
cargo ndk -t arm64-v8a -t x86_64 build -p pso-zk-backend --release --no-default-features
```

The default feature set includes `with-network-srs`, which pulls `reqwest` and a
tokio runtime and makes a missing SRS a blocking HTTP fetch. On a phone that
fetch panics. With the feature off the dependency is gone, a missing SRS is a
hard error instead, and you must supply the CRS yourself — see [SRS](#srs).

### When you must rebuild barretenberg yourself

You only need to build `libbarretenberg` / `libbb-external.a` from source when:

- the target triple isn't in the table above (an unsupported arch/OS), or
- there's no prebuilt for the pinned `BARRETENBERG_VERSION` and that target, or
- you need a locally-patched barretenberg.

Build `libbb-external.a` for the target arch from the
[barretenberg](https://github.com/AztecProtocol/aztec-packages/tree/master/barretenberg)
source (it bundles barretenberg + env + the vm2 stub), then point the crate at it:

```bash
BB_LIB_DIR=/path/to/libbb-dir cargo build -p pso-zk-backend --target <triple>
```

Keep that barretenberg at the **same version** as the `barretenberg-rs` pin so
its proofs/VKs stay compatible with the canonical artifacts.

## SRS

The prover/verifier needs the Aztec CRS (structured reference string). With the
default `with-network-srs` feature the backend uses a local cache and falls back
to downloading the CRS, **verifying the G1 prefix against a pinned SHA-256**
before trusting it. Pinned sizes live in `barretenberg::srs`; an unpinned size
logs a warning to stderr.

Built `--no-default-features` there is no download path at all, so the CRS has to
be on disk and pointed at explicitly with `set_srs_path` (re-exported from the
crate root) before proving. A missing file is then an error rather than a fetch.
That is the required sequence for the mobile builds above.

## Building & testing

```bash
cargo build -p pso-zk-backend
cargo test  -p pso-zk-backend     # prove/verify round-trips against pso-zk-canonical
cargo bench -p pso-zk-backend     # cross-circuit proving cost
```

## License

[MIT](../../LICENSE)
