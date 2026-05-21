# pso-zk-circuits

[![release](https://img.shields.io/github/v/release/psonet/pso-zk-circuits.svg)](https://github.com/psonet/pso-zk-circuits/releases)
[![CI](https://github.com/psonet/pso-zk-circuits/actions/workflows/ci.yml/badge.svg)](https://github.com/psonet/pso-zk-circuits/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Noir circuits and the Rust FFI prover wrapper** for the PSO
zero-knowledge proof system. One of four sibling repos in the
post-extraction layout:

- [`pso-protocol`](https://github.com/psonet/pso-protocol) — consensus-binding hash primitives
  and witness types (consumed here for type definitions).
- **`pso-zk-circuits`** — Noir circuit sources + the vendored `noir_rs`-based
  prover/verifier wrapper + canonical descriptors.
- `pso-integration` (internal) — client-side integration:
  UniFFI wallet bindings, SRA registrar, CLI, VDF FFI (planned), and
  L2-interaction code.
- `pso-chain` (internal) — PSO L2 chain (calls into this crate's
  `derive_canonical_keccak_vk` from `xtask regenerate-canonical`).

This repo absorbs the circuit half of the legacy `pso-zk-proof`
workspace. The integration half (mobile/SRA UniFFI, CLI, NFT domain
types, plus the VDF FFI and L2 RPC code coming next) lives in
`pso-integration`.

## Why split it out

The previous monorepo coupled three concerns: hash primitives, ZK
circuits, and wallet integration. Each has a different cadence:

| Concern               | Cadence                       | Repo               |
| --------------------- | ----------------------------- | ------------------ |
| Consensus formulas    | Hardfork-gated                | `pso-protocol`     |
| ZK circuits + prover  | Coordinated circuit upgrades  | `pso-zk-circuits`  |
| FFI / wallets / CLI   | Wallet release cadence        | `pso-integration`  |

Keeping them in separate repos prevents wallet hotfixes from forcing
chain redeploys, prevents circuit recompiles from rebuilding wallets,
and lets each consumer pin the dependency that matches its release
process.

## Layout

```
pso-zk-circuits/
├── Cargo.toml                          # Three-member workspace
├── crates/
│   ├── pso-zk-circuit-noir/            # noir_rs FFI prover wrapper
│   │   ├── src/
│   │   │   ├── lib.rs                  # NoirFullProofCircuit, NoirOwnershipCircuit,
│   │   │   │                           # NoirSuOwnershipAggregationCircuit + Noir
│   │   │   │                           # witness-map serialization.
│   │   │   ├── circuit_traits.rs       # ZKCircuit, Proof, ZKCircuitVersion
│   │   │   │                           # (used to live in pso-zk-core)
│   │   │   └── testing.rs              # k256-aware witness builders
│   │   │                               # for tests/benches.
│   │   ├── pso-circuit-core/           # Noir package — shared circuit ops
│   │   ├── pso-ownership-circuit/      # Noir package — ownership proof
│   │   ├── pso-full-circuit/           # Noir package — ownership + Merkle
│   │   ├── pso-su-ownership-aggregation-circuit-n{1,2,4,6,8,16,32,64}/
│   │   │                               # Tiered aggregation circuits
│   │   ├── tests/                      # End-to-end prove/verify round-trips
│   │   ├── benches/                    # criterion proof_perf bench
│   │   └── data/                       # Pre-compiled ACIR JSONs (committed
│   │                                   # so consumers don't need a Noir
│   │                                   # toolchain to use the prover).
│   └── pso-zk-canonical/               # Authoritative circuit descriptors:
│                                       # circuit_hash + canonical VK bytes.
│                                       # Pure static data — pso-chain links
│                                       # against this for the on-chain
│                                       # zk_verify precompile.
└── xtask/                              # `cargo xtask regenerate-canonical`
                                        # rebuilds the descriptors via
                                        # noir_rs FFI (so chain-side and
                                        # wallet-side VKs are bit-identical).
```

## Dependencies

- [`pso-protocol`](https://github.com/psonet/pso-protocol) — published
  to crates.io as `pso-protocol = "0.2"`. Provides consensus-binding
  hash primitives and witness types.
- `noir_rs` proving glue — vendored directly into `crates/pso-zk-circuit-noir/src/`
  (Apache-2.0; see `crates/pso-zk-circuit-noir/NOTICE.md`). Derived
  from [zkpassport/noir_rs](https://github.com/zkpassport/noir_rs);
  underlying `noir-lang/noir` crates are direct deps pinned to
  `v1.0.0-beta.20`. Heavy native build (multi-minute first compile).
- `k256` (regular dep) — needed by the `testing.rs` module that the
  crate's own tests/benches use to build witnesses from real keypairs.

## Build

```bash
cargo build --workspace
cargo test  --workspace --tests --no-run     # compile tests
cargo test  -p pso-zk-canonical              # fast: pure-data tests
```

Full round-trip tests (`pso-zk-circuit-noir`'s integration tests) take
tens of seconds per tier under barretenberg. The default exercises only
N=1, N=2; enable the rest with `--features aggregation-full-tiers`.

### Mobile targets

`pso-zk-circuit-noir` compiles to per-target `libpso_zk_circuit_noir.{a,so}`
slices that the Wallet SDK / `pso-integration` UniFFI bindings consume.
Four targets: iOS device + Apple Silicon simulator, Android arm64-v8a +
x86_64. The repo's `mise.toml` ships convenience tasks that mirror the
exact `cargo build` / `cargo ndk` invocations CI runs:

```bash
mise run mobile:setup    # install rust targets + cargo-ndk
mise run build:mobile    # all four targets
mise tasks               # see every mobile task individually
```

See [`crates/pso-zk-circuit-noir/README.md`](https://github.com/psonet/pso-zk-circuits/blob/main/crates/pso-zk-circuit-noir/README.md)
for the full mobile-build prerequisites (NDK install, the API-level
"magic prefix" toolchain wrappers cargo-ndk depends on), raw-`cargo`
invocations for non-mise users, and how to verify the produced
artifacts have the correct target metadata stamped.

## Regenerating canonical descriptors

After any change to a Noir circuit source:

```bash
cargo xtask regenerate-canonical
```

This recompiles each circuit, derives the canonical UltraHonkKeccak VK
via the same `noir_rs` FFI the prover uses, and emits the descriptors
that `pso-zk-canonical` ships. The on-chain `zk_verify` precompile and
every wallet prover will agree on VK bytes by construction.

See the internal `pso-chain` design docs for the background on why
we don't shell out to `bb write_vk` anymore.

## Verifying releases

Releases tagged from `v0.2.5` onward ship sigstore cosign signatures + SLSA build-provenance attestations for every artifact (the `.crate`, every mobile slice that built successfully, and `SHA256SUMS`). See [SECURITY.md](SECURITY.md) for the threat model and the copy-pasteable verify recipe.

The mobile build matrix is best-effort (`continue-on-error: true`) — signing tolerates missing slices, so whichever subset built is what gets signed. The `verify-release` CI job hard-fails if any present signature is invalid, but allows missing slices.

Quick check (crate):

```sh
TAG=v0.2.5
ARTIFACT=pso-zk-canonical-${TAG#v}.crate
gh release download "$TAG" --repo psonet/pso-zk-circuits \
  --pattern "$ARTIFACT" --pattern "$ARTIFACT.sig" --pattern "$ARTIFACT.pem"
cosign verify-blob \
  --certificate "$ARTIFACT.pem" --signature "$ARTIFACT.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/psonet/pso-zk-circuits/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARTIFACT"
```

## License

[MIT](LICENSE) — same as `pso-protocol` / `pso-vdf` / `pso-poseidon`.
