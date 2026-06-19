# pso-zk-circuits

[![release](https://img.shields.io/github/v/release/psonet/pso-zk-circuits.svg)](https://github.com/psonet/pso-zk-circuits/releases)
[![CI](https://github.com/psonet/pso-zk-circuits/actions/workflows/ci.yml/badge.svg)](https://github.com/psonet/pso-zk-circuits/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

The PSO **zero-knowledge layer**: the canonical Noir circuits (their committed
on-chain identities and the witness / public-input types) plus the proving
backend. A Cargo workspace of two crates built on the generic
[`pso-protocol`](https://github.com/psonet/pso-protocol) traits:

- **[`pso-zk-canonical`](crates/pso-zk-canonical)** — concrete circuit + witness
  types (ownership, flat-aggregation tiers n1–n64, full proof) **and** the
  in-code, versioned **circuit registry**: every released circuit version with
  its `circuit_hash` / VK / dotted label — the authoritative on-chain identity
  source `pso-chain` consumes. Pure data + a **read-only `build.rs`** (reads the
  committed frozen artifacts; never runs the toolchain). **Published to crates.io.**
- **[`pso-zk-backend`](crates/pso-zk-backend)** — the Noir proving backend: a
  shared ACVM witness-solving core + a barretenberg (UltraHonkKeccak, FFI)
  prover/verifier. Pulls the noir toolchain (`acir`/`acvm`/`bn254_blackbox_solver`)
  via git and links C++ barretenberg, so it is **`publish = false`** (consumed as
  a workspace / git dependency).

## Layout

```
pso-zk-circuits/
├── Cargo.toml                       # virtual workspace + [workspace.dependencies]
├── crates/
│   ├── pso-zk-canonical/            # circuit + witness types, the registry, frozen artifacts
│   │   ├── noir/                    # .nr circuit sources
│   │   ├── resources/circuits/      # committed frozen bytecode + VKs (per version)
│   │   ├── circuits/manifest.toml   # append-only version manifest
│   │   └── build.rs                 # read-only: frozen artifacts → generated types
│   └── pso-zk-backend/              # ACVM solve + barretenberg FFI prove/verify
├── xtask/                           # `freeze-circuits` — the only step that runs nargo/bb
└── mise.toml                        # toolchain install + task wrappers
```

## Build

```bash
cargo build --workspace
cargo test  --workspace
```

`pso-zk-canonical` builds from its committed frozen artifacts — **no Noir
toolchain needed**. `pso-zk-backend` links C++ barretenberg, so it needs a C++
toolchain (cmake/clang) and network access (noir git deps + first-run SRS).

## Circuit management

Recompiling the circuits + refreshing the frozen artifacts (after editing the
`.nr` sources) is the only step that needs the Noir toolchain:

```bash
mise run install:zk-toolchain   # nargo + bb at the pinned versions (NOIR_VERSION / BB_VERSION)
mise run freeze-circuits        # = cargo run -p xtask -- freeze-circuits
```

`freeze-circuits` recompiles each head circuit, mints a new frozen version for
any whose ACIR changed (deprecating the superseded one), derives its
UltraHonkKeccak VK via `bb`, and updates `manifest.toml`. `BB_VERSION` must match
the `barretenberg-rs` pin in `pso-zk-backend` so freeze-derived VKs match the FFI
verifier.

## Verifying releases

Releases ship sigstore cosign signatures + SLSA build-provenance attestations for the published `pso-zk-canonical` `.crate`. See [SECURITY.md](SECURITY.md) for the threat model and the copy-pasteable verify recipe.

Quick check:

```sh
TAG=v0.8.0
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
