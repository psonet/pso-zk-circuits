# pso-zk-circuits

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Noir circuits and the Rust FFI prover wrapper** for the PSO
zero-knowledge proof system. One of four sibling repos in the
post-extraction layout:

- [`pso-protocol`](../pso-protocol) — consensus-binding hash primitives
  and witness types (consumed here for type definitions).
- **`pso-zk-circuits`** — Noir circuit sources + the `noir_rs`-based
  prover/verifier wrapper + canonical descriptors.
- [`pso-integration`](../pso-integration) — client-side integration:
  UniFFI wallet bindings, SRA registrar, CLI, VDF FFI (planned), and
  L2-interaction code.
- [`pso-chain`](../pso-chain) — PSO L2 chain (calls into this crate's
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

- [`pso-protocol`](../pso-protocol) — path-pinned during the multi-repo
  split. Flip to `version = "0.1"` (crates.io) once published.
- [`noir_rs`](https://github.com/zkpassport/noir_rs) — Noir runtime +
  Barretenberg FFI. Heavy native build (multi-minute first compile).
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

## Regenerating canonical descriptors

After any change to a Noir circuit source:

```bash
cargo xtask regenerate-canonical
```

This recompiles each circuit, derives the canonical UltraHonkKeccak VK
via the same `noir_rs` FFI the prover uses, and emits the descriptors
that `pso-zk-canonical` ships. The on-chain `zk_verify` precompile and
every wallet prover will agree on VK bytes by construction.

See `docs/issues/canonical-vk-toolchain-drift.md` in `pso-chain` for
the background on why we don't shell out to `bb write_vk` anymore.

## License

[MIT](LICENSE) — same as `pso-protocol` / `pso-vdf` / `pso-poseidon`.
