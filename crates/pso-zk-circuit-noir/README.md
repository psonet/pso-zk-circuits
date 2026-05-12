# pso-zk-circuit-noir

Noir circuit implementation for ZK proofs using the Barretenberg backend (UltraHonk).

## Noir Sub-projects

| Directory | Type | Nargo Name | Description |
|-----------|------|------------|-------------|
| `pso-circuit-core/` | lib | `pso_circuit_core` | Shared circuit library (ownership + inclusion modules) |
| `pso-full-circuit/` | bin | `full_proof` | Full proof: ownership + Merkle inclusion |
| `pso-ownership-circuit/` | bin | `ownership_proof` | Ownership-only proof |

## Compiled Bytecodes

Pre-compiled circuit bytecodes are stored in `data/`:
- `data/full_proof.json`
- `data/ownership_proof.json`

## Building Circuits

```bash
# Test all circuits
cd pso-circuit-core && nargo test
cd pso-full-circuit && nargo test
cd pso-ownership-circuit && nargo test

# Compile binary circuits
cd pso-full-circuit && nargo compile
cd pso-ownership-circuit && nargo compile

# Copy bytecodes to data/
cp pso-full-circuit/target/full_proof.json data/
cp pso-ownership-circuit/target/ownership_proof.json data/
```

## Rust Wrapper

The Rust crate provides `NoirFullProofCircuit` and `NoirOwnershipCircuit`, both implementing `ZKCircuit` defined locally in `src/circuit_traits.rs`. They handle witness map construction, proof generation, and verification via the `noir_rs` Barretenberg bindings (zkpassport fork, v1.0.0-beta.19-1).

## Proof Format

The `noir_rs` crate from zkpassport returns proofs with the following format:

```
[num_public_inputs (4 bytes BE)] [public_input_0: 32B] [public_input_1: 32B] ... [proof_bytes...]
```

The `split_proof()` function in `src/lib.rs` parses this format and splits the combined proof into separate public inputs and proof bytes for storage in the `NoirProof` struct.

## Testing

```bash
cargo test -p pso-zk-circuit-noir
```

Note: Full integration tests (test_full_proof_round_trip, test_ownership_proof_round_trip) require circuit artifacts compiled with Nargo v1.0.0-beta.19. See the project README for circuit compilation instructions.
