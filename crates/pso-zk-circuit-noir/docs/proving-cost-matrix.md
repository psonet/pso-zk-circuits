# Proving cost matrix

Cross-option benchmark of PK-build cost (`circuit_compute_vk`) over
the recursive-aggregation tier circuits. Reported as **peak RSS / wall-clock**.

## Bottom line

1. **`oracle_hash_type` and `zk` mode have ~no effect on PK-build cost** (< 2% across cells).
   - Implication: choice of on-chain verifier flavor is a free parameter at the proving cost level.
2. **`low_memory` does not help PK-build** and adds ~3% RAM + ~10% time.
   - Designed for the prove path, but even there our per-SU ownership circuit (~150 MiB)
     is too small to benefit. Useful only when polynomial workspace dominates RAM.
3. **`verify_rolluphonk_proof` does NOT help.** Per-call cost is *higher* than
   `verify_honk_proof_non_zk`, and barretenberg caps accumulated IPA claims at <4,
   so the flat-N variant fails for N ≥ 4.
4. **Flat aggregation scales linearly: ~1.4 GB and ~700 ms per inner verify call.**
   - N=1: 1.34 GB / 0.70s; N=2: 2.74 GB / 1.4s; N=4: 5.5 GB / 2.8s; N=8: 11 GB / 5.5s.
   - Mobile budget (iOS jetsam ≈ 3 GB / Android flagship ≈ 8-12 GB) caps native flat aggregation at N=2.
5. **Hierarchical (N=2 atom, `log2(target)` iterations) is mobile-feasible.**
   - Constant **2.74 GB / 1.4s per step**, regardless of target_N.
   - target_N=8 hierarchical: 4.3s total at 2.74 GB (vs flat N=8 at 5.5s and 11 GB).

---

Methodology:
- One process per cell (RSS reset via fresh process); macOS `getrusage`/`ru_maxrss` for peak.
- `barretenberg-rs 5.0.0-nightly.20260512`; `noir_rs` patched to match
  (see `vendor/noir_rs`); `bb_proof_verification v5.0.0-nightly.20260512`.
- Toolchain: `nargo 1.0.0-beta.20`, bb 5.0-nightly.
- `low_mem=on` enables barretenberg's file-backed polynomial storage
  (`BB_SLOW_LOW_MEMORY=1`), ~2x slower for ~50%+ less RAM.
- `zk=on` enables zero-knowledge variant (UltraHonkZK / ~12% bigger proofs).
- `ipa=on` enables IPA accumulation; required by `verify_rolluphonk_proof`
  and only valid with `oracle=poseidon2`. Barretenberg rejects keccak+ipa.

## Regular path (`verify_honk_proof_non_zk`)

### Oracle = keccak (matches our on-chain UltraHonkKeccak verifier)

| N | zk=off lm=off | zk=off lm=on | zk=on lm=off | zk=on lm=on |
|---|---|---|---|---|
| **N=1** | 1338 MiB / 695ms | 1361 MiB / 767ms | 1340 MiB / 697ms | 1363 MiB / 769ms |
| **N=2** | 2733 MiB / 1.43s | 2783 MiB / 1.53s | 2738 MiB / 1.41s | 2783 MiB / 1.53s |
| **N=4** | 5507 MiB / 2.89s | 5594 MiB / 3.16s | 5517 MiB / 2.81s | 5609 MiB / 3.05s |
| **N=8** | 11072 MiB / 5.55s | 11231 MiB / 6.46s | 11048 MiB / 5.54s | 11251 MiB / 6.33s |

### Oracle = poseidon2 (would need a different on-chain verifier)

| N | zk=off lm=off | zk=off lm=on | zk=on lm=off | zk=on lm=on |
|---|---|---|---|---|
| **N=1** | 1342 MiB / 700ms | 1361 MiB / 796ms | 1340 MiB / 695ms | 1363 MiB / 797ms |
| **N=2** | 2739 MiB / 1.39s | 2783 MiB / 1.58s | 2734 MiB / 1.41s | 2766 MiB / 1.55s |
| **N=4** | 5505 MiB / 2.80s | 5606 MiB / 3.09s | 5505 MiB / 2.85s | 5593 MiB / 3.06s |
| **N=8** | 11071 MiB / 5.55s | 11255 MiB / 6.25s | 11071 MiB / 5.52s | 11253 MiB / 6.41s |

## Rolluphonk path (`verify_rolluphonk_proof`, ipa=true, poseidon2)

Architectural note: `verify_rolluphonk_proof` is designed for
hierarchical rollup trees where each leaf verifies a small number of
inner proofs and **defers the IPA verification** as a public output.
Barretenberg enforces a per-circuit cap on accumulated IPA claims, so
the flat-N variant fails for N≥4 with `Too many nested IPA claims to
accumulate`.

| N | zk=off lm=off | zk=off lm=on | zk=on lm=off | zk=on lm=on |
|---|---|---|---|---|
| **N=1** | 2794 MiB / 888ms | 2815 MiB / 958ms | 2794 MiB / 869ms | 2815 MiB / 947ms |
| **N=2** | 3868 MiB / 1.92s | 3912 MiB / 2.13s | 3869 MiB / 1.94s | 3911 MiB / 2.07s |
| **N=4** | FAIL (circuit_compute_vk: Backend error: Too many nested) | FAIL (circuit_compute_vk: Backend error: Too many nested) | FAIL (circuit_compute_vk: Backend error: Too many nested) | FAIL (circuit_compute_vk: Backend error: Too many nested) |
| **N=8** | FAIL (circuit_compute_vk: Backend error: Too many nested) | FAIL (circuit_compute_vk: Backend error: Too many nested) | FAIL (circuit_compute_vk: Backend error: Too many nested) | FAIL (circuit_compute_vk: Backend error: Too many nested) |

## Ownership-circuit prove (shows real `low_memory` effect)

PK-build (`circuit_compute_vk`) doesn't allocate the polynomial workspaces
that `BB_SLOW_LOW_MEMORY` targets, so the tables above show no `lm` effect.
This section runs an actual end-to-end `prove_ultra_honk_*` on the per-SU
ownership circuit, which IS affected by low_memory mode.

| oracle | low_mem | prove time | peak RSS |
|---|---|---|---|
| keccak | off | 0.20s | 130 MiB |
| keccak | on | 0.22s | 151 MiB |
| poseidon2 | off | 0.21s | 130 MiB |
| poseidon2 | on | 0.24s | 153 MiB |

## Hierarchical / constant-memory analysis

**Key insight**: aggregation cost in a flat recursive circuit scales
**linearly in N** (each `verify_honk_proof_non_zk` call adds ~1.3 GB to
PK-build memory). A hierarchical / binary-tree approach pays
**constant memory per step** using the smallest tier (N=2) as the
aggregation atom, iterated `log2(target_N)` times.

Per-step cost = `regular/N=2/.../zk=off/lm=off` cell of the table above.

Total wall-clock for aggregating `target_N` SUs hierarchically:
  `log2(target_N) * step_time`. Peak RAM stays at the N=2 cell value.

| target_N | levels (log2) | total wall-clock (using zk=off lm=off step) |
|---|---|---|

Reference N=2 step: **2733 MiB / 1.43s** (peak RAM is the same regardless of `target_N`).

| target_N | levels | wall-clock |
|---|---|---|
| 2 | 1 | 1.43s |
| 4 | 2 | 2.86s |
| 8 | 3 | 4.29s |
| 16 | 4 | 5.72s |
| 32 | 5 | 7.15s |
| 64 | 6 | 8.58s |

---

**Raw results**: `/tmp/pso-cost-matrix.jsonl`