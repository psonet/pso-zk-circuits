//! Canonical PSO Noir circuit descriptors.
//!
//! Authoritative on-chain identity source for the PSO L2 `zk_verify`
//! precompile. Consumed by `pso-chain` (the L2 execution layer) which
//! wraps each descriptor with chain-policy timing
//! (`activated_at_block` / `deprecated_at_block`) to form its
//! `CanonicalCircuit` table.
//!
//! Pure static data — no FFI, `no_std`. The heavy work of running
//! `nargo compile` + deriving VKs via Barretenberg + computing
//! `circuit_hash` happens in this workspace's
//! `xtask regenerate-canonical` command; the output is committed
//! straight into this file and `res/vks/*.vk`.
//!
//! ## Append-only
//!
//! Existing entries are **never modified**. New circuit revisions
//! (different source ⇒ different `circuit_hash`) get appended as
//! new descriptors. Deprecation of old descriptors is `pso-chain`'s
//! concern (via `deprecated_at_block`); this crate just records what
//! exists.
//!
//! ## Regenerate
//!
//! After modifying a circuit under `crates/pso-zk-circuit-noir/`:
//!
//! ```bash
//! cargo run --package xtask -- regenerate-canonical
//! ```
//!
//! That command:
//! 1. Compiles every circuit via `nargo`
//! 2. Computes `circuit_hash = keccak256(acir_bytes)` per circuit
//! 3. Derives `vk_bytes` via `noir_rs::barretenberg::verify::
//!    get_ultra_honk_keccak_verification_key`
//! 4. Computes `vk_hash = keccak256(vk_bytes)`
//! 5. Writes `vk_bytes` to `res/vks/<circuit_label>.vk`
//! 6. Regenerates this file's const declarations
//!
//! CI gates a `--check` invocation: regen + diff = fail on stale state.

#![no_std]

/// A canonical Noir circuit descriptor. All fields are content-derived
/// from the compiled ACIR + the chosen proving SRS (UltraHonkKeccak).
#[derive(Debug)]
pub struct CircuitDescriptor {
    /// ACIR bytecode hash: `keccak256(base64_decode(acir_bytecode))`.
    /// Stable identifier for this circuit at this source revision —
    /// this is what `pso-chain`'s `zk_verify` precompile matches
    /// against to dispatch to the right VK.
    pub circuit_hash: [u8; 32],

    /// Human-readable label (e.g. "pso.spending_unit.ownership").
    /// For logs / audit / `circuit_info` precompile output. NOT
    /// authoritative — the `circuit_hash` is.
    pub label: &'static str,

    /// Semver-style version string for human reading ("1.0.0").
    /// NOT authoritative; circuit_hash is the only identity that
    /// matters for verification.
    pub version: &'static str,

    /// Canonical UltraHonkKeccak verification key bytes, derived from
    /// this circuit + the production SRS. Used by `pso-chain`'s
    /// `zk_verify` precompile (Noir + Barretenberg FFI) to verify
    /// proofs claimed against this circuit.
    pub vk_bytes: &'static [u8],

    /// Pre-computed `keccak256(vk_bytes)`. Lets contracts /
    /// `circuit_info` consumers cross-check VK provenance without
    /// re-hashing the (potentially tens-of-KB) VK bytes.
    pub vk_hash: [u8; 32],
}

// === BEGIN GENERATED — do not edit (run `cargo xtask regenerate-canonical`) ===

pub const FULL_PROOF: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "a09844eb07939afe96f88c23cc2748b8c206d8eed0f9bbe69aabeb49ef7f3798"
    ),
    label: "pso.full_proof",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/full_proof.vk"),
    vk_hash: hex_literal::hex!("d0cc00eccd9f5861da67b90ac017a64485566936c73091a37712e55ec4881549"),
};

pub const OWNERSHIP: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "18db006ac6304a0ff2f4b624a1e31961223184f3638ce421161196a6e1b19c57"
    ),
    label: "pso.ownership",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/ownership.vk"),
    vk_hash: hex_literal::hex!("8b0dbc83792074e488b0b63ce62c1ddd08020ffa6fe980917a53ea63c8c08ccf"),
};

pub const FLAT_AGGREGATION_N1: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "501859afd14fffe1f25b72e36adf64ffcb7965d53561f585c2483c0a8ac99d07"
    ),
    label: "pso.flat_aggregation.n1",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n1.vk"),
    vk_hash: hex_literal::hex!("81ba4aab2186484f74201c6efda76ee844b69ff9638da88581226c2d1ab46010"),
};

pub const FLAT_AGGREGATION_N2: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "114421c5b7ae3accef9eac72e35db6c12eb0a8597b967d5ed9a1cde82b957f63"
    ),
    label: "pso.flat_aggregation.n2",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n2.vk"),
    vk_hash: hex_literal::hex!("a780524c3a783e11e257f740a59e8bdf04c80ebf8298826ea0a344d3c09a69a9"),
};

pub const FLAT_AGGREGATION_N4: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "616000a21fdf24c35623938159fcbebdaf0975961c5fc98783ace1f468f09a6c"
    ),
    label: "pso.flat_aggregation.n4",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n4.vk"),
    vk_hash: hex_literal::hex!("43d128ea1bc7e9b101b286ec5388a3151d39264019112c6810e1e9516d6e3df7"),
};

pub const FLAT_AGGREGATION_N8: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "f42a27324ca6a56377130b10e2c3760d0697421c5463fbd1463699727ddedb7b"
    ),
    label: "pso.flat_aggregation.n8",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n8.vk"),
    vk_hash: hex_literal::hex!("5f7901a014e38c7ec0377bf545609f5d3271fbc669374bfab4da8c55c0dbe3ef"),
};

pub const FLAT_AGGREGATION_N16: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "ce83efdd3ccfe05b1d84e44d5056f0b110af99661bc50b578888b968d27549db"
    ),
    label: "pso.flat_aggregation.n16",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n16.vk"),
    vk_hash: hex_literal::hex!("794ccf2dfd137fe170fd24d255c214ff3701815dbc4746e7675548a3c58c92e0"),
};

pub const FLAT_AGGREGATION_N32: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "783b54ce02aec97efb12d71772d2d3123f6d747207e74a6e7d1df217a6f17c88"
    ),
    label: "pso.flat_aggregation.n32",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n32.vk"),
    vk_hash: hex_literal::hex!("fe7cd93a4c44ae2ca6c90ce905bd1a58f5595f1dd6c13a030a8e5beba197a7da"),
};

pub const FLAT_AGGREGATION_N64: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "8e5624c7d39cd6bc0e5fab64475c7bb2944dfd345101d6c7175903dfac36bd89"
    ),
    label: "pso.flat_aggregation.n64",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n64.vk"),
    vk_hash: hex_literal::hex!("7e734ada2d03be09bc923934539837be6cd08cfa717db3c521d6c0df18bf88d5"),
};

pub const ALL_CIRCUITS: &[&CircuitDescriptor] = &[
    &FULL_PROOF,
    &OWNERSHIP,
    &FLAT_AGGREGATION_N1,
    &FLAT_AGGREGATION_N2,
    &FLAT_AGGREGATION_N4,
    &FLAT_AGGREGATION_N8,
    &FLAT_AGGREGATION_N16,
    &FLAT_AGGREGATION_N32,
    &FLAT_AGGREGATION_N64,
];
// === END GENERATED ===

/// Look up a descriptor by its ACIR `circuit_hash`. `O(n)` over a
/// small table — fine for the precompile path (n in single digits).
pub fn find_by_hash(circuit_hash: &[u8; 32]) -> Option<&'static CircuitDescriptor> {
    let mut i = 0;
    while i < ALL_CIRCUITS.len() {
        if &ALL_CIRCUITS[i].circuit_hash == circuit_hash {
            return Some(ALL_CIRCUITS[i]);
        }
        i += 1;
    }
    None
}

// === SU ownership aggregation tier selection ============================ //
//
// Single source of truth for the "given N SUs, which aggregation
// circuit do I use?" decision. The on-chain `TributeDraft` contract,
// the prover-side wallet integrations, and any future tooling all
// resolve through this function so they can never disagree.

/// Ordered tier sizes for the flat aggregation circuits, in ascending
/// order. Must match the `pso-flat-aggregation-circuit-n*` crates on
/// the Noir side. `SU_AGGREGATION_TIERS` and
/// `SU_AGGREGATION_DESCRIPTORS` are kept in lockstep — same length,
/// same index meaning.
pub const SU_AGGREGATION_TIERS: &[u32] = &[1, 2, 4, 8, 16, 32, 64];

/// Canonical descriptors for each aggregation tier, parallel-indexed
/// with [`SU_AGGREGATION_TIERS`].
pub const SU_AGGREGATION_DESCRIPTORS: &[&CircuitDescriptor] = &[
    &FLAT_AGGREGATION_N1,
    &FLAT_AGGREGATION_N2,
    &FLAT_AGGREGATION_N4,
    &FLAT_AGGREGATION_N8,
    &FLAT_AGGREGATION_N16,
    &FLAT_AGGREGATION_N32,
    &FLAT_AGGREGATION_N64,
];

/// Result of resolving an SU count to an aggregation circuit tier.
///
/// `tier_n` is the circuit's fixed slot count and is the value the
/// caller should pad its `derived_owners` array to before generating
/// or verifying a proof. The `descriptor` carries the canonical
/// `circuit_hash` / `vk_bytes` / `vk_hash` for that tier.
#[derive(Debug)]
pub struct AggregationTier {
    pub tier_n: u32,
    pub descriptor: &'static CircuitDescriptor,
}

/// Pick the canonical SU-ownership aggregation circuit for `n` SUs.
///
/// Returns the smallest tier whose `tier_n >= n`. Returns `None` if
/// `n == 0` (no aggregation needed) or if `n` exceeds the largest tier
/// (`64`). Callers should treat the `None` cases as a precondition
/// failure — there is no aggregation circuit that can cover them.
pub fn select_aggregation_tier(n: u32) -> Option<AggregationTier> {
    if n == 0 {
        return None;
    }
    let mut i = 0;
    while i < SU_AGGREGATION_TIERS.len() {
        let tier_n = SU_AGGREGATION_TIERS[i];
        if tier_n >= n {
            return Some(AggregationTier {
                tier_n,
                descriptor: SU_AGGREGATION_DESCRIPTORS[i],
            });
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_hash_returns_none() {
        // An all-zero hash can't appear in ALL_CIRCUITS — keccak256 of
        // any non-empty ACIR is overwhelmingly unlikely to be zero — so
        // lookup must miss. Mirror of the "chain rejects unknown
        // circuits" safety guarantee from the consumer side.
        assert!(find_by_hash(&[0u8; 32]).is_none());
    }

    #[test]
    fn descriptor_size_invariants() {
        // After regeneration, every descriptor must have:
        //   - non-empty label
        //   - non-empty vk_bytes
        //   - keccak256(vk_bytes) == vk_hash (checked by xtask, not here)
        for d in ALL_CIRCUITS {
            assert!(!d.label.is_empty(), "label is empty");
            assert!(!d.vk_bytes.is_empty(), "vk_bytes is empty for {}", d.label);
        }
    }

    #[test]
    fn aggregation_tier_arrays_are_aligned() {
        // SU_AGGREGATION_TIERS and SU_AGGREGATION_DESCRIPTORS are
        // parallel-indexed. Catch any future drift between them.
        assert_eq!(SU_AGGREGATION_TIERS.len(), SU_AGGREGATION_DESCRIPTORS.len());
    }

    #[test]
    fn aggregation_tiers_are_ascending() {
        // Selection relies on early-return-at-first-fit so the table
        // must be strictly ascending.
        for w in SU_AGGREGATION_TIERS.windows(2) {
            assert!(w[0] < w[1], "tier table not strictly ascending: {w:?}");
        }
    }

    #[test]
    fn select_zero_returns_none() {
        assert!(select_aggregation_tier(0).is_none());
    }

    #[test]
    fn select_exact_tier_match() {
        for &n in SU_AGGREGATION_TIERS {
            let t = select_aggregation_tier(n).expect("exact tier must resolve");
            assert_eq!(t.tier_n, n);
        }
    }

    #[test]
    fn select_rounds_up_to_next_tier() {
        // 3 SUs fits N=4 (smallest >= 3). 5..=8 fits N=8. 9..=16 fits
        // N=16. The N=6 tier was dropped — fewer tiers, same ladder.
        assert_eq!(select_aggregation_tier(3).unwrap().tier_n, 4);
        assert_eq!(select_aggregation_tier(5).unwrap().tier_n, 8);
        assert_eq!(select_aggregation_tier(7).unwrap().tier_n, 8);
        assert_eq!(select_aggregation_tier(9).unwrap().tier_n, 16);
        assert_eq!(select_aggregation_tier(33).unwrap().tier_n, 64);
    }

    #[test]
    fn select_above_max_tier_returns_none() {
        assert!(select_aggregation_tier(65).is_none());
        assert!(select_aggregation_tier(u32::MAX).is_none());
    }

    #[test]
    fn descriptor_labels_match_tier_size() {
        // Sanity check: the canonical labels embed the tier size so
        // the cross-reference between the tier table and the
        // descriptors is auditable.
        for (i, &tier_n) in SU_AGGREGATION_TIERS.iter().enumerate() {
            let d = SU_AGGREGATION_DESCRIPTORS[i];
            let expected = match tier_n {
                1 => "pso.flat_aggregation.n1",
                2 => "pso.flat_aggregation.n2",
                4 => "pso.flat_aggregation.n4",
                8 => "pso.flat_aggregation.n8",
                16 => "pso.flat_aggregation.n16",
                32 => "pso.flat_aggregation.n32",
                64 => "pso.flat_aggregation.n64",
                _ => panic!("unmapped tier {tier_n}"),
            };
            assert_eq!(d.label, expected);
        }
    }
}
