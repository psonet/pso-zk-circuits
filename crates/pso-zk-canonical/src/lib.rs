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
//! ## Revision policy: replace-in-place (pre-launch) → append-only (at launch)
//!
//! **Today (pre-launch):** `regenerate-canonical` rewrites every
//! descriptor in place from the current circuit sources — one
//! descriptor per label. Changing a circuit's source changes its
//! `circuit_hash`/`vk` and the old identity is **dropped**, not kept.
//! CI's `--check` enforces `committed == fresh regen`, so the
//! regenerated state is authoritative. This is intentional while the
//! chain is unlaunched: a circuit-security change (e.g. the
//! `binding_hash` proof binding) *should* retire the superseded,
//! vulnerable circuit so its proofs stop verifying.
//!
//! **At chain launch:** switch to **append-only** — existing
//! descriptors must then be frozen (a deployed `circuit_hash` has to
//! keep verifying), new circuit revisions append as new descriptors,
//! and deprecation becomes `pso-chain`'s concern (via
//! `deprecated_at_block`). That requires teaching `regenerate-canonical`
//! to retain prior-hash descriptors rather than overwrite them.
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
        "09b84fdadc1f26d15a4dba33b13a97c024ee6ea4490b1f763eefa5a459ccb813"
    ),
    label: "pso.full_proof",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/full_proof.vk"),
    vk_hash: hex_literal::hex!("9af76486e3d0c1e9e52e22c6f4318871a16d6a3ce423858e339450c7c7495ebe"),
};

pub const OWNERSHIP: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "0eedf65e1bd368514e4b205e0ed5ad201615c3e2f366f3a2a240c09953730199"
    ),
    label: "pso.ownership",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/ownership.vk"),
    vk_hash: hex_literal::hex!("734cd3b84cf89b1ce8255f5a760ef336ea8220871efb28cc5a1108e8c9ca5aaf"),
};

pub const FLAT_AGGREGATION_N1: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "030c57d8979aecc77d711c7e392ad51403b2038d5d2e4639e6139c848f21ab70"
    ),
    label: "pso.flat_aggregation.n1",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n1.vk"),
    vk_hash: hex_literal::hex!("a9972d88c234b04bea98cfaadedd2b445728dedb8eee5c1de58e1868030343ff"),
};

pub const FLAT_AGGREGATION_N2: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "540c226ca0d2ae6ba328e25fc832c12604263c166243b46555a0a8634b8b328c"
    ),
    label: "pso.flat_aggregation.n2",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n2.vk"),
    vk_hash: hex_literal::hex!("0578c2d297d4134c7954ef1f54f5efdb157956c332d78693e3c68c24a8b7cb18"),
};

pub const FLAT_AGGREGATION_N4: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "39053f5e9107ede58ea03c67a7741ddc7ca4890702d99ab37c6e0f655b285c77"
    ),
    label: "pso.flat_aggregation.n4",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n4.vk"),
    vk_hash: hex_literal::hex!("e205cf284fb8c45dfa6e7740c06eb0fbe72984c6906aac50e305e27ea90fe889"),
};

pub const FLAT_AGGREGATION_N8: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "a6af6c76847236cfdd835895714cb0c4d9eeb4a80f22022c5fe767b4c61e3c25"
    ),
    label: "pso.flat_aggregation.n8",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n8.vk"),
    vk_hash: hex_literal::hex!("57b96488e91fd0b5cbeedefbe9593d8e116c3d2c698c488a065febe4d75bb102"),
};

pub const FLAT_AGGREGATION_N16: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "f333f2a85be78bbbb2bd5a8cb8e6806e32fd80b9a2c073503bece8ff762ac4a9"
    ),
    label: "pso.flat_aggregation.n16",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n16.vk"),
    vk_hash: hex_literal::hex!("72d7b69e9a6d78411e4fcbee489866d0ee9b47e35bb23bdfbffebde0a19e3b3f"),
};

pub const FLAT_AGGREGATION_N32: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "5afa364ed03d9d0377100dd370d1aefc351f21c1f7e0763cad177b6968b331d5"
    ),
    label: "pso.flat_aggregation.n32",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n32.vk"),
    vk_hash: hex_literal::hex!("5d127a53b3c94533d7b524a8e6c6f624665cf4ac6f9a1a2da3b258903bb45752"),
};

pub const FLAT_AGGREGATION_N64: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "f670d8e84c1506a75d2513882eea6d9111ec228fbc80c77e69234f0d3123c674"
    ),
    label: "pso.flat_aggregation.n64",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/flat_aggregation_n64.vk"),
    vk_hash: hex_literal::hex!("3887916da4879ccad8b461f8a125d606bf8108429fc880cfb6f43dc14c7298ce"),
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
