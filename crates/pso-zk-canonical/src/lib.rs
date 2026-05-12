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
//
// **STALE PENDING REGENERATION.** The §4.2 redesign rewrote
// `pso-ownership-circuit` (signature is now over Poseidon2(nft_hash,
// nonce); `nft_hash` is a public input), `pso-full-circuit` (now
// composes the same ownership constraint with Merkle inclusion), and
// replaced the 8 `pso-su-ownership-aggregation-circuit-n*` tier crates
// with `pso-recursive-aggregation-circuit-n*` (recursive proof folds N
// inner ownership proofs via bb_proof_verification). The const values
// below — `circuit_hash`, `vk_bytes` (via `include_bytes!`), and
// `vk_hash` — still point at the OLD circuits' VKs. They're left here
// so the workspace compiles; running `cargo xtask regenerate-canonical`
// will compile the new circuits, derive the correct values, overwrite
// the .vk files in `res/vks/`, and rewrite this generated block.
//
// Until that runs:
//   - on-chain `zk_verify` calls against these descriptors will not
//     accept proofs from the new circuits (circuit_hash mismatch);
//   - the `pso_l2_client::wallet::prove_*` paths in pso-integration
//     return `L2ClientError::CircuitNotAvailable` rather than producing
//     bytes the chain would reject.

pub const FULL_PROOF: CircuitDescriptor = CircuitDescriptor {
    // STALE — pre-§4.2 hash. Real value lands on regenerate.
    circuit_hash: hex_literal::hex!(
        "7d7f9f6733d39b0e0215df9a03e31063ba681e0ed46648831e19872a7424006d"
    ),
    label: "pso.full_proof",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/full_proof.vk"),
    vk_hash: hex_literal::hex!("0738a270483c9e03dac46a778339f94d42143e29b8b024130d5d763564355198"),
};

pub const OWNERSHIP: CircuitDescriptor = CircuitDescriptor {
    // STALE — pre-§4.2 hash. Real value lands on regenerate.
    circuit_hash: hex_literal::hex!(
        "54260a584a822b5b8c1b1571c947ba0f92e3224493c29c06120b4d714ec315f3"
    ),
    label: "pso.ownership",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/ownership.vk"),
    vk_hash: hex_literal::hex!("3c01bbc3812ca5f23844c2c64cc3856713f2174a507be111682533de33d4654b"),
};

// 8 recursive-aggregation tiers replacing the deleted
// `SU_OWNERSHIP_AGGREGATION_N*` family. Until regenerate-canonical
// runs, each carries the stale placeholder VK + hash from the
// deleted family (the `.vk` files were git-renamed to
// `recursive_aggregation_n{tier}.vk`) so `include_bytes!` resolves.
// Real values land on regenerate.

pub const RECURSIVE_AGGREGATION_N1: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "5657ef94fffc53073f21ca1332822839b68838c043b4e80115ea4733fabf758f"
    ),
    label: "pso.recursive_aggregation.n1",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/recursive_aggregation_n1.vk"),
    vk_hash: hex_literal::hex!("45edd489c689c995417030cc5569ee059735825cae4f9f17e5661d617a14f031"),
};

pub const RECURSIVE_AGGREGATION_N2: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "6d8a24c8686abfa099f331a25d7cc961d054a55bd7549ce06e063f340bf8b8bb"
    ),
    label: "pso.recursive_aggregation.n2",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/recursive_aggregation_n2.vk"),
    vk_hash: hex_literal::hex!("29c76b2c6cee3c41dc96e52d36e60f2171b3b400db17bb03c1788463ac09ffa3"),
};

pub const RECURSIVE_AGGREGATION_N4: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "9f4e4bd14ff300e774a5ce11c2ad7da8b89b9496bba745e3c9ddda18be8e0c09"
    ),
    label: "pso.recursive_aggregation.n4",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/recursive_aggregation_n4.vk"),
    vk_hash: hex_literal::hex!("db460116fdd3448288135221be9b55eaf515e9444490a280d656498eb194eb29"),
};

pub const RECURSIVE_AGGREGATION_N6: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "6f06808a10b13a7c0b256306231826dcdba457dfd9da5277bc007ad653a992a6"
    ),
    label: "pso.recursive_aggregation.n6",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/recursive_aggregation_n6.vk"),
    vk_hash: hex_literal::hex!("45491217b03ab696d205ed465928433060e98b1386a6f87a039bc8426c3d9f59"),
};

pub const RECURSIVE_AGGREGATION_N8: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "302f749cf37d8a79f6f6321698a0c2fcfb67ffa1cbfcdddd43ad9d4387b25551"
    ),
    label: "pso.recursive_aggregation.n8",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/recursive_aggregation_n8.vk"),
    vk_hash: hex_literal::hex!("9d5c72235d46f8fcc6e48d837d2b4f7164e4cf26217931922af89e395a6fbcb2"),
};

pub const RECURSIVE_AGGREGATION_N16: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "1fa8585e47b9db1d3faabd9ec8e35dd7e9862a5278f9d5561d00bd307973a983"
    ),
    label: "pso.recursive_aggregation.n16",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/recursive_aggregation_n16.vk"),
    vk_hash: hex_literal::hex!("e2f554427ef40f8108411fb36958a945a5ec1b6a2373a1f13cad45ffe90930da"),
};

pub const RECURSIVE_AGGREGATION_N32: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "c7d797b22984f7acca620ed6ed1045441043dab8f53a8fd82319414143b6d639"
    ),
    label: "pso.recursive_aggregation.n32",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/recursive_aggregation_n32.vk"),
    vk_hash: hex_literal::hex!("35e18c003099c9f159473f96a4065d113c9d93ab1a82e7a7be81c98faef0e8a7"),
};

pub const RECURSIVE_AGGREGATION_N64: CircuitDescriptor = CircuitDescriptor {
    circuit_hash: hex_literal::hex!(
        "2f8c0618f5db9f52b7500c804bfe0d67e26493cd2931bbde6c9fe2092cb5703f"
    ),
    label: "pso.recursive_aggregation.n64",
    version: "1.0.0",
    vk_bytes: include_bytes!("../res/vks/recursive_aggregation_n64.vk"),
    vk_hash: hex_literal::hex!("f2dab55592ac69e36ea61057e384a1f93bb2ef95fa6c88e4d43c4fbcc84abaea"),
};

pub const ALL_CIRCUITS: &[&CircuitDescriptor] = &[
    &FULL_PROOF,
    &OWNERSHIP,
    &RECURSIVE_AGGREGATION_N1,
    &RECURSIVE_AGGREGATION_N2,
    &RECURSIVE_AGGREGATION_N4,
    &RECURSIVE_AGGREGATION_N6,
    &RECURSIVE_AGGREGATION_N8,
    &RECURSIVE_AGGREGATION_N16,
    &RECURSIVE_AGGREGATION_N32,
    &RECURSIVE_AGGREGATION_N64,
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

/// Ordered tier sizes for the recursive aggregation circuits, in
/// ascending order. Must match the
/// `pso-recursive-aggregation-circuit-n*` crates on the Noir side.
/// `SU_AGGREGATION_TIERS` and `SU_AGGREGATION_DESCRIPTORS` are kept
/// in lockstep — same length, same index meaning.
pub const SU_AGGREGATION_TIERS: &[u32] = &[1, 2, 4, 6, 8, 16, 32, 64];

/// Canonical descriptors for each aggregation tier, parallel-indexed
/// with [`SU_AGGREGATION_TIERS`].
pub const SU_AGGREGATION_DESCRIPTORS: &[&CircuitDescriptor] = &[
    &RECURSIVE_AGGREGATION_N1,
    &RECURSIVE_AGGREGATION_N2,
    &RECURSIVE_AGGREGATION_N4,
    &RECURSIVE_AGGREGATION_N6,
    &RECURSIVE_AGGREGATION_N8,
    &RECURSIVE_AGGREGATION_N16,
    &RECURSIVE_AGGREGATION_N32,
    &RECURSIVE_AGGREGATION_N64,
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
        // 3 SUs fits the N=4 tier (smallest >= 3). 7 fits N=8. 9 fits N=16.
        assert_eq!(select_aggregation_tier(3).unwrap().tier_n, 4);
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
                1 => "pso.recursive_aggregation.n1",
                2 => "pso.recursive_aggregation.n2",
                4 => "pso.recursive_aggregation.n4",
                6 => "pso.recursive_aggregation.n6",
                8 => "pso.recursive_aggregation.n8",
                16 => "pso.recursive_aggregation.n16",
                32 => "pso.recursive_aggregation.n32",
                64 => "pso.recursive_aggregation.n64",
                _ => panic!("unmapped tier {tier_n}"),
            };
            assert_eq!(d.label, expected);
        }
    }
}
