//! End-to-end test data for the SU-ownership aggregation circuits.
//!
//! Builds real witnesses via `pso_zk_core::generate_aggregation_witness`,
//! runs them through `NoirSuOwnershipAggregationCircuit`, and verifies
//! the proof against the canonical VK shipped in `pso-zk-canonical`.
//!
//! Two properties matter here and both are exercised:
//!
//! 1. **Prove-then-verify round-trip.** Any tier in the aggregation
//!    family must be able to produce a valid proof for a well-formed
//!    witness and have that proof verify against the pinned canonical
//!    VK. If this breaks, the on-chain `zk_verify` precompile would
//!    reject legitimate proofs.
//!
//! 2. **Aggregation under one key.** A single proof must witness N
//!    distinct `derived_owners` values, each derived from the same
//!    secp256k1 keypair with a different per-SU nonce. Padded slots
//!    (zeroed) must be accepted without ownership-check enforcement.
//!
//! These tests run only with the `bb`-backed prover (slow). Default
//! exercises N=1 and N=2; `aggregation-full-tiers` cargo feature
//! unlocks the rest.

#![cfg(test)]

use ark_bn254::Fr;
use ark_ff::UniformRand;
use k256::SecretKey;
use rand::rngs::OsRng;
use rand::RngCore;

use pso_protocol::witness::AggregationSlot;
use pso_zk_canonical::CircuitDescriptor;
use pso_zk_circuit_noir::{circuit_loader, testing, NoirSuOwnershipAggregationCircuit};

fn random_secret_key() -> SecretKey {
    let mut b = [0u8; 32];
    OsRng.fill_bytes(&mut b);
    SecretKey::from_slice(&b).expect("32 random bytes form a valid secp256k1 key")
}

/// Construct a tier circuit instance from `pso-zk-canonical`. Loads
/// the ACIR JSON from `data/<short_name>.json` and binds against the
/// canonical VK.
fn load_tier(
    short_name: &str,
    descriptor: &CircuitDescriptor,
) -> NoirSuOwnershipAggregationCircuit {
    let data_path = format!("{}/data/{short_name}.json", env!("CARGO_MANIFEST_DIR"));
    let circuit = circuit_loader::load_circuit(&data_path)
        .unwrap_or_else(|e| panic!("load {data_path}: {e}"));
    let tier_n: u32 = descriptor
        .label
        .rsplit('n')
        .next()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            panic!(
                "descriptor.label not in expected form: {}",
                descriptor.label
            )
        });
    NoirSuOwnershipAggregationCircuit::new(circuit.bytecode, tier_n, descriptor.vk_bytes.to_vec())
        .expect("aggregation circuit setup")
}

/// Generate `tier_n` real slots under one keypair: pick fresh nonces
/// and compute the matching Poseidon-derived owners.
fn make_real_slots(sk: &SecretKey, tier_n: u32) -> Vec<AggregationSlot> {
    (0..tier_n)
        .map(|_| {
            let nonce = Fr::rand(&mut OsRng);
            let derived_owner =
                testing::ownership_from_secret_key(sk, nonce).expect("Poseidon ownership");
            AggregationSlot {
                nonce,
                derived_owner,
            }
        })
        .collect()
}

fn prove_and_verify_tier(short_name: &str, descriptor: &CircuitDescriptor) {
    let circuit = load_tier(short_name, descriptor);
    let tier_n = descriptor
        .label
        .rsplit('n')
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap();

    let sk = random_secret_key();
    let real_slots = make_real_slots(&sk, tier_n);
    let binding_hash = Fr::rand(&mut OsRng);

    let witness = testing::build_aggregation_witness(&sk, &real_slots, tier_n, binding_hash)
        .expect("generate_aggregation_witness");

    let proof = circuit.prove(&witness).expect("prove");

    // Structural sanity: public-input vector in the proof must echo
    // the witness's public inputs in BIG-ENDIAN encoding, in the same
    // order the on-chain contract assembles its expected vector.
    assert_eq!(
        proof.public_inputs.len(),
        (tier_n + 1) as usize,
        "proof should expose tier_n + 1 public inputs (derived_owners + binding_hash)",
    );
    fn fr_be_bytes(f: &Fr) -> [u8; 32] {
        let mut b = testing::fr_to_le32(f);
        b.reverse();
        b
    }
    for (i, slot) in real_slots.iter().enumerate() {
        assert_eq!(
            &proof.public_inputs[i][..],
            &fr_be_bytes(&slot.derived_owner)[..],
            "public input slot {i} should be derived_owners[{i}] in BE",
        );
    }
    assert_eq!(
        &proof.public_inputs[tier_n as usize][..],
        &fr_be_bytes(&binding_hash)[..],
        "final public input should be binding_hash in BE",
    );

    let ok = circuit.verify(proof).expect("verify");
    assert!(
        ok,
        "proof must verify against pso-zk-canonical VK ({})",
        descriptor.label
    );
}

// -- tier round-trips ----------------------------------------------------- //

#[test]
fn aggregation_n1_round_trip() {
    prove_and_verify_tier(
        "su_ownership_aggregation_n1",
        &pso_zk_canonical::SU_OWNERSHIP_AGGREGATION_N1,
    );
}

#[test]
fn aggregation_n2_round_trip_aggregates_under_one_key() {
    prove_and_verify_tier(
        "su_ownership_aggregation_n2",
        &pso_zk_canonical::SU_OWNERSHIP_AGGREGATION_N2,
    );
}

#[cfg(feature = "aggregation-full-tiers")]
#[test]
fn aggregation_n4_round_trip() {
    prove_and_verify_tier(
        "su_ownership_aggregation_n4",
        &pso_zk_canonical::SU_OWNERSHIP_AGGREGATION_N4,
    );
}

#[cfg(feature = "aggregation-full-tiers")]
#[test]
fn aggregation_n6_round_trip() {
    prove_and_verify_tier(
        "su_ownership_aggregation_n6",
        &pso_zk_canonical::SU_OWNERSHIP_AGGREGATION_N6,
    );
}

#[cfg(feature = "aggregation-full-tiers")]
#[test]
fn aggregation_n8_round_trip() {
    prove_and_verify_tier(
        "su_ownership_aggregation_n8",
        &pso_zk_canonical::SU_OWNERSHIP_AGGREGATION_N8,
    );
}

#[cfg(feature = "aggregation-full-tiers")]
#[test]
fn aggregation_n16_round_trip() {
    prove_and_verify_tier(
        "su_ownership_aggregation_n16",
        &pso_zk_canonical::SU_OWNERSHIP_AGGREGATION_N16,
    );
}

#[cfg(feature = "aggregation-full-tiers")]
#[test]
fn aggregation_n32_round_trip() {
    prove_and_verify_tier(
        "su_ownership_aggregation_n32",
        &pso_zk_canonical::SU_OWNERSHIP_AGGREGATION_N32,
    );
}

#[cfg(feature = "aggregation-full-tiers")]
#[test]
fn aggregation_n64_round_trip() {
    prove_and_verify_tier(
        "su_ownership_aggregation_n64",
        &pso_zk_canonical::SU_OWNERSHIP_AGGREGATION_N64,
    );
}

// -- padded tier (real n < tier_n) ---------------------------------------- //

#[test]
fn aggregation_n2_round_trip_with_padded_slot() {
    let circuit = load_tier(
        "su_ownership_aggregation_n2",
        &pso_zk_canonical::SU_OWNERSHIP_AGGREGATION_N2,
    );

    let sk = random_secret_key();
    // One real slot — the witness builder pads the second with zeros.
    let real_slots = make_real_slots(&sk, 1);
    let binding_hash = Fr::rand(&mut OsRng);

    let witness = testing::build_aggregation_witness(&sk, &real_slots, 2, binding_hash).unwrap();

    let proof = circuit.prove(&witness).expect("prove with padded slot");
    assert!(
        circuit.verify(proof).expect("verify"),
        "padded-tier proof must verify"
    );
}

// -- negative cases ------------------------------------------------------- //

#[test]
fn aggregation_n2_rejects_wrong_derived_owner_in_witness() {
    // Bypass `build_aggregation_witness` and inject an inconsistent
    // `derived_owner` directly so we exercise the circuit-side
    // constraint rather than the witness-helper invariant.
    use pso_protocol::witness::{
        AggregationPrivateInputs, AggregationPublicInputs, AggregationWitness,
    };

    let circuit = load_tier(
        "su_ownership_aggregation_n2",
        &pso_zk_canonical::SU_OWNERSHIP_AGGREGATION_N2,
    );

    let sk = random_secret_key();
    let (public_key_x, public_key_y) = testing::sec1_coords(&sk);

    let nonces = [Fr::rand(&mut OsRng), Fr::rand(&mut OsRng)];
    // Slot 0 owner is consistent with nonce[0]; slot 1 owner is bogus.
    let owner_0 = testing::ownership_from_secret_key(&sk, nonces[0]).unwrap();
    let bogus_owner_1 = Fr::rand(&mut OsRng);

    let binding_hash = Fr::rand(&mut OsRng);
    let sig_bytes = testing::sign_prehash_le(&sk, &binding_hash).unwrap();

    let witness = AggregationWitness {
        private_inputs: AggregationPrivateInputs {
            public_key_x,
            public_key_y,
            nonces: nonces.iter().map(testing::fr_to_le32).collect(),
            signature: sig_bytes,
        },
        public_inputs: AggregationPublicInputs {
            derived_owners: vec![
                testing::fr_to_le32(&owner_0),
                testing::fr_to_le32(&bogus_owner_1),
            ],
            binding_hash: testing::fr_to_le32(&binding_hash),
        },
    };

    let result = circuit.prove(&witness);
    assert!(
        result.is_err(),
        "prove should fail when a derived_owner does not match Poseidon(pk, nonce)",
    );
}

#[test]
fn aggregation_witness_rejects_oversized_real_slots() {
    let sk = random_secret_key();
    let real_slots = make_real_slots(&sk, 3); // 3 reals
    let result = testing::build_aggregation_witness(
        &sk,
        &real_slots,
        2, // smaller tier — must reject
        Fr::rand(&mut OsRng),
    );
    assert!(
        result.is_err(),
        "witness builder must reject real_slots.len() > tier_n",
    );
}
