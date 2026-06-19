//! Real barretenberg prove→verify round-trip (feature `barretenberg`).
//!
//! Generates an actual UltraHonkKeccak proof for the ownership circuit from a
//! genuine witness and verifies it through the FFI backend — the full on-device
//! path. Run with `cargo test -p pso-zk-backend --features barretenberg`.

use ark_ff::UniformRand;

use pso_protocol::error::Error;
use pso_protocol::primitive::signature::SignatureScheme;
use pso_protocol::protocol::entity::{Entity, Owned};
use pso_protocol::protocol::key::{NftSecret, Signer};
use pso_protocol::protocol::zk::{ProofGenerator, ProofVerifier};
use pso_protocol::{PsoV1, Suite};
use pso_zk_backend::barretenberg::Barretenberg;
use pso_zk_canonical::noir::ownership_proof::OwnershipProof;
use pso_zk_canonical::ownership::Provable;

type Fr = <PsoV1 as Suite>::Field;

struct TestNft {
    id: Fr,
    owner: Fr,
    fields: Vec<Fr>,
}

impl Entity<PsoV1> for TestNft {
    fn id_seed(&self) -> Result<Fr, Error> {
        Ok(self.id)
    }
    fn encode_id_body(&self, _out: &mut Vec<Fr>) -> Result<(), Error> {
        Ok(())
    }
    fn encode_body(&self, out: &mut Vec<Fr>) -> Result<(), Error> {
        out.extend_from_slice(&self.fields);
        Ok(())
    }
}
impl Owned<PsoV1> for TestNft {
    fn owner(&self) -> Result<Fr, Error> {
        Ok(self.owner)
    }
}

#[test]
fn ownership_prove_verify_round_trip() {
    let mut rng = ark_std::test_rng();
    let (sk, pk) = <PsoV1 as Suite>::Signature::keypair(&mut rng);
    let nonce = Fr::rand(&mut rng);
    let owner = PsoV1::derive_owner(&pk, nonce).unwrap();
    let binding = PsoV1::binding(&[1u8; 20], &[2u8; 32], 7).unwrap();
    let td = TestNft {
        id: owner,
        owner,
        fields: vec![Fr::from(978u64), Fr::from(100u64)],
    };
    let signer = Signer::from_secret(NftSecret::new(sk), nonce).unwrap();
    let (witness, public) = td
        .derive_ownership_witness(&mut rng, &signer, binding)
        .unwrap();

    // Generate a real UltraHonkKeccak proof and verify it.
    let proof = ProofGenerator::<PsoV1, OwnershipProof>::generate(
        &Barretenberg::default(),
        &witness,
        &public,
    )
    .expect("bb prove");
    assert!(
        ProofVerifier::<PsoV1, OwnershipProof>::verify(&Barretenberg::default(), &public, &proof)
            .unwrap(),
        "valid proof must verify"
    );

    // Verifying against a different claim (tampered binding) must fail.
    let mut wrong = public.clone();
    wrong.binding_hash += Fr::from(1u64);
    assert!(
        !ProofVerifier::<PsoV1, OwnershipProof>::verify(&Barretenberg::default(), &wrong, &proof)
            .unwrap(),
        "proof must not verify against a different public input"
    );
}
