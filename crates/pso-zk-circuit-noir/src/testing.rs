//! k256-aware test helpers.
//!
//! Bridge between the `pso-protocol` byte-oriented APIs and the k256
//! secret/public-key types our test code uses. The witness builders
//! that lived in `pso-zk-core::witness` moved to `pso-integration`;
//! the circuit's own round-trip tests want a self-contained way to
//! produce well-formed witnesses without pulling pso-integration in
//! as a dev-dep (which would create a cycle).
//!
//! This is a regular `pub mod` rather than a `#[cfg(test)]` /
//! feature-gated module so that integration tests (`tests/*.rs`) and
//! benches (`benches/*.rs`) — which compile against this crate as if
//! it were any downstream consumer — can use it without Cargo gymnastics.
//! Production proving paths never call into this module; the cost is
//! negligible next to barretenberg-rs in the same dependency tree.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::SecretKey;

use pso_protocol::merkle::MerklePathElement;
use pso_protocol::witness::{
    AggregationPrivateInputs, AggregationPublicInputs, AggregationSlot, AggregationWitness,
    FullProofPrivateInputs, FullProofPublicInputs, FullProofWitness, HashableNFT, OwnableNFT,
    OwnershipPrivateInputs, OwnershipPublicInputs, OwnershipWitness,
};

/// Encode an `Fr` as 32 little-endian bytes (right-padded with zeros).
pub fn fr_to_le32(value: &Fr) -> [u8; 32] {
    let le = value.into_bigint().to_bytes_le();
    let mut out = [0u8; 32];
    let n = le.len().min(32);
    out[..n].copy_from_slice(&le[..n]);
    out
}

/// Extract the SEC1 (uncompressed) x/y coordinates of a `SecretKey`'s
/// public key as 32-byte big-endian arrays.
pub fn sec1_coords(secret_key: &SecretKey) -> ([u8; 32], [u8; 32]) {
    let pk = secret_key.public_key();
    let point = pk.to_sec1_point(false);
    let x_slice: &[u8] = point.x().expect("x coordinate");
    let y_slice: &[u8] = point.y().expect("y coordinate");
    let mut x = [0u8; 32];
    let mut y = [0u8; 32];
    x.copy_from_slice(x_slice);
    y.copy_from_slice(y_slice);
    (x, y)
}

/// Compute the ownership commitment from a `SecretKey` and a nonce.
///
/// Equivalent to the old `pso_zk_core::generate_ownership`, with the
/// k256 → bytes extraction moved into the test layer so
/// `pso-protocol` itself stays free of an EC dependency.
pub fn ownership_from_secret_key(secret_key: &SecretKey, nonce: Fr) -> anyhow::Result<Fr> {
    let (x, y) = sec1_coords(secret_key);
    pso_protocol::ownership::compute_ownership(&x, &y, nonce)
        .map_err(|e| anyhow::anyhow!("compute_ownership: {e}"))
}

/// ECDSA-secp256k1 prehash signature over `digest.to_bytes_le()`.
pub fn sign_prehash_le(secret_key: &SecretKey, digest: &Fr) -> anyhow::Result<[u8; 64]> {
    let signing_key = SigningKey::from_bytes(&secret_key.to_bytes())?;
    let prehash = fr_to_le32(digest);
    let sig: Signature = signing_key.sign_prehash(&prehash)?;
    Ok(sig.to_bytes().into())
}

// --------------------------------------------------------------------- //
// Witness builders (formerly `OwnableNFT::generate_witness` blanket impls
// in `pso-zk-core::witness`).
// --------------------------------------------------------------------- //

/// Build an `OwnershipWitness` from any `OwnableNFT` plus a key
/// material context.
pub fn build_ownership_witness<T: OwnableNFT>(
    nft: &T,
    secret_key: &SecretKey,
    nonce: Fr,
) -> anyhow::Result<OwnershipWitness> {
    let (public_key_x, public_key_y) = sec1_coords(secret_key);
    let ownership_fr = nft.ownership();
    let ownership = fr_to_le32(&ownership_fr);
    let signature = sign_prehash_le(secret_key, &ownership_fr)?;
    let nonce_bytes = fr_to_le32(&nonce);

    Ok(OwnershipWitness {
        private_inputs: OwnershipPrivateInputs {
            nonce: nonce_bytes,
            public_key_x,
            public_key_y,
        },
        public_inputs: OwnershipPublicInputs {
            ownership,
            signature,
        },
    })
}

/// Build a `FullProofWitness` from any `OwnableNFT + HashableNFT`.
pub fn build_full_proof_witness<T: OwnableNFT + HashableNFT>(
    nft: &T,
    secret_key: &SecretKey,
    nonce: Fr,
    merkle_path: &[MerklePathElement],
) -> anyhow::Result<FullProofWitness> {
    let (public_key_x, public_key_y) = sec1_coords(secret_key);
    let ownership_fr = nft.ownership();
    let ownership = fr_to_le32(&ownership_fr);
    let signature = sign_prehash_le(secret_key, &ownership_fr)?;
    let nonce_bytes = fr_to_le32(&nonce);

    let entity_hash_fr = nft
        .hash()
        .map_err(|e| anyhow::anyhow!("entity hash: {e}"))?;
    let entity_hash = fr_to_le32(&entity_hash_fr);

    let merkle_root_fr = pso_protocol::merkle::compute_merkle_root(
        &entity_hash_fr,
        merkle_path,
        pso_protocol::merkle::SPARSE_MERKLE_PATH_DEPTH,
    )
    .map_err(|e| anyhow::anyhow!("merkle root: {e}"))?;
    let merkle_root = fr_to_le32(&merkle_root_fr);

    Ok(FullProofWitness {
        private_inputs: FullProofPrivateInputs {
            ownership: OwnershipPrivateInputs {
                nonce: nonce_bytes,
                public_key_x,
                public_key_y,
            },
            merkle_path: merkle_path.to_vec(),
        },
        public_inputs: FullProofPublicInputs {
            ownership: OwnershipPublicInputs {
                ownership,
                signature,
            },
            entity_hash,
            merkle_root,
        },
    })
}

/// Build the SU-ownership aggregation witness.
///
/// `tier_n` is the compile-time slot count of the target circuit. Real
/// slots are filled from `real_slots`; the rest are zero-padded
/// (nonce = 0, derived_owner = 0). The circuit's ownership-check
/// trivializes for zero `derived_owner` slots.
///
/// `binding_hash` is the wallet's pre-computed
/// `pso_protocol::binding::compute_binding_hash(...)` for the
/// TributeDraft being submitted.
pub fn build_aggregation_witness(
    secret_key: &SecretKey,
    real_slots: &[AggregationSlot],
    tier_n: u32,
    binding_hash: Fr,
) -> anyhow::Result<AggregationWitness> {
    if (real_slots.len() as u32) > tier_n {
        anyhow::bail!(
            "real slot count {} exceeds tier size {}",
            real_slots.len(),
            tier_n,
        );
    }

    let (public_key_x, public_key_y) = sec1_coords(secret_key);

    let n = tier_n as usize;
    let mut nonces: Vec<[u8; 32]> = Vec::with_capacity(n);
    let mut derived_owners: Vec<[u8; 32]> = Vec::with_capacity(n);
    for slot in real_slots {
        nonces.push(fr_to_le32(&slot.nonce));
        derived_owners.push(fr_to_le32(&slot.derived_owner));
    }
    while nonces.len() < n {
        nonces.push([0u8; 32]);
        derived_owners.push([0u8; 32]);
    }

    let signature = sign_prehash_le(secret_key, &binding_hash)?;

    Ok(AggregationWitness {
        private_inputs: AggregationPrivateInputs {
            public_key_x,
            public_key_y,
            nonces,
            signature,
        },
        public_inputs: AggregationPublicInputs {
            derived_owners,
            binding_hash: fr_to_le32(&binding_hash),
        },
    })
}
