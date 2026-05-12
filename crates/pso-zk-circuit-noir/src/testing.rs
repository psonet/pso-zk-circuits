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
//!
//! The witness builders here match the §4.2 privacy-preserving L2
//! spec: signature is over `Poseidon2(nft_hash, nonce)`, and
//! `nft_hash` lives inside `OwnershipPublicInputs` (no duplicate
//! `entity_hash` at the outer level). Same semantics as
//! `pso_integrations_shared::witness::*`.

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::ecdsa::{Signature, SigningKey};
use k256::elliptic_curve::sec1::ToSec1Point;
use k256::SecretKey;

use pso_protocol::merkle::MerklePathElement;
use pso_protocol::witness::{
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
// Witness builders. Match the §4.2 semantics shared with
// `pso_integrations_shared::witness::*` — the signature payload is
// `Poseidon2(nft_hash, nonce)`, and `nft_hash` lives inside
// `OwnershipPublicInputs`.
// --------------------------------------------------------------------- //

/// Build an `OwnershipWitness` per §4.2.
pub fn build_ownership_witness<T: OwnableNFT + HashableNFT>(
    nft: &T,
    secret_key: &SecretKey,
    nonce: Fr,
) -> anyhow::Result<OwnershipWitness> {
    let (public_key_x, public_key_y) = sec1_coords(secret_key);
    let ownership_fr = nft.ownership();
    let ownership = fr_to_le32(&ownership_fr);
    let nonce_bytes = fr_to_le32(&nonce);

    let nft_hash_fr = nft.hash().map_err(|e| anyhow::anyhow!("nft hash: {e}"))?;
    let nft_hash = fr_to_le32(&nft_hash_fr);

    // Sign Poseidon2(nft_hash, nonce) per §4.2.
    let prehash_fr = pso_protocol::hash::poseidon2(nft_hash_fr, nonce)
        .map_err(|e| anyhow::anyhow!("poseidon2(nft_hash, nonce): {e}"))?;
    let signature = sign_prehash_le(secret_key, &prehash_fr)?;

    Ok(OwnershipWitness {
        private_inputs: OwnershipPrivateInputs {
            nonce: nonce_bytes,
            public_key_x,
            public_key_y,
        },
        public_inputs: OwnershipPublicInputs {
            ownership,
            nft_hash,
            signature,
        },
    })
}

/// Build a `FullProofWitness` per §4.2 — same ownership semantics as
/// [`build_ownership_witness`], composed with a Merkle inclusion
/// against the same `nft_hash`.
pub fn build_full_proof_witness<T: OwnableNFT + HashableNFT>(
    nft: &T,
    secret_key: &SecretKey,
    nonce: Fr,
    merkle_path: &[MerklePathElement],
) -> anyhow::Result<FullProofWitness> {
    let (public_key_x, public_key_y) = sec1_coords(secret_key);
    let ownership_fr = nft.ownership();
    let ownership = fr_to_le32(&ownership_fr);
    let nonce_bytes = fr_to_le32(&nonce);

    let nft_hash_fr = nft.hash().map_err(|e| anyhow::anyhow!("nft hash: {e}"))?;
    let nft_hash = fr_to_le32(&nft_hash_fr);

    let prehash_fr = pso_protocol::hash::poseidon2(nft_hash_fr, nonce)
        .map_err(|e| anyhow::anyhow!("poseidon2(nft_hash, nonce): {e}"))?;
    let signature = sign_prehash_le(secret_key, &prehash_fr)?;

    let merkle_root_fr = pso_protocol::merkle::compute_merkle_root(
        &nft_hash_fr,
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
                nft_hash,
                signature,
            },
            merkle_root,
        },
    })
}

// The old `build_aggregation_witness` is removed — the
// `NoirSuOwnershipAggregationCircuit` it served has been replaced by
// the recursive aggregation circuit family
// (`pso-recursive-aggregation-circuit-n*`), which folds N per-SU
// ownership proofs into one recursive proof. See
// `docs/aggregation-redesign.md` in psonet/pso-integration.
