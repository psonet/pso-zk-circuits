// SU ownership aggregation circuit, tier N = 2.
//
// One of 8 fixed-shape tiers (1, 2, 4, 6, 8, 16, 32, 64). The on-chain
// TributeDraft contract picks the smallest tier >= `suIds.length` and
// pads unused `derived_owners` slots with `bytes32(0)` on the EVM
// side. The circuit body lives in `pso_circuit_core::aggregation`;
// this bin just pins `N` at compile time.
//
// See `crates/pso-zk-circuit-noir/pso-circuit-core/src/aggregation.nr`
// for the full public-input layout and the rationale for the binding
// hash construction.

use pso_circuit_core::aggregation;

global N: u32 = 2;

pub fn main(
    // Private inputs (witness)
    pk_x_bytes: [u8; 32],
    pk_y_bytes: [u8; 32],
    nonces: [Field; N],
    signature: [u8; 64],
    // Public inputs
    derived_owners: pub [Field; N],
    binding_hash: pub Field,
) {
    aggregation::verify(
        pk_x_bytes,
        pk_y_bytes,
        nonces,
        signature,
        derived_owners,
        binding_hash,
    );
}
