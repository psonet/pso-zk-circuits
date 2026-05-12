// SU ownership aggregation circuit, tier N = 8.
//
// One of 8 fixed-shape tiers (1, 2, 4, 6, 8, 16, 32, 64). The on-chain
// TributeDraft contract picks the smallest tier >= `suIds.length` and
// pads unused `derived_owners` slots with `bytes32(0)` on the EVM
// side. The circuit body lives in `pso_circuit_core::aggregation`;
// this bin just pins `N` at compile time.

use pso_circuit_core::aggregation;

global N: u32 = 8;

pub fn main(
    pk_x_bytes: [u8; 32],
    pk_y_bytes: [u8; 32],
    nonces: [Field; N],
    signature: [u8; 64],
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
