// SPDX-License-Identifier: Apache-2.0
// Vendored from zkpassport/noir_rs (Apache-2.0).
// See `pso-zk-circuit-noir/vendor/noir_rs/LICENSE` for the original license.
//
// Mirrors the upstream `noir_rs/src/lib.rs` module layout. The
// `pub use acvm::*;` re-export upstream is intentionally dropped —
// downstream callers in this crate import `WitnessMap`, `AcirField`,
// and `FieldElement` directly from `acvm`.

pub mod circuit;
pub mod execute;
pub mod witness;
mod backends;

pub use backends::barretenberg;
