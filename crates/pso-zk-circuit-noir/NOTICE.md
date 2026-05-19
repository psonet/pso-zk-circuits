## Third-party code attribution

This crate includes code derived from
[zkpassport/noir_rs](https://github.com/zkpassport/noir_rs) (Apache-2.0),
vendored under `src/vendor/noir_rs/`.

See `vendor/noir_rs/LICENSE` for the original license terms.

The vendored code is byte-identical to the upstream source at
`v1.0.0-beta.20` (commit `d2bb6e5`). The only project-local override is
the `barretenberg-rs` version pin (`=5.0.0-nightly.20260512`), which is
declared in this crate's `Cargo.toml` rather than carried as a source
modification.
