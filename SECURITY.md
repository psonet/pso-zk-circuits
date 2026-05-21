# Security policy

## Release signing

Starting with the first release tagged after this file lands (expected: **v0.2.5**, the cog-bumped patch following PR `release/sigstore-signing`), every artifact attached to a `pso-zk-circuits` GitHub Release is signed with [sigstore cosign](https://docs.sigstore.dev/cosign/overview/) keyless OIDC and carries an [SLSA v1.0](https://slsa.dev/spec/v1.0/) build-provenance attestation minted by `actions/attest-build-provenance`.

### Signed artifacts

This repo ships two artifact families. Both are signed when present:

**Rust (`pso-zk-canonical` crate, always present on release):**

| File | What it is |
|---|---|
| `pso-zk-canonical-X.Y.Z.crate` | The byte-identical .crate uploaded to crates.io. |
| `pso-zk-canonical-X.Y.Z.crate.sig` / `.pem` | cosign blob signature + Fulcio cert. |

**Mobile slices (best-effort; whichever produced):**

| File | What it is |
|---|---|
| `pso-zk-circuit-noir-ios-arm64-libpso_zk_circuit_noir.a` | iOS device static lib. |
| `pso-zk-circuit-noir-ios-sim-arm64-libpso_zk_circuit_noir.a` | iOS Apple-Silicon simulator static lib. |
| `pso-zk-circuit-noir-ios-xcframework-libpso_zk_circuit_noir.xcframework.zip` | Combined xcframework for SwiftPM / Xcode. |
| `pso-zk-circuit-noir-android-arm64-v8a-libpso_zk_circuit_noir.so` | Android arm64 shared lib. |
| `pso-zk-circuit-noir-android-x86_64-libpso_zk_circuit_noir.so` | Android x86_64 shared lib. |

Each mobile artifact gets a sibling `.sig` + `.pem`.

**Common:**

| File | What it is |
|---|---|
| `SHA256SUMS` | SHA-256 of every other file attached to the release. |
| `SHA256SUMS.sig` / `.pem` | cosign sig + cert for the manifest. |

Build-provenance attestations are not attached to the Release — they live in GitHub's attestation store and are queried via `gh attestation verify`.

### Matrix-aware signing

The mobile build matrix runs with `continue-on-error: true` because the upstream `barretenberg-rs` cross-toolchain has occasional regressions on individual targets. The signing pipeline tolerates this: **whichever subset of mobile slices made it through the matrix gets signed**; missing slices contribute zero signatures. `SHA256SUMS` covers whichever files made it. The post-publish `verify-release` job then verifies every signed pair on the release; it fails if any signature is invalid OR if zero artifacts were signed (i.e., the entire matrix collapsed).

### Threat model

The signing pipeline protects against:

- **Tampered binaries on the Release page.** A re-uploaded `.crate`, mobile slice, or `SHA256SUMS` won't verify against the original cert + sig.
- **A compromised crates.io API token.** The same maintainer who can `cargo publish` cannot mint a sigstore signature whose Fulcio cert identity matches `https://github.com/psonet/pso-zk-circuits/.github/workflows/ci.yml@refs/tags/vX.Y.Z`. That identity is only obtainable from inside a tag-triggered GitHub Actions run of this repo.
- **A compromised mobile signing key (not applicable here).** Mobile slices are *unsigned at the platform level* — neither iOS Developer ID nor Android v2/v3 — but they ARE sigstore-signed. Wallets embedding them should re-sign with their own platform identity after fetching + verifying the sigstore signature.
- **A typo or mis-targeted action update** silently weakening verification. The post-publish `verify-release` job hard-fails the workflow on any bad signature.

It does **not** protect against:

- A compromise of `github.com/psonet/pso-zk-circuits` itself (an attacker with push access to `main` can edit the workflow to remove or weaken signing).
- A compromise of the sigstore public-good trust root (Fulcio CA, Rekor transparency log).
- Tampering with the crates.io copy of the `pso-zk-canonical` tarball. crates.io has no first-party signing channel; the GH-Release-attached `.crate` is byte-identical to the crates.io upload, so a paranoid consumer can `cargo fetch`, hash, and compare against `SHA256SUMS`.
- A `barretenberg-rs` upstream supply-chain compromise. The mobile slices are built against whichever prebuilt FFI binaries `barretenberg-rs`'s `build.rs` fetches at CI time. The signature attests "this is the binary CI produced on this tagged run," not "this binary contains untampered barretenberg code."
- Existing (pre-cutoff) releases. Those are **not** retroactively signed.

### Verification recipe

You need [cosign](https://docs.sigstore.dev/cosign/installation/) and [`gh`](https://cli.github.com/) on `$PATH`.

```sh
REPO=psonet/pso-zk-circuits
TAG=v0.2.5  # or any release ≥ the cutoff

# Crate verification.
ARTIFACT=pso-zk-canonical-${TAG#v}.crate
gh release download "$TAG" --repo "$REPO" \
  --pattern "$ARTIFACT" \
  --pattern "$ARTIFACT.sig" \
  --pattern "$ARTIFACT.pem"

cosign verify-blob \
  --certificate "$ARTIFACT.pem" \
  --signature   "$ARTIFACT.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/psonet/pso-zk-circuits/\.github/workflows/ci\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARTIFACT"

# Mobile slice verification (replace ARTIFACT with whichever slice).
ARTIFACT='pso-zk-circuit-noir-ios-arm64-libpso_zk_circuit_noir.a'
gh release download "$TAG" --repo "$REPO" \
  --pattern "$ARTIFACT" \
  --pattern "$ARTIFACT.sig" \
  --pattern "$ARTIFACT.pem"
cosign verify-blob \
  --certificate "$ARTIFACT.pem" --signature "$ARTIFACT.sig" \
  --certificate-identity-regexp \
    '^https://github\.com/psonet/pso-zk-circuits/\.github/workflows/ci\.yml@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$ARTIFACT"

# Optional: SLSA build-provenance attestation.
gh attestation verify "$ARTIFACT" --repo "$REPO"
```

CI's own `verify-release` job runs the same loop on every published release; a green `verify-release` is your signal that the regex above is the correct one.

### Retroactive signing

Releases tagged **before** the cutoff are not signed. Backfilling would mint signatures whose Fulcio identity reads "a manual workflow_dispatch on YYYY-MM-DD by a maintainer," not "a tag-triggered run of the original release," which is weaker provenance than the absence of a signature.

## Reporting vulnerabilities

For security issues in `pso-zk-circuits` itself (not the signing pipeline), open a [private security advisory](https://github.com/psonet/pso-zk-circuits/security/advisories/new) on GitHub. Do not file a public issue.

## References

- [sigstore docs](https://docs.sigstore.dev/)
- [SLSA v1.0 specification](https://slsa.dev/spec/v1.0/)
- [`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)
- [`sigstore/cosign-installer`](https://github.com/sigstore/cosign-installer)
