# Security policy

## Release signing

Since **v0.2.5**, every artifact attached to a `pso-zk-circuits` GitHub Release is signed with [sigstore cosign](https://docs.sigstore.dev/cosign/overview/) keyless OIDC and carries an [SLSA v1.0](https://slsa.dev/spec/v1.0/) build-provenance attestation minted by `actions/attest-build-provenance`.

### Signed artifacts

This repo ships one artifact family, signed when present:

**Rust (`pso-zk-canonical` crate):**

| File | What it is |
|---|---|
| `pso-zk-canonical-X.Y.Z.crate` | The byte-identical .crate uploaded to crates.io. |
| `pso-zk-canonical-X.Y.Z.crate.sig` / `.pem` | cosign blob signature + Fulcio cert. |

There are no mobile artifacts. The FFI surface lives in the downstream UniFFI
wallet crate, not here, and no job in `ci.yml` cross-compiles for iOS or
Android. If you are looking for a signed `.a`, `.so` or `.xcframework`, it is
not produced by this repository.

**Common:**

| File | What it is |
|---|---|
| `SHA256SUMS` | SHA-256 of every other file attached to the release. |
| `SHA256SUMS.sig` / `.pem` | cosign sig + cert for the manifest. |

Build-provenance attestations are not attached to the Release — they live in GitHub's attestation store and are queried via `gh attestation verify`.

### When nothing gets signed

`publish-crates-io` runs with `continue-on-error: true`, and the crate is staged
for signing only if that job succeeded. So an ordinary crates.io flake — a
timeout, an index lag, a version already published — leaves nothing to sign:
`has_artifacts` goes false, the release is created with no signed pair, and
`verify-release` then hard-fails with `no signed artifacts found`.

That error means "the publish step did not produce a crate", not "a signature
was bad". Check `publish-crates-io` first; it will be green-with-a-cross,
because `continue-on-error` reports success to the workflow while recording the
failure on the job.

`verify-release` also fails if any signature present on the release is invalid.
Both conditions are hard failures; neither is tolerated.

### Threat model

The signing pipeline protects against:

- **Tampered binaries on the Release page.** A re-uploaded `.crate` or `SHA256SUMS` won't verify against the original cert + sig.
- **A compromised crates.io API token.** The same maintainer who can `cargo publish` cannot mint a sigstore signature whose Fulcio cert identity matches `https://github.com/psonet/pso-zk-circuits/.github/workflows/ci.yml@refs/heads/main` (the cog flow) or `@refs/tags/vX.Y.Z` (a manual tag-push re-release). Those identities are only obtainable from inside a GitHub Actions run of this repo's `ci.yml` workflow.
- **A typo or mis-targeted action update** silently weakening verification. The post-publish `verify-release` job hard-fails the workflow on any bad signature.

It does **not** protect against:

- A compromise of `github.com/psonet/pso-zk-circuits` itself (an attacker with push access to `main` can edit the workflow to remove or weaken signing).
- A compromise of the sigstore public-good trust root (Fulcio CA, Rekor transparency log).
- Tampering with the crates.io copy of the `pso-zk-canonical` tarball. crates.io has no first-party signing channel; the GH-Release-attached `.crate` is byte-identical to the crates.io upload, so a paranoid consumer can `cargo fetch`, hash, and compare against `SHA256SUMS`.
- A `barretenberg-rs` upstream supply-chain compromise. `pso-zk-backend` links whichever prebuilt FFI binary `barretenberg-rs`'s `build.rs` fetches at build time. That crate is `publish = false` and ships in no release artifact, so nothing here is signed over it — but anything downstream that builds it inherits the exposure. A signature attests "this is what CI produced on this tagged run," not "this contains untampered barretenberg code."
- Existing (pre-cutoff) releases. Those are **not** retroactively signed.

### Verification recipe

You need [cosign](https://docs.sigstore.dev/cosign/installation/) and [`gh`](https://cli.github.com/) on `$PATH`.

```sh
REPO=psonet/pso-zk-circuits
TAG=v0.11.0  # or any release ≥ the cutoff

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
    '^https://github\.com/psonet/pso-zk-circuits/\.github/workflows/ci\.yml@refs/(heads/main|tags/v[0-9]+\.[0-9]+\.[0-9]+)$' \
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
