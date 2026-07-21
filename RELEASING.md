# Releasing s-gw

Releases should be reproducible, signed where the platform supports it, and explicit about preview status.

## Repository Settings

Before the first public release:

- set the repository description, website, topics, and social preview;
- enable private vulnerability reporting;
- enable secret scanning and push protection;
- protect `main` and require the CI workflow;
- confirm issues use the repository forms and security reports use private advisories;
- review every branch and tag for credentials or private artifacts before changing visibility.

The prepared social image is `docs/images/social-preview.png`.

## Version

Update `package.json` and `package-lock.json` together. Add user-visible changes to `CHANGELOG.md`. Use semantic versions once the first public tag is published.

## Verification

Maintainer releases require a private `barryqy/s-gw-rust-core` checkout. Set `SGW_RUST_CORE_DIR` to that checkout and `SGW_REQUIRE_RUST_CORE=1` so packaging fails closed when the proprietary runner is unavailable.

```bash
export SGW_RUST_CORE_DIR=../s-gw-rust-core
export SGW_REQUIRE_RUST_CORE=1
npm ci
npm run verify
npm run build:installers
```

Exercise the [quick-start trust loop](docs/quickstart.md) with a disposable store. Platform builds also require the relevant native tests and an install/uninstall smoke test on the target operating system.

## Artifacts

`npm run build:installers` writes release files and SHA-256 checksums under `dist/installers`.

The macOS DMG is a self-contained `s-gw.app` plus an Applications shortcut. The default `notarized` release mode requires Developer ID signing, hardened runtime, Apple notarization, stapling, and Gatekeeper assessment. The `release-assets` workflow fails closed unless these repository secrets are present:

- `APPLE_DEVELOPER_ID_P12_BASE64`
- `APPLE_DEVELOPER_ID_P12_PASSWORD`
- `APPLE_NOTARY_KEY_P8_BASE64`
- `APPLE_NOTARY_KEY_ID`
- `APPLE_NOTARY_ISSUER_ID`

`unsigned` is the Apple-ID-free macOS mode. It produces the primary `s-gw.dmg` plus a versioned compatibility copy and uses the ordinary `vVERSION` tag, while the normal npm package remains the primary installation path. Its release notes and DMG README lead with `npm install -g @s-gw/s-gw` and explain the required Gatekeeper override for the desktop alternative. Local builds use ad-hoc signatures only. Do not describe the Windows package as a production download until it is signed and validated on supported Windows versions.

## Publish

1. Create an annotated `vX.Y.Z` tag from a green `main` commit.
2. Ensure private `barryqy/s-gw-rust-core` has the same immutable tag.
3. Run **Publish release** with `release_tag=vX.Y.Z`, `publish_release=true`, `publish_npm_only=false`, and `macos_distribution=notarized` for a signed release or `macos_distribution=unsigned` when an Apple Developer ID is unavailable.
4. The normal workflow verifies the tag/version pair, builds, signs, notarizes, staples, and Gatekeeper-assesses the DMG before it creates or updates a **draft** GitHub release.
5. It uploads every installer and checksum, confirms their GitHub asset state is `uploaded`, then verifies and publishes the scoped npm package from the immutable tag. This protected OIDC step is independent of macOS notarization.
6. After npm verification succeeds, it publishes the draft. MCP Registry publication follows the successful npm publication and does not hold the GitHub release open.
7. To inspect assets without notifying users, run the workflow with `publish_release=false` and `publish_npm_only=false`; the release remains a draft and npm is not changed. Re-run with `true` only after review.
8. Verify checksums from a clean download and install the release on clean macOS and Windows test accounts.
9. Confirm the update checker sees the release and opens the correct notes.

When signing is unavailable, use `unsigned`. It creates a normal SemVer release so installed clients can discover it, and it still publishes the normal npm package before the GitHub release. The release notes must lead with the npm command and state the Gatekeeper override for the DMG. The Windows package may still be labeled as a preview artifact with its limitations stated in the release notes.

If an existing public GitHub release missed npm or MCP Registry publication, run **Publish release** with `release_tag=vX.Y.Z` and `publish_npm_only=true`. This verifies the immutable tag and matching private core, publishes or verifies the scoped npm version through the existing OIDC environment, and then publishes the same version to the MCP Registry. It does not rebuild assets or alter the GitHub release.
