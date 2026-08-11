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

Build the Windows x64 or Linux x64 desktop preview on its target operating system:

```bash
npm ci
npm run check:desktop-app
npm run test:desktop-app
npm run build:desktop-app
```

The desktop build stages the production npm package and a checksum-pinned Node runtime before invoking Tauri. Cross-building these installers is not supported; build NSIS on Windows and the Debian package on Linux.

## Artifacts

`npm run build:installers` writes release files and SHA-256 checksums under `dist/installers`.

`npm run build:desktop-app` writes the platform-native preview under `native/desktop-app/target/release/bundle`: an NSIS installer under `nsis` on Windows or a Debian package under `deb` on Linux. These files are unsigned CI artifacts in the current release process. The publish workflow does not upload them to GitHub Releases, and they must not be described as supported public downloads.

The installed desktop app bundles Node.js 24, the production s-gw package, and the loopback console assets. Users do not need a separate Node.js or npm installation. Windows uses a per-user NSIS install and requires Microsoft Edge WebView2; the installer is configured to download the WebView2 bootstrapper if necessary. The Linux x64 package requires WebKitGTK, `libsecret-tools`, a graphical session, and an unlocked Secret Service keyring.

Building requires Node.js 20 or newer and the Rust toolchain. Windows builds need the MSVC Rust target and the normal Tauri Windows build prerequisites. Ubuntu/Debian build hosts need the Tauri WebKitGTK 4.1 and AppIndicator development packages in addition to the ordinary compiler toolchain.

The macOS DMG is a self-contained `s-gw.app` plus an Applications shortcut. The default `notarized` release mode requires Developer ID signing, hardened runtime, Apple notarization, stapling, and Gatekeeper assessment. The `release-assets` workflow fails closed unless these repository secrets are present:

- `APPLE_DEVELOPER_ID_P12_BASE64`
- `APPLE_DEVELOPER_ID_P12_PASSWORD`
- `APPLE_NOTARY_KEY_P8_BASE64`
- `APPLE_NOTARY_KEY_ID`
- `APPLE_NOTARY_ISSUER_ID`

`unsigned` is the Apple-ID-free macOS mode. It produces the primary `s-gw.dmg` plus a versioned compatibility copy and uses the ordinary `vVERSION` tag, while the normal npm package remains the primary installation path. Its release notes and DMG README lead with `npm install -g @s-gw/s-gw` and explain the required Gatekeeper override for the desktop alternative. Local builds use ad-hoc signatures only. Do not describe the Windows or Linux desktop package as a production download until it is signed and validated on supported target systems.

Public Windows distribution requires an Authenticode-signed executable and installer plus clean-machine SmartScreen and install/uninstall testing. Public Linux distribution requires signed repository or release metadata, checksum publication, and install/uninstall testing on the supported distributions. Adding a CI artifact does not satisfy either release bar.

## Publish

1. Create an annotated `vX.Y.Z` tag from a green `main` commit.
2. Ensure private `barryqy/s-gw-rust-core` has the same immutable tag.
3. Run **Publish release** with `release_tag=vX.Y.Z`, `publish_release=true`, `publish_npm_only=false`, and `macos_distribution=notarized` for a signed release or `macos_distribution=unsigned` when an Apple Developer ID is unavailable.
4. The normal workflow verifies the tag/version pair, builds, signs, notarizes, staples, and Gatekeeper-assesses the DMG before it creates or updates a **draft** GitHub release.
5. It uploads every installer and checksum, confirms their GitHub asset state is `uploaded`, then verifies and publishes the scoped npm package from the immutable tag. This protected OIDC step is independent of macOS notarization.
6. After npm verification succeeds, it publishes the draft. MCP Registry publication follows the successful npm publication and does not hold the GitHub release open.
7. To inspect assets without notifying users, run the workflow with `publish_release=false` and `publish_npm_only=false`; the release remains a draft and npm is not changed. Re-run with `true` only after review.
8. Verify checksums from a clean download and install the release on clean macOS and Windows test accounts. Validate Linux artifacts separately before adding them to any release.
9. Confirm the update checker sees the release and opens the correct notes.

When Apple signing is unavailable, use `unsigned`. It creates a normal SemVer release so installed clients can discover it, and it still publishes the normal npm package before the GitHub release. The release notes must lead with the npm command and state the Gatekeeper override for the DMG. Keep the Windows and Linux desktop builds as CI previews until their separate signing and target-system validation requirements are met.

If an existing public GitHub release missed npm or MCP Registry publication, run **Publish release** with `release_tag=vX.Y.Z` and `publish_npm_only=true`. This verifies the immutable tag and matching private core, rejects current high-severity audit findings without letting a newly disclosed low-severity advisory make the immutable tag unrepairable, and clean-installs and exercises an existing npm artifact instead of comparing it with a non-reproducible native rebuild. If the npm version is absent, the workflow publishes it and requires the registry integrity to match the local package. It then publishes the same version to the MCP Registry without rebuilding assets or altering the GitHub release.
