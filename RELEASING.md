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

```bash
npm ci
npm run verify
npm run build:installers
```

Exercise the [quick-start trust loop](docs/quickstart.md) with a disposable store. Platform builds also require the relevant native tests and an install/uninstall smoke test on the target operating system.

## Artifacts

`npm run build:installers` writes versioned files and SHA-256 checksums under `dist/installers`.

Do not describe the macOS DMG as a production download until the application, helper, and installer are signed with Developer ID and notarized. Do not describe the Windows package as a production download until it is signed and validated on supported Windows versions.

## Publish

1. Create an annotated `vX.Y.Z` tag from a green `main` commit.
2. Create a GitHub release using the matching changelog entry.
3. Attach signed platform artifacts, the npm tarball, and `SHA256SUMS.txt`.
4. Verify checksums from a clean download.
5. Install the release on clean macOS and Windows test accounts.
6. Confirm the update checker sees the release and opens the correct notes.

If signing is not available, label installers as preview artifacts and state the signing and notarization limitations in the release notes.
