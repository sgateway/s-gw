# Contributing To s-gw

Thanks for helping improve s-gw. Focused issues and pull requests are easiest to review and safest to ship.

## Before You Start

- Use a GitHub issue for bugs and feature proposals.
- Use [private vulnerability reporting](SECURITY.md) for security-sensitive findings.
- Keep unrelated refactors out of functional changes.
- Never commit real credentials, local ledgers, approval history, or screenshots containing private data.

## Development Setup

Requirements:

- Node.js 20 or newer;
- npm;
- Swift on macOS when changing the native app, menu helper, or Keychain helper;
- PowerShell on Windows when changing the preview client or credential helper.

```bash
git clone https://github.com/barryqy/s-gw.git
cd s-gw
npm ci
npm run build
npm test
```

Run the local console during UI work:

```bash
npm run dev:console-ui
```

The console uses sanitized sample data when it is not connected to a live local daemon.

## Change Guidelines

- Follow the existing TypeScript, React, Swift, and PowerShell patterns.
- Prefer small functions and explicit error handling.
- Add focused tests for behavior changes and regressions.
- Update the threat model when a trust boundary or security claim changes.
- Update user documentation when commands, storage, approvals, or platform support change.
- Keep third-party asset sources and licenses current in `docs/ui/THIRD_PARTY_NOTICES.md`.

Changes to credential handling, approval scope, command normalization, sanitization, local HTTP authorization, or native helpers require tests that exercise the failure path as well as the successful path.

## Verification

Run the full local verification before opening a pull request:

```bash
npm run verify
```

Platform-specific changes should also run the relevant build:

```bash
npm run build:macos-app
npm run build:menubar
npm run build:windows-client
```

macOS builds are expected to skip on other platforms. Windows preview artifacts can be staged on any platform, but behavior changes should be exercised on Windows before being described as supported.

## Pull Requests

Describe the problem, the user-visible behavior, the security impact, and how the change was verified. Screenshots are useful for UI changes, but use sample data and crop out usernames, paths, credentials, request IDs, and machine details.

By contributing, you agree that your contribution is licensed under the Apache License, Version 2.0.

Maintainers should follow [RELEASING.md](RELEASING.md) for versioning, platform signing, artifacts, and repository publication settings.
