# Changelog

Notable changes to s-gw are documented here. The project follows [Semantic Versioning](https://semver.org/) once public releases begin.

## Unreleased

## 0.1.0 - 2026-07-03

### Added

- Compiled Rust execution core for approved environment commands on macOS, Windows, and Linux builds.
- Cross-language execution, timeout, environment-isolation, sanitization, and proof compatibility tests.
- Local credential handles backed by macOS Keychain, Windows Credential Manager, 1Password references, or an encrypted ledger.
- Action-scoped approval policies and reusable grants.
- MCP tools for scanning, handle discovery, approved command execution, and owned SSH sessions.
- Native macOS management app and standalone menu helper.
- Windows preview client, tray helper, credential helper, and installer staging.
- Agent profiles for major coding agents and MCP clients.
- Local activity, audit, policy, credential, and usage-flow views.

### Changed

- Runtime packages contain the compiled application without source maps or native source files. The complete source remains available in the repository.

### Security

- Approved credential values reach the Rust core over stdin, never command arguments or inherited environment variables.
- The broker rejects malformed core responses, unsanitized credential output, and invalid execution proofs.
- Local console write operations require a per-session token.
- Raw credential values are accepted over stdin rather than process arguments.
- Approved command output is scanned and tokenized before it is returned to the caller.
