# Changelog

Notable changes to s-gw are documented here. The project follows [Semantic Versioning](https://semver.org/) once public releases begin.

## Unreleased

### Added

- Safe, idempotent setup for detected agent MCP configurations and the packaged s-gw skill, with dry-run, status, backups, conflict handling, and scoped uninstall.
- A tested migration path from the legacy unscoped `s-gw` npm package to `@s-gw/s-gw`.
- A release-only legacy bridge package so the original `0.1.0` desktop updater can install the fixed updater before the scoped-package migration.

### Fixed

- macOS update checks now continue for the app process lifetime, retry failed checks, and deliver one system notification per release.
- Update checks fall back to GitHub's public Atom feed when the unauthenticated Releases API is rate-limited.
- The updater accepts both per-file SHA-256 assets and `SHA256SUMS.txt`, and release automation uploads both formats.
- Native upgrades use the migration-aware installer instead of invoking npm directly.
- Windows agent registration launches the packaged server through `node.exe` instead of an npm `.cmd` shim and honors custom Codex, Gemini CLI, and Copilot homes.
- GitHub Copilot CLI registrations include its required local-server tool allowlist.
- OpenCode JSONC and the default VS Code user profile now support comment-preserving managed install and uninstall.

## 0.1.1 - 2026-07-10

### Added

- Official MCP Registry metadata for discovery and one-command launch through npm.
- `s-gw mcp` as a primary CLI entry point for the stdio MCP server.

### Changed

- MCP server version reporting now stays aligned with the package version.

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
