# Changelog

Notable changes to s-gw are documented here. The project follows [Semantic Versioning](https://semver.org/) once public releases begin.

## Unreleased

### Added

- Local credential handles backed by macOS Keychain, Windows Credential Manager, 1Password references, or an encrypted ledger.
- Action-scoped approval policies and reusable grants.
- MCP tools for scanning, handle discovery, approved command execution, and owned SSH sessions.
- Native macOS management app and standalone menu helper.
- Windows preview client, tray helper, credential helper, and installer staging.
- Agent profiles for major coding agents and MCP clients.
- Local activity, audit, policy, credential, and usage-flow views.

### Security

- Local console write operations require a per-session token.
- Raw credential values are accepted over stdin rather than process arguments.
- Approved command output is scanned and tokenized before it is returned to the caller.
