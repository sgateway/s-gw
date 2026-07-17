# s-gw Documentation

## Start Here

- [macOS app install](deployment.md#macos-app-apple-silicon): drag the self-contained Apple Silicon app to Applications.
- [Quick start](quickstart.md): npm/source installation and the disposable trust-loop demo.
- [Architecture](architecture.md): components, data flow, and local process boundaries.
- [Threat model](threat-model.md): intended guarantees, attacker assumptions, and non-goals.
- [Deployment](deployment.md): platform support, setup, packaging, upgrade, and uninstall.

## Integrations

- [Agent integrations](integrations.md): Codex, Claude Code, Cursor, OpenCode, and VS Code configuration.
- [Agent profiles](agents.md): known clients, aliases, config paths, and compatibility status.
- [macOS Keychain and Windows Credential Manager](keychain.md): operating system credential-store handles.
- [1Password](onepassword.md): optional `op://` reference-backed handles.

## Security Details

- [Secret detection](detection.md): local credential-pattern scanning and tokenization.
- [Security policy](../SECURITY.md): private vulnerability reporting.
- [Third-party notices](ui/THIRD_PARTY_NOTICES.md): bundled code, artwork, and licenses.

The native app and local console expose the same local store and CLI behavior. Documentation should describe supported behavior rather than a specific UI layout unless the distinction matters.
