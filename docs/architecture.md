# Architecture

s-gw is a local credential broker. Its storage, approval, execution, and user interfaces run on the same machine as the coding agent.

```mermaid
flowchart LR
    Agent["Coding agent or MCP client"] --> MCP["s-gw MCP server"]
    CLI["s-gw CLI"] --> Store["Encrypted ledger"]
    MCP --> Store
    Store --> Review["Native app / menu helper / local console"]
    Review --> Store
    Store --> Broker["Approval broker"]
    Keychain[("Keychain / Credential Manager") ] --> Broker
    OnePassword[("Optional 1Password source") ] --> Broker
    Broker --> Runner["Rust execution core"]
    Runner --> Sanitizer["Bounded output sanitizer"]
    Sanitizer --> MCP
```

## Components

### CLI And MCP Server

The TypeScript CLI owns setup, handle enrollment, request creation, approval orchestration, diagnostics, and integration output. The stdio MCP server exposes the narrower agent-facing surface: scan data, list or describe non-secret handles, create requests, and execute requests that have already been approved.

### Encrypted Ledger

The ledger stores handle metadata, encrypted local values or credential-store pointers, request manifests, reusable grants, policy rules, and audit events. Its unlock material comes from the operating system credential store during normal desktop use. `SGW_MASTER_PASSPHRASE` exists for tests and controlled automation.

### Credential Backends

- **macOS Keychain:** the preferred backend on macOS.
- **Windows Credential Manager:** the preview backend on Windows.
- **Encrypted local value:** compatibility and test path.
- **1Password reference:** optional source backed by the local `op` CLI, with an encrypted local cache for a bounded reusable approval.

Backends resolve values only inside the local approved execution path. Agent-facing APIs return handles and metadata.

### Approval Surfaces

The native macOS app, standalone menu helper, local web console, and CLI read and update the same request records. A request includes the handle, action kind, command or SSH destination, environment binding, working directory, agent identity, reason, and state.

Reusable approvals are matched against their stored scope. They are not a general unlock for the credential store.

### Local Runner

The approval broker claims the request, validates the handle policy again, and resolves credential values locally. Approved environment commands are then sent to the compiled `sgw-core` runner over stdin using protocol version 1. Credential values never appear in runner arguments or its inherited environment.

The Rust runner clears the child environment, restores a small allowlist of ordinary process variables, injects only approved credential bindings, enforces the timeout, captures bounded stdout and stderr, replaces known values with handles, and returns a proof-bound result. The broker rejects malformed responses, raw credential output, or an invalid proof before updating the request record.

Owned SSH sessions use the TypeScript execution path. Native runners live under `dist/native/<platform>-<architecture>/`, and automatic mode only selects the current target. The public npm package includes the macOS arm64 runner; Linux, Windows, and other architectures use the TypeScript compatibility path when their target directory is absent. Native Windows source builds produce `dist/native/win32-x64/s-gw-core.exe`. `SGW_EXECUTION_ENGINE=rust` requires a compatible compiled runner, while `SGW_EXECUTION_ENGINE=typescript` selects the compatibility path explicitly.

### User Interfaces

The React console is served on loopback and requires a per-session token for state-changing requests. The native macOS app and menu helper use the installed CLI and local store. The Windows preview client hosts the loopback console in a browser app window and provides a tray helper for queue actions.

## Process Boundaries

- MCP uses stdio and does not expose a remote credential API.
- The browser console binds to `127.0.0.1` by default.
- New secrets and unlock values are accepted over stdin, not command-line arguments.
- Approved environment-command credentials cross from the broker to `sgw-core` over a private stdin pipe, not process arguments or inherited environment variables.
- Secret-backed commands run as child processes of the local s-gw process under the current operating system user.
- s-gw-owned SSH sessions use private control sockets under the local s-gw home.

See the [threat model](threat-model.md) for what these boundaries do and do not protect.

## Deployment Models

The open-source product is a complete standalone endpoint: Rust core, local storage, approvals, policies, agent integrations, audit history, and desktop clients. Independent local installations do not require a control plane.

Team deployments can add a control plane for endpoint fleets, shared policy, delegated approvals, identity, compliance retention, and enterprise vault references. The intended boundary exchanges handle metadata, signed policy, approval state, and sanitized events. Raw credentials remain in the endpoint credential store or an enterprise vault.
