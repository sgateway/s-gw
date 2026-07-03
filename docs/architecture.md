# Architecture

s-gw is a local credential broker. Its storage, approval, execution, and user interfaces run on the same machine as the coding agent.

```mermaid
flowchart LR
    Agent["Coding agent or MCP client"] --> MCP["s-gw MCP server"]
    CLI["s-gw CLI"] --> Store["Encrypted ledger"]
    MCP --> Store
    Store --> Review["Native app / menu helper / local console"]
    Review --> Store
    Store --> Runner["Constrained local runner"]
    Keychain[("Keychain / Credential Manager") ] --> Runner
    OnePassword[("Optional 1Password source") ] --> Runner
    Runner --> Sanitizer["Output sanitizer"]
    Sanitizer --> MCP
```

## Components

### CLI And MCP Server

The TypeScript CLI owns setup, handle enrollment, request creation, approval, execution, diagnostics, and integration output. The stdio MCP server exposes the narrower agent-facing surface: scan data, list or describe non-secret handles, create requests, and execute requests that have already been approved.

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

The runner validates the request and handle policy again immediately before execution. It resolves the credential, injects it into the child environment or owned SSH path, captures output, sanitizes known credential values, records the result, and returns the sanitized response.

### User Interfaces

The React console is served on loopback and requires a per-session token for state-changing requests. The native macOS app and menu helper use the installed CLI and local store. The Windows preview client hosts the loopback console in a browser app window and provides a tray helper for queue actions.

## Process Boundaries

- MCP uses stdio and does not expose a remote credential API.
- The browser console binds to `127.0.0.1` by default.
- New secrets and unlock values are accepted over stdin, not command-line arguments.
- Secret-backed commands run as child processes of the local s-gw process under the current operating system user.
- s-gw-owned SSH sessions use private control sockets under the local s-gw home.

See the [threat model](threat-model.md) for what these boundaries do and do not protect.
