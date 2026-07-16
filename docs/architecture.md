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

Control-plane changes use a pending transaction marker and fingerprinted manifest. Before replacing the primary ledger, s-gw verifies the prior control state and seals the candidate new state in both the local home and a separate recovery home; if that seal cannot be written, the primary ledger is left unchanged. These `checkpoint-*` files are create-only, read-only, and never pruned automatically. The manifest pins the recovery-vault identity, ledger namespace, and checkpoint name, so a foreign manifest or a different `SGW_RECOVERY_HOME` cannot silently replace a newer ledger with an older vault. A new recovery location is accepted only after it contains the exact anchored checkpoint.

High-frequency environment-command execution uses a separate decision path rather than a rate threshold. `aws run`, `run env-command`, and the MCP `sgw_run_execution` tool return a short-lived in-memory permit when an allow policy or reusable grant already authorizes the normalized action. Permits are validated before materialization and again inside a launch fence immediately before the child starts, so a policy or grant change either rejects the launch or follows it. The permit path does not append a request or audit record, rewrite `store.json`, or create a rolling backup for each invocation. The first 1Password resolution for a matching grant or allow policy can write one encrypted, authority-bound cache entry; later matching runs leave the ledger untouched, and policy/grant changes remove or invalidate that cache. Repeated unapproved calls coalesce to one pending durable request. A durable request that was automatically approved by a grant or policy is rechecked at execution time; an explicit manual approval remains an explicit decision. SSH remains on the durable request path so a long-lived remote command never holds the ledger lock.

Request-only durable writes retain their normal ledger records, but rolling backups are created at most once per five minutes; every control-plane change forces a rolling backup. High-frequency clients therefore cannot rotate away credential or policy history. A mismatched, corrupt, missing, or jointly replaced primary ledger and manifest is quarantined when available and restored from the newest fingerprint-validated external checkpoint. Once a ledger has a sealed recovery anchor, a missing vault fails closed rather than being silently re-created from the primary ledger.

The recovery home is a local recovery vault, not a physical WORM guarantee: a process running as the same operating-system user can still delete, chmod, or replace it. Production deployments that need immutable retention must replicate the recovery namespace to a separately controlled, versioned/WORM destination (for example, object storage with retention lock). The recovery home may not overlap the primary ledger home. Checkpoints preserve s-gw ledger records and encrypted local values or provider references; Keychain/1Password backing values and the unlock key still require their provider-native recovery plan.

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

The runner is proprietary and maintained in the private `barryqy/s-gw-rust-core` repository. This public repository contains the protocol integration and TypeScript compatibility path, but not the Rust source. Maintainer builds locate a sibling checkout or use `SGW_RUST_CORE_DIR`; release automation requires the private checkout and packages only the compiled runner.

Owned SSH sessions use the TypeScript execution path. Native runners live under `dist/native/<platform>-<architecture>/`, and automatic mode only selects the current target. The public npm package includes the macOS arm64 runner; Linux, Windows, and other architectures use the TypeScript compatibility path when their target directory is absent. Native Windows maintainer builds produce `dist/native/win32-x64/s-gw-core.exe`. `SGW_EXECUTION_ENGINE=rust` requires a compatible compiled runner, while `SGW_EXECUTION_ENGINE=typescript` selects the compatibility path explicitly.

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

The standalone endpoint is a mixed-source distribution: the broker, local storage, approvals, policies, agent integrations, audit history, and desktop clients are open source, while the compiled Rust execution core is proprietary. Independent local installations do not require a control plane.

Team deployments can add a control plane for endpoint fleets, shared policy, delegated approvals, identity, compliance retention, and enterprise vault references. The intended boundary exchanges handle metadata, signed policy, approval state, and sanitized events. Raw credentials remain in the endpoint credential store or an enterprise vault.
