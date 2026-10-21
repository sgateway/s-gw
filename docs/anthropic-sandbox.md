# Anthropic sandbox and owned connections

Use the opt-in mode to let s-gw initiate approved credential-backed operations outside an agent's sandbox:

```sh
s-gw guard doctor --sandbox anthropic
s-gw run codex --sandbox anthropic --cwd /path/to/project -- exec "your task"
s-gw run claude-code --sandbox anthropic --cwd /path/to/project
```

The existing builtin guard is still the default. macOS and Linux use Anthropic sandbox-runtime 0.0.50. Linux needs bubblewrap, socat, ripgrep, and a writable delegated cgroup v2. The pinned runtime has no native Windows backend; the existing Windows app, CLI, SSH, and integrations remain supported.

## Credential-backed actions

The sandbox MCP connection exposes handle metadata, HTTPS requests, SSH requests, SSH uploads, and approved execution. It does not expose scanning, raw secret reads, or generic credential-bearing commands. Ordinary MCP retains its existing tools.

For HTTPS, allow the exact destination and the owned executor on an existing handle through the trusted operator CLI:

```sh
s-gw secret allow-command HANDLE --command s-gw:https-request
s-gw secret allow-destination HANDLE --destination api.example.com
```

Use `sgw_request_http` with the handle, full HTTPS URL, method, headers, optional body, and bearer, named-header, or basic authentication. s-gw displays that exact operation for local approval, opens the TLS connection to the service, attaches the credential, and returns a sanitized response. Redirects, credential echoing, response token fields, and ambiguous request headers are restricted. It does not terminate the agent's TLS connections or mint certificates.

Use `sgw_request_ssh_session` for a bounded remote command or `sgw_request_ssh_transfer` for an upload. A regular-file request records `approvalScope: content-sha256`; s-gw verifies its digest and copies the bytes into protected storage before connecting. A named-pipe request records `approvalScope: path-stream`: approval binds its path and destination, while the producer controls the bytes supplied during execution. The approval UI and audit events show this distinction. There is no added upload size limit. Credential paths and explicit read denies cannot be uploaded. These sandbox operations use individual connections with revocation monitoring. Ordinary SSH keeps its existing session behavior.

A content-bound named-pipe mode would need to consume the complete stream into protected storage before asking for approval, then retain and clean up that snapshot across approval, denial, expiry, and restart. It also needs cancellation and producer coordination so a pipe that never closes cannot hold an approval request forever. That separate mode is not offered yet; existing pipe streaming starts after approval.

For a pinned SSH destination, an operator can add a managed route with `s-gw ssh route add --name NAME --host HOST --user USER --port PORT --host-public-key 'ssh-ed25519 AAAA...'`. Agents request it by `routeId` rather than supplying a host or key. The approval screen shows the final `user@host:port` and SHA256 host-key fingerprint; changed or removed routes require a new request. CLI approvals require `--confirm-route` with that endpoint and fingerprint. Managed execution ignores user SSH configuration and uses the pinned host key. Existing target-based requests remain available and may follow the user's OpenSSH aliases, proxies, and jump hosts.

## Explicit policy controls

- `--allow-host HOST` adds an agent network destination. `--strict-egress` removes the default agent provider allowlist, so needed login/model hosts must be explicitly allowed.
- `--allow-write PATH` adds a writable path. `--deny-read PATH` restricts a path or supported glob.
- Saved agent login files remain readable by default. `--deny-agent-auth` blocks known login files. A disposable macOS Keychain test showed that flag alone still permits native item retrieval through another IPC route. `--deny-keychain` blocks both known Keychain service endpoints and denied the tested item read; `--isolated-auth` also applies that stricter IPC denial. Complete native Keychain isolation has not been established.
- macOS `--allow-agent-keychain` allows read access to only the encrypted login Keychain database for agents that use native authentication. That database contains more than agent credentials. Keychain services still authorize item access, writes and sibling databases remain blocked, and explicit read denies win.
- `--strict-broker-env` starts the trusted outside-sandbox MCP child with a validated environment allowlist. It keeps the store and recovery paths, supported backend and Keychain settings, 1Password credentials and session settings, a local user session bus, and custom CA files outside agent-writable paths. It removes Node preload/loader variables and test isolation overrides. Custom CA files and `SGW_OP_CLI` must be absolute files outside agent-writable paths. `--isolated-auth` also selects this broker setting. The default launch environment remains unchanged.
- `--isolated-auth` starts the agent with a fresh temporary home, a small environment, denied reads of the original home, strict egress, and the strict broker environment. This is an experimental probe for workflows that do not require saved agent login. The selected workspace and required runtime files remain readable; credentials stored there are still exposed. Native Codex and Claude model login is not yet brokered through this profile.
- `--strict-isolated-auth` includes `--isolated-auth` and checks the native account home independently of `HOME`. It requires an existing workspace, rejects overlap with the store, recovery vault, sandbox session root, or s-gw runtime package, and permits extra writable paths only when they already exist inside it. The s-gw runtime package and broker Node binary must be outside the writable workspace. The package must also be outside both the native and original account homes. Other runtime read allowances, including the agent command and CA files, must be outside those homes or inside the selected workspace. A development checkout or agent executable under the account home can therefore prevent strict mode from starting; stage an independent trusted s-gw installation outside those homes. The profile does not create a separate OS user or make workspace contents confidential from the agent.

The mode cannot protect credentials already embedded in prompts or returned by unrelated tools. Agent login is a separate credential boundary. A service or database needs an owned protocol executor before sandboxed agents can use its credential; HTTPS covers HTTP APIs, and SSH covers approved commands/uploads. There is no arbitrary database driver in this release.

The current launcher and broker run under the same OS user, and the agent can read its broker capability. Neither the default profile nor `--isolated-auth` establishes a kernel-verifiable agent principal. The cross-platform design and rollout gates are in [OS identity for confined agents](agent-os-identity.md).

Sandbox launch manifests and MCP configuration now live in a private per-user session root. A confined process can read its own session directory, while the sandbox denies the shared root used by other updated sessions. If a workspace or runtime allowance overlaps that root, the launcher warns that cross-session capability isolation cannot be guaranteed. This file rule does not protect against other unrestricted processes running as the same OS user.

## Validation

`npm run test:anthropic-e2e` installs a fresh packed package into a disposable home and exercises ordinary MCP compatibility, confinement, approval, HTTPS authentication, SSH authentication, output sanitization, and cleanup. `--real-agent codex` uses a native Codex session. Synthetic credentials and test homes are isolated from the live store.

For the strict lane, the Node binary running the test must also be outside the native account home. If the usual `node` lives there, run `node scripts/test-anthropic-e2e.mjs --strict-isolated-auth` with an independently installed Node binary outside that home.
