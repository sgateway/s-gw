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

Use `sgw_request_ssh_session` for a bounded remote command or `sgw_request_ssh_transfer` for an upload. Approved files are hashed and copied into protected storage before connecting. A named pipe is approved by path and destination; its bytes are produced during execution. There is no added upload size limit. Credential paths and explicit read denies cannot be uploaded. These sandbox operations use individual connections with revocation monitoring. Ordinary SSH keeps its existing session behavior.

## Explicit policy controls

- `--allow-host HOST` adds an agent network destination. `--strict-egress` removes the default agent provider allowlist, so needed login/model hosts must be explicitly allowed.
- `--allow-write PATH` adds a writable path. `--deny-read PATH` restricts a path or supported glob.
- Saved agent login files remain readable by default. `--deny-agent-auth` blocks known login files and disables Keychain access.
- macOS `--allow-agent-keychain` allows read access to only the encrypted login Keychain database for agents that use native authentication. That database contains more than agent credentials. Keychain services still authorize item access, writes and sibling databases remain blocked, and explicit read denies win.

The mode cannot protect credentials already embedded in prompts or returned by unrelated tools. Agent login is a separate credential boundary. A service or database needs an owned protocol executor before sandboxed agents can use its credential; HTTPS covers HTTP APIs, and SSH covers approved commands/uploads. There is no arbitrary database driver in this release.

## Validation

`npm run test:anthropic-e2e` installs a fresh packed package into a disposable home and exercises ordinary MCP compatibility, confinement, approval, HTTPS authentication, SSH authentication, output sanitization, and cleanup. `--real-agent codex` uses a native Codex session. Synthetic credentials and test homes are isolated from the live store.
