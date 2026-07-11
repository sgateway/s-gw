# s-gw Integrations

s-gw is intended to run locally. Coding tools should launch the local stdio MCP server instead of calling a remote service that would need to trust or store credentials.

s-gw's preferred desktop backend is the local OS credential store: macOS Keychain on macOS and Windows Credential Manager on Windows preview builds. Add handles with `s-gw secret add-keychain`; reusable approval reads the credential only inside approved local execution. See [keychain.md](keychain.md).

s-gw can also use 1Password as an optional source/backend for handles. Store an encrypted `op://...` reference with `s-gw secret add-1password`; reusable approval reads the local `op` CLI once, then uses s-gw's encrypted keystore copy until the approval expires or is revoked. See [onepassword.md](onepassword.md).

For installation, supported operating systems, and packaging channels, see [deployment.md](deployment.md).

For the broader agent profile matrix, including OpenClaw, ZeptoClaw, Hermes, Windsurf, Gemini CLI, GitHub Copilot CLI, OpenHands, Antigravity, OpenCode, and OmniGent, see [agents.md](agents.md). You can also run `s-gw agent list` and `s-gw agent mcp-snippet <agent>` when the profile has a normal MCP surface.

Install and initialize s-gw:

```bash
npm install -g @s-gw/s-gw
s-gw setup
```

Contributors working from source can use `npm ci`, `npm run build`, and `npm link` from a repository checkout.

If you skipped `s-gw setup`, store a local unlock passphrase in the OS credential store before starting the MCP server:

```bash
read -rsp "s-gw passphrase: " SGW_UNLOCK
printf '%s' "$SGW_UNLOCK" | s-gw unlock keychain set --value-stdin
unset SGW_UNLOCK
s-gw unlock status
```

For automation, `SGW_MASTER_PASSPHRASE` still works as a fallback. Keep real passphrases in a local user environment or OS credential store, not in project-scoped MCP files. On macOS, the normal path uses the bundled native helper at `dist/native/s-gw-keychain-helper`; on Windows preview builds it uses `dist\windows\s-gw-credential.ps1`. Both helpers receive new passphrases on stdin.

## Guarded Launch

MCP registration gives the agent SGW tools, but it does not intercept every prompt, file read, or environment variable by itself. For CLI agents, start with guard mode when you need launch-environment interception:

```bash
s-gw run codex --dry-run -- -v
s-gw run codex -- --ask-for-approval never
s-gw guard run claude-code -- --help
```

A real guarded run stores detected environment credentials locally, replaces the child process value with a `<<SGW_SECRET:...>>` handle, and sets guard instructions for the launched process. Use `--command CMD` for agents without a default launcher.

## Codex

Install as a local plugin by pointing Codex at a marketplace that includes this plugin, or add the MCP server directly while developing:

```bash
codex mcp add s-gw -- node /path/to/s-gw/dist/mcp-server.js
```

Equivalent `~/.codex/config.toml` snippet:

```toml
[mcp_servers.s-gw]
command = "node"
args = ["/path/to/s-gw/dist/mcp-server.js"]
env = { SGW_HOME = "~/.s-gw" }
startup_timeout_sec = 10
tool_timeout_sec = 60
default_tools_approval_mode = "prompt"
```

## Claude Code

```bash
claude mcp add --transport stdio --scope user s-gw -- node /path/to/s-gw/dist/mcp-server.js
```

Project-scoped `.mcp.json`:

```json
{
  "mcpServers": {
    "s-gw": {
      "command": "node",
      "args": ["/path/to/s-gw/dist/mcp-server.js"],
      "env": {
        "SGW_HOME": "~/.s-gw"
      }
    }
  }
}
```

## Cursor

Add to `~/.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "s-gw": {
      "command": "node",
      "args": ["/path/to/s-gw/dist/mcp-server.js"],
      "env": {
        "SGW_HOME": "~/.s-gw"
      }
    }
  }
}
```

## OpenCode

`s-gw setup` safely merges this entry into `$OPENCODE_CONFIG_DIR` when set, otherwise the global `~/.config/opencode/opencode.jsonc` or `.json` file, and installs the packaged skill. Use this snippet only for project-specific configuration:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "s-gw": {
      "type": "local",
      "command": ["node", "/path/to/s-gw/dist/mcp-server.js"],
      "enabled": true,
      "environment": {
        "SGW_HOME": "~/.s-gw"
      }
    }
  }
}
```

## VS Code / GitHub Copilot Agent Mode

`s-gw setup` safely manages the default VS Code user profile and installs a personal skill. Named, portable, Insiders, and custom user-data profiles remain explicit. For a project-scoped server, add `.vscode/mcp.json`:

```json
{
  "servers": {
    "s-gw": {
      "type": "stdio",
      "command": "node",
      "args": ["/path/to/s-gw/dist/mcp-server.js"],
      "env": {
        "SGW_HOME": "~/.s-gw"
      }
    }
  }
}
```

## Local Approval Flow

MCP clients should not receive reusable secret authority. The agent calls `sgw_request_execution` to create a pending manifest; nothing runs yet. You review and approve it locally (native app, menu bar, console, or CLI):

```bash
s-gw requests
s-gw approve <request-id>
```

Only after approval may the agent call `sgw_execute_request`. The executor injects the secret inside the local child process, sanitizes the output, records an audit event, and returns a tokenized result — the agent never receives the raw value:

```json
{
  "exitCode": 0,
  "stdout": "<<SGW_SECRET:s-gw:api-token:x-AaH8zvtj96>>\n",
  "proof": "s-gw-proof:req_...",
  "sanitized": true
}
```

For SSH, use `sgw_request_ssh_session` rather than asking the agent to run raw `ssh`. s-gw opens the approved connection through its own persistent ControlMaster socket, then runs later commands over that socket with `BatchMode=yes` while the approval grant is still valid. The matching CLI flow is:

```bash
s-gw secret allow-command "$HANDLE" --command s-gw:ssh-session
s-gw ssh request "$HANDLE" --target ubuntu@example.com --arg hostname
s-gw approve <request-id> --mode timed-session --duration 8h
s-gw ssh run --request-id <request-id>
```

To watch the generic credential loop run against a disposable store before wiring up an agent, see "See the Trust Loop End to End" in the [README](../README.md).

## Unlock Commands

```bash
s-gw unlock status
read -rsp "s-gw passphrase: " SGW_UNLOCK
printf '%s' "$SGW_UNLOCK" | s-gw unlock keychain set --value-stdin
unset SGW_UNLOCK
s-gw unlock keychain delete
```

The MCP server never exposes the unlock passphrase as a tool result. It only uses the local unlock material to decrypt a handle during an approved local execution.

## Command Grants

s-gw treats command grants as exact strings after normalization:

```bash
printf '%s' "$TOKEN" | s-gw secret add --name prod-token --type api-token --value-stdin --inject-env TOKEN --allow-command "$(command -v node)"
```

If a handle is enrolled with `/opt/homebrew/bin/node`, an agent request for plain `node` is denied. If a handle is enrolled with plain `node`, an agent request for `/opt/homebrew/bin/node` is denied. Prefer absolute command paths for production policies.
