# Agent Support

s-gw maintains a small profile for each known coding agent: canonical name, aliases, configuration paths, MCP shape, skills or plugin directories, and limitations. The registry structure is informed by DefenseClaw's connector model.

This does not turn s-gw into a remote guardrail proxy. s-gw stays local and uses MCP tools plus local approval to keep raw credentials out of the agent.

## CLI

List known profiles:

```bash
s-gw agent list
```

Inspect, install, or remove local agent connections:

```bash
s-gw agent status
s-gw agent install codex --dry-run
s-gw agent install codex
s-gw agent uninstall codex --dry-run
s-gw agent uninstall codex
```

`s-gw setup` detects installed agents and connects the profiles with safe user-level config targets. Use `s-gw setup --no-agents` when setup should initialize only the gateway. npm installation never changes agent configuration.

Automatic registration currently covers Claude Code, Codex, Cursor, Gemini CLI, and GitHub Copilot CLI. It merges only the `s-gw` MCP entry, installs the packaged `s-gw` skill where the agent supports a user-level skill directory, preserves unrelated settings, and writes a `0600` backup before changing an existing file. Ownership is recorded in `~/.s-gw/agent-integrations.json`, so uninstall removes only content installed by s-gw.

Conflicting `s-gw` entries, malformed config, symlinks, and changed s-gw-owned content are refused without overwriting the file. One agent conflict does not stop setup for other detected agents. Profiled/manual agents and formats without a safe merge path, including OpenCode JSONC, remain snippet-only.

Show one profile with an MCP snippet:

```bash
s-gw agent show codex
s-gw agent show openclaw
s-gw agent show claude-code
```

Render only the snippet:

```bash
s-gw agent mcp-snippet codex
s-gw agent mcp-snippet openclaw
s-gw agent mcp-snippet cursor
```

Show the Project CodeGuard hardening path for an agent:

```bash
s-gw agent codeguard-plan codex
s-gw agent codeguard-plan claude-code
s-gw agent codeguard-plan opencode
```

For source builds or development, override the command:

```bash
s-gw agent mcp-snippet codex \
  --command node \
  --arg /path/to/s-gw/dist/mcp-server.js \
  --env SGW_HOME=~/.s-gw
```

The packaged default command is:

```bash
s-gw-mcp
```

## Guard Mode

Use guard mode when launching a CLI coding agent from the terminal:

```bash
s-gw guard status
s-gw run codex --dry-run -- -v
s-gw run codex -- --ask-for-approval never
s-gw guard run claude-code -- --help
```

Guard mode scans the launch environment, stores credential-looking values in the local encrypted ledger during a real run, and replaces the child process values with `<<SGW_SECRET:...>>` handles. It also sets `SGW_GUARD_MODE`, `SGW_GUARD_AGENT`, `SGW_GUARD_INSTRUCTIONS`, and `SGW_GUARD_TOKENIZED_ENV` for the launched process.

Use `--command CMD` for agents without a safe default CLI launcher:

```bash
s-gw guard run cursor --command cursor --dry-run
```

`--dry-run` uses preview handles and does not write to the store. A real run may use `--allow-command CMD` to attach an initial approved-execution policy to any handles created from environment variables, but production policies should remain narrow.

## Agent Profile Registry

s-gw tracks the 13 first-class agents documented by DefenseClaw as of tag `0.8.3`: OpenClaw, ZeptoClaw, Claude Code, Codex, Hermes, Cursor, Windsurf, Gemini CLI, GitHub Copilot CLI, OpenHands, Antigravity, OpenCode, and OmniGent.

Status is intentionally strict. `Supported` means s-gw has a documented stdio MCP path for the agent; it does not imply that every config format is safe to patch automatically. `Profiled/manual` means s-gw knows the likely local config surface and can render a snippet, but setup should stay manual and should not be described as fully compatible until the app has passed a hands-on smoke test with that agent. `Planned/profiled` means the connector shape is useful for roadmap and UI inventory, but s-gw should not emit a normal MCP install snippet.

| Profile | Agent | Status | MCP config surface | Notes |
| --- | --- | --- | --- | --- |
| `openclaw` | OpenClaw | Profiled/manual | `~/.openclaw/openclaw.json` | Manual write path; prefer OpenClaw config command/UI when available. |
| `zeptoclaw` | ZeptoClaw | Profiled/manual | `~/.zeptoclaw/config.json`, `./.mcp.json` | Manual write path because ZeptoClaw owns config autosave. |
| `claudecode` | Claude Code | Supported | `./.mcp.json` (project), `~/.claude.json` via `claude mcp add` | Standard stdio MCP. Use `claude mcp add` or `.mcp.json`, not `settings.json`. Alias: `claude-code`. |
| `codex` | Codex | Supported | `~/.codex/config.toml`, `./.mcp.json` | Standard stdio MCP and packaged Codex plugin. |
| `hermes` | Hermes Agent | Profiled/manual | `~/.hermes/config.yaml` | YAML snippet; no automatic patcher yet. |
| `cursor` | Cursor | Supported | `./.cursor/mcp.json`, `~/.cursor/mcp.json` | Project-local config preferred. |
| `windsurf` | Windsurf | Profiled/manual | `~/.codeium/windsurf/mcp_config.json`, `~/.codeium/windsurf/mcp.json` | Do not create guessed config paths. |
| `geminicli` | Gemini CLI | Supported | `~/.gemini/settings.json`, `./.gemini/settings.json` | Alias: `gemini`. |
| `copilot` | GitHub Copilot CLI | Supported | `~/.copilot/mcp-config.json`, `./.github/mcp.json`, `./.mcp.json` | Workspace config preferred. |
| `openhands` | OpenHands | Profiled/manual | `~/.openhands/mcp.json` | Global MCP config; optional workspace hooks only when intentionally scoped. |
| `antigravity` | Antigravity | Profiled/manual | `~/.gemini/config/mcp_config.json`, `./.agents/mcp_config.json` | MCP config is separate from global hook config. Alias: `agy`. |
| `opencode` | OpenCode | Supported | `~/.config/opencode/opencode.json`, `opencode.json`, `.jsonc` variants | Top-level `mcp` map, not `mcpServers`. |
| `omnigent` | OmniGent | Planned/profiled | `$OMNIGENT_CONFIG_HOME/config.yaml`, `~/.omnigent/config.yaml` | DefenseClaw uses a custom policy bridge, not a normal MCP server entry. |

The registry also includes this general MCP client profile:

| Profile | Agent | Status | MCP config surface |
| --- | --- | --- | --- |
| `vscode` | VS Code / GitHub Copilot Agent Mode | Supported | `./.vscode/mcp.json` |

## Project CodeGuard Layer

Project CodeGuard is useful as a companion layer, not a replacement for s-gw. CodeGuard gives agents secure coding guidance and review rules; s-gw keeps credentials local, tokenizes them into handles, and requires local authorization before secret-backed actions run.

The current CodeGuard project is under CoSAI/OASIS at `https://github.com/cosai-oasis/project-codeguard`. s-gw does not vendor CodeGuard's CC BY rule content; it points users to upstream release artifacts so rules can be installed, pinned, and audited intentionally.

Use:

```bash
s-gw agent codeguard-plan AGENT
```

Recommended current paths:

| Agent | CodeGuard route | Install surface |
| --- | --- | --- |
| Claude Code | Plugin marketplace | `/plugin install codeguard-security@project-codeguard` |
| Codex | Agent Skill | `./.agents/skills/codeguard` |
| Cursor | Rule files | `./.cursor/rules` |
| Windsurf | Rule files | `./.windsurf/rules` |
| GitHub Copilot CLI / VS Code Copilot | Repository instructions | `./.github/instructions` |
| Antigravity | Rule files | `./.agents/rules` |
| OpenCode | Agent Skill | `./.opencode/skills/codeguard` |
| OpenClaw | Agent Skill | `./.openclaw/skills/codeguard` |
| Hermes | Agent Skill | `./.hermes/skills/codeguard` |

Codex deserves extra care: CodeGuard's current package uses project-local `.agents/skills/codeguard`. Project-local `.codex/skills` was used by older packages and should be treated as stale for CodeGuard. User-level Codex skills under `~/.codex/skills` are still a separate Codex home-level surface.

## Agent Enforcement Surfaces

MCP registration and an agent's enforcement surface are separate concerns. MCP gives an agent tools; hooks, plugins, and policies determine whether a product can observe prompts, tool calls, command execution, or post-tool output. The table records those distinctions without claiming that s-gw installs every hook.

| Agent | DefenseClaw hook style | Config surface | Native ask? | s-gw implication |
| --- | --- | --- | --- | --- |
| OpenClaw, ZeptoClaw | Proxy connectors | App-owned proxy/config files | Proxy-owned | Use local MCP registration; remote proxying is outside s-gw's credential boundary. |
| Claude Code | Native hooks | `~/.claude/settings.json` | PreToolUse | Keep warning users that MCP config is `.mcp.json`/`~/.claude.json`, not `settings.json`. |
| Codex | Native hooks plus OTel/notify | `~/.codex/config.toml` | Permission flow | Current support covers local MCP registration and s-gw approval for credential-backed actions. |
| Cursor | Native hooks | `~/.cursor/hooks.json` | `beforeShellExecution`, `beforeMCPExecution` | Hook installation is not currently managed by s-gw. |
| Windsurf | Cascade hooks | `~/.codeium/windsurf/hooks.json` | No | s-gw approval remains the supported credential control path. |
| Gemini CLI | Native hooks | `~/.gemini/settings.json` | No | MCP and hooks share a file, so installer must preserve unrelated settings carefully. |
| GitHub Copilot CLI | Hook JSON | `~/.copilot/hooks/defenseclaw.json`, `./.github/hooks/defenseclaw.json` | `preToolUse` | s-gw currently documents MCP setup rather than installing hook files. |
| OpenHands | Hook JSON | `~/.openhands/hooks.json`, optional `./.openhands/hooks.json` | No | Global hook install by default; workspace install only on explicit request. |
| Antigravity | Native lifecycle hooks | `~/.gemini/config/hooks.json` | `decision=ask` on pre-action events | Write only the canonical global hook file to avoid duplicate firings. |
| OpenCode | Auto-loaded JS plugin | `~/.config/opencode/plugins/defenseclaw.js` | No | Hook installer would be a managed plugin, not a JSON hook entry. |
| OmniGent | Custom Python policy API | `$OMNIGENT_CONFIG_HOME/config.yaml`, `~/.omnigent/config.yaml` | Pre-action policy phases | Needs a real s-gw policy bridge before public compatibility claims. |

## Integration Boundary

DefenseClaw connectors often patch hooks, proxy routes, telemetry, and subprocess shims. s-gw intentionally starts narrower:

- register a local stdio MCP server;
- launch CLI agents with credential-like environment values replaced by SGW handles;
- expose tokenization and handle metadata;
- require local user approval before secret-backed execution;
- inject secrets only into local child processes;
- sanitize command output before returning it to the agent.

s-gw automatically manages only the user-level MCP and skill resources listed above. It does not install enforcement hooks, edit project configuration, or rewrite general `AGENTS.md`/`CLAUDE.md` instructions. Use `s-gw agent mcp-snippet` for manual profiles and project-scoped configuration.
