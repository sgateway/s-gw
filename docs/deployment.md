# s-gw Deployment

s-gw is deployed on the same machine that runs the coding agent. Do not deploy it as a remote MCP server that receives credential material.

## Deployment Model

The supported local model is:

1. Install the local `s-gw` CLI and `s-gw-mcp` stdio server.
2. Store the local ledger unlock passphrase in the user's OS credential store.
3. Initialize the local encrypted ledger under `SGW_HOME`.
4. Enroll secrets from the local terminal, not from chat.
5. Configure each coding tool to launch the local stdio MCP server.
6. Launch CLI agents through guard mode when environment credential interception is needed.
7. Approve secret-backed actions locally with the native macOS app or `s-gw approve <request-id>`.

Raw credentials stay in the local encrypted ledger and are decrypted only inside an approved local execution path.

## Distribution Options

### npm Registry

The public npm package is the recommended installation path for individual users. It installs the `s-gw`, `sgw`, `s-gw-mcp`, and `secret-gateway-mcp` commands. Releases are built on macOS arm64 so Apple Silicon users also receive the native app, menu helper, Keychain helper, and matching Rust core. Linux and Windows use the TypeScript execution path when the package has no matching native core. Intel Macs must build the native Keychain and desktop surfaces from source; packaged arm64-only helpers are rejected before launch.

```bash
npm install -g @s-gw/s-gw
s-gw setup
```

For Apple Silicon Mac users, this is the complete first run. `s-gw setup` generates a strong local unlock secret, stores it in macOS Keychain, initializes the encrypted ledger, installs `s-gw.app` in `/Applications` (or `~/Applications` when required), installs and starts the console LaunchAgent, installs and starts the menu-bar helper, and opens the native macOS app. The browser console remains installed as a fallback local UI.

### Local Tarball Or Source

To build and install a tarball from a source checkout:

```bash
npm run package:local
npm install -g ./s-gw-s-gw-VERSION.tgz
s-gw setup
```

The scoped npm name produces a local pack filename such as `s-gw-s-gw-0.1.0.tgz`. Release tooling renames installer payloads to the shorter `s-gw-VERSION.tgz` form.

For source-based installs:

```bash
git clone <repo-url> s-gw
cd s-gw
npm install
npm run build
npm link
```

### Signed macOS Installer

Before publishing a macOS download, package a signed and notarized installer that includes:

- Node runtime or a bundled standalone executable;
- `s-gw` CLI;
- `s-gw-mcp` stdio server;
- native macOS Keychain helper;
- native macOS management app;
- a launcher or profile script that puts `s-gw` on PATH;
- optional managed defaults for `SGW_HOME` and policy templates.

This is the preferred enterprise deployment shape for MDM/Jamf/Kandji-style rollout. The installer should not pre-seed user passphrases or raw secrets.

### Homebrew

Homebrew is a good developer-friendly channel after the native helper is code signed. It is less controlled than an enterprise `.pkg`, but easy for individual developers:

```bash
brew install s-gw
```

### Not Recommended: Remote MCP Hosting

Do not host s-gw as a shared remote MCP service for user credentials. Remote services may provide documentation, policy templates, inventory, or aggregate reporting, but secret storage and redemption should remain local.

## First-Run Setup

### Recommended: One Command

```bash
s-gw setup
```

Useful variants:

```bash
s-gw setup --no-open-app
s-gw setup --passphrase-stdin
s-gw setup --no-menubar
```

`--no-open-console` is still accepted for compatibility with early builds.

After setup:

```bash
s-gw status
s-gw start
s-gw stop
s-gw guard status
```

### Manual Setup

Set the local unlock passphrase:

```bash
read -rsp "s-gw passphrase: " SGW_UNLOCK
printf '%s' "$SGW_UNLOCK" | s-gw unlock keychain set --value-stdin
unset SGW_UNLOCK
s-gw unlock status
```

Initialize local storage:

```bash
s-gw init
```

Enroll a secret with an exact command grant:

```bash
printf '%s' "$MY_API_TOKEN" | s-gw secret add \
  --name demo-token \
  --type api-token \
  --value-stdin \
  --inject-env API_TOKEN \
  --allow-command "$(command -v node)"
```

Configure the coding tool using [integrations.md](integrations.md).

Launch supported CLI agents through guard mode:

```bash
s-gw run codex --dry-run -- -v
s-gw run codex -- --ask-for-approval never
s-gw guard run claude-code -- --help
```

Guard mode tokenizes credential-looking environment values before the agent starts. It does not yet claim OS-wide prompt, file, shell, or terminal interception; those should be added through explicit agent config installers and command wrappers with backups and dry-run previews.

Launch the native macOS management app:

```bash
s-gw app open
```

The app shows daemon health, Keychain status, credential handles, pending approvals, configured agents, and audit events. It uses the installed local CLI and store; raw secret values are only provided to local approved execution paths.

Choose the approval mode in the app's Settings panel, or configure it from the CLI:

```bash
s-gw approval set --mode per-transaction
s-gw approval set --mode timed-session --duration 15m
s-gw approval set --mode login-session
```

`per-transaction` asks for every request. `timed-session` and `login-session` reuse approval only for the same handle and local action fingerprint, so approving one command does not authorize unrelated commands or credentials.

For managed installs, use approval policy rules for per-agent and per-credential defaults that should survive restarts:

```bash
s-gw approval policy add \
  --name "Cursor may use dev GitHub token" \
  --decision allow \
  --handle "$HANDLE" \
  --agent Cursor \
  --command "$(command -v git)" \
  --inject-env GITHUB_TOKEN

s-gw approval policy add \
  --name "Critical secrets ask first" \
  --decision ask \
  --min-severity critical \
  --priority 10
```

Policy rules can match credential handles, types, providers, minimum severity, agent names, action kinds, commands, injected environment names, working directories, SSH targets, and SSH ports. `allow` skips the approval popup for matching requests, `ask` keeps the normal approval/grant flow, and `deny` blocks matching requests before local execution.

Launch the fallback browser console when needed:

```bash
s-gw console
```

The console binds to `127.0.0.1`, serves the UI from the installed package, and injects a per-session token into the page. That token is required for local API writes such as approving or denying requests, so another browser origin cannot silently drive the credential API with a plain form post.

For a background setup, install the per-user console LaunchAgent instead:

```bash
s-gw service install --start
s-gw service status
```

This starts `s-gw console --host 127.0.0.1 --port 8718 --no-open` at login and writes logs under `~/.s-gw/logs`.

Launch the native menu-bar helper:

```bash
s-gw menubar open
```

Use the menu-bar count to choose what appears next to the icon:

```bash
s-gw menubar open --count pending
s-gw menubar open --count credentials
s-gw menubar open --count none
```

Install it as a login item:

```bash
s-gw menubar install --start --count pending
s-gw menubar status
```

The standalone helper is the only menu-bar owner. It is a small `LSUIElement` app bundled at `dist/s-gw Menu Bar.app`, remains available when the main app is closed, opens the native app by default, and keeps the web console as a fallback action.

### Windows Preview Client

The package also stages a Windows client and tray helper:

```powershell
npm run build:windows-client
s-gw app open
s-gw helper open
```

On Windows, `s-gw app open` launches `dist\windows\s-gw-client.ps1`. It starts the local console on `127.0.0.1` if needed, then opens the UI in Edge or Chrome app mode. `s-gw helper open` launches `dist\windows\s-gw-helper.ps1`, a lightweight tray helper that shows pending approvals, opens the approval queue, and can approve or deny the oldest pending request through the local CLI.

The Windows Credential Manager helper is staged at `dist\windows\s-gw-credential.ps1`. It uses the Windows credential APIs and receives new values on stdin, so unlock passphrases and secret values are not passed as process arguments. Signed `.exe` wrappers, login-start registration, and MSIX/installer packaging are still separate hardening work.

### Local Installer Artifacts

Build both platform downloads from the current source and package version:

```bash
npm run build:installers
```

The command rebuilds the native clients and console, then writes these files under `dist/installers`:

- `s-gw-VERSION-macos.dmg`, containing the local npm package and a double-clickable setup command;
- `s-gw-VERSION-windows.zip`, containing the local npm package plus PowerShell and CMD setup launchers;
- `s-gw-VERSION.tgz`, used by both installers and the in-app updater;
- `0-s-gw-legacy-VERSION.tgz`, a release-only unscoped bridge for the original `0.1.0` updater;
- `SHA256SUMS.txt` and per-artifact `.sha256` files.

The release build validates the scoped tarball, legacy bridge, and both generated checksum formats before upload. The bridge contains the same versioned code under the old unscoped package identity and is never published to npm. Checksum assets are uploaded first, followed by the bridge as the first `.tgz`, so the original `0.1.0` updater can upgrade in place without the scoped binary collision. That recovery release must be published as a normal, non-prerelease GitHub release because `0.1.0` reads the `/releases/latest` endpoint. Current updaters select the exact `s-gw-VERSION.tgz` asset instead. The installer scripts require Node.js 20 or newer, install the bundled package globally, and run `s-gw setup`. They do not contain credentials or pre-seeded unlock material. The macOS DMG is not ready for public distribution until Developer ID signing and notarization are added. The Windows ZIP remains a preview until it is validated on Windows and replaced or supplemented by a signed installer format.

## Data Locations

Default local ledger:

```text
~/.s-gw/store.json
```

Append-only local recovery checkpoints:

```text
~/.s-gw-recovery/control-plane/<ledger-namespace>/
```

The recovery checkpoints contain credential records, approval settings, grants, and policy rules. They omit request history, audit history, and cached values, which keeps them small and prevents high-volume request traffic from rotating away the last usable control-plane state. s-gw writes each `checkpoint-*` file create-only and read-only; it never rewrites or automatically prunes this control-plane history. `head.json` is a mutable O(1) index for the newest checkpoint, while the checkpoint files remain the recovery history. Each primary ledger gets a separate namespace even when several ledgers share `SGW_RECOVERY_HOME`; the control manifest pins that namespace as well as its vault and checkpoint.

Ordinary rolling backups remain under `~/.s-gw/backups/`, are deliberately separate from this history, and are created at most once per five minutes for request-only traffic. A credential or policy change forces a rolling backup immediately. Reusable, already-authorized environment commands (`aws run`, `run env-command`, and MCP `sgw_run_execution`) do not append a request/audit record or rewrite the ledger per invocation. They revalidate inside an authorization fence immediately before spawn. SSH stays on the durable request path so a remote session cannot hold the ledger lock. A first 1Password cache fill under a matching reusable grant or allow policy is the bounded exception; it is authority-bound and later matching runs do not rewrite the ledger. Repeated unapproved calls coalesce to one pending request.

Before a control-plane mutation replaces `store.json`, s-gw confirms that the preceding state and the candidate new state are sealed in the recovery home. If it cannot write the candidate recovery copy, the primary ledger is left unchanged. Every committed control-plane change updates an integrity manifest through a pending transaction record. The manifest includes hashes of the configured recovery-home identity and ledger namespace, so changing `SGW_RECOVERY_HOME` fails closed unless the new location already contains the exact anchored checkpoint for this ledger. If the primary ledger and manifest are jointly replaced from another ledger, s-gw recognizes the foreign namespace and restores this ledger's newest fingerprint-validated external checkpoint. If a manifest-pinned checkpoint disappears from this ledger's namespace, s-gw fails closed rather than rolling back credentials or policies to an older checkpoint. If recovery evidence exists but no valid copy remains, s-gw fails closed instead of initializing an empty ledger.

`~/.s-gw-recovery` protects against application faults and accidental local loss; it is not true immutable storage because the same macOS/Linux user can still remove, chmod, or replace it. Set `SGW_RECOVERY_HOME` to a separate protected location and replicate each ledger namespace to a separately controlled versioned/WORM backup target when credentials and policies require retention guarantees. Do not place the recovery home inside `SGW_HOME`; s-gw rejects overlapping paths. Keychain and 1Password records restore their handles and policies, but their backing provider values and the keychain-held unlock material still need provider-native recovery if they are deleted.

Default Keychain item:

```text
service: com.s-gw.sgw.master-passphrase
account: <local username>
```

Environment overrides:

```bash
export SGW_HOME="$HOME/.s-gw"
export SGW_RECOVERY_HOME="$HOME/.s-gw-recovery"
export SGW_KEYCHAIN_SERVICE="com.s-gw.sgw.master-passphrase"
export SGW_KEYCHAIN_ACCOUNT="$USER"
```

`SGW_MASTER_PASSPHRASE` remains available for automation and tests, but should not be used in repo-scoped MCP config.

### macOS Keychain backend

For individual macOS users, prefer Keychain-backed handles. The local ledger stores only encrypted handle metadata and a Keychain pointer; the credential value is stored in the user's login Keychain:

```bash
printf '%s' "$GITHUB_TOKEN" | s-gw secret add-keychain \
  --name github-prod \
  --type api-token \
  --value-stdin \
  --inject-env GITHUB_TOKEN \
  --allow-command "$(command -v gh)"
```

Use `SGW_SECRET_KEYCHAIN_SERVICE` or `--service` to isolate test, work, or user credential namespaces.

### 1Password backend

If credentials already live in 1Password, s-gw can use `op://...` references as an optional backend or migration source. Matching reusable grants and allow policies read 1Password once, then keep an encrypted local cache until that authority expires, is revoked, or changes:

```bash
s-gw secret add-1password \
  --name github-prod \
  --type api-token \
  --ref 'op://Example/GitHub/credential' \
  --inject-env GITHUB_TOKEN \
  --allow-command "$(command -v gh)" \
  --verify
```

For interactive desktop users, the first approved reusable use may still require the normal 1Password app/CLI unlock. Later matching uses stay in s-gw until the authority ends or changes. For team automation, set `OP_SERVICE_ACCOUNT_TOKEN` in the environment used by the local s-gw service.

## Operational Recovery

If the machine sleeps or a command is killed mid-run, the in-flight request can be left in an `executing` state. s-gw reaps these automatically a few minutes after the runner goes silent, so the store self-heals without intervention. An operator who wants to clear them immediately can:

```bash
s-gw requests                       # inspect request states
s-gw requests --recover             # fail every stranded execution now
s-gw requests --recover REQUEST_ID  # fail one specific stranded execution
```

The native app and browser console expose the same action on a stuck request. Recovery only moves a stranded execution to `failed`; it never reveals a secret or re-runs the command. Retrying means creating a fresh request that goes through approval again.

## OS Support

| OS | Current status | Unlock provider | Notes |
| --- | --- | --- | --- |
| macOS arm64 | Primary development platform | Native Swift helper using Security.framework | Native app, menu helper, and Keychain path are covered by local tests. |
| macOS Intel | Build-from-source candidate | Native Swift helper using Security.framework | Expected to work when built on Intel macOS with Node >= 20 and Swift toolchain, but not yet QA-tested here. |
| Linux | Experimental CLI | `SGW_MASTER_PASSPHRASE` fallback | Needs a Secret Service/libsecret helper before desktop support. |
| Windows | Preview client/helper | Windows Credential Manager helper | PowerShell client opens the local console in browser app mode; tray helper supports queue/status actions. Needs Windows QA, signing, and installer work before production support. |

The current preview is developed primarily on macOS with the native Keychain helper. Windows has a packaged preview path through Credential Manager, but the client and helper still require broader QA, signing, and installer hardening.

## Coding Tool Support

| Tool | Current status | Integration path | Config doc |
| --- | --- | --- | --- |
| Codex CLI / IDE extension | Supported | Local plugin manifest or stdio MCP config | `~/.codex/config.toml` or plugin `.mcp.json` |
| Claude Code | Supported | Local stdio MCP server | `claude mcp add --transport stdio ...` or `.mcp.json` |
| Cursor | Supported | Local MCP server config | `~/.cursor/mcp.json` |
| OpenClaw | Profiled | Local MCP server config | `~/.openclaw/openclaw.json` |
| ZeptoClaw | Profiled | Manual local MCP registration | `~/.zeptoclaw/config.json` or `.mcp.json` |
| Hermes Agent | Profiled | Local MCP server config | `~/.hermes/config.yaml` |
| Windsurf | Profiled | Existing local MCP config only | `~/.codeium/windsurf/mcp_config.json` or `mcp.json` |
| Gemini CLI | Supported | Local MCP server config | `~/.gemini/settings.json` |
| GitHub Copilot CLI | Supported | Local MCP server config | `~/.copilot/mcp-config.json`, `.github/mcp.json`, or `.mcp.json` |
| OpenHands | Profiled | Local MCP server config plus optional hooks | `~/.openhands/mcp.json`, `~/.openhands/hooks.json` |
| Antigravity | Profiled | Local MCP server config plus global hooks | `~/.gemini/config/mcp_config.json`, `./.agents/mcp_config.json`, `~/.gemini/config/hooks.json` |
| OpenCode | Supported | Managed user/config-directory JSONC MCP entry and user skill; plugin hook surface profiled | `~/.config/opencode/opencode.json`, `.jsonc` variant, or `$OPENCODE_CONFIG_DIR` |
| OmniGent | Planned/profiled | Custom policy bridge, not normal MCP | `$OMNIGENT_CONFIG_HOME/config.yaml` or `~/.omnigent/config.yaml` |
| VS Code + GitHub Copilot Agent Mode | Supported | Managed default user-profile stdio MCP server and personal skill | Default profile `mcp.json`; `.vscode/mcp.json` for explicit project scope |
| Zed, JetBrains, other MCP clients | Not yet profiled | Likely possible through stdio MCP | Add after hands-on testing and docs. |

Supported means s-gw has a documented standard MCP stdio path. Profiled means `s-gw agent list` and, when applicable, `s-gw agent mcp-snippet <agent>` know the likely local surfaces, but a hands-on client smoke test is still required before claiming full compatibility. Planned/profiled entries describe known integration shapes without emitting a normal MCP snippet. Automated end-to-end coverage uses the official MCP SDK client rather than every individual IDE UI.

## Upgrade

The CLI and local console cache successful responses from the public `sgateway/s-gw` GitHub Releases feed for six hours. Drafts are ignored; preview releases are included while s-gw is in preview. If GitHub's unauthenticated Releases API is rate-limited, clients fall back to the repository's public Atom release feed; the macOS app then checks the deterministic package and checksum URLs before offering an upgrade. The CLI prints a notice in interactive terminals and supports `s-gw update check`, the local console shows an update banner, and the Windows tray helper shows a notification plus a release link. The login-started macOS menu helper checks immediately and every 15 minutes, while the main app performs one startup check and supports manual checks. Both skip the network until six hours after the last successful response. A failed request does not advance that timestamp, so the helper retries on its next poll. The helper sends one macOS notification per available version and opens the matching release when clicked; the main app retains its in-app banner when notification permission is unavailable.

The release workflow runs the full verification suite, then builds and uploads the scoped package, legacy bridge, platform installers, `SHA256SUMS.txt`, and per-file `.sha256` assets. It refuses to upload an update package whose identity or checksum cannot be verified. The macOS app accepts either checksum format, installs through the same package migration path as the CLI, waits for the old app process to exit, refreshes the copy in Applications and the service/menu helper, and reopens s-gw with bounded retries. Relaunch output is retained in `~/.s-gw/logs/update-relaunch.log`. The original `0.1.0` app can take the legacy bridge on its next update check; once that fixed app is installed, later releases migrate it to the scoped package automatically. Other clients open the release page for the platform installer. Update checks fail quietly when GitHub is unavailable and never block local credential operations.

Review the update plan, then install it:

```bash
s-gw update plan
s-gw update install --dry-run
s-gw update install
s-gw setup
```

Use `--package PATH_OR_SPEC` with `plan` or `install` for a verified local tarball or a specific npm version. The installer checks the target package metadata before changing anything. If the legacy unscoped `s-gw` package is installed, it creates and verifies a temporary local rollback tarball, stops the running surfaces, removes only that legacy package, and then installs `@s-gw/s-gw`. A failed migration restores and verifies that rollback before restarting previously running surfaces. If automatic rollback fails, the error retains commands pointing to the saved local tarball; it never suggests the unpublished `s-gw@0.1.0` registry package. If the existing data directory disappears, services stay stopped and setup is withheld until the user restores the backup.

If the original `0.1.0` app cannot reach a release containing the legacy bridge, bootstrap that one upgrade with the current scoped CLI without installing it over the old command first:

```bash
npx --yes --package @s-gw/s-gw@latest s-gw update plan
npx --yes --package @s-gw/s-gw@latest s-gw update install
s-gw setup
```

The update path never removes `~/.s-gw`, the encrypted ledger, or the operating-system credential-store item. `s-gw setup` refreshes service and agent configuration after the package location changes.

For an offline upgrade, verify the downloaded `s-gw-VERSION.tgz` with either checksum asset from the matching GitHub release, then pass its path with `--package`.

## Uninstall

Remove the tool:

```bash
s-gw menubar uninstall
s-gw service uninstall
npm uninstall -g @s-gw/s-gw
```

Remove local unlock material:

```bash
s-gw unlock keychain delete
```

Remove local ledger if desired:

```bash
rm -rf ~/.s-gw
```

Also remove the MCP server entry from each configured coding tool.

## Packaging Checklist

Before publishing a build:

```bash
npm run verify
npm run validate:npm-package
npm pack
```

For macOS production packages, also verify:

- native helper exists at `dist/native/darwin-arm64/s-gw-keychain-helper`;
- metadata-only Keychain inspector exists at `dist/native/darwin-arm64/s-gw-keychain-inspector`;
- Rust core exists at `dist/native/darwin-arm64/s-gw-core`;
- all five native executables report `arm64` through `lipo -verify_arch`;
- native macOS app exists at `dist/s-gw.app`;
- `s-gw unlock status` reports `provider: "native-helper"`;
- real Keychain + MCP e2e passes with no `SGW_MASTER_PASSPHRASE`;
- `s-gw app open` launches the native app and shows the Overview window;
- `s-gw console --no-open` serves the local UI and the console HTTP e2e test passes;
- `s-gw doctor` finds the installed CLI, MCP server, native Keychain helper, and menu-bar app bundle;
- `s-gw service install --start` loads the console LaunchAgent;
- `s-gw menubar open` launches the menu-bar helper and sees pending requests;
- package or installer is signed and notarized;
- install/uninstall leaves no raw secrets in logs or shell history.

For Windows preview packages, also verify:

- Windows scripts exist under `dist/windows`;
- `s-gw unlock keychain set --value-stdin` stores unlock material through Credential Manager;
- `s-gw app open` starts the local console and opens the client shell;
- `s-gw helper open` creates a tray icon and sees pending requests;
- helper approve/deny actions use the CLI and do not require the console API token;
- installer/startup registration does not log raw secrets or command stdin.

## What The Package Contains

The public npm package contains:

- `s-gw` CLI and `s-gw-mcp` stdio MCP server;
- compiled TypeScript under `dist`;
- compiled Rust execution core at `dist/native/darwin-arm64/s-gw-core`;
- native macOS Keychain helper at `dist/native/darwin-arm64/s-gw-keychain-helper`;
- metadata-only macOS Keychain inspector at `dist/native/darwin-arm64/s-gw-keychain-inspector`;
- native macOS management app at `dist/s-gw.app`;
- native macOS menu-bar helper app at `dist/s-gw Menu Bar.app`;
- local console HTML/CSS/JS assets under `docs/ui`;
- integration docs and agent profile docs;

Native executable paths are scoped by platform and architecture. A source build writes its runner and helper under `dist/native/<platform>-<architecture>/`; automatic execution ignores binaries for other targets and uses the TypeScript path when no matching core exists. The package intentionally does not contain native application source files, source maps, credentials, user policy files, npm build caches, SwiftPM `.build` caches, or any pre-seeded Keychain material.

## Reference Docs

- OpenAI Docs MCP quickstart covers Codex, VS Code, Cursor, and Claude Code MCP setup patterns: https://developers.openai.com/learn/docs-mcp
- Claude Code MCP docs cover stdio servers, scopes, and `.mcp.json`: https://code.claude.com/docs/en/mcp
- VS Code MCP configuration reference covers `.vscode/mcp.json`, stdio fields, and Agent Mode commands: https://code.visualstudio.com/docs/agents/reference/mcp-configuration
- OpenCode MCP docs cover local MCP server configuration: https://thdxr.dev.opencode.ai/docs/mcp-servers/
- DefenseClaw connector docs are one source for agent hook, plugin, and policy surfaces: https://github.com/cisco-ai-defense/defenseclaw/tree/main/docs-site/content/docs/connectors
