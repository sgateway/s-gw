# Changelog

Notable changes to s-gw are documented here. The project follows [Semantic Versioning](https://semver.org/) once public releases begin.

## 0.1.14 - 2026-07-16

### Fixed

- macOS update availability now survives app restarts and is acknowledged separately from notification delivery. The menu helper owns automatic alerts, respects disabled macOS alerts, retries only on a bounded schedule, and cannot overwrite a newer dismissal or reminder request.

## 0.1.13 - 2026-07-15

### Changed

- Moved the proprietary Rust execution core to a separate private repository. The public repository now contains the broker integration and TypeScript compatibility path, while maintainer release builds package the compiled core from a private checkout.

### Fixed

- High-frequency authorized environment commands now keep their reusable decision in memory, so routine AWS, MCP, and environment-command calls do not churn the ledger or rolling backups.
- Credential, approval-policy, grant, and settings recovery checkpoints are append-only. s-gw seals a candidate checkpoint before it changes the primary ledger and fails closed if the recovery anchor is missing, malformed, or from another ledger.
- Automatically approved durable requests now revalidate the original policy or grant before execution, so disabling or revoking that authority takes effect before the command starts.
- Test runs require disposable, explicitly configured s-gw and recovery homes, preventing test processes from using a real local ledger.

## 0.1.12 - 2026-07-15

### Fixed

- An initialized credential ledger that is missing, corrupt, or replaced now recovers from a verified encrypted checkpoint instead of silently starting empty.
- Compact control-plane checkpoints are retained separately from request traffic and outside the primary s-gw home, so retry storms or whole-home deletion cannot erase every credential and policy recovery point.
- The test suite refuses to use the live s-gw home, including during module startup and child CLI runs.
- The macOS menu helper LaunchAgent now remains available after a clean singleton handoff instead of staying stopped.

## 0.1.11 - 2026-07-13

### Added

- `s-gw unlock keychain repair` verifies and repairs the master unlock item and every Keychain-backed credential without exposing their values.

### Fixed

- macOS Keychain access now validates the helper's exact trusted-application identity before reading or deleting an item, so an unknown helper fails with a repair error instead of opening a login-password dialog.
- Existing items are transactionally rebound to the persistent helper through a verified temporary Keychain backup, with automatic recovery after an interrupted repair.
- The macOS installer preserves the pre-upgrade helper before npm replaces its package path, allowing old ACLs to be migrated after an upgrade.
- Upgrades pin the preserved helper back at the npm compatibility path used by already-running MCP servers, preventing stale agent sessions from launching a newly built helper identity.

## 0.1.10 - 2026-07-13

### Fixed

- macOS setup now pins the first working Keychain helper under `~/.s-gw`, and package upgrades preserve that exact binary so credential access does not acquire a new requester identity.
- Direct credential-store enrollment and redemption also establish the persistent helper before touching Keychain, covering users who do not rerun setup.

## 0.1.9 - 2026-07-13

### Fixed

- Repeated approval is now idempotent when another app surface or policy already approved the request.
- Approval sheets now close and report the current decision instead of leaving an obsolete pending request on screen.

## 0.1.8 - 2026-07-13

### Fixed

- Successful CLI updates now restore the console, menu helper, and native app state that was running before installation instead of leaving every surface stopped.
- Update restart snapshots now require both an installed LaunchAgent plist and a loaded launchd job, avoiding false restart attempts from unrelated user environments.

## 0.1.7 - 2026-07-13

### Fixed

- Routine macOS status and menu refreshes now check Keychain item metadata without reading the stored unlock passphrase, preventing authorization prompts when no credential is being used.

## 0.1.6 - 2026-07-12

### Fixed

- The macOS menu helper now requests and reads notification authorization through actor-safe async APIs instead of crashing when UserNotifications calls a main-actor completion handler on its own queue.

## 0.1.5 - 2026-07-12

### Fixed

- The macOS app now shows its native recovery screen when the local console service is stopped instead of opening a blank white web view.
- The embedded console retries transient startup failures and uses a dark loading background while the local service becomes available.
- macOS setup tests now install into isolated temporary folders without changing the user's Applications folder or app preferences.

## 0.1.4 - 2026-07-12

### Added

- `s-gw app install` for explicitly installing or repairing the packaged native macOS app.

### Fixed

- macOS setup and app launch now install `s-gw.app` atomically in the system Applications folder, with a user Applications fallback when the system folder is not writable.
- Native upgrades wait for the previous app process to exit, refresh the installed app and services, and retry reopening instead of silently leaving s-gw closed. Relaunch failures are retained in `~/.s-gw/logs/update-relaunch.log`.
- The native app remembers the updated CLI location so Finder launches continue to work after npm changes the package path.
- Rust execution now handles an early child-process exit without leaking an unhandled stdin error.

## 0.1.3 - 2026-07-11

### Added

- Persistent update checks and notifications in the login-started macOS menu helper, including release links and durable per-version deduplication.
- Platform-and-architecture-scoped native executable paths with package validation for the Apple Silicon npm release.

### Changed

- Settings now use clear section cards and plain-language approval duration choices instead of the previous compact tab switcher and raw millisecond field.
- The public npm package includes the Apple Silicon native app, menu helper, Keychain helper, and Rust execution core; other targets use the TypeScript execution path when no matching core is present.

### Fixed

- Light mode now applies consistently to activity tables, dashboard widgets, menus, dialogs, settings, status text, and code panels.
- TypeScript and Swift update comparisons now follow SemVer precedence, so stable releases outrank their prereleases and invalid tags are ignored.
- Failed package updates restore previously running console and menu services after safe-to-recover failures, without masking the original update error if restart also fails. A missing-data guard keeps services stopped until backup restoration.
- Legacy package migration retains verified rollback instructions when inspection fails after removal.
- Concurrent agent installs and uninstalls are serialized so ownership-manifest entries cannot overwrite each other.
- Automatic execution rejects incompatible native binaries before launch and safely falls back to TypeScript; explicitly required Rust execution still fails closed.

## 0.1.2 - 2026-07-11

### Added

- Safe, idempotent setup for detected agent MCP configurations and the packaged s-gw skill, with dry-run, status, backups, conflict handling, and scoped uninstall.
- A tested migration path from the legacy unscoped `s-gw` npm package to `@s-gw/s-gw`.
- A release-only legacy bridge package so the original `0.1.0` desktop updater can install the fixed updater before the scoped-package migration.

### Fixed

- macOS update checks now continue for the app process lifetime, retry failed checks, and deliver one system notification per release.
- Update checks fall back to GitHub's public Atom feed when the unauthenticated Releases API is rate-limited.
- The updater accepts both per-file SHA-256 assets and `SHA256SUMS.txt`, and release automation uploads both formats.
- Native upgrades use the migration-aware installer instead of invoking npm directly.
- Windows agent registration launches the packaged server through `node.exe` instead of an npm `.cmd` shim and honors custom Codex, Gemini CLI, and Copilot homes.
- GitHub Copilot CLI registrations include its required local-server tool allowlist.
- OpenCode JSONC and the default VS Code user profile now support comment-preserving managed install and uninstall.

## 0.1.1 - 2026-07-10

### Added

- Official MCP Registry metadata for discovery and one-command launch through npm.
- `s-gw mcp` as a primary CLI entry point for the stdio MCP server.

### Changed

- MCP server version reporting now stays aligned with the package version.

## 0.1.0 - 2026-07-03

### Added

- Compiled Rust execution core for approved environment commands on macOS, Windows, and Linux builds.
- Cross-language execution, timeout, environment-isolation, sanitization, and proof compatibility tests.
- Local credential handles backed by macOS Keychain, Windows Credential Manager, 1Password references, or an encrypted ledger.
- Action-scoped approval policies and reusable grants.
- MCP tools for scanning, handle discovery, approved command execution, and owned SSH sessions.
- Native macOS management app and standalone menu helper.
- Windows preview client, tray helper, credential helper, and installer staging.
- Agent profiles for major coding agents and MCP clients.
- Local activity, audit, policy, credential, and usage-flow views.

### Changed

- Runtime packages contain the compiled application without source maps or native source files. The complete source remains available in the repository.

### Security

- Approved credential values reach the Rust core over stdin, never command arguments or inherited environment variables.
- The broker rejects malformed core responses, unsanitized credential output, and invalid execution proofs.
- Local console write operations require a per-session token.
- Raw credential values are accepted over stdin rather than process arguments.
- Approved command output is scanned and tokenized before it is returned to the caller.
