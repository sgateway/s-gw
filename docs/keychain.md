# OS Credential Store Backend

s-gw can store credential values in the local OS credential store: macOS Keychain, Linux Secret Service, or Windows Credential Manager. Agents still receive only handles such as `s-gw:api-token:...`; the raw value is read from the local store only after s-gw has an approved local request to execute.

## Add A Credential-Store-Backed Handle

```bash
printf '%s' "$MY_API_TOKEN" | s-gw secret add-keychain \
  --name prod-api-token \
  --type api-token \
  --value-stdin \
  --inject-env API_TOKEN \
  --allow-command "$(command -v node)"
```

The raw credential is written through the bundled helper on stdin. The encrypted s-gw ledger keeps only handle metadata and an encrypted credential-store pointer:

```json
{
  "service": "com.s-gw.sgw.secret",
  "account": "s-gw:api-token:..."
}
```

Use `--service SERVICE` or `SGW_SECRET_KEYCHAIN_SERVICE` when you want a separate credential-store namespace for testing, work, or isolated profiles.

On Linux, install the distribution's `secret-tool` package and make sure the user's Secret Service keyring is unlocked before setup. Ubuntu and Debian provide it in `libsecret-tools`. s-gw calls the fixed system helper directly, sends new values on stdin, bounds each helper call, and scopes each item with application, service, and account attributes. `secret-tool` cannot safely accept values larger than 8,191 UTF-8 bytes, so s-gw rejects those before storage instead of risking truncation. If Secret Service is unavailable, locked, or does not respond in time, credential operations stop with an actionable error.

On macOS, setup copies the first working Keychain helper to `~/.s-gw/native/darwin-arm64/s-gw-keychain-helper` with owner-only permissions. A Keychain ACL records the creating helper's path and code-signing requirement; macOS grants access only when the executing helper satisfies that requirement. npm updates preserve the existing helper before replacing a package, and later releases do not overwrite it silently. The self-contained app also copies its helper to that persistent path, but never modifies the installed app bundle itself.

After an upgrade, s-gw checks each item's trusted-application metadata before any credential read. An item tied to an older package path is copied through a verified temporary Keychain backup and recreated for the persistent helper. The original is not deleted until the recovery copy has been verified. Run the same repair explicitly at any time:

```bash
s-gw unlock keychain repair
```

The command reports counts and per-handle errors, but never prints credential values. If no trusted legacy helper can be verified, s-gw stops before invoking a helper and leaves the item unchanged.

Already-running MCP servers may keep an older s-gw module in memory across an npm application upgrade. Setup and the npm updater therefore pin the preserved helper at both the persistent path and the package compatibility path used by those sessions. New agent sessions use the persistent path directly. A self-contained app keeps its sealed runtime untouched and refreshes its background services after an app replacement.

Automatic capture paths, including guard mode and the local console API, prefer the OS credential store on macOS, Linux, and Windows. A Linux session unlocked explicitly with `SGW_MASTER_PASSPHRASE` defaults to the encrypted local ledger because a headless Secret Service may not be usable; set `SGW_SECRET_BACKEND=keychain` only to request Secret Service explicitly in that mode.

## Local Execution Flow

1. An agent sees a tokenized handle, not the credential.
2. The agent asks s-gw to use the handle for a concrete action.
3. s-gw applies policy and asks for approval when required.
4. During approved execution, s-gw reads the credential from the local store and injects it into the local child process.
5. Command output is sanitized back to handles before it is returned.

On macOS, routine status uses the packaged native inspector and asks Security.framework for attributes only; it does not call `/usr/bin/security` or request the password data. The app and menu helper keep four-second approval polling, but cache this runtime status for five minutes between launches, activations, manual refreshes, and relevant setup or service changes. Set `SGW_ALLOW_SECURITY_CLI=1` only as an explicit compatibility fallback when the packaged inspector is unavailable; that fallback may be visible to endpoint monitoring. Linux `secret-tool` has no metadata-only lookup, so a status check asks the already-unlocked Secret Service for the item and discards the value without printing or serializing it. If an unexpected macOS Keychain password dialog appears, cancel it and run `s-gw unlock keychain repair`; current releases fail closed before starting an unverified helper.

## 1Password Migration Later

Do not read or migrate real 1Password values as part of normal setup. The safe migration path should be an explicit user-approved command that reads selected `op://...` references, writes those values into credential-store-backed handles, updates the encrypted ledger pointers, and leaves an audit event for each migrated handle.
