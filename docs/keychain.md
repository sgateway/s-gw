# OS Credential Store Backend

s-gw can store credential values in the local OS credential store: macOS Keychain on macOS and Windows Credential Manager on Windows preview builds. Agents still receive only handles such as `s-gw:api-token:...`; the raw value is read from the local store only after s-gw has an approved local request to execute.

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

On macOS, setup copies the first working Keychain helper to `~/.s-gw/native/darwin-arm64/s-gw-keychain-helper` with owner-only permissions. A Keychain ACL records the creating helper's path and code-signing requirement; macOS grants access only when the executing helper satisfies that requirement. The updater preserves the existing helper before replacing a package, and later releases do not overwrite it silently.

After an upgrade, s-gw checks each item's trusted-application metadata before any credential read. An item tied to an older package path is copied through a verified temporary Keychain backup and recreated for the persistent helper. The original is not deleted until the recovery copy has been verified. Run the same repair explicitly at any time:

```bash
s-gw unlock keychain repair
```

The command reports counts and per-handle errors, but never prints credential values. If no trusted legacy helper can be verified, s-gw stops before invoking a helper and leaves the item unchanged.

Already-running MCP servers may keep an older s-gw module in memory across an application upgrade. Setup and the updater therefore pin the preserved helper at both the persistent path and the package compatibility path used by those sessions. New agent sessions use the persistent path directly.

Automatic capture paths, including guard mode and the local console API, prefer the OS credential store on macOS and Windows. Set `SGW_SECRET_BACKEND=local` only for compatibility testing or environments without the native helper.

## Local Execution Flow

1. An agent sees a tokenized handle, not the credential.
2. The agent asks s-gw to use the handle for a concrete action.
3. s-gw applies policy and asks for approval when required.
4. During approved execution, s-gw reads the credential from the local store and injects it into the local child process.
5. Command output is sanitized back to handles before it is returned.

Routine status, dashboard, and menu refreshes inspect only Keychain metadata. They do not read the unlock passphrase or credential values and should not open a macOS password prompt. If an unexpected s-gw Keychain password dialog appears, cancel it and run `s-gw unlock keychain repair`; current releases fail closed before starting an unverified helper.

## 1Password Migration Later

Do not read or migrate real 1Password values as part of normal setup. The safe migration path should be an explicit user-approved command that reads selected `op://...` references, writes those values into credential-store-backed handles, updates the encrypted ledger pointers, and leaves an audit event for each migrated handle.
