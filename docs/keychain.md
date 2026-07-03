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

Automatic capture paths, including guard mode and the local console API, prefer the OS credential store on macOS and Windows. Set `SGW_SECRET_BACKEND=local` only for compatibility testing or environments without the native helper.

## Local Execution Flow

1. An agent sees a tokenized handle, not the credential.
2. The agent asks s-gw to use the handle for a concrete action.
3. s-gw applies policy and asks for approval when required.
4. During approved execution, s-gw reads the credential from the local store and injects it into the local child process.
5. Command output is sanitized back to handles before it is returned.

## 1Password Migration Later

Do not read or migrate real 1Password values as part of normal setup. The safe migration path should be an explicit user-approved command that reads selected `op://...` references, writes those values into credential-store-backed handles, updates the encrypted ledger pointers, and leaves an audit event for each migrated handle.
