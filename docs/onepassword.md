# 1Password Integration

s-gw can use 1Password as an optional local secret backend or migration source. The s-gw ledger stores an encrypted `op://...` reference, not the raw secret value. After the user grants reusable approval, the first approved execution reads the value from the local 1Password CLI, stores an encrypted copy in the s-gw keystore for the approval TTL, and injects that value only into approved local child processes.

Agents still see typed handles such as `s-gw:api-token:...`; they never receive the raw value. One-time approvals read 1Password for that single execution. Timed, login-session, and unlimited approvals reuse the encrypted s-gw keystore copy until the approval expires or is revoked.

## Requirements

- Install and configure the 1Password CLI as `op`.
- Use a 1Password secret reference:

```text
op://vault-name/item-name/[section-name/]field-name
```

The 1Password CLI also supports service-account use through `OP_SERVICE_ACCOUNT_TOKEN`; that is useful for team automation, while desktop users can rely on the normal 1Password app approval flow.

## Add A 1Password-Backed Handle

```bash
s-gw onepassword status

s-gw secret add-1password \
  --name openai-prod \
  --type api-token \
  --ref 'op://Example/OpenAI/credential' \
  --inject-env OPENAI_API_KEY \
  --allow-command "$(command -v node)"
```

Use `--verify` when you want s-gw to call `op read` immediately and fail early if the reference is wrong or 1Password is locked:

```bash
s-gw secret add-1password \
  --name openai-prod \
  --type api-token \
  --ref 'op://Example/OpenAI/credential' \
  --inject-env OPENAI_API_KEY \
  --allow-command "$(command -v node)" \
  --verify
```

Without `--verify`, s-gw stores the encrypted reference and resolves it later, when the approved command actually runs.

## Capture Text Into 1Password

When a local agent or UI hands s-gw text that contains a credential, capture it through stdin so the value never appears in shell history:

```bash
s-gw onepassword capture \
  --vault Dev \
  --name "captured ssh credential" \
  --text-stdin \
  --inject-env SGW_SSH_PASSWORD \
  --allow-command "$(command -v ssh)"
```

The command scans the supplied text, creates a 1Password item in the `Dev` vault for each detected secret, stores only an encrypted `op://...` reference in the s-gw ledger, and returns tokenized text containing `<<SGW_SECRET:...>>` handles.

## Approved Execution

```bash
HANDLE="s-gw:api-token:..."

s-gw request env-command "$HANDLE" \
  --command "$(command -v node)" \
  --inject-env OPENAI_API_KEY \
  --arg -e \
  --arg 'console.log(process.env.OPENAI_API_KEY)'

s-gw approve req_...
s-gw execute req_...
```

If the child process prints the secret, s-gw sanitizes it back to the handle token before returning output to the agent.

## Operational Notes

- The `op://...` reference is encrypted in the local s-gw store.
- For reusable approvals, the raw value is read from 1Password once, then cached encrypted in the s-gw keystore until the approval TTL, login session, unlimited grant, revoke, clear, or credential deletion ends it.
- For one-time approvals, s-gw does not keep a cached value after the execution.
- `SGW_OP_CLI=/path/to/op` can point s-gw at a non-default CLI path.
- `SGW_ONEPASSWORD_TIMEOUT_MS=60000` can extend the approval/read timeout.
- For service-account automation, provide `OP_SERVICE_ACCOUNT_TOKEN` to the local environment that runs the s-gw daemon or CLI.
