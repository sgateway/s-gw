# Quick Start

This guide covers the npm/source path and exercises its approval boundary with disposable data. It does not require a real credential. For the self-contained Apple Silicon macOS app, see the [macOS app installation](deployment.md#macos-app-apple-silicon) first.

The supported npm installation requires Node.js 20 or newer.

## Install

```bash
npm install -g @s-gw/s-gw
```

For normal use, run `s-gw setup`. The demonstration below instead uses a temporary home and an environment-provided passphrase so it leaves the operating system credential store untouched.

## Run The Trust Loop

Create a disposable store:

```bash
export SGW_HOME="$(mktemp -d)/home"
PASS="$(openssl rand -base64 32)"
printf -v SGW_MASTER_PASSPHRASE '%s' "$PASS"
export SGW_MASTER_PASSPHRASE
s-gw init
```

Enroll a fake value and permit only the local `printenv` executable to receive it:

```bash
printf '%s' "demo-token-value" | s-gw secret add \
  --name demo-token \
  --type api-token \
  --value-stdin \
  --inject-env DEMO_TOKEN \
  --allow-command "$(command -v printenv)"
```

Get the generated handle. The list contains metadata, not the credential value:

```bash
HANDLE=$(s-gw secret list | node -e '
let data = "";
process.stdin.on("data", chunk => data += chunk);
process.stdin.on("end", () => console.log(JSON.parse(data)[0].handle));
')
```

Create a request as an agent would:

```bash
REQUEST=$(s-gw request env-command "$HANDLE" \
  --command "$(command -v printenv)" \
  --arg DEMO_TOKEN \
  --inject-env DEMO_TOKEN \
  --reason "Read the disposable token")

REQUEST_ID=$(printf '%s' "$REQUEST" | node -e '
let data = "";
process.stdin.on("data", chunk => data += chunk);
process.stdin.on("end", () => console.log(JSON.parse(data).id));
')
```

Execution is refused while the request is pending:

```bash
s-gw execute "$REQUEST_ID"
```

Approve it locally, then execute it:

```bash
s-gw approve "$REQUEST_ID"
s-gw execute "$REQUEST_ID"
```

The child process reads `demo-token-value`, but the returned output contains an s-gw handle:

```json
{
  "exitCode": 0,
  "stdout": "<<SGW_SECRET:s-gw:api-token:...>>\n",
  "proof": "s-gw-proof:req_...",
  "sanitized": true
}
```

Remove the disposable store:

```bash
rm -rf "$SGW_HOME"
unset SGW_HOME SGW_MASTER_PASSPHRASE HANDLE REQUEST REQUEST_ID
```

## Next Steps

- Run `s-gw setup` for a persistent local installation.
- `s-gw setup` automatically connects detected agents with safe user-level config targets. Run `s-gw agent status` to review the result or `s-gw setup --no-agents` to skip it.
- Use `s-gw agent mcp-snippet <agent>` for manual profiles and project-scoped configuration.
- Read the [threat model](threat-model.md) before enrolling sensitive credentials.
- Open the native app with `s-gw app open` or the fallback console with `s-gw console`.

## Build From Source

Contributors need the Rust toolchain pinned by `rust-toolchain.toml`. Building the native macOS surfaces also requires Swift.

```bash
git clone https://github.com/sgateway/s-gw.git
cd s-gw
npm ci
npm run build
npm link
```
