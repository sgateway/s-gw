# Quick Start

This guide covers the recommended npm installation and exercises its approval boundary with disposable data. It does not require a real credential. For the self-contained Apple Silicon macOS desktop alternative, see the [macOS app installation](deployment.md#macos-app-apple-silicon).

The supported npm installation requires Node.js 20 or newer.

## Install

```bash
npm install -g @s-gw/s-gw
```

For normal use, run `s-gw setup`. The demonstration below instead uses a temporary home and an environment-provided passphrase so it leaves the operating system credential store untouched.

## Run The Trust Loop On macOS Or Linux

Create a disposable store:

```bash
DEMO_ROOT="$(mktemp -d)"
export SGW_HOME="$DEMO_ROOT/home"
export SGW_RECOVERY_HOME="$DEMO_ROOT/recovery"
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
rm -rf "$DEMO_ROOT"
unset DEMO_ROOT SGW_HOME SGW_RECOVERY_HOME SGW_MASTER_PASSPHRASE PASS HANDLE REQUEST REQUEST_ID
```

## Run The Trust Loop On Windows

Run the following in PowerShell. It uses a disposable store and the trusted Windows PowerShell executable as the approved child command:

```powershell
$DemoRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("sgw-quickstart-" + [guid]::NewGuid().ToString("N"))
$env:SGW_HOME = Join-Path $DemoRoot "home"
$RandomBytes = New-Object byte[] 32
$Random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
try { $Random.GetBytes($RandomBytes) } finally { $Random.Dispose() }
$env:SGW_MASTER_PASSPHRASE = [Convert]::ToBase64String($RandomBytes)
$DemoCommand = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
s-gw init
```

Enroll a fake value, then create its approval request:

```powershell
"demo-token-value" | s-gw secret add `
  --name demo-token `
  --type api-token `
  --value-stdin `
  --inject-env DEMO_TOKEN `
  --allow-command $DemoCommand

$Handle = (s-gw secret list | ConvertFrom-Json)[0].handle
$Request = s-gw request env-command $Handle `
  --command $DemoCommand `
  --arg=-NoProfile `
  --arg=-NonInteractive `
  --arg=-Command `
  --arg='[Console]::Write($env:DEMO_TOKEN)' `
  --inject-env DEMO_TOKEN `
  --reason "Read the disposable token" | ConvertFrom-Json
```

The first execution is refused while pending. Approve locally, then execute again:

```powershell
s-gw execute $Request.id
s-gw approve $Request.id
s-gw execute $Request.id
```

The successful response contains an s-gw handle in place of the fake value. Remove the disposable data and process-local variables when finished:

```powershell
Remove-Item -LiteralPath $DemoRoot -Recurse -Force
Remove-Item Env:\SGW_HOME, Env:\SGW_MASTER_PASSPHRASE -ErrorAction SilentlyContinue
Remove-Variable DemoRoot, RandomBytes, Random, DemoCommand, Handle, Request -ErrorAction SilentlyContinue
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
