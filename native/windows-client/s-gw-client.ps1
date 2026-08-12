[CmdletBinding()]
param(
  [int]$Port = 8718,
  [string]$ConsoleUrl = "",
  [string]$InstanceKey = "",
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"

$expectedInstanceKey = $InstanceKey.Trim().ToLowerInvariant()
if ($expectedInstanceKey -notmatch '^[a-f0-9]{64}$') {
  throw 'Launch the Windows client through s-gw-client.cmd or s-gw app open.'
}

function Resolve-CliPath {
  if ($env:SGW_CLI_PATH -and (Test-Path -LiteralPath $env:SGW_CLI_PATH)) {
    return (Resolve-Path -LiteralPath $env:SGW_CLI_PATH).Path
  }

  $distDir = Split-Path -Parent $PSScriptRoot
  $candidate = Join-Path $distDir "cli.js"
  if (Test-Path -LiteralPath $candidate) {
    return (Resolve-Path -LiteralPath $candidate).Path
  }

  throw "Unable to find s-gw CLI. Set SGW_CLI_PATH to dist\cli.js."
}

function Resolve-NodePath {
  if ($env:SGW_NODE_PATH) {
    return $env:SGW_NODE_PATH
  }
  return "node"
}

function New-ConsoleUrl {
  if ($ConsoleUrl.Trim()) {
    return $ConsoleUrl.Trim()
  }
  return "http://127.0.0.1:$Port/"
}

function Get-OriginUrl([string]$Url) {
  $uri = [Uri]$Url
  return $uri.GetLeftPart([UriPartial]::Authority) + "/"
}

function Test-ConsoleReady([string]$Url) {
  $origin = Get-OriginUrl $Url
  try {
    $health = Invoke-RestMethod -Method Get -Uri ($origin + "api/health") -TimeoutSec 1
    return ($health.ok -eq $true -and [string]$health.instanceKey -eq $expectedInstanceKey)
  } catch {
    return $false
  }
}

function Test-ConsoleOwner([string]$CliPath, [string]$NodePath) {
  try {
    $connections = @(Get-NetTCPConnection -State Listen -LocalPort $Port | Where-Object {
      [string]$_.LocalAddress -eq '127.0.0.1'
    })
    $listenerPids = @($connections | Select-Object -ExpandProperty OwningProcess -Unique)
    if ($listenerPids.Count -ne 1) {
      return $false
    }

    $listenerPid = [int]$listenerPids[0]
    $item = Get-CimInstance Win32_Process -Filter "ProcessId = $listenerPid" -ErrorAction Stop
    $owner = Invoke-CimMethod -InputObject $item -MethodName GetOwnerSid -ErrorAction Stop
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $currentSessionId = [int](Get-Process -Id $PID).SessionId
    if ($owner.ReturnValue -ne 0 -or [string]$owner.Sid -ne $currentSid -or [int]$item.SessionId -ne $currentSessionId) {
      return $false
    }

    if (-not [string]::Equals(
      [IO.Path]::GetFullPath([string]$item.ExecutablePath),
      [IO.Path]::GetFullPath($NodePath),
      [StringComparison]::OrdinalIgnoreCase
    )) {
      return $false
    }

    $line = [string]$item.CommandLine
    $cliPattern = '(?i)(?:^|\s)"?' + [regex]::Escape($CliPath) + '"?(?:\s|$)'
    $portPattern = '(?i)(?:^|\s)--port(?:\s+|:|=)"?' + [regex]::Escape([string]$Port) + '"?(?:\s|$)'
    $anyPortPattern = '(?i)(?:^|\s)--port(?:\s+|:|=)'
    $hostPattern = '(?i)(?:^|\s)--host(?:\s+|:|=)"?127\.0\.0\.1"?(?:\s|$)'
    $anyHostPattern = '(?i)(?:^|\s)--host(?:\s+|:|=)'
    $hostMatches = $line -match $hostPattern -or $line -notmatch $anyHostPattern
    $portMatches = $line -match $portPattern -or ($Port -eq 8718 -and $line -notmatch $anyPortPattern)
    return (
      $line -match $cliPattern -and
      $line -match '(?i)(?:^|\s)console(?:\s|$)' -and
      $portMatches -and
      $hostMatches
    )
  } catch {
    return $false
  }
}

function Start-ConsoleDaemon([string]$CliPath, [string]$NodePath) {
  $logs = Join-Path $env:LOCALAPPDATA "s-gw\logs"
  New-Item -ItemType Directory -Force -Path $logs | Out-Null

  $args = @($CliPath, "console", "--host", "127.0.0.1", "--port", [string]$Port, "--no-open")
  $root = Split-Path -Parent (Split-Path -Parent $CliPath)

  Start-Process `
    -FilePath $NodePath `
    -ArgumentList $args `
    -WorkingDirectory $root `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $logs "console.log") `
    -RedirectStandardError (Join-Path $logs "console.err.log") | Out-Null
}

function Wait-Console([string]$Url, [string]$CliPath, [string]$NodePath) {
  for ($i = 0; $i -lt 30; $i += 1) {
    if ((Test-ConsoleReady $Url) -and (Test-ConsoleOwner $CliPath $NodePath)) {
      return $true
    }
    Start-Sleep -Milliseconds 250
  }
  return $false
}

function Open-ConsoleWindow([string]$Url) {
  $edge = Get-Command "msedge.exe" -ErrorAction SilentlyContinue
  if ($edge) {
    Start-Process -FilePath $edge.Source -ArgumentList @("--app=$Url") | Out-Null
    return
  }

  $chrome = Get-Command "chrome.exe" -ErrorAction SilentlyContinue
  if ($chrome) {
    Start-Process -FilePath $chrome.Source -ArgumentList @("--app=$Url") | Out-Null
    return
  }

  Start-Process $Url | Out-Null
}

$url = New-ConsoleUrl
$cliPath = Resolve-CliPath
$nodePath = Resolve-NodePath
$ready = (Test-ConsoleReady $url) -and (Test-ConsoleOwner $cliPath $nodePath)

if ($NoStart -and -not $ready) {
  throw "s-gw console authority did not match at $url. Stop the existing console or choose another port."
}

if (-not $NoStart -and -not $ready) {
  Start-ConsoleDaemon -CliPath $cliPath -NodePath $nodePath
  if (-not (Wait-Console $url $cliPath $nodePath)) {
    throw "s-gw console did not become ready at $url. Check $env:LOCALAPPDATA\s-gw\logs."
  }
}

Open-ConsoleWindow $url
