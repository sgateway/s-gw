[CmdletBinding()]
param(
  [int]$Port = 8718,
  [string]$ConsoleUrl = "",
  [switch]$NoStart
)

$ErrorActionPreference = "Stop"

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
    return ($health.ok -eq $true)
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

function Wait-Console([string]$Url) {
  for ($i = 0; $i -lt 30; $i += 1) {
    if (Test-ConsoleReady $Url) {
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

if (-not $NoStart -and -not (Test-ConsoleReady $url)) {
  Start-ConsoleDaemon -CliPath $cliPath -NodePath $nodePath
  if (-not (Wait-Console $url)) {
    throw "s-gw console did not become ready at $url. Check $env:LOCALAPPDATA\s-gw\logs."
  }
}

Open-ConsoleWindow $url
