[CmdletBinding()]
param(
  [int]$Port = 8718,
  [switch]$NoOpen
)

$ErrorActionPreference = "Stop"
$packagePath = Join-Path $PSScriptRoot "__PACKAGE_FILE__"

if (-not (Test-Path -LiteralPath $packagePath)) {
  throw "The bundled s-gw package is missing."
}

$nodeCommand = Get-Command "node.exe" -ErrorAction SilentlyContinue
$npmCommand = Get-Command "npm.cmd" -ErrorAction SilentlyContinue
if (-not $nodeCommand -or -not $npmCommand) {
  throw "Node.js 20 or newer is required. Install it from https://nodejs.org and run this installer again."
}

$nodeMajor = [int](& $nodeCommand.Source -p "Number(process.versions.node.split('.')[0])")
if ($nodeMajor -lt 20) {
  throw "Node.js 20 or newer is required."
}

Write-Host "Installing s-gw __VERSION__..."
& $npmCommand.Source install --global -- $packagePath
if ($LASTEXITCODE -ne 0) {
  throw "npm could not install s-gw. Check your npm global-directory permissions."
}

$sgwCommand = Get-Command "s-gw.cmd" -ErrorAction SilentlyContinue
if (-not $sgwCommand) {
  $sgwCommand = Get-Command "s-gw" -ErrorAction SilentlyContinue
}
if (-not $sgwCommand) {
  throw "s-gw was installed but its command is not on PATH. Restart Windows and run s-gw setup."
}

$setupArgs = @("setup", "--port", [string]$Port)
if ($NoOpen) {
  $setupArgs += "--no-open-app"
}
& $sgwCommand.Source @setupArgs
if ($LASTEXITCODE -ne 0) {
  throw "Initial s-gw setup did not complete."
}

Write-Host "s-gw __VERSION__ is installed."
