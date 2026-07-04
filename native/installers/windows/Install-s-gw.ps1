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

if ($sgwCommand) {
  $sgwCommandPath = $sgwCommand.Source
} else {
  $npmPrefixOutput = @(& $npmCommand.Source prefix --global)
  $npmPrefixExitCode = $LASTEXITCODE
  if ($npmPrefixExitCode -ne 0 -or $npmPrefixOutput.Count -eq 0) {
    throw "s-gw was installed, but npm did not report its global command directory."
  }

  $npmPrefix = [string]($npmPrefixOutput | Select-Object -Last 1)
  $npmPrefix = $npmPrefix.Trim()
  if ([string]::IsNullOrWhiteSpace($npmPrefix)) {
    throw "s-gw was installed, but npm returned an empty global command directory."
  }

  $sgwCommandPath = Join-Path $npmPrefix "s-gw.cmd"
  if (-not (Test-Path -LiteralPath $sgwCommandPath)) {
    throw "s-gw was installed, but its command was not found at $sgwCommandPath."
  }

  $processPathEntries = @($env:Path -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  if ($processPathEntries -notcontains $npmPrefix) {
    $env:Path = "$env:Path;$npmPrefix"
  }

  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  $savedPathEntries = @("$userPath;$machinePath" -split ";" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  if ($savedPathEntries -notcontains $npmPrefix) {
    $nextUserPath = $npmPrefix
    if (-not [string]::IsNullOrWhiteSpace($userPath)) {
      $nextUserPath = "$userPath;$npmPrefix"
    }
    [Environment]::SetEnvironmentVariable("Path", $nextUserPath, "User")
    Write-Host "Added $npmPrefix to your user PATH."
  }
}

$setupArgs = @("setup", "--port", [string]$Port)
if ($NoOpen) {
  $setupArgs += "--no-open-app"
}
& $sgwCommandPath @setupArgs
if ($LASTEXITCODE -ne 0) {
  throw "Initial s-gw setup did not complete."
}

Write-Host "s-gw __VERSION__ is installed."
