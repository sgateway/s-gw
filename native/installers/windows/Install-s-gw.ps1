[CmdletBinding()]
param(
  [int]$Port = 8718,
  [switch]$NoOpen
)

$ErrorActionPreference = "Stop"
$packagePath = Join-Path $PSScriptRoot "__PACKAGE_FILE__"

function Stop-SgwWindowsSurfaces {
  Get-CimInstance Win32_Process | ForEach-Object {
    $line = [string]$_.CommandLine
    $helper = $line -match '(?i)s-gw-(helper|client)\.ps1'
    $console = $line -match '(?i)[\\/]dist[\\/]cli\.js' -and $line -match '(?i)\sconsole(?:\s|$)' -and $line -match '(?i)s-gw'
    if ($_.ProcessId -ne $PID -and ($helper -or $console)) {
      Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
  }
}

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

$npmPrefixOutput = @(& $npmCommand.Source prefix --global)
if ($LASTEXITCODE -ne 0 -or $npmPrefixOutput.Count -eq 0) {
  throw "npm did not report its global prefix."
}
$npmPrefix = [string]($npmPrefixOutput | Select-Object -Last 1)
$npmPrefix = $npmPrefix.Trim()
if ([string]::IsNullOrWhiteSpace($npmPrefix)) {
  throw "npm returned an empty global prefix."
}

$npmRootOutput = @(& $npmCommand.Source root --global --prefix $npmPrefix)
if ($LASTEXITCODE -ne 0 -or $npmRootOutput.Count -eq 0) {
  throw "npm did not report its global package directory."
}
$npmRoot = [string]($npmRootOutput | Select-Object -Last 1)
$npmRoot = $npmRoot.Trim()

$packageMetadataOutput = @(& $npmCommand.Source pack --dry-run --ignore-scripts --json -- $packagePath)
if ($LASTEXITCODE -ne 0) {
  throw "The bundled package metadata could not be verified."
}
try {
  $packageMetadata = @((($packageMetadataOutput -join "`n") | ConvertFrom-Json))[0]
} catch {
  throw "The bundled package metadata is invalid."
}
if ($packageMetadata.name -ne "@s-gw/s-gw" -or [string]::IsNullOrWhiteSpace([string]$packageMetadata.version)) {
  throw "The bundled archive is not the scoped @s-gw/s-gw package."
}
$packageVersion = [string]$packageMetadata.version

$sgwCommand = Get-Command "s-gw.cmd" -ErrorAction SilentlyContinue
if (-not $sgwCommand) {
  $sgwCommand = Get-Command "s-gw" -ErrorAction SilentlyContinue
}
if (-not $sgwCommand) {
  $prefixCommand = Join-Path $npmPrefix "s-gw.cmd"
  if (Test-Path -LiteralPath $prefixCommand) {
    $sgwCommand = Get-Command $prefixCommand -ErrorAction SilentlyContinue
  }
}
if ($sgwCommand) {
  & $sgwCommand.Source stop | Out-Null
  if ($LASTEXITCODE -ne 0) {
    throw "The existing s-gw services could not be stopped. Close s-gw and try again."
  }
}
Stop-SgwWindowsSurfaces

$legacyRoot = Join-Path $npmRoot "s-gw"
$legacyPackageJson = Join-Path $legacyRoot "package.json"
$legacyVersion = $null
$rollbackDir = $null
$rollbackPath = $null
if (Test-Path -LiteralPath $legacyPackageJson) {
  try {
    $legacyMetadata = Get-Content -LiteralPath $legacyPackageJson -Raw | ConvertFrom-Json
  } catch {
    throw "The existing legacy package metadata could not be read."
  }
  if ($legacyMetadata.name -eq "s-gw" -and -not [string]::IsNullOrWhiteSpace([string]$legacyMetadata.version)) {
    $legacyVersion = [string]$legacyMetadata.version
  }
}

if ($legacyVersion) {
  Write-Host "Migrating legacy s-gw $legacyVersion to @s-gw/s-gw $packageVersion..."
  $rollbackDir = Join-Path ([IO.Path]::GetTempPath()) ("s-gw-rollback-" + [Guid]::NewGuid().ToString("N"))
  New-Item -ItemType Directory -Path $rollbackDir | Out-Null
  $rollbackMetadataOutput = @(& $npmCommand.Source pack --ignore-scripts --json --pack-destination $rollbackDir -- $legacyRoot)
  if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $rollbackDir -Recurse -Force -ErrorAction SilentlyContinue
    throw "A rollback copy of legacy s-gw could not be created. The existing package was not removed."
  }
  try {
    $rollbackMetadata = @((($rollbackMetadataOutput -join "`n") | ConvertFrom-Json))[0]
  } catch {
    Remove-Item -LiteralPath $rollbackDir -Recurse -Force -ErrorAction SilentlyContinue
    throw "The rollback copy of legacy s-gw could not be verified. The existing package was not removed."
  }
  if ($rollbackMetadata.name -ne "s-gw" -or $rollbackMetadata.version -ne $legacyVersion -or [string]::IsNullOrWhiteSpace([string]$rollbackMetadata.filename)) {
    Remove-Item -LiteralPath $rollbackDir -Recurse -Force -ErrorAction SilentlyContinue
    throw "The rollback copy of legacy s-gw could not be verified. The existing package was not removed."
  }
  $rollbackFile = Split-Path -Leaf ([string]$rollbackMetadata.filename)
  $rollbackPath = Join-Path $rollbackDir $rollbackFile
  if (-not (Test-Path -LiteralPath $rollbackPath)) {
    Remove-Item -LiteralPath $rollbackDir -Recurse -Force -ErrorAction SilentlyContinue
    throw "npm did not create the rollback package. The existing package was not removed."
  }

  & $npmCommand.Source uninstall --global --prefix $npmPrefix --ignore-scripts -- "s-gw"
  if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $rollbackDir -Recurse -Force -ErrorAction SilentlyContinue
    throw "npm could not remove the legacy s-gw package. The scoped package was not installed."
  }
  Write-Host "Legacy package removed. Existing data under ~/.s-gw was left in place."
}

Write-Host "Installing @s-gw/s-gw $packageVersion..."
& $npmCommand.Source install --global --prefix $npmPrefix --ignore-scripts -- $packagePath
if ($LASTEXITCODE -ne 0) {
  if ($rollbackPath -and (Test-Path -LiteralPath $rollbackPath)) {
    Write-Warning "The scoped install failed. Restoring legacy s-gw $legacyVersion from the local rollback copy..."
    & $npmCommand.Source uninstall --global --prefix $npmPrefix --ignore-scripts -- "@s-gw/s-gw" | Out-Null
    & $npmCommand.Source install --global --prefix $npmPrefix --ignore-scripts -- $rollbackPath
    if ($LASTEXITCODE -eq 0) {
      Remove-Item -LiteralPath $rollbackDir -Recurse -Force -ErrorAction SilentlyContinue
      throw "The new package could not be installed; legacy s-gw was restored. Your ~/.s-gw data was preserved."
    }
    throw "The new package and automatic rollback both failed. Your ~/.s-gw data was preserved. Restore with: npm uninstall --global --prefix `"$npmPrefix`" @s-gw/s-gw; npm install --global --prefix `"$npmPrefix`" `"$rollbackPath`""
  }
  throw "npm could not install s-gw. Check your npm global-directory permissions. Your ~/.s-gw data was preserved."
}
if ($rollbackDir) {
  Remove-Item -LiteralPath $rollbackDir -Recurse -Force -ErrorAction SilentlyContinue
}

$sgwCommandPath = Join-Path $npmPrefix "s-gw.cmd"
if (-not (Test-Path -LiteralPath $sgwCommandPath)) {
  $installedCommand = Get-Command "s-gw.cmd" -ErrorAction SilentlyContinue
  if (-not $installedCommand) {
    $installedCommand = Get-Command "s-gw" -ErrorAction SilentlyContinue
  }
  if ($installedCommand) {
    $sgwCommandPath = $installedCommand.Source
  } else {
    throw "s-gw was installed, but its command was not found under $npmPrefix."
  }
}

if (-not (Get-Command "s-gw.cmd" -ErrorAction SilentlyContinue)) {
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
  throw "Package installation completed, but setup did not. Run `"$sgwCommandPath setup --port $Port`" after closing this window."
}

Write-Host "s-gw $packageVersion is installed. Existing ~/.s-gw data was preserved."
