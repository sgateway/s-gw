[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)]
  [string]$HelperPath,

  [Parameter(Mandatory = $true)]
  [ValidateRange(1, 65535)]
  [int]$Port,

  [Parameter(Mandatory = $true)]
  [string]$ConsoleUrl,

  [Parameter(Mandatory = $true)]
  [string]$InstanceKey,

  [Parameter(Mandatory = $true)]
  [string]$LaunchNonce
)

$ErrorActionPreference = "Stop"

function Quote-NativeArg([string]$Value) {
  if ($Value.IndexOfAny([char[]]@('"', "`r", "`n", [char]0)) -ge 0) {
    throw "The helper launch arguments contain unsupported characters."
  }
  if ($Value.Length -gt 0 -and $Value -notmatch '\s') {
    return $Value
  }
  return '"' + $Value + '"'
}

$expectedHelper = Join-Path $PSScriptRoot "s-gw-helper.ps1"
if (-not (Test-Path -LiteralPath $expectedHelper -PathType Leaf)) {
  throw "The s-gw Windows helper is missing."
}
$resolvedHelper = (Resolve-Path -LiteralPath $HelperPath).Path
$resolvedExpected = (Resolve-Path -LiteralPath $expectedHelper).Path
if (-not [string]::Equals($resolvedHelper, $resolvedExpected, [StringComparison]::OrdinalIgnoreCase)) {
  throw "The helper bootstrap can only launch its packaged sibling."
}

$parsedUrl = $null
if (-not [Uri]::TryCreate($ConsoleUrl, [UriKind]::Absolute, [ref]$parsedUrl)) {
  throw "The Windows console URL is invalid."
}
if (
  $parsedUrl.Scheme -cne "http" -or
  $parsedUrl.Host -notin @("127.0.0.1", "localhost") -or
  $parsedUrl.Port -ne $Port -or
  $parsedUrl.AbsolutePath -cne "/" -or
  $parsedUrl.UserInfo -or
  $parsedUrl.Query -or
  $parsedUrl.Fragment
) {
  throw "The Windows console URL must be the selected local HTTP endpoint."
}
if ($InstanceKey -notmatch '^[a-fA-F0-9]{64}$') {
  throw "The Windows helper instance key is invalid."
}
if ($LaunchNonce -notmatch '^[a-fA-F0-9]{64}$') {
  throw "The Windows helper launch nonce is invalid."
}

$powerShellPath = Join-Path $PSHOME "powershell.exe"
if (-not (Test-Path -LiteralPath $powerShellPath -PathType Leaf)) {
  throw "The Windows PowerShell executable is missing."
}

$helperArgs = @(
  "-NoProfile",
  "-Sta",
  "-ExecutionPolicy",
  "Bypass",
  "-File",
  $resolvedHelper,
  "-Port",
  [string]$Port,
  "-ConsoleUrl",
  $parsedUrl.AbsoluteUri,
  "-InstanceKey",
  $InstanceKey.ToLowerInvariant(),
  "-LaunchNonce",
  $LaunchNonce.ToLowerInvariant()
)
$argumentLine = ($helperArgs | ForEach-Object { Quote-NativeArg ([string]$_) }) -join " "
$process = $null
try {
  $process = Microsoft.PowerShell.Management\Start-Process -FilePath $powerShellPath -ArgumentList $argumentLine -WindowStyle Hidden -PassThru
  if ($null -eq $process) {
    throw "Windows did not start the s-gw helper."
  }

  [PSCustomObject]@{
    pid = [int]$process.Id
    startedAtUtcTicks = [string]$process.StartTime.ToUniversalTime().Ticks
    launchNonce = $LaunchNonce.ToLowerInvariant()
  } | ConvertTo-Json -Compress
} catch {
  $launchError = $_
  $cleanupError = $null
  if ($null -ne $process) {
    try {
      if (-not $process.HasExited) {
        $process.Kill()
        if (-not $process.WaitForExit(5000)) {
          throw "The failed s-gw helper launch did not stop."
        }
      }
    } catch {
      $cleanupError = $_.Exception.Message
    }
  }
  if ($cleanupError) {
    throw "$($launchError.Exception.Message); $cleanupError"
  }
  throw $launchError
}
