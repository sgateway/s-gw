param([switch]$SharedHost)

$ErrorActionPreference = 'Stop'
if (-not $SharedHost -and -not $env:SGW_WINDOWS_NATIVE_ACCEPTANCE_ROOT) {
  throw 'Set SGW_WINDOWS_NATIVE_ACCEPTANCE_ROOT to a separate prepared NTFS/ReFS volume root.'
}

$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (-not (Test-Path $vswhere)) { throw 'Visual Studio installation discovery is unavailable.' }
$vsRoot = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
if (-not $vsRoot) { throw 'MSVC C tools are unavailable.' }
$devCmd = Join-Path $vsRoot 'Common7\Tools\VsDevCmd.bat'
if (-not (Test-Path $devCmd)) { throw 'MSVC environment setup is unavailable.' }

$modeSuffix = if ($SharedHost) { ' --shared-host' } else { '' }
$compile = 'call "' + $devCmd + '" -arch=amd64 -host_arch=amd64 >nul && npm run build:windows-peer-identity && node scripts/test-windows-peer-identity.mjs' + $modeSuffix
if ($SharedHost) {
  & cmd.exe /d /s /c $compile
  if ($LASTEXITCODE -ne 0) { throw 'The shared-host Windows peer checks failed.' }
  return
}

$activeAdapters = @(Get-NetAdapter | Where-Object Status -eq 'Up')
if ($activeAdapters.Count -eq 0) { throw 'The isolated host has no active network adapter for DNS capture.' }
$dnsServers = @($activeAdapters | ForEach-Object {
  Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex |
    ForEach-Object { $_.ServerAddresses }
} | Where-Object { $_ })
if ($dnsServers.Count -eq 0 -or @($dnsServers | Where-Object { $_ -notin @('127.0.0.1', '::1') }).Count -ne 0) {
  throw 'Every active adapter must use only the prepared loopback DNS resolver (127.0.0.1 or ::1).'
}

$consoleKey = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Console')
if (-not $consoleKey) { throw 'Could not open the Windows console settings.' }
$hadLowBoxValue = $consoleKey.GetValueNames() -contains 'LowBoxConsoleEnabled'
if ($hadLowBoxValue) {
  $oldLowBoxValue = $consoleKey.GetValue('LowBoxConsoleEnabled', $null,
    [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
  $oldLowBoxKind = $consoleKey.GetValueKind('LowBoxConsoleEnabled')
}
try {
  $consoleKey.SetValue('LowBoxConsoleEnabled', 1, [Microsoft.Win32.RegistryValueKind]::DWord)
  & cmd.exe /d /s /c $compile
  if ($LASTEXITCODE -ne 0) { throw 'Native Windows peer acceptance failed.' }
} finally {
  if ($hadLowBoxValue) {
    $consoleKey.SetValue('LowBoxConsoleEnabled', $oldLowBoxValue, $oldLowBoxKind)
  } else {
    $consoleKey.DeleteValue('LowBoxConsoleEnabled', $false)
  }
  $consoleKey.Dispose()
}
