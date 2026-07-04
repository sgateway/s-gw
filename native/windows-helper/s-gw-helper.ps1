[CmdletBinding()]
param(
  [int]$Port = 8718,
  [string]$ConsoleUrl = ""
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

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
    return $ConsoleUrl.Trim().TrimEnd("/") + "/"
  }
  return "http://127.0.0.1:$Port/"
}

function Quote-Arg([string]$Value) {
  if ($Value.Length -eq 0) {
    return '""'
  }
  return '"' + $Value.Replace('"', '\"') + '"'
}

function Invoke-CliJson([string[]]$Args) {
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $script:NodePath
  $allArgs = @($script:CliPath) + $Args
  $psi.Arguments = ($allArgs | ForEach-Object { Quote-Arg ([string]$_) }) -join " "
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true

  $proc = [System.Diagnostics.Process]::Start($psi)
  $stdout = $proc.StandardOutput.ReadToEnd()
  $stderr = $proc.StandardError.ReadToEnd()
  $proc.WaitForExit()
  if ($proc.ExitCode -ne 0) {
    throw ($stderr.Trim() + " " + $stdout.Trim()).Trim()
  }
  if (-not $stdout.Trim()) {
    return $null
  }
  return $stdout | ConvertFrom-Json
}

function Start-Client([string]$Path = "") {
  $clientScript = Join-Path $PSScriptRoot "s-gw-client.ps1"
  $url = $script:BaseConsoleUrl
  if ($Path) {
    $url = $script:BaseConsoleUrl.TrimEnd("/") + "/" + $Path.TrimStart("/")
  }
  Start-Process `
    -FilePath "powershell.exe" `
    -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $clientScript, "-Port", [string]$Port, "-ConsoleUrl", $url) | Out-Null
}

function Get-PendingRequests {
  try {
    $pending = Invoke-CliJson @("requests", "--state", "pending", "--limit", "25")
    if ($null -eq $pending) {
      return @()
    }
    if ($pending -is [array]) {
      return $pending
    }
    return @($pending)
  } catch {
    $script:LastError = $_.Exception.Message
    return @()
  }
}

function Add-MenuItem([System.Windows.Forms.ContextMenuStrip]$Menu, [string]$Text, [scriptblock]$Handler, [bool]$Enabled = $true) {
  $item = New-Object System.Windows.Forms.ToolStripMenuItem
  $item.Text = $Text
  $item.Enabled = $Enabled
  if ($Handler) {
    $item.Add_Click($Handler)
  }
  [void]$Menu.Items.Add($item)
  return $item
}

function Approve-FirstPending {
  $pending = Get-PendingRequests
  if ($pending.Count -eq 0) {
    return
  }
  $request = $pending[$pending.Count - 1]
  Invoke-CliJson @("approve", [string]$request.id) | Out-Null
  $script:Notify.ShowBalloonTip(2500, "s-gw", "Approved $($request.id)", [System.Windows.Forms.ToolTipIcon]::Info)
  Update-Menu
}

function Deny-FirstPending {
  $pending = Get-PendingRequests
  if ($pending.Count -eq 0) {
    return
  }
  $request = $pending[$pending.Count - 1]
  Invoke-CliJson @("deny", [string]$request.id) | Out-Null
  $script:Notify.ShowBalloonTip(2500, "s-gw", "Denied $($request.id)", [System.Windows.Forms.ToolTipIcon]::Info)
  Update-Menu
}

function Update-Menu {
  $pending = Get-PendingRequests
  $count = $pending.Count
  $script:Menu.Items.Clear()

  $status = if ($script:LastError) { "s-gw helper - check setup" } elseif ($count -eq 1) { "1 approval waiting" } else { "$count approvals waiting" }
  Add-MenuItem $script:Menu $status $null $false | Out-Null
  [void]$script:Menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))

  Add-MenuItem $script:Menu "Open s-gw" { Start-Client } | Out-Null
  Add-MenuItem $script:Menu "Approve Queue" { Start-Client "approvals" } | Out-Null
  Add-MenuItem $script:Menu "Refresh" { $script:LastError = ""; Update-Menu } | Out-Null
  Add-MenuItem $script:Menu "Approve oldest request" { Approve-FirstPending } ($count -gt 0) | Out-Null
  Add-MenuItem $script:Menu "Deny oldest request" { Deny-FirstPending } ($count -gt 0) | Out-Null
  [void]$script:Menu.Items.Add((New-Object System.Windows.Forms.ToolStripSeparator))
  Add-MenuItem $script:Menu "Quit helper" {
    $script:Timer.Stop()
    $script:Notify.Visible = $false
    $script:Notify.Dispose()
    [System.Windows.Forms.Application]::Exit()
  } | Out-Null

  $script:Notify.Text = if ($count -gt 0) { "s-gw - $count approval(s) waiting" } else { "s-gw - no pending approvals" }
  if ($script:LastPendingCount -ge 0 -and $count -gt $script:LastPendingCount) {
    $script:Notify.ShowBalloonTip(3000, "s-gw approval required", "$count request(s) waiting for local approval.", [System.Windows.Forms.ToolTipIcon]::Info)
  }
  $script:LastPendingCount = $count
}

$script:CliPath = Resolve-CliPath
$script:NodePath = Resolve-NodePath
$script:BaseConsoleUrl = New-ConsoleUrl
$script:LastError = ""
$script:LastPendingCount = -1

[System.Windows.Forms.Application]::EnableVisualStyles()
$script:Menu = New-Object System.Windows.Forms.ContextMenuStrip
$script:Notify = New-Object System.Windows.Forms.NotifyIcon
$script:Notify.Icon = [System.Drawing.SystemIcons]::Shield
$script:Notify.Text = "s-gw"
$script:Notify.Visible = $true
$script:Notify.ContextMenuStrip = $script:Menu
$script:Notify.Add_DoubleClick({ Start-Client "approvals" })

$script:Timer = New-Object System.Windows.Forms.Timer
$script:Timer.Interval = 15000
$script:Timer.Add_Tick({ Update-Menu })

Update-Menu
$script:Timer.Start()
[System.Windows.Forms.Application]::Run()
