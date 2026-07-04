[CmdletBinding()]
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [ValidateSet("get", "set", "delete", "status")]
  [string]$Command,

  [Parameter(Mandatory = $true)]
  [string]$Service,

  [Parameter(Mandatory = $true)]
  [string]$Account,

  [string]$Label = "s-gw local secret"
)

$ErrorActionPreference = "Stop"

if (-not $IsWindows -and $PSVersionTable.PSEdition -eq "Core") {
  throw "Windows Credential Manager is only available on Windows."
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class SgwCredMan {
  public const UInt32 CRED_TYPE_GENERIC = 1;
  public const UInt32 CRED_PERSIST_LOCAL_MACHINE = 2;

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct CREDENTIAL {
    public UInt32 Flags;
    public UInt32 Type;
    public string TargetName;
    public string Comment;
    public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
    public UInt32 CredentialBlobSize;
    public IntPtr CredentialBlob;
    public UInt32 Persist;
    public UInt32 AttributeCount;
    public IntPtr Attributes;
    public string TargetAlias;
    public string UserName;
  }

  [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool CredRead(string target, UInt32 type, UInt32 flags, out IntPtr credentialPtr);

  [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool CredWrite(ref CREDENTIAL credential, UInt32 flags);

  [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
  public static extern bool CredDelete(string target, UInt32 type, UInt32 flags);

  [DllImport("advapi32.dll", EntryPoint = "CredFree", SetLastError = true)]
  public static extern void CredFree(IntPtr buffer);
}
"@

function Get-TargetName {
  return "s-gw/$Service/$Account"
}

function Get-LastErrorCode {
  return [Runtime.InteropServices.Marshal]::GetLastWin32Error()
}

function Throw-Win32([string]$Action) {
  $code = Get-LastErrorCode
  $message = (New-Object ComponentModel.Win32Exception($code)).Message
  throw "$Action failed ($code): $message"
}

function Read-CredentialValue([string]$Target) {
  $ptr = [IntPtr]::Zero
  if (-not [SgwCredMan]::CredRead($Target, [SgwCredMan]::CRED_TYPE_GENERIC, 0, [ref]$ptr)) {
    $code = Get-LastErrorCode
    if ($code -eq 1168) {
      exit 44
    }
    Throw-Win32 "CredRead"
  }

  try {
    $cred = [Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][SgwCredMan+CREDENTIAL])
    $bytes = New-Object byte[] $cred.CredentialBlobSize
    [Runtime.InteropServices.Marshal]::Copy($cred.CredentialBlob, $bytes, 0, $bytes.Length)
    return [Text.Encoding]::Unicode.GetString($bytes).TrimEnd([char]0)
  } finally {
    [SgwCredMan]::CredFree($ptr)
  }
}

function Test-CredentialValue([string]$Target) {
  $ptr = [IntPtr]::Zero
  if (-not [SgwCredMan]::CredRead($Target, [SgwCredMan]::CRED_TYPE_GENERIC, 0, [ref]$ptr)) {
    return $false
  }

  [SgwCredMan]::CredFree($ptr)
  return $true
}

function Write-CredentialValue([string]$Target, [string]$Value) {
  if (-not $Value) {
    throw "Cannot store an empty Credential Manager value."
  }

  $bytes = [Text.Encoding]::Unicode.GetBytes($Value)
  $pinned = [Runtime.InteropServices.GCHandle]::Alloc($bytes, [Runtime.InteropServices.GCHandleType]::Pinned)

  try {
    $cred = New-Object "SgwCredMan+CREDENTIAL"
    $cred.Type = [SgwCredMan]::CRED_TYPE_GENERIC
    $cred.TargetName = $Target
    $cred.Comment = $Label
    $cred.CredentialBlobSize = [uint32]$bytes.Length
    $cred.CredentialBlob = $pinned.AddrOfPinnedObject()
    $cred.Persist = [SgwCredMan]::CRED_PERSIST_LOCAL_MACHINE
    $cred.UserName = "$env:USERDOMAIN\$env:USERNAME"

    if (-not [SgwCredMan]::CredWrite([ref]$cred, 0)) {
      Throw-Win32 "CredWrite"
    }
  } finally {
    $pinned.Free()
  }
}

function Remove-CredentialValue([string]$Target) {
  if ([SgwCredMan]::CredDelete($Target, [SgwCredMan]::CRED_TYPE_GENERIC, 0)) {
    return $true
  }

  $code = Get-LastErrorCode
  if ($code -eq 1168) {
    return $false
  }
  Throw-Win32 "CredDelete"
}

$target = Get-TargetName

switch ($Command) {
  "get" {
    [Console]::Out.Write((Read-CredentialValue $target))
    break
  }
  "set" {
    $value = [Console]::In.ReadToEnd()
    Write-CredentialValue -Target $target -Value $value
    break
  }
  "delete" {
    $deleted = Remove-CredentialValue $target
    [Console]::Out.WriteLine((@{ deleted = $deleted } | ConvertTo-Json -Compress))
    break
  }
  "status" {
    [Console]::Out.WriteLine((@{
      supported = $true
      target = $target
      configured = Test-CredentialValue $target
    } | ConvertTo-Json -Compress))
    break
  }
}
