import { spawn } from "node:child_process";
import path from "node:path";
import { trustedWindowsPowerShellSync, windowsSystemEnvironment } from "./windows-system.js";

const systemSid = "S-1-5-18";
const administratorsSid = "S-1-5-32-544";
const trustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const trustedOwners = [systemSid, administratorsSid, trustedInstallerSid];
const addChildRights = 0x00000004 | 0x00000002;
const unsafeRights = 0x10000000 | 0x40000000 | 0x01000000 | 0x00010000 |
  0x00040000 | 0x00080000 | 0x00000100 | 0x00000040 | 0x00000010;
const inheritOnlyAce = 0x08;
const inheritFlags = 0x01 | 0x02;
const supportedAceFlags = 0x01 | 0x02 | 0x04 | 0x08 | 0x10;

export interface WindowsHelperAclSnapshot {
  path: string;
  sha256: string;
  localFixedDrive: boolean;
  entries: Array<{
    path: string;
    kind: "directory" | "file";
    reparsePoint: boolean;
    ownerSid: string;
    daclPresent: boolean;
    aces: Array<{ type: string; sid: string; mask: number; flags: number }>;
  }>;
}

const inspectScript = String.raw`
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)

$inputPath = $env:SGW_PEER_HELPER_PATH
$fullPath = [System.IO.Path]::GetFullPath($inputPath)
$root = [System.IO.Path]::GetPathRoot($fullPath)
$localFixedDrive = $fullPath -cmatch '^[A-Za-z]:\\' -and
    [System.IO.DriveInfo]::new($root).DriveType -eq [System.IO.DriveType]::Fixed
if (-not $localFixedDrive) { throw 'The peer helper must be on a local fixed drive.' }
$sections = [System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner
$entries = New-Object 'System.Collections.Generic.List[object]'
$cursor = $fullPath
while ($true) {
  $attributes = [System.IO.File]::GetAttributes($cursor)
  if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'The peer helper path contains a reparse point.'
  }
  $isDirectory = ($attributes -band [System.IO.FileAttributes]::Directory) -ne 0
  $acl = if ($isDirectory) {
    [System.IO.Directory]::GetAccessControl($cursor, $sections)
  } else {
    [System.IO.File]::GetAccessControl($cursor, $sections)
  }
  $raw = [System.Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
  $aces = New-Object 'System.Collections.Generic.List[object]'
  if ($raw.DiscretionaryAcl) {
    foreach ($ace in $raw.DiscretionaryAcl) {
      if ($ace -isnot [System.Security.AccessControl.CommonAce]) {
        throw 'Unsupported helper-path access rule.'
      }
      $aces.Add(@{
        type = $ace.AceType.ToString()
        sid = $ace.SecurityIdentifier.Value
        mask = ([int64]$ace.AccessMask -band [int64]4294967295)
        flags = [int]$ace.AceFlags
      })
    }
  }
  $entries.Add(@{
    path = $cursor
    kind = $(if ($isDirectory) { 'directory' } else { 'file' })
    reparsePoint = (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
    ownerSid = $raw.Owner.Value
    daclPresent = (($raw.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) -ne 0 -and $null -ne $raw.DiscretionaryAcl)
    aces = @($aces.ToArray())
  })
  if ([string]::Equals($cursor, $root, [System.StringComparison]::OrdinalIgnoreCase)) { break }
  $cursor = [System.IO.Directory]::GetParent($cursor).FullName
}
$stream = [System.IO.File]::Open($fullPath, [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
try {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { $hash = [BitConverter]::ToString($sha.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
  finally { $sha.Dispose() }
} finally { $stream.Dispose() }
@{
  path = $fullPath
  sha256 = $hash
  localFixedDrive = $localFixedDrive
  entries = @($entries.ToArray())
} | ConvertTo-Json -Compress -Depth 8
`;

export function assessWindowsPeerHelperAcl(
  snapshot: WindowsHelperAclSnapshot,
  helperPath: string,
  expectedSha256: string
): void {
  const expectedPaths = helperPathChain(helperPath);
  if (!/^[a-f0-9]{64}$/i.test(expectedSha256) || !snapshot.localFixedDrive ||
      !samePath(snapshot.path, helperPath) ||
      snapshot.sha256.toLowerCase() !== expectedSha256.toLowerCase() ||
      snapshot.entries.length !== expectedPaths.length) {
    throw new Error("Windows peer helper has no matching installer attestation.");
  }

  for (let index = 0; index < expectedPaths.length; index++) {
    const entry = snapshot.entries[index];
    if (!entry || !samePath(entry.path, expectedPaths[index]) || entry.reparsePoint ||
        entry.kind !== (index === 0 ? "file" : "directory") || !entry.daclPresent ||
        !trustedOwners.includes(entry.ownerSid) || !Array.isArray(entry.aces)) {
      throw new Error("Windows peer helper or an ancestor is replaceable.");
    }
    for (const ace of entry.aces) {
      if (!["AccessAllowed", "AccessDenied"].includes(ace.type) || !Number.isInteger(ace.mask) ||
          ace.mask < 0 || ace.mask > 0xffffffff || typeof ace.sid !== "string") {
        throw new Error("Windows peer helper has an unsupported access rule.");
      }
      if (!Number.isInteger(ace.flags) || ace.flags < 0 || (ace.flags & ~supportedAceFlags) !== 0 ||
          ((ace.flags & inheritOnlyAce) !== 0 && (ace.flags & inheritFlags) === 0)) {
        throw new Error("Windows peer helper has unsupported inheritance flags.");
      }
      if (ace.type === "AccessDenied" || (ace.flags & inheritOnlyAce) !== 0 ||
          trustedOwners.includes(ace.sid)) continue;
      const forbidden = unsafeRights | (index < 2 ? addChildRights : 0);
      if ((ace.mask & forbidden) !== 0) {
        throw new Error("Windows peer helper or an ancestor grants agent-writable access.");
      }
    }
  }
}

export async function inspectWindowsPeerHelperAcl(
  helperPath: string,
  expectedSha256: string
): Promise<void> {
  if (process.platform !== "win32") throw new Error("Windows helper ACL inspection requires Windows.");
  helperPathChain(helperPath);
  const powershell = trustedWindowsPowerShellSync();
  const env = windowsSystemEnvironment({ SGW_PEER_HELPER_PATH: helperPath });
  const child = spawn(powershell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand",
    Buffer.from(inspectScript, "utf16le").toString("base64")], {
    cwd: path.dirname(powershell), env, windowsHide: true, stdio: ["ignore", "pipe", "pipe"]
  });
  let output = "";
  let tooLarge = false;
  child.stdout.on("data", (chunk: Buffer) => {
    if (tooLarge) return;
    if (output.length + chunk.length > 64 * 1024) {
      tooLarge = true;
      child.kill();
      return;
    }
    output += chunk.toString("utf8");
  });
  child.stderr.on("data", () => {});
  let timedOut = false;
  const timeout = setTimeout(() => { timedOut = true; child.kill(); }, 30_000);
  const status = await new Promise<number | null>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", code => resolve(code));
  }).finally(() => clearTimeout(timeout));
  if (timedOut || tooLarge || status !== 0) {
    throw new Error("Windows peer helper ACL inspection failed.");
  }
  let snapshot: WindowsHelperAclSnapshot;
  try {
    snapshot = JSON.parse(output) as WindowsHelperAclSnapshot;
  } catch {
    throw new Error("Windows peer helper ACL inspection returned invalid data.");
  }
  assessWindowsPeerHelperAcl(snapshot, helperPath, expectedSha256);
}

function helperPathChain(input: string): string[] {
  if (!/^[A-Za-z]:\\/.test(input) || input.slice(2).includes(":") ||
      path.win32.basename(input).toLowerCase() !== "s-gw-windows-peer-identity.exe" ||
      !samePath(path.win32.normalize(input), input) ||
      input.slice(3).split("\\").some(part => !part || part === "." || part === ".." || /[. ]$/.test(part))) {
    throw new Error("Windows peer helper needs a canonical local executable path.");
  }
  const paths = [input];
  const root = path.win32.parse(input).root;
  let cursor = input;
  while (!samePath(cursor, root)) {
    cursor = path.win32.dirname(cursor);
    paths.push(cursor);
  }
  return paths;
}

function samePath(left: string, right: string): boolean {
  return left.toLowerCase() === right.toLowerCase();
}
