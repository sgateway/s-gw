import { spawn } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import path from "node:path";

const ACL_TIMEOUT_MS = 10_000;
const WINDOWS_GLOBAL_SYSTEM_ROOT = String.raw`\\?\GLOBALROOT\SystemRoot`;

const WINDOWS_ACL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$OutputEncoding = [Console]::OutputEncoding

$mode = $env:SGW_WINDOWS_ACL_MODE
$target = [System.IO.Path]::GetFullPath($env:SGW_WINDOWS_ACL_PATH)
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentSid = $identity.User.Value
$systemSid = 'S-1-5-18'

if ((New-Object System.Uri($target)).IsUnc) {
  throw 'The SSH temporary path must not use a UNC location.'
}
$volumeRoot = [System.IO.Path]::GetPathRoot($target)
$volume = New-Object System.IO.DriveInfo($volumeRoot)
if ($volume.DriveType -ne [System.IO.DriveType]::Fixed) {
  throw 'The SSH temporary path must use a fixed local volume.'
}

if ($env:SGW_WINDOWS_ACL_EXPECTED_SID -and $env:SGW_WINDOWS_ACL_EXPECTED_SID -ne $currentSid) {
  throw 'The Windows identity changed while preparing the SSH key.'
}

if ($mode -eq 'apply-directory') {
  if (-not [System.IO.Directory]::Exists($target)) {
    throw 'The SSH temporary directory does not exist.'
  }
  $dirInfo = [System.IO.DirectoryInfo]::new($target)
  if (($dirInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $dirInfo.FullName -ne $target) {
    throw 'The SSH temporary directory is not a stable local directory.'
  }

  $acl = [System.Security.AccessControl.DirectorySecurity]::new()
  $acl.SetAccessRuleProtection($true, $false)
  $acl.SetOwner($identity.User)
  $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $propagation = [System.Security.AccessControl.PropagationFlags]::None
  $allow = [System.Security.AccessControl.AccessControlType]::Allow
  $full = [System.Security.AccessControl.FileSystemRights]::FullControl
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($identity.User, $full, $inherit, $propagation, $allow))
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new($systemSid), $full, $inherit, $propagation, $allow))
  $dirInfo.SetAccessControl($acl)
}

if ($mode -eq 'verify-file') {
  if (-not [System.IO.File]::Exists($target)) {
    throw 'The SSH private-key file does not exist.'
  }
  $fileInfo = [System.IO.FileInfo]::new($target)
  if (($fileInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $fileInfo.FullName -ne $target) {
    throw 'The SSH private-key path is not a stable local file.'
  }
  $acl = $fileInfo.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner)
} elseif ($mode -eq 'apply-directory' -or $mode -eq 'verify-directory') {
  $dirInfo = [System.IO.DirectoryInfo]::new($target)
  if (($dirInfo.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $dirInfo.FullName -ne $target) {
    throw 'The SSH temporary directory is not a stable local directory.'
  }
  $acl = $dirInfo.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access -bor [System.Security.AccessControl.AccessControlSections]::Owner)
  if (-not $acl.AreAccessRulesProtected) {
    throw 'The SSH temporary directory still inherits access rules.'
  }
} else {
  throw 'Unsupported Windows ACL operation.'
}

$ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
if ($ownerSid -ne $currentSid) {
  throw ('The SSH temporary path owner is not the current Windows identity: ' + $ownerSid)
}

$rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
$currentSeen = $false
foreach ($rule in $rules) {
  $sid = $rule.IdentityReference.Value
  if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) {
    throw 'The SSH temporary path contains a non-allow access rule.'
  }
  if ($sid -ne $currentSid -and $sid -ne $systemSid) {
    throw ('The SSH temporary path grants access to an unexpected identity: ' + $sid)
  }
  if (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne [System.Security.AccessControl.FileSystemRights]::FullControl) {
    throw ('The SSH temporary path has an incomplete access rule for ' + $sid)
  }
  if ($sid -eq $currentSid) {
    $currentSeen = $true
  }
}

if (-not $currentSeen) {
  throw 'The current Windows identity does not control the SSH temporary path.'
}

[Console]::Out.WriteLine('{"verified":true,"sid":"' + $currentSid + '","rules":' + $rules.Count + '}')
`;

export async function applyPrivateWindowsDirectoryAcl(dirPath: string): Promise<string> {
  const result = await runAclOperation("apply-directory", dirPath);
  return result.sid;
}

export async function verifyPrivateWindowsKeyFile(filePath: string, expectedSid: string): Promise<void> {
  await runAclOperation("verify-file", filePath, expectedSid);
  await runAclOperation("verify-directory", path.dirname(filePath), expectedSid);
}

interface AclResult {
  verified: true;
  sid: string;
  rules: number;
}

async function runAclOperation(mode: string, target: string, expectedSid?: string): Promise<AclResult> {
  const systemRoot = await trustedWindowsSystemRoot();
  const powershell = await trustedWindowsSystemExecutableAtRoot(
    systemRoot,
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe"
  );
  const encoded = Buffer.from(WINDOWS_ACL_SCRIPT, "utf16le").toString("base64");
  const env = windowsSystemEnv(systemRoot);
  env.SGW_WINDOWS_ACL_MODE = mode;
  env.SGW_WINDOWS_ACL_PATH = target;
  if (expectedSid) {
    env.SGW_WINDOWS_ACL_EXPECTED_SID = expectedSid;
  }

  const child = spawn(powershell, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-EncodedCommand", encoded
  ], {
    env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true
  });

  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    stdout = appendSmall(stdout, chunk.toString("utf8"));
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = appendSmall(stderr, chunk.toString("utf8"));
  });

  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    child.kill("SIGKILL");
  }, ACL_TIMEOUT_MS);
  const status = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  }).finally(() => clearTimeout(timeout));

  if (timedOut) {
    throw new Error("Timed out while securing the Windows SSH private-key path.");
  }
  if (status.code !== 0) {
    const detail = (stderr || stdout).trim();
    throw new Error(`Could not secure the Windows SSH private-key path${detail ? `: ${detail}` : "."}`);
  }

  const line = stdout.trim().split(/\r?\n/).filter(Boolean).at(-1) || "";
  let parsed: unknown;
  try {
    parsed = JSON.parse(line);
  } catch {
    throw new Error("Windows ACL verification returned an invalid response.");
  }
  if (!isAclResult(parsed) || (expectedSid && parsed.sid !== expectedSid)) {
    throw new Error("Windows ACL verification did not confirm the current user boundary.");
  }
  return parsed;
}

export async function trustedWindowsSystemExecutable(...parts: string[]): Promise<string> {
  const systemRoot = await trustedWindowsSystemRoot();
  return trustedWindowsSystemExecutableAtRoot(systemRoot, ...parts);
}

export async function trustedWindowsSystemRoot(): Promise<string> {
  if (path.sep !== "\\") {
    return simulatedWindowsSystemRoot();
  }

  const info = await lstat(WINDOWS_GLOBAL_SYSTEM_ROOT).catch(() => undefined);
  if (!info?.isDirectory()) {
    throw new Error("The kernel-anchored Windows system directory is unavailable.");
  }
  const systemRoot = await realpath(WINDOWS_GLOBAL_SYSTEM_ROOT).catch(() => "");
  if (!systemRoot || !path.isAbsolute(systemRoot)) {
    throw new Error("The kernel-anchored Windows system directory could not be resolved.");
  }
  return systemRoot;
}

async function simulatedWindowsSystemRoot(): Promise<string> {
  if (process.env.SGW_TEST_MODE !== "1") {
    throw new Error("A simulated Windows system directory is allowed only in isolated test mode.");
  }
  const systemRoot = process.env.SystemRoot?.trim();
  const winDir = process.env.WINDIR?.trim();
  if (!systemRoot || !winDir) {
    throw new Error("Windows SystemRoot and WINDIR are required to test SSH private-key protection.");
  }
  const resolvedRoot = path.resolve(systemRoot);
  if (!sameWindowsPath(resolvedRoot, path.resolve(winDir))) {
    throw new Error("Windows SystemRoot and WINDIR do not identify the same test directory.");
  }
  const realRoot = await realpath(resolvedRoot).catch(() => "");
  if (!realRoot || !sameWindowsPath(realRoot, resolvedRoot)) {
    throw new Error("The simulated Windows system directory could not be validated.");
  }
  return realRoot;
}

async function trustedWindowsSystemExecutableAtRoot(systemRoot: string, ...parts: string[]): Promise<string> {
  const candidate = path.join(systemRoot, "System32", ...parts);
  const info = await lstat(candidate).catch(() => undefined);
  if (!info?.isFile() || info.isSymbolicLink()) {
    throw new Error("A required trusted Windows system executable is unavailable; refusing to materialize the SSH key.");
  }

  const realCandidate = await realpath(candidate).catch(() => "");
  if (!realCandidate || !sameWindowsPath(realCandidate, candidate)) {
    throw new Error("Trusted Windows system executable path validation failed; refusing to materialize the SSH key.");
  }
  return realCandidate;
}

function windowsSystemEnv(systemRoot: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    SystemRoot: systemRoot,
    WINDIR: systemRoot,
    PATH: `${path.join(systemRoot, "System32")};${systemRoot}`
  };
  for (const key of ["USERPROFILE", "TEMP", "TMP"]) {
    const value = process.env[key];
    if (value) {
      env[key] = value;
    }
  }
  return env;
}

function isAclResult(value: unknown): value is AclResult {
  if (!value || typeof value !== "object") {
    return false;
  }
  const result = value as Partial<AclResult>;
  return result.verified === true
    && typeof result.sid === "string"
    && /^S-\d+(?:-\d+)+$/.test(result.sid)
    && Number.isInteger(result.rules)
    && Number(result.rules) >= 1
    && Number(result.rules) <= 2;
}

function sameWindowsPath(left: string, right: string): boolean {
  return path.normalize(left).replace(/[\\/]+$/, "").toLowerCase()
    === path.normalize(right).replace(/[\\/]+$/, "").toLowerCase();
}

function appendSmall(current: string, chunk: string): string {
  const combined = current + chunk;
  return Buffer.byteLength(combined, "utf8") <= 8_192 ? combined : combined.slice(0, 8_192);
}
