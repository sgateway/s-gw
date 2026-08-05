import { randomUUID } from "node:crypto";
import { access, cp, copyFile, mkdir, realpath, rm, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

if (process.platform !== "win32") {
  throw new Error("The private Windows test runner is only available on Windows.");
}

const sourceRoot = await realpath(path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."));
try {
  await Promise.all([
    access(path.join(sourceRoot, "dist", "cli.js")),
    access(path.join(sourceRoot, "node_modules", "vitest", "vitest.mjs"))
  ]);
} catch {
  throw new Error("The Windows test runner requires a complete checkout. Run `npm ci --ignore-scripts` and `npm run build` first.");
}
const localAppData = process.env.LOCALAPPDATA?.trim() || path.join(os.homedir(), "AppData", "Local");
const tempParent = path.join(localAppData, "Temp");
await mkdir(tempParent, { recursive: true });

const runRoot = path.join(tempParent, `sgw-windows-ci-${randomUUID()}`);
const stagedRoot = path.join(runRoot, "source");
const privateNode = path.join(runRoot, "node.exe");
let testResult;
let cleanupError;

try {
  createPrivateDirectory(runRoot);
  await cp(sourceRoot, stagedRoot, {
    recursive: true,
    filter: (_source, destination) => {
      const relative = path.relative(stagedRoot, destination);
      if (!relative) return true;
      const first = relative.split(path.sep)[0];
      return first !== ".git" && first !== "node_modules";
    }
  });
  await copyFile(process.execPath, privateNode);
  await symlink(path.join(sourceRoot, "node_modules"), path.join(stagedRoot, "node_modules"), "junction");

  const vitest = path.join(stagedRoot, "node_modules", "vitest", "vitest.mjs");
  testResult = spawnSync(privateNode, [vitest, "run", "--no-file-parallelism"], {
    cwd: stagedRoot,
    env: process.env,
    stdio: "inherit",
    windowsHide: true
  });
} finally {
  try {
    await rm(runRoot, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 });
  } catch (error) {
    cleanupError = error;
  }
}

if (testResult?.error) {
  throw combinedFailure(testResult.error, cleanupError);
}
if (testResult?.status !== 0) {
  if (cleanupError) {
    throw combinedFailure(new Error(`Windows tests exited with status ${testResult?.status ?? "unknown"}.`), cleanupError);
  }
  process.exitCode = testResult?.status || 1;
} else if (cleanupError) {
  throw cleanupError;
}

function combinedFailure(testError, cleanup) {
  if (!cleanup) return testError;
  const cleanupMessage = cleanup instanceof Error ? cleanup.message : String(cleanup);
  return new Error(`${testError.message} Private test cleanup also failed: ${cleanupMessage}`);
}

function createPrivateDirectory(target) {
  const script = String.raw`
$ErrorActionPreference = 'Stop'
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$systemSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$full = [System.Security.AccessControl.FileSystemRights]::FullControl
$inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$none = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($identity.User)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($identity.User, $full, $inherit, $none, $allow))
if ($identity.User.Value -ne $systemSid.Value) {
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($systemSid, $full, $inherit, $none, $allow))
}
$null = [System.IO.Directory]::CreateDirectory($env:SGW_WINDOWS_PRIVATE_TEST_ROOT, $acl)
`;
  const encoded = Buffer.from(script, "utf16le").toString("base64");
  const systemRoot = process.env.SystemRoot?.trim() || process.env.WINDIR?.trim();
  if (!systemRoot || !path.isAbsolute(systemRoot)) {
    throw new Error("A trusted Windows system root is required for the private test runner.");
  }
  const powershell = path.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const result = spawnSync(powershell, [
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-ExecutionPolicy", "Bypass",
    "-EncodedCommand", encoded
  ], {
    cwd: path.dirname(powershell),
    encoding: "utf8",
    env: { ...process.env, SGW_WINDOWS_PRIVATE_TEST_ROOT: target },
    stdio: ["ignore", "pipe", "pipe"],
    timeout: 30_000,
    windowsHide: true
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || "").trim() || "Could not create the private Windows test root.");
  }
}
