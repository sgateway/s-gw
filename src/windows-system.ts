import { lstatSync, realpathSync } from "node:fs";
import path from "node:path";

const WINDOWS_GLOBAL_SYSTEM_ROOT = String.raw`\\?\GLOBALROOT\SystemRoot`;

export function trustedWindowsSystemRootSync(): string {
  if (process.env.SGW_TEST_MODE === "1" || path.sep !== "\\") {
    return simulatedWindowsSystemRoot();
  }

  let info;
  try {
    info = lstatSync(WINDOWS_GLOBAL_SYSTEM_ROOT);
  } catch {
    throw new Error("The kernel-anchored Windows system directory is unavailable.");
  }
  if (!info.isDirectory() || info.isSymbolicLink()) {
    throw new Error("The kernel-anchored Windows system directory is unavailable.");
  }

  return WINDOWS_GLOBAL_SYSTEM_ROOT;
}

export function trustedWindowsSystemExecutableSync(...parts: string[]): string {
  const systemRoot = trustedWindowsSystemRootSync();
  const candidate = path.join(systemRoot, "System32", ...parts);
  let info;
  try {
    info = lstatSync(candidate);
  } catch {
    throw new Error("A required trusted Windows system executable is unavailable.");
  }
  if (!info.isFile() || info.isSymbolicLink()) {
    throw new Error("A required trusted Windows system executable is unavailable.");
  }

  if (path.sep === "\\" && sameWindowsPath(systemRoot, WINDOWS_GLOBAL_SYSTEM_ROOT)) {
    return candidate;
  }

  let realCandidate = "";
  try {
    realCandidate = realpathSync(candidate);
  } catch {
    // Fail below without attempting PATH fallback.
  }
  if (!realCandidate || !sameWindowsPath(realCandidate, candidate)) {
    throw new Error("Trusted Windows system executable path validation failed.");
  }
  return realCandidate;
}

export function trustedWindowsPowerShellSync(): string {
  return trustedWindowsSystemExecutableSync("WindowsPowerShell", "v1.0", "powershell.exe");
}

export function windowsSystemEnvironment(extra: NodeJS.ProcessEnv = {}): NodeJS.ProcessEnv {
  const systemRoot = trustedWindowsSystemRootSync();
  const env: NodeJS.ProcessEnv = {
    SystemRoot: systemRoot,
    WINDIR: systemRoot,
    PATH: `${path.join(systemRoot, "System32")};${systemRoot}`
  };
  for (const key of [
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "USERDOMAIN",
    "USERNAME",
    "USERPROFILE"
  ]) {
    const value = process.env[key];
    if (value) env[key] = value;
  }
  for (const [key, value] of Object.entries(extra)) {
    if (value === undefined) continue;
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)
      || value.length > 8_192
      || /[\0\r\n]/.test(value)) {
      throw new Error(`Invalid bounded Windows child environment value: ${key}`);
    }
    if (["PATH", "SYSTEMROOT", "WINDIR"].includes(key.toUpperCase())) {
      throw new Error(`Windows child environment cannot override trusted ${key}.`);
    }
    env[key] = value;
  }
  return env;
}

function simulatedWindowsSystemRoot(): string {
  if (process.env.SGW_TEST_MODE !== "1") {
    throw new Error("A simulated Windows system directory is allowed only in isolated test mode.");
  }
  const systemRoot = process.env.SystemRoot?.trim();
  const winDir = process.env.WINDIR?.trim();
  if (!systemRoot || !winDir) {
    throw new Error("Windows SystemRoot and WINDIR are required for Windows system-path tests.");
  }
  const resolvedRoot = path.resolve(systemRoot);
  if (!sameWindowsPath(resolvedRoot, path.resolve(winDir))) {
    throw new Error("Windows SystemRoot and WINDIR do not identify the same test directory.");
  }

  let realRoot = "";
  try {
    realRoot = realpathSync(resolvedRoot);
  } catch {
    // Fail below.
  }
  if (!realRoot || !sameWindowsPath(realRoot, resolvedRoot)) {
    throw new Error("The simulated Windows system directory could not be validated.");
  }
  return realRoot;
}

function sameWindowsPath(left: string, right: string): boolean {
  return path.normalize(left).replace(/[\\/]+$/, "").toLowerCase()
    === path.normalize(right).replace(/[\\/]+$/, "").toLowerCase();
}
