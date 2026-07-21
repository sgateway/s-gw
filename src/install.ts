import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  accessSync,
  constants,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync
} from "node:fs";
import { mkdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getSgwHome, getStorePath } from "./paths.js";
import {
  isInstalledMacAppLocation,
  isSelfContainedMacApp,
  resolveSelfContainedMacRuntime
} from "./self-contained-runtime.js";
import { unlockStatus } from "./unlock.js";
import { CURRENT_VERSION } from "./version.js";

export const consoleLabel = "com.s-gw.sgw.console";
export const menuBarLabel = "com.s-gw.sgw.menubar";

export interface PackageLayout {
  packageRoot: string;
  nodePath: string;
  isSelfContainedMacApp: boolean;
  standaloneMacAppInstalled: boolean;
  cliPath: string;
  mcpPath: string;
  keychainHelperPath: string;
  packagedMacAppPath: string;
  packagedMacAppBinaryPath: string;
  installedMacAppPath: string;
  macAppPath: string;
  macAppBinaryPath: string;
  menuBarAppPath: string;
  menuBarBinaryPath: string;
  windowsClientScriptPath: string;
  windowsClientLauncherPath: string;
  windowsHelperScriptPath: string;
  windowsHelperLauncherPath: string;
  windowsCredentialHelperPath: string;
}

export interface LaunchAgentStatus {
  label: string;
  plistPath: string;
  installed: boolean;
  loaded: boolean;
}

interface LaunchAgentDefinition {
  label: string;
  programArguments: string[];
  environment: Record<string, string>;
  runAtLoad: boolean;
  keepAlive: boolean;
  stdoutPath: string;
  stderrPath: string;
  limitToAqua?: boolean;
}

export interface ServiceInstallOptions {
  port?: number;
  start?: boolean;
}

export interface MenuBarOptions {
  consoleUrl?: string;
  port?: number;
  start?: boolean;
  show?: boolean;
  notify?: boolean;
  countMode?: MenuBarCountMode;
}

export type MenuBarCountMode = "pending" | "credentials" | "none";

export interface MacAppProcessInfo {
  pid: number;
  source: "record" | "process-list";
  alive: boolean;
  recordPath?: string;
  bundleIdentifier?: string;
  bundlePath?: string;
  executablePath?: string;
  command?: string;
  startedAt?: string;
  updatedAt?: string;
  otherPids?: number[];
}

export interface MacAppOpenResult {
  appPath: string;
  consoleUrl: string;
  reusedExisting: boolean;
  process?: MacAppProcessInfo;
}

export interface MacAppInstallResult {
  appPath: string;
  sourcePath: string;
  changed: boolean;
}

export interface MacAppInstallOptions {
  applicationsDir?: string;
  registerCliPath?: boolean;
}

export interface WindowsOpenResult {
  scriptPath: string;
  launcherPath: string;
  consoleUrl: string;
  pid?: number;
}

export interface WindowsStoppedSurfaces {
  pids: number[];
  console: boolean;
  helper: boolean;
  client: boolean;
}

export interface WindowsRestartResult {
  console?: WindowsOpenResult;
  helper?: WindowsOpenResult;
  client?: WindowsOpenResult;
}

export function getPackageLayout(): PackageLayout {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const packageRoot = path.basename(here) === "dist" ? path.dirname(here) : path.dirname(here);
  const nativeTarget = `${process.platform}-${process.arch}`;
  const runtime = resolveSelfContainedMacRuntime(packageRoot);
  const packagedMacAppPath = runtime?.appPath || path.join(packageRoot, "dist", "s-gw.app");
  const standaloneAppPath = runtime ? undefined : findInstalledSelfContainedMacApp();
  const installedMacAppPath = runtime?.appPath || standaloneAppPath || path.join(macApplicationsDirectory(), "s-gw.app");
  const macAppPath = runtime?.appPath || (existsSync(installedMacAppPath) ? installedMacAppPath : packagedMacAppPath);
  const menuBarAppPath = runtime?.menuBarAppPath || path.join(packageRoot, "dist", "s-gw Menu Bar.app");

  return {
    packageRoot,
    nodePath: runtime?.nodePath || process.execPath,
    isSelfContainedMacApp: runtime !== undefined,
    standaloneMacAppInstalled: runtime !== undefined || standaloneAppPath !== undefined,
    cliPath: runtime?.cliPath || path.join(packageRoot, "dist", "cli.js"),
    mcpPath: runtime?.mcpPath || path.join(packageRoot, "dist", "mcp-server.js"),
    keychainHelperPath: path.join(packageRoot, "dist", "native", nativeTarget, "s-gw-keychain-helper"),
    packagedMacAppPath,
    packagedMacAppBinaryPath: macAppBinaryPath(packagedMacAppPath),
    installedMacAppPath,
    macAppPath,
    macAppBinaryPath: macAppBinaryPath(macAppPath),
    menuBarAppPath,
    menuBarBinaryPath: path.join(
      menuBarAppPath,
      "Contents",
      "MacOS",
      "s-gw-menu-bar-helper"
    ),
    windowsClientScriptPath: path.join(packageRoot, "dist", "windows", "s-gw-client.ps1"),
    windowsClientLauncherPath: path.join(packageRoot, "dist", "windows", "s-gw-client.cmd"),
    windowsHelperScriptPath: path.join(packageRoot, "dist", "windows", "s-gw-helper.ps1"),
    windowsHelperLauncherPath: path.join(packageRoot, "dist", "windows", "s-gw-helper.cmd"),
    windowsCredentialHelperPath: path.join(packageRoot, "dist", "windows", "s-gw-credential.ps1")
  };
}

export function packageHealth(port = 8718) {
  const layout = getPackageLayout();
  const unlock = unlockStatus();
  const cli = pathStatus(layout.cliPath);
  const mcp = pathStatus(layout.mcpPath);

  // "Ready" means a fresh user could actually store and redeem a secret: the CLI/MCP
  // entry points exist and there is some unlock source. Without this, `status` looked
  // healthy (every path exists) even when the encrypted ledger could not be unlocked.
  const unlockConfigured = unlock.activeSource !== "none";
  const ready = unlockConfigured && cli.exists && mcp.exists;

  return {
    version: CURRENT_VERSION,
    packageRoot: layout.packageRoot,
    selfContainedMacApp: layout.isSelfContainedMacApp,
    nodePath: pathStatus(layout.nodePath),
    ready,
    readiness: buildReadiness({ unlockConfigured, cli: cli.exists, mcp: mcp.exists }),
    cliPath: cli,
    mcpPath: mcp,
    keychainHelperPath: pathStatus(layout.keychainHelperPath),
    packagedMacAppPath: pathStatus(layout.packagedMacAppPath),
    installedMacAppPath: pathStatus(layout.installedMacAppPath),
    macAppPath: pathStatus(layout.macAppPath),
    macAppBinaryPath: pathStatus(layout.macAppBinaryPath),
    menuBarAppPath: pathStatus(layout.menuBarAppPath),
    menuBarBinaryPath: pathStatus(layout.menuBarBinaryPath),
    windowsClientScriptPath: pathStatus(layout.windowsClientScriptPath),
    windowsClientLauncherPath: pathStatus(layout.windowsClientLauncherPath),
    windowsHelperScriptPath: pathStatus(layout.windowsHelperScriptPath),
    windowsHelperLauncherPath: pathStatus(layout.windowsHelperLauncherPath),
    windowsCredentialHelperPath: pathStatus(layout.windowsCredentialHelperPath),
    storePath: getStorePath(),
    consoleUrl: consoleUrl(port),
    unlock,
    launchAgents: {
      console: launchAgentStatus("console"),
      menuBar: launchAgentStatus("menubar")
    }
  };
}

export interface ReadinessVerdict {
  ok: boolean;
  summary: string;
  blockers: string[];
}

// Console/native surfaces share this so the "not ready" wording stays identical
// everywhere. The console process is, by definition, running from a built package,
// so it only needs to report unlock readiness.
export function readinessForUnlock(unlockConfigured: boolean): ReadinessVerdict {
  return buildReadiness({ unlockConfigured, cli: true, mcp: true });
}

function buildReadiness(checks: { unlockConfigured: boolean; cli: boolean; mcp: boolean }): ReadinessVerdict {
  const blockers: string[] = [];
  if (!checks.cli || !checks.mcp) {
    blockers.push("Build artifacts are missing. Run `npm run build` (or reinstall the package).");
  }
  if (!checks.unlockConfigured) {
    blockers.push(
      "No local unlock material. Run `s-gw setup`, or `s-gw unlock keychain set --value-stdin`, or set SGW_MASTER_PASSPHRASE."
    );
  }

  const ok = blockers.length === 0;
  return {
    ok,
    summary: ok ? "s-gw is ready to store and redeem secrets." : "s-gw is not ready yet.",
    blockers
  };
}

export async function installConsoleLaunchAgent(options: ServiceInstallOptions = {}): Promise<LaunchAgentStatus> {
  requireMac("launchd service install");
  assertMacRuntimeForManagedSurfaces();
  const port = options.port || 8718;
  const plistPath = launchAgentPath(consoleLabel);
  const logs = await ensureLogDir();
  await writeFile(plistPath, buildConsoleLaunchAgentPlist(port, logs), { mode: 0o644 });

  if (options.start) {
    startLaunchAgent(consoleLabel, plistPath);
  }

  return launchAgentStatus("console");
}

export async function uninstallConsoleLaunchAgent(): Promise<LaunchAgentStatus> {
  requireMac("launchd service uninstall");
  stopLaunchAgent(consoleLabel);
  await rm(launchAgentPath(consoleLabel), { force: true });
  return launchAgentStatus("console");
}

export async function installMenuBarLaunchAgent(options: MenuBarOptions = {}): Promise<LaunchAgentStatus> {
  requireMac("menu-bar install");
  assertMacRuntimeForManagedSurfaces();
  assertMenuBarExists();
  const plistPath = launchAgentPath(menuBarLabel);
  const logs = await ensureLogDir();
  await writeFile(plistPath, buildMenuBarLaunchAgentPlist(options, logs), { mode: 0o644 });

  if (options.start) {
    startLaunchAgent(menuBarLabel, plistPath);
  }

  return launchAgentStatus("menubar");
}

export async function uninstallMenuBarLaunchAgent(): Promise<LaunchAgentStatus> {
  requireMac("menu-bar uninstall");
  stopLaunchAgent(menuBarLabel);
  await rm(launchAgentPath(menuBarLabel), { force: true });
  return launchAgentStatus("menubar");
}

export function startInstalledLaunchAgent(kind: "console" | "menubar"): LaunchAgentStatus {
  requireMac("launch-agent start");
  assertMacRuntimeForManagedSurfaces();
  const label = kind === "console" ? consoleLabel : menuBarLabel;
  const plistPath = launchAgentPath(label);
  if (!existsSync(plistPath)) {
    throw new Error(`LaunchAgent is not installed: ${plistPath}`);
  }

  startLaunchAgent(label, plistPath);
  return launchAgentStatus(kind);
}

export async function refreshMacRuntimeServices(): Promise<{
  console: LaunchAgentStatus;
  menuBar: LaunchAgentStatus;
}> {
  requireMac("macOS runtime refresh");
  assertMacRuntimeForManagedSurfaces();
  const console = launchAgentStatus("console");
  const menuBar = launchAgentStatus("menubar");
  return {
    console: await refreshConsoleLaunchAgent(console),
    menuBar: await refreshMenuBarLaunchAgent(menuBar)
  };
}

export function stopInstalledLaunchAgent(kind: "console" | "menubar"): LaunchAgentStatus {
  requireMac("launch-agent stop");
  stopLaunchAgent(kind === "console" ? consoleLabel : menuBarLabel);
  return launchAgentStatus(kind);
}

async function refreshConsoleLaunchAgent(status: LaunchAgentStatus): Promise<LaunchAgentStatus> {
  if (!status.installed) return status;

  const args = launchAgentProgramArguments(status.plistPath);
  const env = launchAgentEnvironment(status.plistPath);
  const port = numberAfter(args, "--port") || 8718;
  const logs = await ensureLogDir(env.SGW_HOME);
  if (status.loaded) stopLaunchAgent(consoleLabel);
  await writeFile(status.plistPath, buildConsoleLaunchAgentPlist(port, logs, env), { mode: 0o644 });
  if (status.loaded) startLaunchAgent(consoleLabel, status.plistPath);
  return launchAgentStatus("console");
}

async function refreshMenuBarLaunchAgent(status: LaunchAgentStatus): Promise<LaunchAgentStatus> {
  if (!status.installed) return status;

  const args = launchAgentProgramArguments(status.plistPath);
  const env = launchAgentEnvironment(status.plistPath);
  const logs = await ensureLogDir(env.SGW_HOME);
  if (status.loaded) stopLaunchAgent(menuBarLabel);
  await writeFile(status.plistPath, buildMenuBarLaunchAgentPlist({
    consoleUrl: env.SGW_CONSOLE_URL,
    countMode: normalizeMenuBarCountMode(env.SGW_MENU_BAR_COUNT_MODE),
    notify: !args.includes("--no-notify")
  }, logs, env), { mode: 0o644 });
  if (status.loaded) startLaunchAgent(menuBarLabel, status.plistPath);
  return launchAgentStatus("menubar");
}

function launchAgentProgramArguments(plistPath: string): string[] {
  const plist = readLaunchAgentPlist(plistPath);
  const match = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(plist);
  if (!match) return [];
  return [...match[1].matchAll(/<string>([\s\S]*?)<\/string>/g)].map((item) => xmlUnescape(item[1]));
}

function launchAgentEnvironment(plistPath: string): Record<string, string> {
  const plist = readLaunchAgentPlist(plistPath);
  const match = /<key>EnvironmentVariables<\/key>\s*<dict>([\s\S]*?)<\/dict>/.exec(plist);
  if (!match) return {};

  const env: Record<string, string> = {};
  for (const item of match[1].matchAll(/<key>([\s\S]*?)<\/key>\s*<string>([\s\S]*?)<\/string>/g)) {
    env[xmlUnescape(item[1])] = xmlUnescape(item[2]);
  }
  return env;
}

function readLaunchAgentPlist(plistPath: string): string {
  try {
    return readFileSync(plistPath, "utf8");
  } catch {
    return "";
  }
}

function numberAfter(values: string[], flag: string): number | undefined {
  const index = values.indexOf(flag);
  if (index === -1) return undefined;
  const value = Number(values[index + 1]);
  return Number.isInteger(value) && value > 0 && value <= 65_535 ? value : undefined;
}

export function stopMacApp(): MacAppProcessInfo | undefined {
  requireMac("macOS app stop");
  if (process.env.SGW_SKIP_APP_STOP === "1") return undefined;

  const script = [
    "ObjC.import('AppKit')",
    "const apps = $.NSRunningApplication.runningApplicationsWithBundleIdentifier('com.s-gw.sgw.app')",
    "const pids = []",
    "for (let i = 0; i < apps.count; i += 1) {",
    "  const app = apps.objectAtIndex(i)",
    "  pids.push(Number(app.processIdentifier))",
    "  app.terminate",
    "}",
    "JSON.stringify(pids)"
  ].join("\n");
  const result = spawnSync("osascript", ["-l", "JavaScript", "-e", script], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Could not close the running s-gw macOS app.");
  }

  const parsed = JSON.parse(result.stdout.trim() || "[]") as unknown;
  const pids = Array.isArray(parsed)
    ? parsed.filter((pid): pid is number => Number.isInteger(pid) && pid > 0)
    : [];
  if (pids.length === 0) return undefined;
  for (const pid of pids) waitForPidToExit(pid);
  if (pids.some(isPidAlive)) {
    throw new Error("The s-gw macOS app is still running. Close it and retry the update.");
  }
  return {
    pid: pids[0],
    source: "process-list",
    alive: false,
    bundleIdentifier: "com.s-gw.sgw.app",
    otherPids: pids.slice(1)
  };
}

export function stopWindowsSurfaces(): WindowsStoppedSurfaces {
  requireWindows("Windows surface stop");
  const script = [
    "$stopped = @()",
    "Get-CimInstance Win32_Process | ForEach-Object {",
    "  $line = [string]$_.CommandLine",
    "  $helper = $line -match '(?i)s-gw-helper\\.ps1'",
    "  $client = $line -match '(?i)s-gw-client\\.ps1'",
    "  $console = $line -match '(?i)[\\\\/]dist[\\\\/]cli\\.js' -and $line -match '(?i)\\sconsole(?:\\s|$)' -and $line -match '(?i)s-gw'",
    "  if ($_.ProcessId -ne $PID -and ($helper -or $client -or $console)) {",
    "    $kind = if ($helper) { 'helper' } elseif ($client) { 'client' } else { 'console' }",
    "    Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue",
    "    $stopped += [PSCustomObject]@{ pid = [int]$_.ProcessId; kind = $kind }",
    "  }",
    "}",
    "$stopped | ConvertTo-Json -Compress"
  ].join("\n");
  const result = spawnSync("powershell.exe", ["-NoProfile", "-Command", script], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Could not stop the running s-gw Windows surfaces.");
  }
  if (!result.stdout.trim()) return { pids: [], console: false, helper: false, client: false };
  const parsed = JSON.parse(result.stdout) as unknown;
  const entries = (Array.isArray(parsed) ? parsed : [parsed]).filter((entry): entry is { pid: number; kind: string } => {
    if (!entry || typeof entry !== "object") return false;
    const item = entry as { pid?: unknown; kind?: unknown };
    return typeof item.pid === "number" && Number.isInteger(item.pid) && item.pid > 0 && typeof item.kind === "string";
  });
  return {
    pids: entries.map((entry) => entry.pid),
    console: entries.some((entry) => entry.kind === "console"),
    helper: entries.some((entry) => entry.kind === "helper"),
    client: entries.some((entry) => entry.kind === "client")
  };
}

export function startWindowsConsole(options: MenuBarOptions = {}): WindowsOpenResult {
  requireWindows("Windows console start");
  const layout = getPackageLayout();
  const port = options.port || 8718;
  const url = options.consoleUrl || consoleUrl(port);
  const child = spawn(process.execPath, [
    layout.cliPath,
    "console",
    "--host",
    "127.0.0.1",
    "--port",
    String(port),
    "--no-open"
  ], {
    detached: true,
    env: windowsEnvironment(url),
    stdio: "ignore",
    windowsHide: true
  });
  child.unref();
  return {
    scriptPath: layout.cliPath,
    launcherPath: process.execPath,
    consoleUrl: url,
    pid: child.pid
  };
}

export async function restartWindowsSurfaces(
  stopped: WindowsStoppedSurfaces,
  options: MenuBarOptions = {}
): Promise<WindowsRestartResult> {
  requireWindows("Windows surface restart");
  const result: WindowsRestartResult = {};
  const failures: string[] = [];
  try {
    if (stopped.client) {
      result.client = openWindowsClient(options);
    } else if (stopped.console) {
      result.console = startWindowsConsole(options);
    }
  } catch (error) {
    failures.push(`console/client: ${error instanceof Error ? error.message : String(error)}`);
  }
  if (stopped.helper) {
    try {
      result.helper = openWindowsHelper(options);
    } catch (error) {
      failures.push(`helper: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  if ((stopped.console || stopped.client) && (result.console || result.client)) {
    try {
      await waitForWindowsConsole(options.consoleUrl || consoleUrl(options.port || 8718));
    } catch (error) {
      failures.push(`console health: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
  if (result.helper) {
    await new Promise((resolve) => setTimeout(resolve, 300));
    if (!result.helper.pid || !isPidAlive(result.helper.pid)) {
      failures.push("helper: process exited during startup");
    }
  }
  if (failures.length > 0) {
    throw new Error(failures.join("; "));
  }
  return result;
}

async function waitForWindowsConsole(url: string): Promise<void> {
  const healthUrl = new URL("/api/health", url).toString();
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(healthUrl, { signal: AbortSignal.timeout(500) });
      if (response.ok) return;
    } catch {
      // The restored process can take a moment to bind after npm finishes.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`s-gw console did not become healthy at ${healthUrl}`);
}

export function launchAgentStatus(kind: "console" | "menubar"): LaunchAgentStatus {
  const label = kind === "console" ? consoleLabel : menuBarLabel;
  const plistPath = launchAgentPath(label);

  return {
    label,
    plistPath,
    installed: existsSync(plistPath),
    loaded: process.platform === "darwin" ? isLaunchAgentLoaded(label) : false
  };
}

export function openMenuBarHelper(options: MenuBarOptions = {}): { appPath: string; consoleUrl: string } {
  requireMac("menu-bar open");
  assertMacRuntimeForManagedSurfaces();
  assertMenuBarExists();
  const layout = getPackageLayout();
  const url = options.consoleUrl || consoleUrl(options.port || 8718);
  const env = menuBarEnvironment(url, options.countMode);
  const args: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    args.push("--env", `${key}=${value}`);
  }

  args.push(layout.menuBarAppPath, "--args");
  if (options.show) {
    args.push("--show-on-launch");
  }
  if (options.notify !== false) {
    args.push("--notify-on-launch");
  } else {
    args.push("--no-notify");
  }

  const result = spawnSync("open", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Failed to open s-gw menu-bar helper.");
  }

  return { appPath: layout.menuBarAppPath, consoleUrl: url };
}

export function openMacApp(options: MenuBarOptions = {}): MacAppOpenResult {
  requireMac("mac app open");
  installMacAppBundle();
  assertMacAppExists();
  const layout = getPackageLayout();
  const url = options.consoleUrl || consoleUrl(options.port || 8718);

  const existing = existingMacAppProcess(layout);
  if (existing) {
    focusMacAppProcess(existing, layout.macAppPath);
    return {
      appPath: layout.macAppPath,
      consoleUrl: url,
      reusedExisting: true,
      process: existing
    };
  }

  const env = menuBarEnvironment(url);
  const args: string[] = [];
  for (const [key, value] of Object.entries(env)) {
    args.push("--env", `${key}=${value}`);
  }

  args.push(layout.macAppPath);
  const result = spawnSync("open", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Failed to open s-gw macOS app.");
  }

  return { appPath: layout.macAppPath, consoleUrl: url, reusedExisting: false };
}

export function installMacAppBundle(options: MacAppInstallOptions = {}): MacAppInstallResult {
  requireMac("mac app install");
  const layout = getPackageLayout();
  assertMacRuntimeForManagedSurfaces(layout);
  const sourcePath = layout.packagedMacAppPath;
  const sourceBinary = layout.packagedMacAppBinaryPath;
  if (!existsSync(sourcePath) || !existsSync(sourceBinary)) {
    throw new Error(`Packaged macOS app is missing. Expected app bundle at ${sourcePath}`);
  }
  assertMacExecutableCompatible(sourceBinary, "macOS app");

  if (layout.isSelfContainedMacApp) {
    return { appPath: sourcePath, sourcePath, changed: false };
  }

  const applicationsDir = path.resolve(options.applicationsDir || macApplicationsDirectory());
  const appPath = path.join(applicationsDir, "s-gw.app");
  const registerCliPath = options.registerCliPath !== false
    && process.env.SGW_SKIP_MAC_APP_CLI_REGISTRATION !== "1";
  if (isSelfContainedMacApp(appPath)) {
    return { appPath, sourcePath, changed: false };
  }

  if (path.resolve(sourcePath) === path.resolve(appPath)) {
    if (registerCliPath) registerMacAppCliPath(layout.cliPath);
    return { appPath, sourcePath, changed: false };
  }

  mkdirSync(applicationsDir, { recursive: true });
  if (sameMacAppBundle(sourcePath, appPath)) {
    if (registerCliPath) registerMacAppCliPath(layout.cliPath);
    return { appPath, sourcePath, changed: false };
  }

  const suffix = `${process.pid}-${Date.now()}`;
  const stagingPath = path.join(applicationsDir, `.s-gw.app.install-${suffix}`);
  const backupPath = path.join(applicationsDir, `.s-gw.app.backup-${suffix}`);
  rmSync(stagingPath, { recursive: true, force: true });
  rmSync(backupPath, { recursive: true, force: true });

  const copied = spawnSync("/usr/bin/ditto", [sourcePath, stagingPath], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (copied.status !== 0) {
    rmSync(stagingPath, { recursive: true, force: true });
    throw new Error(copied.stderr.trim() || `Could not copy s-gw to ${applicationsDir}.`);
  }
  assertMacExecutableCompatible(macAppBinaryPath(stagingPath), "installed macOS app");

  let movedExisting = false;
  try {
    if (existsSync(appPath)) {
      renameSync(appPath, backupPath);
      movedExisting = true;
    }
    renameSync(stagingPath, appPath);
    rmSync(backupPath, { recursive: true, force: true });
  } catch (error) {
    rmSync(stagingPath, { recursive: true, force: true });
    if (movedExisting && !existsSync(appPath) && existsSync(backupPath)) {
      renameSync(backupPath, appPath);
    }
    throw new Error(`Could not install s-gw in ${applicationsDir}: ${error instanceof Error ? error.message : String(error)}`);
  }

  if (registerCliPath) registerMacAppCliPath(layout.cliPath);
  return { appPath, sourcePath, changed: true };
}

export function openWindowsClient(options: MenuBarOptions = {}): WindowsOpenResult {
  requireWindows("Windows client open");
  assertWindowsClientExists();
  const layout = getPackageLayout();
  const url = options.consoleUrl || consoleUrl(options.port || 8718);
  const result = spawnSync(
    "powershell.exe",
    [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      layout.windowsClientScriptPath,
      "-Port",
      String(options.port || 8718),
      "-ConsoleUrl",
      url
    ],
    {
      encoding: "utf8",
      env: windowsEnvironment(url),
      stdio: ["ignore", "pipe", "pipe"]
    }
  );

  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || "Failed to open s-gw Windows client.");
  }

  return {
    scriptPath: layout.windowsClientScriptPath,
    launcherPath: layout.windowsClientLauncherPath,
    consoleUrl: url
  };
}

export function openWindowsHelper(options: MenuBarOptions = {}): WindowsOpenResult {
  requireWindows("Windows helper open");
  assertWindowsHelperExists();
  const layout = getPackageLayout();
  const url = options.consoleUrl || consoleUrl(options.port || 8718);
  const child = spawn(
    "powershell.exe",
    [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      layout.windowsHelperScriptPath,
      "-Port",
      String(options.port || 8718),
      "-ConsoleUrl",
      url
    ],
    {
      detached: true,
      env: windowsEnvironment(url),
      stdio: "ignore"
    }
  );
  child.unref();

  return {
    scriptPath: layout.windowsHelperScriptPath,
    launcherPath: layout.windowsHelperLauncherPath,
    consoleUrl: url,
    pid: child.pid
  };
}

export function macAppProcessRecordPath(): string {
  return path.join(os.homedir(), "Library", "Application Support", "s-gw", "s-gw-app.process.json");
}

function existingMacAppProcess(layout: PackageLayout): MacAppProcessInfo | undefined {
  const record = readMacAppProcessRecord();
  if (record?.alive) {
    return record;
  }

  return findRunningMacAppProcess(layout);
}

function readMacAppProcessRecord(): MacAppProcessInfo | undefined {
  const recordPath = macAppProcessRecordPath();
  if (!existsSync(recordPath)) {
    return undefined;
  }

  try {
    const parsed = JSON.parse(readFileSync(recordPath, "utf8")) as Record<string, unknown>;
    const pid = Number(parsed.pid);
    if (!Number.isInteger(pid) || pid <= 0) {
      return undefined;
    }

    return {
      pid,
      source: "record",
      alive: isPidAlive(pid),
      recordPath,
      bundleIdentifier: stringValue(parsed.bundleIdentifier),
      bundlePath: stringValue(parsed.bundlePath),
      executablePath: stringValue(parsed.executablePath),
      startedAt: stringValue(parsed.startedAt),
      updatedAt: stringValue(parsed.updatedAt)
    };
  } catch {
    return undefined;
  }
}

function findRunningMacAppProcess(layout: PackageLayout): MacAppProcessInfo | undefined {
  const result = spawnSync("pgrep", ["-x", "s-gw"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.status !== 0) {
    return undefined;
  }

  const pids = result.stdout
    .split(/\s+/)
    .map((item) => Number(item.trim()))
    .filter((pid) => Number.isInteger(pid) && pid > 0 && isPidAlive(pid));
  if (pids.length === 0) {
    return undefined;
  }

  const candidates = pids.map((pid) => ({
    pid,
    command: commandForPid(pid)
  }));
  const selected = candidates.find((item) => commandMatchesPath(item.command, layout.macAppBinaryPath)) || candidates[0];

  return {
    pid: selected.pid,
    source: "process-list",
    alive: true,
    bundleIdentifier: "com.s-gw.sgw.app",
    bundlePath: layout.macAppPath,
    executablePath: layout.macAppBinaryPath,
    command: selected.command,
    otherPids: candidates
      .filter((item) => item.pid !== selected.pid)
      .map((item) => item.pid)
  };
}

function focusMacAppProcess(app: MacAppProcessInfo, appPath: string): void {
  if (postOpenMainWindowNotification()) {
    return;
  }

  if (app.bundleIdentifier) {
    const byBundle = spawnSync("open", ["-b", app.bundleIdentifier], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
    if (byBundle.status === 0) {
      return;
    }
  }

  const byPath = spawnSync("open", [appPath], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (byPath.status !== 0) {
    throw new Error(byPath.stderr.trim() || "Failed to focus running s-gw macOS app.");
  }
}

function postOpenMainWindowNotification(): boolean {
  const script = [
    "ObjC.import('Foundation')",
    "$.NSDistributedNotificationCenter.defaultCenter.postNotificationNameObjectUserInfoDeliverImmediately(",
    "  'com.s-gw.sgw.openMainWindow', null, null, true",
    ")"
  ].join("\n");
  const result = spawnSync("osascript", ["-l", "JavaScript", "-e", script], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  return result.status === 0;
}

function commandForPid(pid: number): string | undefined {
  const result = spawnSync("ps", ["-p", String(pid), "-o", "command="], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status !== 0) {
    return undefined;
  }

  return result.stdout.trim() || undefined;
}

function commandMatchesPath(command: string | undefined, targetPath: string): boolean {
  return command === targetPath || command?.startsWith(`${targetPath} `) === true;
}

function isPidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code === "EPERM";
  }
}

function waitForPidToExit(pid: number): void {
  const flag = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; i < 40; i += 1) {
    if (!isPidAlive(pid)) return;
    Atomics.wait(flag, 0, 0, 50);
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

export function buildConsoleLaunchAgentPlist(
  port: number,
  logsDir: string,
  inheritedEnvironment: Record<string, string> = {}
): string {
  const layout = getPackageLayout();
  return buildLaunchAgentPlist({
    label: consoleLabel,
    programArguments: [
      layout.nodePath,
      layout.cliPath,
      "console",
      "--host",
      "127.0.0.1",
      "--port",
      String(port),
      "--no-open"
    ],
    environment: launchdBaseEnvironment(inheritedEnvironment),
    runAtLoad: true,
    keepAlive: true,
    stdoutPath: path.join(logsDir, "console.log"),
    stderrPath: path.join(logsDir, "console.err.log")
  });
}

export function buildMenuBarLaunchAgentPlist(
  options: MenuBarOptions,
  logsDir: string,
  inheritedEnvironment: Record<string, string> = {}
): string {
  const layout = getPackageLayout();
  const args = [layout.menuBarBinaryPath];
  if (options.notify !== false) {
    args.push("--notify-on-launch");
  } else {
    args.push("--no-notify");
  }

  return buildLaunchAgentPlist({
    label: menuBarLabel,
    programArguments: args,
    environment: menuBarEnvironment(options.consoleUrl || consoleUrl(options.port || 8718), options.countMode, inheritedEnvironment),
    runAtLoad: true,
    keepAlive: true,
    stdoutPath: path.join(logsDir, "menubar.log"),
    stderrPath: path.join(logsDir, "menubar.err.log"),
    limitToAqua: true
  });
}

function buildLaunchAgentPlist(definition: LaunchAgentDefinition): string {
  const envPairs = Object.entries(definition.environment)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `    <key>${xmlEscape(key)}</key>\n    <string>${xmlEscape(value)}</string>`)
    .join("\n");
  const programArgs = definition.programArguments
    .map((item) => `    <string>${xmlEscape(item)}</string>`)
    .join("\n");
  const aqua = definition.limitToAqua
    ? "  <key>LimitLoadToSessionType</key>\n  <string>Aqua</string>\n"
    : "";

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${xmlEscape(definition.label)}</string>
  <key>ProgramArguments</key>
  <array>
${programArgs}
  </array>
  <key>EnvironmentVariables</key>
  <dict>
${envPairs}
  </dict>
  <key>RunAtLoad</key>
  <${definition.runAtLoad ? "true" : "false"}/>
  <key>KeepAlive</key>
  <${definition.keepAlive ? "true" : "false"}/>
${aqua}  <key>StandardOutPath</key>
  <string>${xmlEscape(definition.stdoutPath)}</string>
  <key>StandardErrorPath</key>
  <string>${xmlEscape(definition.stderrPath)}</string>
</dict>
</plist>
`;
}

function startLaunchAgent(label: string, plistPath: string): void {
  stopLaunchAgent(label);
  runLaunchctl(["bootstrap", launchdDomain(), plistPath]);
  runLaunchctl(["kickstart", "-k", `${launchdDomain()}/${label}`]);
}

function stopLaunchAgent(label: string): void {
  const plistPath = launchAgentPath(label);
  if (existsSync(plistPath)) {
    spawnSync("launchctl", ["bootout", launchdDomain(), plistPath], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
  }

  spawnSync("launchctl", ["bootout", `${launchdDomain()}/${label}`], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  waitForLaunchAgentToUnload(label);
}

function runLaunchctl(args: string[]): void {
  const result = spawnSync("launchctl", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `launchctl ${args.join(" ")} failed.`);
  }
}

function isLaunchAgentLoaded(label: string): boolean {
  const result = spawnSync("launchctl", ["print", `${launchdDomain()}/${label}`], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  return result.status === 0;
}

function waitForLaunchAgentToUnload(label: string): void {
  const flag = new Int32Array(new SharedArrayBuffer(4));
  for (let i = 0; i < 20; i += 1) {
    if (!isLaunchAgentLoaded(label)) {
      return;
    }
    Atomics.wait(flag, 0, 0, 50);
  }
}

function launchdDomain(): string {
  return `gui/${process.getuid?.() ?? os.userInfo().uid}`;
}

function launchAgentPath(label: string): string {
  return path.join(os.homedir(), "Library", "LaunchAgents", `${label}.plist`);
}

async function ensureLogDir(sgwHome?: string): Promise<string> {
  const logs = path.join(path.resolve(sgwHome || getSgwHome()), "logs");
  await mkdir(logs, { recursive: true, mode: 0o700 });
  await mkdir(path.dirname(launchAgentPath(consoleLabel)), { recursive: true });
  return logs;
}

function launchdBaseEnvironment(inherited: Record<string, string> = {}): Record<string, string> {
  const layout = getPackageLayout();
  const env: Record<string, string> = {
    PATH: inherited.PATH || process.env.PATH || "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin",
    SGW_NODE_PATH: layout.nodePath
  };

  for (const key of ["SGW_HOME", "SGW_KEYCHAIN_SERVICE", "SGW_KEYCHAIN_ACCOUNT"]) {
    copyEnvironmentValue(env, inherited, key);
  }
  if (process.env.SGW_KEYCHAIN_HELPER) {
    env.SGW_KEYCHAIN_HELPER = process.env.SGW_KEYCHAIN_HELPER;
  }
  return env;
}

export function normalizeMenuBarCountMode(value?: string): MenuBarCountMode | undefined {
  if (!value) {
    return undefined;
  }

  switch (value.trim().toLowerCase()) {
    case "pending":
    case "approval":
    case "approvals":
    case "authorization":
    case "authorizations":
    case "auth":
      return "pending";
    case "credential":
    case "credentials":
    case "secret":
    case "secrets":
    case "handle":
    case "handles":
      return "credentials";
    case "none":
    case "off":
    case "hide":
    case "hidden":
      return "none";
    default:
      throw new Error("--count must be pending, credentials, or none.");
  }
}

function menuBarEnvironment(
  url: string,
  countMode?: MenuBarCountMode,
  inheritedEnvironment: Record<string, string> = {}
): Record<string, string> {
  const layout = getPackageLayout();
  const env: Record<string, string> = {
    ...launchdBaseEnvironment(inheritedEnvironment),
    SGW_REPO_ROOT: layout.packageRoot,
    SGW_CLI_PATH: layout.cliPath,
    SGW_CONSOLE_URL: url,
    SGW_APP_PATH: layout.macAppPath
  };

  if (countMode) {
    env.SGW_MENU_BAR_COUNT_MODE = countMode;
  }

  return env;
}

function windowsEnvironment(url: string): NodeJS.ProcessEnv {
  const layout = getPackageLayout();
  return {
    ...process.env,
    SGW_NODE_PATH: process.execPath,
    SGW_CLI_PATH: layout.cliPath,
    SGW_CONSOLE_URL: url,
    SGW_APP_PATH: layout.windowsClientLauncherPath
  };
}

function copyEnvironmentValue(
  target: Record<string, string>,
  inherited: Record<string, string>,
  key: string
): void {
  const value = inherited[key] || process.env[key];
  if (value) {
    target[key] = value;
  }
}

function consoleUrl(port: number): string {
  return `http://127.0.0.1:${port}/`;
}

function pathStatus(filePath: string) {
  return {
    path: filePath,
    exists: existsSync(filePath)
  };
}

function macApplicationsDirectory(): string {
  const override = process.env.SGW_APPLICATIONS_DIR?.trim();
  if (override) return path.resolve(override);

  if (process.platform === "darwin") {
    try {
      accessSync("/Applications", constants.W_OK);
      return "/Applications";
    } catch {
      // Standard users can still keep a normal app bundle under their home directory.
    }
  }
  return path.join(os.homedir(), "Applications");
}

function findInstalledSelfContainedMacApp(): string | undefined {
  const override = process.env.SGW_APPLICATIONS_DIR?.trim();
  if (process.env.SGW_TEST_MODE === "1" && !override) {
    // Tests must not inherit a developer's real /Applications state.
    return undefined;
  }
  if (override) {
    const candidate = path.resolve(override, "s-gw.app");
    return isSelfContainedMacApp(candidate) ? candidate : undefined;
  }

  const candidates = [
    path.join(macApplicationsDirectory(), "s-gw.app"),
    "/Applications/s-gw.app",
    path.join(os.homedir(), "Applications", "s-gw.app")
  ];

  for (const candidate of new Set(candidates.map((item) => path.resolve(item)))) {
    if (isSelfContainedMacApp(candidate)) return candidate;
  }

  return undefined;
}

export function assertMacRuntimeForManagedSurfaces(
  layout: Pick<PackageLayout, "isSelfContainedMacApp" | "standaloneMacAppInstalled" | "macAppPath"> = getPackageLayout()
): void {
  if (layout.isSelfContainedMacApp) {
    if (!isInstalledMacAppLocation(layout.macAppPath)) {
      throw new Error("Move s-gw.app to /Applications or ~/Applications before setup. Services and agent connections cannot safely run from a mounted disk image, App Translocation path, or other temporary location.");
    }
    return;
  }

  if (layout.standaloneMacAppInstalled) {
    throw new Error("A self-contained s-gw.app is already installed. Open that app to manage s-gw services, the menu bar, agents, or updates.");
  }
}

function macAppBinaryPath(appPath: string): string {
  return path.join(appPath, "Contents", "MacOS", "s-gw");
}

function sameMacAppBundle(sourcePath: string, installedPath: string): boolean {
  if (!existsSync(installedPath)) return false;
  const checkedFiles = [
    path.join("Contents", "Info.plist"),
    path.join("Contents", "MacOS", "s-gw"),
    path.join("Contents", "Resources", "AppIcon.icns"),
    path.join("Contents", "Resources", "MenuBarTemplate.png")
  ];

  try {
    for (const relativePath of checkedFiles) {
      const source = path.join(sourcePath, relativePath);
      const installed = path.join(installedPath, relativePath);
      if (!existsSync(source) || !existsSync(installed) || fileSHA256(source) !== fileSHA256(installed)) {
        return false;
      }
    }
    return true;
  } catch {
    return false;
  }
}

function fileSHA256(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function registerMacAppCliPath(cliPath: string): void {
  const result = spawnSync(
    "/usr/bin/defaults",
    ["write", "com.s-gw.sgw.app", "sgwBinaryPath", "-string", cliPath],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
  );
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || "Could not save the s-gw CLI path for the macOS app.");
  }
}

function assertMenuBarExists(): void {
  const layout = getPackageLayout();
  if (!existsSync(layout.menuBarAppPath) || !existsSync(layout.menuBarBinaryPath)) {
    throw new Error(`Menu-bar helper is missing. Expected app bundle at ${layout.menuBarAppPath}`);
  }
  assertMacExecutableCompatible(layout.menuBarBinaryPath, "menu-bar helper");
}

function assertMacAppExists(): void {
  const layout = getPackageLayout();
  if (!existsSync(layout.macAppPath) || !existsSync(layout.macAppBinaryPath)) {
    throw new Error(`macOS app is missing. Expected app bundle at ${layout.macAppPath}`);
  }
  assertMacExecutableCompatible(layout.macAppBinaryPath, "macOS app");
}

function assertMacExecutableCompatible(binaryPath: string, label: string): void {
  if (process.platform !== "darwin") return;
  const arch = process.arch === "x64" ? "x86_64" : process.arch;
  const check = spawnSync("/usr/bin/lipo", [binaryPath, "-verify_arch", arch], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (check.status === 0) return;
  throw new Error(
    `The packaged ${label} is not compatible with darwin-${process.arch}. ` +
    "Public npm and DMG releases currently include Apple Silicon native surfaces; Intel Macs must build them from source."
  );
}

function assertWindowsClientExists(): void {
  const layout = getPackageLayout();
  if (!existsSync(layout.windowsClientScriptPath)) {
    throw new Error(`Windows client is missing. Expected script at ${layout.windowsClientScriptPath}`);
  }
}

function assertWindowsHelperExists(): void {
  const layout = getPackageLayout();
  if (!existsSync(layout.windowsHelperScriptPath)) {
    throw new Error(`Windows helper is missing. Expected script at ${layout.windowsHelperScriptPath}`);
  }
}

function requireMac(action: string): void {
  if (process.platform !== "darwin") {
    throw new Error(`${action} is only available on macOS.`);
  }
}

function requireWindows(action: string): void {
  if (process.platform !== "win32") {
    throw new Error(`${action} is only available on Windows.`);
  }
}

function xmlEscape(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function xmlUnescape(value: string): string {
  return value
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'")
    .replaceAll("&amp;", "&");
}
