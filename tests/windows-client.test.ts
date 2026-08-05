import { execFileSync, spawn, spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  ensureWindowsConsole,
  getPackageLayout,
  openWindowsHelper,
  restartWindowsSurfaces,
  selectWindowsHelperPid,
  startWindowsConsole,
  stopWindowsSurfaces
} from "../src/install.js";
import { getSgwInstanceKey } from "../src/paths.js";

const repoRoot = process.cwd();

describe("Windows client packaging", () => {
  it("selects helpers only from the current Windows user session", () => {
    const processes = [
      { pid: 410, ownerSid: "S-1-5-21-100", sessionId: 0, instanceKey: "a".repeat(64), exactPath: true },
      { pid: 420, ownerSid: "S-1-5-21-200", sessionId: 3, instanceKey: "a".repeat(64), exactPath: true },
      { pid: 430, ownerSid: "S-1-5-21-100", sessionId: 3, instanceKey: "a".repeat(64), exactPath: true }
    ];

    expect(selectWindowsHelperPid(processes, "s-1-5-21-100", 3)).toBe(430);
    expect(selectWindowsHelperPid(processes, "S-1-5-21-100", 7)).toBeUndefined();
  });

  it("stages launchers for the client, tray helper, and Credential Manager helper", async () => {
    execFileSync(process.execPath, ["scripts/build-windows-client.mjs"], {
      cwd: repoRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });

    const layout = getPackageLayout();
    expect(existsSync(layout.windowsClientScriptPath)).toBe(true);
    expect(existsSync(layout.windowsClientLauncherPath)).toBe(true);
    expect(existsSync(layout.windowsHelperScriptPath)).toBe(true);
    expect(existsSync(layout.windowsHelperBootstrapPath)).toBe(true);
    expect(existsSync(layout.windowsHelperLauncherPath)).toBe(true);
    expect(existsSync(layout.windowsCredentialHelperPath)).toBe(true);

    const client = await readFile(layout.windowsClientScriptPath, "utf8");
    const helper = await readFile(layout.windowsHelperScriptPath, "utf8");
    const helperBootstrap = await readFile(layout.windowsHelperBootstrapPath, "utf8");
    const helperLauncher = await readFile(layout.windowsHelperLauncherPath, "utf8");
    const credential = await readFile(layout.windowsCredentialHelperPath, "utf8");
    const launcher = await readFile(path.join(repoRoot, "dist/windows/s-gw-client.cmd"), "utf8");

    expect(client).toContain("Start-ConsoleDaemon");
    expect(client).toContain("--app=$Url");
    expect(client).toContain("InstanceKey");
    expect(client).toContain("Get-NetTCPConnection");
    expect(client).toContain("GetOwnerSid");
    expect(helper).toContain("NotifyIcon");
    expect(helper).toContain("Approve Queue");
    expect(helper).toContain('Invoke-CliJson $args');
    expect(helper).toContain('"update", "check"');
    expect(helper).toContain("s-gw update available");
    expect(helper).toContain("Check for Updates");
    expect(helper).toContain("New-HelperMutexName");
    expect(helper).toContain("Local\\s-gw-helper-");
    expect(helper).toContain("WaitOne(0)");
    expect(helper).toContain("AbandonedMutexException");
    expect(helper).toContain("InstanceKey");
    expect(helper).toContain("LaunchNonce");
    expect(helperBootstrap).toContain("Microsoft.PowerShell.Management\\Start-Process");
    expect(helperBootstrap).toContain("$PSHOME");
    expect(helperBootstrap).toContain("startedAtUtcTicks");
    expect(helperBootstrap).toContain("$process.Kill()");
    expect(helperBootstrap).not.toContain("cmd.exe");
    expect(helperLauncher).toContain("helper open");
    expect(helperLauncher).toContain("..\\cli.js");
    expect(helperLauncher).not.toContain("s-gw-helper.ps1");
    expect(credential).toContain("CredReadW");
    expect(credential).toContain("CredWriteW");
    expect(credential).toContain("[Console]::In.ReadToEnd()");
    expect(launcher).toContain("app open");
    expect(launcher).not.toContain("s-gw-client.ps1");

    const combined = `${client}\n${helper}\n${credential}`;
    expect(combined).not.toContain("SGW_MASTER_PASSPHRASE");
  });

  it("cleans up when the helper bootstrap fails after starting", async () => {
    if (process.platform !== "win32") return;
    execFileSync(process.execPath, ["scripts/build-windows-client.mjs"], { cwd: repoRoot });
    const layout = getPackageLayout();
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-bootstrap-home-"));
    const helperPath = layout.windowsHelperScriptPath;
    const bootstrapPath = path.join(
      path.dirname(layout.windowsHelperBootstrapPath),
      `s-gw-helper-bootstrap-failure-${process.pid}-${Date.now()}.ps1`
    );
    const port = await freePort();
    const instanceKey = "a".repeat(64);
    const launchNonce = "b".repeat(64);

    try {
      const bootstrap = await readFile(layout.windowsHelperBootstrapPath, "utf8");
      const launchLine = "  $process = Microsoft.PowerShell.Management\\Start-Process -FilePath $powerShellPath -ArgumentList $argumentLine -WindowStyle Hidden -PassThru";
      expect(bootstrap).toContain(launchLine);
      await writeFile(bootstrapPath, bootstrap.replace(launchLine, `${launchLine}\n  throw "forced post-start bootstrap failure"`));

      const result = spawnSync("powershell.exe", [
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        bootstrapPath,
        "-HelperPath",
        helperPath,
        "-Port",
        String(port),
        "-ConsoleUrl",
        `http://127.0.0.1:${port}/`,
        "-InstanceKey",
        instanceKey,
        "-LaunchNonce",
        launchNonce
      ], {
        encoding: "utf8",
        env: {
          ...process.env,
          SGW_HOME: home,
          SGW_RECOVERY_HOME: `${home}-recovery`,
          SGW_MASTER_PASSPHRASE: "windows bootstrap failure passphrase",
          SGW_DISABLE_UPDATE_CHECK: "1",
          SGW_NODE_PATH: process.execPath,
          SGW_CLI_PATH: layout.cliPath,
          SGW_CONSOLE_URL: `http://127.0.0.1:${port}/`
        },
        stdio: ["ignore", "pipe", "pipe"],
        timeout: 10_000,
        windowsHide: true
      });
      expect(result.status).not.toBe(0);
      expect(`${result.stdout || ""}${result.stderr || ""}`).toMatch(/forced post-start bootstrap failure/);

      let residues: number[] = [];
      for (let attempt = 0; attempt < 20; attempt += 1) {
        residues = windowsHelperPids(port);
        if (residues.length === 0) break;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      expect(residues).toEqual([]);
    } finally {
      stopWindowsSurfaces();
      await rm(bootstrapPath, { force: true });
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);

  it("restores a running console after an update failure", async () => {
    if (process.platform !== "win32") return;
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-restart-"));
    const port = await freePort();
    const oldHome = process.env.SGW_HOME;
    const oldRecoveryHome = process.env.SGW_RECOVERY_HOME;
    const oldPassphrase = process.env.SGW_MASTER_PASSPHRASE;
    const oldUpdateCheck = process.env.SGW_DISABLE_UPDATE_CHECK;
    process.env.SGW_HOME = home;
    process.env.SGW_RECOVERY_HOME = `${home}-recovery`;
    process.env.SGW_MASTER_PASSPHRASE = "windows restart test passphrase";
    process.env.SGW_DISABLE_UPDATE_CHECK = "1";

    try {
      startWindowsConsole({ port });
      await waitForHealth(port);
      const stopped = stopWindowsSurfaces();
      expect(stopped.console).toBe(true);
      expect(stopped.pids.length).toBeGreaterThan(0);

      await restartWindowsSurfaces(stopped, { port });
      await waitForHealth(port);
    } finally {
      stopWindowsSurfaces();
      restoreEnv("SGW_HOME", oldHome);
      restoreEnv("SGW_RECOVERY_HOME", oldRecoveryHome);
      restoreEnv("SGW_MASTER_PASSPHRASE", oldPassphrase);
      restoreEnv("SGW_DISABLE_UPDATE_CHECK", oldUpdateCheck);
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);

  it("reuses a directly started console with default host and port arguments", async () => {
    if (process.platform !== "win32") return;
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-default-console-"));
    const oldHome = process.env.SGW_HOME;
    const oldRecoveryHome = process.env.SGW_RECOVERY_HOME;
    const oldPassphrase = process.env.SGW_MASTER_PASSPHRASE;
    const oldUpdateCheck = process.env.SGW_DISABLE_UPDATE_CHECK;
    process.env.SGW_HOME = home;
    process.env.SGW_RECOVERY_HOME = `${home}-recovery`;
    process.env.SGW_MASTER_PASSPHRASE = "windows default console passphrase";
    process.env.SGW_DISABLE_UPDATE_CHECK = "1";
    const layout = getPackageLayout();
    let consoleProcess: ReturnType<typeof spawn> | undefined;

    try {
      stopWindowsSurfaces();
      consoleProcess = spawn(process.execPath, [layout.cliPath, "console", "--no-open"], {
        cwd: repoRoot,
        env: process.env,
        stdio: "ignore",
        windowsHide: true
      });
      await waitForHealth(8718);
      const existing = await ensureWindowsConsole({ port: 8718 });
      expect(existing.pid).toBeUndefined();
    } finally {
      stopWindowsSurfaces();
      consoleProcess?.kill();
      restoreEnv("SGW_HOME", oldHome);
      restoreEnv("SGW_RECOVERY_HOME", oldRecoveryHome);
      restoreEnv("SGW_MASTER_PASSPHRASE", oldPassphrase);
      restoreEnv("SGW_DISABLE_UPDATE_CHECK", oldUpdateCheck);
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);

  it("reuses one tray helper across repeated opens", async () => {
    if (process.platform !== "win32") return;
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-helper-"));
    const otherHome = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-helper-other-"));
    const port = await freePort();
    const oldHome = process.env.SGW_HOME;
    const oldRecoveryHome = process.env.SGW_RECOVERY_HOME;
    const oldPassphrase = process.env.SGW_MASTER_PASSPHRASE;
    const oldUpdateCheck = process.env.SGW_DISABLE_UPDATE_CHECK;
    process.env.SGW_HOME = home;
    process.env.SGW_RECOVERY_HOME = `${home}-recovery`;
    process.env.SGW_MASTER_PASSPHRASE = "windows helper test passphrase";
    process.env.SGW_DISABLE_UPDATE_CHECK = "1";

    try {
      const first = await openWindowsHelper({
        port,
        consoleUrl: `http://127.0.0.1:${port}/approvals`
      });
      expect(first.pid).toBeGreaterThan(0);
      expect(first.reusedExisting).toBe(false);
      expect(first.consoleUrl).toBe(`http://127.0.0.1:${port}/`);
      await waitForPid(first.pid!);

      const second = await openWindowsHelper({ port });
      expect(second.pid).toBe(first.pid);
      expect(second.reusedExisting).toBe(true);

      const routedConsole = await ensureWindowsConsole({
        port,
        consoleUrl: `http://127.0.0.1:${port}/approvals`
      });
      expect(routedConsole.pid).toBeUndefined();

      process.env.SGW_HOME = otherHome;
      process.env.SGW_RECOVERY_HOME = `${otherHome}-recovery`;
      await expect(openWindowsHelper({ port })).rejects.toThrow(/another credential home|credential authority/);
      await expect(ensureWindowsConsole({ port })).rejects.toThrow(/another credential home|credential authority/i);

      process.env.SGW_HOME = home;
      process.env.SGW_RECOVERY_HOME = `${home}-recovery`;
      const original = await openWindowsHelper({ port });
      expect(original.pid).toBe(first.pid);
      expect(original.reusedExisting).toBe(true);

      const alternateUrl = `http://localhost:${port}/`;
      await expect(openWindowsHelper({ port, consoleUrl: alternateUrl })).rejects.toThrow(/Run s-gw stop/);

      const otherPort = await freePort();
      await expect(openWindowsHelper({
        port,
        consoleUrl: `http://127.0.0.1:${otherPort}/`
      })).rejects.toThrow(/must match --port/);
    } finally {
      stopWindowsSurfaces();
      restoreEnv("SGW_HOME", oldHome);
      restoreEnv("SGW_RECOVERY_HOME", oldRecoveryHome);
      restoreEnv("SGW_MASTER_PASSPHRASE", oldPassphrase);
      restoreEnv("SGW_DISABLE_UPDATE_CHECK", oldUpdateCheck);
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
      await rm(otherHome, { recursive: true, force: true });
      await rm(`${otherHome}-recovery`, { recursive: true, force: true });
    }
  }, 60_000);

  it("rejects a healthy console from another credential home", async () => {
    if (process.platform !== "win32") return;
    const firstHome = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-console-first-"));
    const otherHome = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-console-other-"));
    const port = await freePort();
    const oldHome = process.env.SGW_HOME;
    const oldRecoveryHome = process.env.SGW_RECOVERY_HOME;
    const oldPassphrase = process.env.SGW_MASTER_PASSPHRASE;
    process.env.SGW_HOME = firstHome;
    process.env.SGW_RECOVERY_HOME = `${firstHome}-recovery`;
    process.env.SGW_MASTER_PASSPHRASE = "windows console identity passphrase";

    try {
      startWindowsConsole({ port });
      await waitForHealth(port);

      process.env.SGW_HOME = otherHome;
      process.env.SGW_RECOVERY_HOME = `${otherHome}-recovery`;
      await expect(ensureWindowsConsole({ port })).rejects.toThrow(/another credential home/);
    } finally {
      stopWindowsSurfaces();
      restoreEnv("SGW_HOME", oldHome);
      restoreEnv("SGW_RECOVERY_HOME", oldRecoveryHome);
      restoreEnv("SGW_MASTER_PASSPHRASE", oldPassphrase);
      await rm(firstHome, { recursive: true, force: true });
      await rm(`${firstHome}-recovery`, { recursive: true, force: true });
      await rm(otherHome, { recursive: true, force: true });
      await rm(`${otherHome}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);

  it("rejects a matching health response from a different listener process", async () => {
    if (process.platform !== "win32") return;
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-listener-owner-"));
    const oldHome = process.env.SGW_HOME;
    const oldRecoveryHome = process.env.SGW_RECOVERY_HOME;
    const oldPassphrase = process.env.SGW_MASTER_PASSPHRASE;
    process.env.SGW_HOME = home;
    process.env.SGW_RECOVERY_HOME = `${home}-recovery`;
    process.env.SGW_MASTER_PASSPHRASE = "windows listener owner passphrase";
    const server = createServer((request, response) => {
      if (request.url !== "/api/health") {
        response.writeHead(404).end();
        return;
      }
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, name: "s-gw", instanceKey: getSgwInstanceKey() }));
    });

    try {
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(0, "127.0.0.1", resolve);
      });
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      await expect(ensureWindowsConsole({ port })).rejects.toThrow(/not owned by this user's s-gw console/i);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      restoreEnv("SGW_HOME", oldHome);
      restoreEnv("SGW_RECOVERY_HOME", oldRecoveryHome);
      restoreEnv("SGW_MASTER_PASSPHRASE", oldPassphrase);
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);

  it("does not open another credential home's console in the browser", async () => {
    if (process.platform !== "win32") return;
    const firstHome = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-browser-first-"));
    const otherHome = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-browser-other-"));
    const port = await freePort();
    const oldHome = process.env.SGW_HOME;
    const oldRecoveryHome = process.env.SGW_RECOVERY_HOME;
    const oldPassphrase = process.env.SGW_MASTER_PASSPHRASE;
    const oldDisableKeychain = process.env.SGW_DISABLE_KEYCHAIN;
    process.env.SGW_HOME = firstHome;
    process.env.SGW_RECOVERY_HOME = `${firstHome}-recovery`;
    process.env.SGW_MASTER_PASSPHRASE = "windows browser authority passphrase";
    process.env.SGW_DISABLE_KEYCHAIN = "1";

    try {
      startWindowsConsole({ port });
      await waitForHealth(port);
      const layout = getPackageLayout();
      const env = {
        ...process.env,
        SGW_HOME: otherHome,
        SGW_RECOVERY_HOME: `${otherHome}-recovery`
      };
      await expect(runProcess(process.execPath, [
        layout.cliPath,
        "start",
        "--no-service",
        "--no-menubar",
        "--port",
        String(port)
      ], env)).rejects.toThrow(/another credential home|credential authority/i);
    } finally {
      stopWindowsSurfaces();
      restoreEnv("SGW_HOME", oldHome);
      restoreEnv("SGW_RECOVERY_HOME", oldRecoveryHome);
      restoreEnv("SGW_MASTER_PASSPHRASE", oldPassphrase);
      restoreEnv("SGW_DISABLE_KEYCHAIN", oldDisableKeychain);
      await rm(firstHome, { recursive: true, force: true });
      await rm(`${firstHome}-recovery`, { recursive: true, force: true });
      await rm(otherHome, { recursive: true, force: true });
      await rm(`${otherHome}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);

  it("returns one live tray helper when two CLI opens race", async () => {
    if (process.platform !== "win32") return;
    execFileSync(process.execPath, ["scripts/build-windows-client.mjs"], { cwd: repoRoot });
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-helper-race-"));
    const port = await freePort();
    const layout = getPackageLayout();
    const testEnv = {
      ...process.env,
      SGW_HOME: home,
      SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_MASTER_PASSPHRASE: "windows helper race passphrase",
      SGW_DISABLE_UPDATE_CHECK: "1",
      SGW_NODE_PATH: process.execPath,
      SGW_CLI_PATH: layout.cliPath,
      SGW_CONSOLE_URL: `http://127.0.0.1:${port}/`
    };
    try {
      stopWindowsSurfaces();
      const args = [layout.cliPath, "menubar", "open", "--port", String(port)];
      const opened = await Promise.all([
        runProcess(process.execPath, args, testEnv),
        runProcess(process.execPath, args, testEnv)
      ]);
      const returnedPids = opened.map((output) => Number(JSON.parse(output).pid));
      expect(new Set(returnedPids).size).toBe(1);

      const pids = await waitForOneWindowsHelper(port);
      expect(pids).toHaveLength(1);
      expect(returnedPids[0]).toBe(pids[0]);
      expect(() => process.kill(returnedPids[0], 0)).not.toThrow();
    } finally {
      stopWindowsSurfaces();
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 60_000);

  it("keeps one authority when two credential homes race on one port", async () => {
    if (process.platform !== "win32") return;
    execFileSync(process.execPath, ["scripts/build-windows-client.mjs"], { cwd: repoRoot });
    const firstHome = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-helper-authority-a-"));
    const secondHome = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-helper-authority-b-"));
    const port = await freePort();
    const layout = getPackageLayout();
    const baseEnv = {
      ...process.env,
      SGW_MASTER_PASSPHRASE: "windows helper authority race passphrase",
      SGW_DISABLE_UPDATE_CHECK: "1",
      SGW_NODE_PATH: process.execPath,
      SGW_CLI_PATH: layout.cliPath,
      SGW_CONSOLE_URL: `http://127.0.0.1:${port}/`
    };
    const args = [layout.cliPath, "helper", "open", "--port", String(port)];

    try {
      stopWindowsSurfaces();
      const results = await Promise.allSettled([
        runProcess(process.execPath, args, {
          ...baseEnv,
          SGW_HOME: firstHome,
          SGW_RECOVERY_HOME: `${firstHome}-recovery`
        }),
        runProcess(process.execPath, args, {
          ...baseEnv,
          SGW_HOME: secondHome,
          SGW_RECOVERY_HOME: `${secondHome}-recovery`
        })
      ]);
      const succeeded = results.filter((result): result is PromiseFulfilledResult<string> => result.status === "fulfilled");
      const failed = results.filter((result): result is PromiseRejectedResult => result.status === "rejected");
      expect(succeeded).toHaveLength(1);
      expect(failed).toHaveLength(1);
      expect(String(failed[0].reason)).toMatch(/another credential home|credential authority|Run s-gw stop/);

      const pids = await waitForOneWindowsHelper(port);
      expect(pids).toHaveLength(1);
      expect(Number(JSON.parse(succeeded[0].value).pid)).toBe(pids[0]);
    } finally {
      stopWindowsSurfaces();
      await rm(firstHome, { recursive: true, force: true });
      await rm(`${firstHome}-recovery`, { recursive: true, force: true });
      await rm(secondHome, { recursive: true, force: true });
      await rm(`${secondHome}-recovery`, { recursive: true, force: true });
    }
  }, 60_000);

  it("starts headless and stops every Windows surface through the CLI", async () => {
    if (process.platform !== "win32") return;
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-lifecycle-"));
    const port = await freePort();
    const oldHome = process.env.SGW_HOME;
    const oldRecoveryHome = process.env.SGW_RECOVERY_HOME;
    const oldPassphrase = process.env.SGW_MASTER_PASSPHRASE;
    const oldDisableKeychain = process.env.SGW_DISABLE_KEYCHAIN;
    const oldUpdateCheck = process.env.SGW_DISABLE_UPDATE_CHECK;
    process.env.SGW_HOME = home;
    process.env.SGW_RECOVERY_HOME = `${home}-recovery`;
    process.env.SGW_MASTER_PASSPHRASE = "windows lifecycle test passphrase";
    process.env.SGW_DISABLE_KEYCHAIN = "1";
    process.env.SGW_DISABLE_UPDATE_CHECK = "1";
    const testEnv = {
      ...process.env,
    };

    try {
      const started = JSON.parse(runBuiltCli([
        "start",
        "--port",
        String(port),
        "--no-open-app",
        "--no-menubar"
      ], testEnv));
      expect(started.ok).toBe(true);
      expect(started.console.consoleUrl).toBe(`http://127.0.0.1:${port}/`);
      expect(started.helper).toBeUndefined();
      await waitForHealth(port);

      const existing = await ensureWindowsConsole({ port });
      expect(existing.pid).toBeUndefined();

      const stopped = JSON.parse(runBuiltCli(["stop"], testEnv));
      expect(stopped.ok).toBe(true);
      expect(stopped.windows.console).toBe(true);
      await waitForHealthToStop(port);
    } finally {
      stopWindowsSurfaces();
      restoreEnv("SGW_HOME", oldHome);
      restoreEnv("SGW_RECOVERY_HOME", oldRecoveryHome);
      restoreEnv("SGW_MASTER_PASSPHRASE", oldPassphrase);
      restoreEnv("SGW_DISABLE_KEYCHAIN", oldDisableKeychain);
      restoreEnv("SGW_DISABLE_UPDATE_CHECK", oldUpdateCheck);
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);
});

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      server.close((error) => error ? reject(error) : resolve(port));
    });
  });
}

async function waitForHealth(port: number): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/api/health`);
      if (response.ok) return;
    } catch {
      // The background process can take a moment to bind its port on Windows runners.
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`s-gw console did not become healthy on port ${port}.`);
}

async function waitForHealthToStop(port: number): Promise<void> {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      await fetch(`http://127.0.0.1:${port}/api/health`);
    } catch {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`s-gw console remained healthy on port ${port}.`);
}

async function waitForPid(pid: number): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 500));
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      process.kill(pid, 0);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error(`s-gw helper process ${pid} did not remain running.`);
}

function windowsHelperPids(port: number): number[] {
  const script = [
    "$sessionId = [int](Get-Process -Id $PID).SessionId",
    `$portPattern = '(?i)(?:^|\\s)-Port(?:\\s+|:)\"?${port}\"?(?:\\s|$)'`,
    "$helperPattern = '(?i)(?:^|\\s)-File(?:\\s+|:)(?:\"[^\"]*[\\\\/]|[^\\s\"]*[\\\\/])?s-gw-helper\\.ps1\"?(?:\\s|$)'",
    "$pids = @(Get-CimInstance Win32_Process | Where-Object {",
    "  [int]$_.SessionId -eq $sessionId -and [string]$_.CommandLine -match $helperPattern -and [string]$_.CommandLine -match $portPattern",
    "} | ForEach-Object { [int]$_.ProcessId })",
    "$pids | ConvertTo-Json -Compress"
  ].join("\n");
  const output = execFileSync("powershell.exe", ["-NoProfile", "-Command", script], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  }).trim();
  if (!output) return [];
  const parsed = JSON.parse(output) as number | number[];
  return Array.isArray(parsed) ? parsed : [parsed];
}

async function waitForOneWindowsHelper(port: number): Promise<number[]> {
  let lastPids: number[] = [];
  for (let attempt = 0; attempt < 30; attempt += 1) {
    lastPids = windowsHelperPids(port);
    if (lastPids.length === 1) {
      await new Promise((resolve) => setTimeout(resolve, 150));
      const confirmed = windowsHelperPids(port);
      if (confirmed.length === 1 && confirmed[0] === lastPids[0]) return confirmed;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`Expected one s-gw helper process, found ${lastPids.length}.`);
}

async function runProcess(file: string, args: string[], env: NodeJS.ProcessEnv): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { cwd: repoRoot, env, windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += String(chunk); });
    child.stderr.on("data", (chunk) => { stderr += String(chunk); });
    child.once("error", reject);
    child.once("exit", (code) => {
      if (code === 0) {
        resolve(stdout.trim());
        return;
      }
      reject(new Error(stderr.trim() || `${file} exited with ${code}`));
    });
  });
}

function runBuiltCli(args: string[], env: NodeJS.ProcessEnv): string {
  const layout = getPackageLayout();
  return execFileSync(process.execPath, [layout.cliPath, ...args], {
    cwd: repoRoot,
    env,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
}

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }
  process.env[name] = value;
}
