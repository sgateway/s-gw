import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  getPackageLayout,
  restartWindowsSurfaces,
  startWindowsConsole,
  stopWindowsSurfaces
} from "../src/install.js";

const repoRoot = process.cwd();

describe("Windows client packaging", () => {
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
    expect(existsSync(layout.windowsHelperLauncherPath)).toBe(true);
    expect(existsSync(layout.windowsCredentialHelperPath)).toBe(true);

    const client = await readFile(layout.windowsClientScriptPath, "utf8");
    const helper = await readFile(layout.windowsHelperScriptPath, "utf8");
    const credential = await readFile(layout.windowsCredentialHelperPath, "utf8");
    const launcher = await readFile(path.join(repoRoot, "dist/windows/s-gw-client.cmd"), "utf8");

    expect(client).toContain("Start-ConsoleDaemon");
    expect(client).toContain("--app=$Url");
    expect(helper).toContain("NotifyIcon");
    expect(helper).toContain("Approve Queue");
    expect(helper).toContain('Invoke-CliJson $args');
    expect(helper).toContain('"update", "check"');
    expect(helper).toContain("s-gw update available");
    expect(helper).toContain("Check for Updates");
    expect(credential).toContain("CredReadW");
    expect(credential).toContain("CredWriteW");
    expect(credential).toContain("[Console]::In.ReadToEnd()");
    expect(launcher).toContain("ExecutionPolicy Bypass");

    const combined = `${client}\n${helper}\n${credential}`;
    expect(combined).not.toContain("SGW_MASTER_PASSPHRASE");
  });

  it("restores a running console after an update failure", async () => {
    if (process.platform !== "win32") return;
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-restart-"));
    const port = await freePort();
    const oldHome = process.env.SGW_HOME;
    const oldPassphrase = process.env.SGW_MASTER_PASSPHRASE;
    const oldUpdateCheck = process.env.SGW_DISABLE_UPDATE_CHECK;
    process.env.SGW_HOME = home;
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
      restoreEnv("SGW_MASTER_PASSPHRASE", oldPassphrase);
      restoreEnv("SGW_DISABLE_UPDATE_CHECK", oldUpdateCheck);
      await rm(home, { recursive: true, force: true });
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

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }
  process.env[name] = value;
}
