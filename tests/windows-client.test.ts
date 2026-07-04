import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { getPackageLayout } from "../src/install.js";

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
    expect(credential).toContain("CredReadW");
    expect(credential).toContain("CredWriteW");
    expect(credential).toContain("[Console]::In.ReadToEnd()");
    expect(launcher).toContain("ExecutionPolicy Bypass");

    const combined = `${client}\n${helper}\n${credential}`;
    expect(combined).not.toContain("SGW_MASTER_PASSPHRASE");
  });
});
