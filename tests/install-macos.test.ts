import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { getPackageLayout, installMacAppBundle } from "../src/install.js";

describe("macOS app installation", () => {
  it.skipIf(process.platform !== "darwin")("installs the app bundle once and replaces a changed copy", async () => {
    const applicationsDir = await mkdtemp(path.join(os.tmpdir(), "sgw-app-install-"));

    try {
      const first = installMacAppBundle({ applicationsDir, registerCliPath: false });
      expect(first.changed).toBe(true);
      expect(first.appPath).toBe(path.join(applicationsDir, "s-gw.app"));

      const second = installMacAppBundle({ applicationsDir, registerCliPath: false });
      expect(second.changed).toBe(false);

      const installedInfo = path.join(first.appPath, "Contents", "Info.plist");
      const originalInfo = await readFile(installedInfo);
      await writeFile(installedInfo, "outdated app bundle");

      const replaced = installMacAppBundle({ applicationsDir, registerCliPath: false });
      expect(replaced.changed).toBe(true);
      expect(await readFile(installedInfo)).toEqual(originalInfo);
    } finally {
      await rm(applicationsDir, { recursive: true, force: true });
    }
  });

  it.skipIf(process.platform !== "darwin")("keeps the menu helper alive through notification startup", async () => {
    const layout = getPackageLayout();
    const tmp = await mkdtemp(path.join(os.tmpdir(), "sgw-menu-startup-"));
    let stderr = "";
    const helper = spawn(layout.menuBarBinaryPath, [], {
      env: {
        ...process.env,
        SGW_REPO_ROOT: layout.packageRoot,
        SGW_CLI_PATH: "/usr/bin/true",
        SGW_NODE_PATH: "/usr/bin/true",
        SGW_CONSOLE_URL: "http://127.0.0.1:9/",
        SGW_MENU_BAR_LOCK_PATH: path.join(tmp, "menu-helper.lock")
      },
      stdio: ["ignore", "ignore", "pipe"]
    });
    helper.stderr.setEncoding("utf8");
    helper.stderr.on("data", (chunk: string) => { stderr += chunk; });

    const earlyExit = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
      helper.once("error", () => resolve({ code: -1, signal: null }));
      helper.once("exit", (code, signal) => resolve({ code, signal }));
    });

    try {
      const result = await Promise.race([
        earlyExit,
        new Promise<null>((resolve) => setTimeout(() => resolve(null), 1_500))
      ]);
      expect(result, stderr || "menu helper exited during startup").toBeNull();
    } finally {
      if (helper.exitCode === null && helper.signalCode === null) {
        helper.kill();
        await earlyExit;
      }
      await rm(tmp, { recursive: true, force: true });
    }
  }, 10_000);
});
