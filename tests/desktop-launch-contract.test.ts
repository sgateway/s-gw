import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it } from "vitest";
import { desktopAppEnvironment } from "../src/install.js";

const repoRoot = process.cwd();
const tsxCli = path.join(repoRoot, "node_modules", "tsx", "dist", "cli.mjs");

describe("native desktop launch contract", () => {
  it("does not pass a console URL to the Linux desktop process", () => {
    const env = desktopAppEnvironment("http://127.0.0.1:9812/", {
      DISPLAY: ":42",
      SGW_CONSOLE_URL: "http://127.0.0.1:7777/",
      SGW_MASTER_PASSPHRASE: "synthetic-do-not-copy"
    }, "linux");

    expect(env.SGW_CONSOLE_URL).toBeUndefined();
    expect(env.SGW_MASTER_PASSPHRASE).toBeUndefined();
    expect(env.DISPLAY).toBe(":42");
  });

  it("passes the validated console URL to the native process without starting a console", async () => {
    const source = await readFile(path.join(repoRoot, "src/install.ts"), "utf8");
    const start = source.indexOf("export async function openDesktopApp");
    const end = source.indexOf("\nfunction waitForDesktopLaunch", start);
    const nativeLaunch = source.slice(start, end);

    expect(nativeLaunch).toContain('"--console-url"');
    expect(nativeLaunch).toMatch(/"--console-url",\s*url/u);
    expect(nativeLaunch).not.toContain("ensureBrowserConsole");
    expect(nativeLaunch).toContain('"--instance-key"');
    expect(nativeLaunch).toContain('"--cli-path"');
  });

  it.runIf(process.platform !== "win32")("preserves custom port settings for the native browser backup", async () => {
    const tmpRoot = await mkdtemp(path.join(os.tmpdir(), "sgw-native-port-"));
    const home = path.join(tmpRoot, "home");
    const preloadPath = path.join(tmpRoot, "linux-platform.mjs");
    const fakeDesktop = path.join(tmpRoot, "s-gw-desktop");
    const systemctlLog = path.join(tmpRoot, "systemctl.log");
    const fakeSystemctl = path.join(tmpRoot, "systemctl");

    try {
      await mkdir(home, { recursive: true });
      await writeFile(preloadPath, [
        "Object.defineProperty(process, 'platform', {",
        "  configurable: true,",
        "  value: 'linux'",
        "});",
        ""
      ].join("\n"));
      await writeFile(fakeSystemctl, [
        "#!/bin/sh",
        `printf '%s\\n' \"$*\" >> ${JSON.stringify(systemctlLog)}`,
        "exit 0",
        ""
      ].join("\n"));
      await chmod(fakeSystemctl, 0o755);

      const cases = [
        { flags: ["--port", "9812"], url: "http://127.0.0.1:9812/" },
        { flags: ["--console-url", "http://127.0.0.1:9813/"], url: "http://127.0.0.1:9813/" }
      ];
      for (let index = 0; index < cases.length; index += 1) {
        const current = cases[index];
        const argvLog = path.join(tmpRoot, `desktop-${index}.args`);
        await writeFile(fakeDesktop, [
          "#!/bin/sh",
          `printf '%s\\n' \"$@\" > ${JSON.stringify(argvLog)}`,
          "exit 0",
          ""
        ].join("\n"));
        await chmod(fakeDesktop, 0o755);

        const result = spawnSync(process.execPath, [
          tsxCli,
          path.join(repoRoot, "src/cli.ts"),
          "app",
          "open",
          ...current.flags
        ], {
          cwd: repoRoot,
          encoding: "utf8",
          timeout: 5_000,
          env: {
            ...process.env,
            HOME: home,
            NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
            SGW_DESKTOP_APP_PATH: fakeDesktop,
            SGW_DISABLE_UPDATE_CHECK: "1",
            SGW_HOME: path.join(tmpRoot, "state"),
            SGW_RECOVERY_HOME: path.join(tmpRoot, "recovery"),
            SGW_SYSTEMCTL: fakeSystemctl,
            SGW_TEST_HOME_ROOT: tmpRoot,
            SGW_TEST_MODE: "1",
            XDG_CONFIG_HOME: path.join(tmpRoot, "config")
          },
          stdio: ["ignore", "pipe", "pipe"]
        });

        expect(result.error).toBeUndefined();
        expect(result.status).toBe(0);
        const argv = (await readFile(argvLog, "utf8")).trim().split("\n");
        const consoleUrlIndex = argv.indexOf("--console-url");
        expect(consoleUrlIndex).toBeGreaterThanOrEqual(0);
        expect(argv[consoleUrlIndex + 1]).toBe(current.url);
        expect(JSON.parse(result.stdout)).toMatchObject({
          kind: "desktop-app",
          consoleUrl: current.url
        });
      }

      expect(existsSync(systemctlLog)).toBe(false);
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it.runIf(process.platform === "win32")("does not pass browser launch settings to the Windows desktop process", () => {
    const env = desktopAppEnvironment("http://127.0.0.1:9812/", process.env, "win32");
    expect(env.SGW_CONSOLE_URL).toBeUndefined();
    expect(env.SGW_APP_PATH).toBeUndefined();
  });

  it("reports a missing native app without starting the browser console", async () => {
    const tmpRoot = await mkdtemp(path.join(os.tmpdir(), "sgw-native-launch-"));
    const home = path.join(tmpRoot, "home");
    const systemctlLog = path.join(tmpRoot, "systemctl.log");
    const preloadPath = path.join(tmpRoot, "linux-platform.mjs");
    const fakeSystemctl = path.join(tmpRoot, "systemctl");

    try {
      await mkdir(home, { recursive: true });
      await writeFile(preloadPath, [
        "Object.defineProperty(process, 'platform', {",
        "  configurable: true,",
        "  value: 'linux'",
        "});",
        ""
      ].join("\n"));
      await writeFile(fakeSystemctl, [
        "#!/bin/sh",
        `printf '%s\\n' \"$*\" >> ${JSON.stringify(systemctlLog)}`,
        "exit 0",
        ""
      ].join("\n"));
      await chmod(fakeSystemctl, 0o755);

      const result = spawnSync(process.execPath, [
        tsxCli,
        path.join(repoRoot, "src/cli.ts"),
        "app",
        "open"
      ], {
        cwd: repoRoot,
        encoding: "utf8",
        timeout: 5_000,
        env: {
          ...process.env,
          HOME: home,
          NODE_OPTIONS: `--import=${pathToFileURL(preloadPath).href}`,
          SGW_DESKTOP_APP_PATH: path.join(tmpRoot, "missing", "s-gw-desktop"),
          SGW_DISABLE_UPDATE_CHECK: "1",
          SGW_HOME: path.join(tmpRoot, "state"),
          SGW_RECOVERY_HOME: path.join(tmpRoot, "recovery"),
          SGW_SYSTEMCTL: fakeSystemctl,
          SGW_TEST_HOME_ROOT: tmpRoot,
          SGW_TEST_MODE: "1",
          XDG_CONFIG_HOME: path.join(tmpRoot, "config")
        },
        stdio: ["ignore", "pipe", "pipe"]
      });

      expect(result.error).toBeUndefined();
      expect(result.status).toBe(1);
      expect(result.stderr).toContain("Native desktop app is missing");
      expect(result.stderr).toContain("s-gw app open --browser");
      expect(existsSync(systemctlLog)).toBe(false);
      expect(result.stdout).toBe("");
    } finally {
      await rm(tmpRoot, { recursive: true, force: true });
    }
  });

  it("keeps browser startup behind the explicit browser flag", async () => {
    const source = await readFile(path.join(repoRoot, "src/cli.ts"), "utf8");
    const appHandlerStart = source.indexOf("async function handleAppCommand");
    const openActionStart = source.indexOf('if (action === "open")', appHandlerStart);
    const openActionEnd = source.indexOf("\n  throw new Error", openActionStart);
    const openAction = source.slice(openActionStart, openActionEnd);
    const nativeStart = source.indexOf("async function openPreferredUi");
    const nativeEnd = source.indexOf("\n  try {", nativeStart);
    const windowsAndLinuxLaunch = source.slice(nativeStart, nativeEnd);

    expect(openAction).toContain('hasFlag(flags, "browser")');
    expect(openAction).toContain("ensureBrowserConsole(port)");
    expect(openAction).toContain("waitForConsoleAuthority(consoleUrl)");
    expect(openAction).toContain("openBrowser(consoleUrl)");
    expect(windowsAndLinuxLaunch).toContain("openDesktopApp({ port, consoleUrl })");
    expect(windowsAndLinuxLaunch).not.toMatch(/ensureBrowserConsole|openBrowser|openWindowsClient|web-console|windows-client/u);
  });
});
