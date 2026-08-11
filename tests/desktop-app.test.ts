import { readFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  desktopAppCandidates,
  desktopAppEnvironment,
  desktopAuthorityArguments,
  packageHealth,
  waitForConsoleAuthority
} from "../src/install.js";
import { getSgwInstanceKey } from "../src/paths.js";

const root = process.cwd();
const appRoot = path.join(root, "native/desktop-app");

describe("Windows and Linux desktop app", () => {
  it("finds packaged and installed native executables without replacing the browser fallback", () => {
    const windows = desktopAppCandidates("C:\\pkg", "win32-x64", "win32", {
      LOCALAPPDATA: "C:\\Users\\dev\\AppData\\Local",
      SGW_DESKTOP_APP_PATH: "C:\\custom\\s-gw-desktop.exe"
    });
    expect(windows[0]).toContain("custom");
    expect(windows).toContain(path.win32.join("C:\\pkg", "dist", "native", "win32-x64", "s-gw-desktop.exe"));
    expect(windows.some((item) => item.endsWith(path.win32.join("s-gw", "s-gw-desktop.exe")))).toBe(true);

    const linux = desktopAppCandidates("/opt/s-gw", "linux-x64", "linux", {});
    expect(linux).toContain("/opt/s-gw/dist/native/linux-x64/s-gw-desktop");
    expect(linux).toContain("/usr/bin/s-gw-desktop");
  });

  it("ships a locked-down Tauri shell and platform-native installer targets", async () => {
    const [cargoRaw, buildSource, baseRaw, windowsRaw, linuxRaw, rustSource, loadingPage] = await Promise.all([
      readFile(path.join(appRoot, "Cargo.toml"), "utf8"),
      readFile(path.join(appRoot, "build.rs"), "utf8"),
      readFile(path.join(appRoot, "tauri.conf.json"), "utf8"),
      readFile(path.join(appRoot, "tauri.windows.conf.json"), "utf8"),
      readFile(path.join(appRoot, "tauri.linux.conf.json"), "utf8"),
      readFile(path.join(appRoot, "src/main.rs"), "utf8"),
      readFile(path.join(appRoot, "frontend/index.html"), "utf8")
    ]);
    const base = JSON.parse(baseRaw);
    const windows = JSON.parse(windowsRaw);
    const linux = JSON.parse(linuxRaw);

    expect(cargoRaw).toContain('tauri = { version = "=2.11.5"');
    expect(cargoRaw).toContain('features = ["tray-icon"]');
    expect(cargoRaw).toContain('tauri-plugin-single-instance = "=2.4.3"');
    expect(cargoRaw).not.toContain("tauri-plugin-autostart");
    expect(base.app.windows).toEqual([]);
    expect(base.app.security.csp).toContain("connect-src 'none'");
    expect(base.bundle.resources).toEqual(["runtime/"]);
    expect(windows.bundle.targets).toEqual(["nsis"]);
    expect(windows.bundle.windows.nsis.installMode).toBe("currentUser");
    expect(linux.bundle.targets).toEqual(["deb"]);
    expect(linux.bundle.linux.deb.depends).toContain("libsecret-tools");

    expect(rustSource).toContain("WebviewUrl::App");
    expect(rustSource).toContain(".incognito(true)");
    expect(rustSource).toContain(".browser_extensions_enabled(false)");
    expect(rustSource).toContain("is_console_navigation");
    expect(rustSource).toContain("NewWindowResponse::Deny");
    expect(rustSource).toContain("parse_health_response");
    expect(rustSource).toContain('arg("__desktop-instance-key")');
    expect(rustSource).toContain("current_windows_default_instance_key");
    expect(rustSource).toContain("GetUserNameW");
    expect(rustSource).toContain("GetUserProfileDirectoryW");
    expect(rustSource).toContain('run_lifecycle(&runtime, "setup"');
    expect(rustSource).toContain('"Open browser backup"');
    expect(rustSource).not.toContain("#[tauri::command]");
    expect(loadingPage).not.toContain("<script");
    expect(buildSource).toContain('env::var("PROFILE").as_deref() != Ok("release")');
    expect(buildSource).toContain("desktop runtime target does not match the Rust target");
    expect(buildSource).toContain('runtime_root.join("package/dist/cli.js")');
  });

  it("pins and verifies the bundled Node runtimes", async () => {
    const [runtimeRaw, stageSource] = await Promise.all([
      readFile(path.join(appRoot, "runtime.json"), "utf8"),
      readFile(path.join(root, "scripts/stage-desktop-runtime.mjs"), "utf8")
    ]);
    const runtime = JSON.parse(runtimeRaw);

    expect(runtime.nodeVersion).toMatch(/^24\./);
    expect(Object.keys(runtime.targets).sort()).toEqual(["linux-x64", "win32-x64"]);
    for (const target of Object.values(runtime.targets) as Array<{ url: string; sha256: string }>) {
      expect(target.url).toMatch(/^https:\/\/nodejs\.org\/dist\//);
      expect(target.sha256).toMatch(/^[a-f0-9]{64}$/);
    }
    expect(stageSource).toContain("Embedded Node archive checksum mismatch");
    expect(stageSource).toContain('[npmCli, "ci", "--omit=dev", "--ignore-scripts"');
    expect(stageSource).toContain("Desktop runtime staging must run on");
    expect(stageSource).toContain("replaceRuntime(stagedRoot, runtimeRoot)");
    expect(stageSource).toContain('[resolve(packageRoot, "dist/cli.js"), "help"]');
    expect(stageSource).toContain("process.env.npm_execpath");
    expect(stageSource).toContain("process.execPath");
    expect(stageSource).not.toContain('"npm.cmd"');
  });

  it("exposes only the non-secret local instance identity in status", () => {
    const health = packageHealth();
    expect(health.instanceKey).toBe(getSgwInstanceKey());
    expect(health.instanceKey).toMatch(/^[a-f0-9]{64}$/);
  });

  it("does not pass shell credentials into the long-lived desktop process", () => {
    const env = desktopAppEnvironment(
      "http://127.0.0.1:8718/",
      {
        DISPLAY: ":1",
        HOME: "/tmp/untrusted-home",
        OPENAI_API_KEY: "do-not-inherit",
        PATH: process.env.PATH,
        SGW_MASTER_PASSPHRASE: "do-not-inherit",
        XDG_RUNTIME_DIR: "/run/user/1000"
      },
      "linux"
    );

    expect(env.DISPLAY).toBe(":1");
    expect(env.XDG_RUNTIME_DIR).toBe("/run/user/1000");
    expect(env.OPENAI_API_KEY).toBeUndefined();
    expect(env.SGW_MASTER_PASSPHRASE).toBeUndefined();
    expect(env.SGW_CONSOLE_URL).toBe("http://127.0.0.1:8718/");
  });

  it("passes only explicit authority overrides to the desktop process", () => {
    const normalized = {
      SGW_HOME: "/home/dev/.s-gw",
      SGW_RECOVERY_HOME: "/home/dev/.s-gw-recovery",
      SGW_KEYCHAIN_SERVICE: "com.s-gw.sgw.master-passphrase"
    };

    expect(desktopAuthorityArguments({}, normalized)).toEqual([]);
    expect(desktopAuthorityArguments({ SGW_HOME: "~/.s-gw" }, normalized)).toEqual([
      "--authority",
      "SGW_HOME=/home/dev/.s-gw"
    ]);
  });

  it("opens browser backup only for the expected local authority", async () => {
    const expectedKey = "a".repeat(64);
    let servedKey = expectedKey;
    const server = createServer((_request, response) => {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ ok: true, name: "s-gw", instanceKey: servedKey }));
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = (server.address() as AddressInfo).port;
    const url = `http://127.0.0.1:${port}/`;

    try {
      await expect(waitForConsoleAuthority(url, expectedKey, 500)).resolves.toBeUndefined();
      servedKey = "b".repeat(64);
      await expect(waitForConsoleAuthority(url, expectedKey, 500)).rejects.toThrow(
        "Refusing to open an unverified local service"
      );
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  });
});
