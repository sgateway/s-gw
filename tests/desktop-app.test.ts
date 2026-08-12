import { access, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { describe, expect, it } from "vitest";
import {
  desktopAppCandidates,
  desktopAppEnvironment,
  desktopAuthorityArguments,
  packageHealth,
  waitForConsoleAuthority
} from "../src/install.js";
import { getSgwInstanceKey } from "../src/paths.js";
import { replaceDirectory } from "../scripts/replace-directory.mjs";

const root = process.cwd();
const appRoot = path.join(root, "native/desktop-app");
const execFileAsync = promisify(execFile);

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

  it("ships a compiled native UI with no WebView or bundled web page", async () => {
    const [cargoRaw, buildSource, packageSource, packageRaw, workflowSource, smokeSource, rustFiles] = await Promise.all([
      readFile(path.join(appRoot, "Cargo.toml"), "utf8"),
      readFile(path.join(appRoot, "build.rs"), "utf8"),
      readFile(path.join(root, "scripts/package-desktop-app.mjs"), "utf8"),
      readFile(path.join(root, "package.json"), "utf8"),
      readFile(path.join(root, ".github/workflows/ci.yml"), "utf8"),
      readFile(path.join(root, "scripts/verify-desktop-deb.sh"), "utf8"),
      readdir(path.join(appRoot, "src"))
    ]);
    const rustSource = (
      await Promise.all(
        rustFiles
          .filter((name) => name.endsWith(".rs"))
          .map((name) => readFile(path.join(appRoot, "src", name), "utf8"))
      )
    ).join("\n");
    const packageInfo = JSON.parse(packageRaw);

    expect(cargoRaw).toContain('eframe = { version = "=0.36.1"');
    expect(cargoRaw).toContain('features = ["accesskit", "default_fonts", "glow", "wayland", "x11"]');
    expect(cargoRaw).toContain('egui = "=0.36.1"');
    expect(cargoRaw).toContain('egui_extras = "=0.36.1"');
    expect(cargoRaw).toContain('tray-icon = "=0.24.2"');
    expect(cargoRaw).toContain('gtk = "=0.18.2"');
    expect(cargoRaw).toContain('single-instance = "=0.3.3"');
    expect(cargoRaw).toContain('open = "=5.4.1"');
    expect(cargoRaw).not.toMatch(/\btauri\b/iu);
    expect(cargoRaw).not.toMatch(/\bwry\b/iu);
    expect(packageInfo.devDependencies["@crabnebula/packager"]).toBe("0.11.2");
    expect(packageInfo.devDependencies["@tauri-apps/cli"]).toBeUndefined();

    expect(rustSource).toContain("eframe::run_native");
    expect(rustSource).toContain("impl eframe::App");
    expect(rustSource).toContain("parse_health_response");
    expect(rustSource).toContain('"__desktop-instance-key"');
    expect(rustSource).toContain("current_windows_default_instance_key");
    expect(rustSource).toContain("GetUserNameW");
    expect(rustSource).toContain("GetUserProfileDirectoryW");
    expect(rustSource).toContain('"Open browser backup"');
    expect(rustSource).toContain("gtk::init()");
    expect(rustSource).toContain("gtk::main_iteration_do(false)");
    expect(buildSource).not.toContain("tauri_build");
    expect(buildSource).toContain('env::var("PROFILE").as_deref() != Ok("release")');
    expect(buildSource).toContain("desktop runtime target does not match the Rust target");
    expect(buildSource).toContain('runtime_root.join("package/dist/cli.js")');

    expect(packageSource).toContain('formats: ["nsis"]');
    expect(packageSource).toContain('formats: ["deb"]');
    expect(packageSource).toContain('installMode: "currentUser"');
    for (const dependency of [
      "libayatana-appindicator3-1",
      "libgl1",
      "libgtk-3-0",
      "libsecret-tools",
      "libxdo3",
      "libxkbcommon-x11-0"
    ]) {
      expect(packageSource).toContain(`"${dependency}"`);
      expect(workflowSource).toContain(dependency);
    }
    expect(workflowSource).toContain('grep -Fq "$dependency"');
    expect(workflowSource).toContain("Clean-install and launch deb");
    expect(workflowSource).toContain("ubuntu:22.04");
    expect(workflowSource).toContain("verify-desktop-deb.sh");
    expect(workflowSource).toContain("$allowedInstallerHelper = Join-Path $unpacked '$PLUGINSDIR\\nsis_tauri_utils.dll'");
    expect(workflowSource).toContain("$_.FullName -cne $allowedInstallerHelper");
    expect(workflowSource).toContain("$_.Name -match '(tauri|wry|webview2|webkit|javascriptcore)'");
    expect(smokeSource).toContain("xauth");
    expect(smokeSource).toContain("xvfb-run");
    expect(smokeSource).toContain("timeout 8s");
    expect(packageSource).not.toMatch(/webview|webkit/iu);

    await expect(access(path.join(appRoot, "frontend"))).rejects.toThrow();
    await expect(access(path.join(appRoot, "tauri.conf.json"))).rejects.toThrow();
    await expect(access(path.join(appRoot, "tauri.windows.conf.json"))).rejects.toThrow();
    await expect(access(path.join(appRoot, "tauri.linux.conf.json"))).rejects.toThrow();

    const [metadata, windowsTree, linuxTree] = await Promise.all([
      execFileAsync(
        "cargo",
        ["metadata", "--locked", "--format-version", "1", "--manifest-path", path.join(appRoot, "Cargo.toml")],
        { maxBuffer: 20 * 1024 * 1024 }
      ),
      execFileAsync(
        "cargo",
        [
          "tree", "--locked", "--edges", "normal", "--target", "x86_64-pc-windows-msvc",
          "--manifest-path", path.join(appRoot, "Cargo.toml")
        ],
        { maxBuffer: 20 * 1024 * 1024 }
      ),
      execFileAsync(
        "cargo",
        [
          "tree", "--locked", "--edges", "normal", "--target", "x86_64-unknown-linux-gnu",
          "--manifest-path", path.join(appRoot, "Cargo.toml")
        ],
        { maxBuffer: 20 * 1024 * 1024 }
      )
    ]);
    const packageNames = (JSON.parse(metadata.stdout).packages as Array<{ name: string }>).map((item) => item.name);
    expect(packageNames.filter((name) => /^(tauri|wry|webview2-com|webkit2gtk|javascriptcore-rs)/u.test(name))).toEqual([]);
    for (const activeTree of [windowsTree.stdout, linuxTree.stdout]) {
      expect(activeTree).toMatch(/\begui_glow v/u);
      expect(activeTree).toMatch(/\bglow v/u);
      expect(activeTree).toMatch(/\bglutin v/u);
      expect(activeTree).not.toMatch(/\b(?:egui-wgpu|gpu-allocator|wgpu(?:-[a-z0-9-]+)?) v/iu);
    }
  }, 30_000);

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
    expect(stageSource).toContain("await replaceDirectory(stagedRoot, runtimeRoot)");
    expect(stageSource).toContain('[resolve(packageRoot, "dist/cli.js"), "help"]');
    expect(stageSource).toContain("process.env.npm_execpath");
    expect(stageSource).toContain("process.execPath");
    expect(stageSource).not.toContain('"npm.cmd"');
  });

  it("retries transient Windows locks while publishing the staged runtime", async () => {
    const scratch = await mkdtemp(path.join(tmpdir(), "s-gw-runtime-replace-"));
    const staged = path.join(scratch, "staged");
    const destination = path.join(scratch, "runtime");
    const backup = path.join(scratch, "backup");
    const waits: number[] = [];
    let publishAttempts = 0;

    try {
      await mkdir(staged);
      await mkdir(destination);
      await writeFile(path.join(staged, "ready.txt"), "ready");
      await writeFile(path.join(destination, "old.txt"), "old");

      await replaceDirectory(staged, destination, {
        backupPath: backup,
        platform: "win32",
        renamePath: async (source: string, target: string) => {
          if (source === staged && target === destination) {
            publishAttempts += 1;
            if (publishAttempts < 3) {
              throw Object.assign(new Error("simulated Windows sharing violation"), { code: "EPERM" });
            }
          }
          await rename(source, target);
        },
        wait: async (delayMs: number) => {
          waits.push(delayMs);
        }
      });

      await expect(readFile(path.join(destination, "ready.txt"), "utf8")).resolves.toBe("ready");
      await expect(access(path.join(destination, "old.txt"))).rejects.toThrow();
      await expect(access(staged)).rejects.toThrow();
      await expect(access(backup)).rejects.toThrow();
      expect(publishAttempts).toBe(3);
      expect(waits).toEqual([250, 250]);
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  });

  it("restores the previous runtime when a replacement cannot be published", async () => {
    const scratch = await mkdtemp(path.join(tmpdir(), "s-gw-runtime-rollback-"));
    const staged = path.join(scratch, "staged");
    const destination = path.join(scratch, "runtime");
    const backup = path.join(scratch, "backup");

    try {
      await mkdir(staged);
      await mkdir(destination);
      await writeFile(path.join(staged, "new.txt"), "new");
      await writeFile(path.join(destination, "current.txt"), "current");

      await expect(replaceDirectory(staged, destination, {
        backupPath: backup,
        platform: "win32",
        renamePath: async (source: string, target: string) => {
          if (source === staged && target === destination) {
            throw Object.assign(new Error("simulated permanent failure"), { code: "EIO" });
          }
          await rename(source, target);
        },
        wait: async () => undefined
      })).rejects.toThrow("simulated permanent failure");

      await expect(readFile(path.join(destination, "current.txt"), "utf8")).resolves.toBe("current");
      await expect(readFile(path.join(staged, "new.txt"), "utf8")).resolves.toBe("new");
      await expect(access(backup)).rejects.toThrow();
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  });

  it("preserves the backup when both publish and rollback fail", async () => {
    const scratch = await mkdtemp(path.join(tmpdir(), "s-gw-runtime-backup-"));
    const staged = path.join(scratch, "staged");
    const destination = path.join(scratch, "runtime");
    const backup = path.join(scratch, "backup");

    try {
      await mkdir(staged);
      await mkdir(destination);
      await writeFile(path.join(staged, "new.txt"), "new");
      await writeFile(path.join(destination, "current.txt"), "current");

      await expect(replaceDirectory(staged, destination, {
        backupPath: backup,
        platform: "win32",
        renamePath: async (source: string, target: string) => {
          if (source === staged || source === backup) {
            throw Object.assign(new Error("simulated filesystem failure"), { code: "EIO" });
          }
          await rename(source, target);
        },
        wait: async () => undefined
      })).rejects.toThrow(`Backup: ${backup}`);

      await expect(readFile(path.join(backup, "current.txt"), "utf8")).resolves.toBe("current");
      await expect(readFile(path.join(staged, "new.txt"), "utf8")).resolves.toBe("new");
      await expect(access(destination)).rejects.toThrow();
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  });

  it("preserves the previous runtime if the destination reappears during publish", async () => {
    const scratch = await mkdtemp(path.join(tmpdir(), "s-gw-runtime-collision-"));
    const staged = path.join(scratch, "staged");
    const destination = path.join(scratch, "runtime");
    const backup = path.join(scratch, "backup");

    try {
      await mkdir(staged);
      await mkdir(destination);
      await writeFile(path.join(staged, "new.txt"), "new");
      await writeFile(path.join(destination, "current.txt"), "current");

      await expect(replaceDirectory(staged, destination, {
        backupPath: backup,
        platform: "win32",
        renamePath: async (source: string, target: string) => {
          if (source === staged && target === destination) {
            await mkdir(destination);
            await writeFile(path.join(destination, "foreign.txt"), "foreign");
            throw Object.assign(new Error("simulated destination collision"), { code: "ENOTEMPTY" });
          }
          await rename(source, target);
        },
        wait: async () => undefined
      })).rejects.toThrow(`Previous runtime: ${backup}`);

      await expect(readFile(path.join(backup, "current.txt"), "utf8")).resolves.toBe("current");
      await expect(readFile(path.join(destination, "foreign.txt"), "utf8")).resolves.toBe("foreign");
      await expect(readFile(path.join(staged, "new.txt"), "utf8")).resolves.toBe("new");
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
  });

  it("does not remove a backup path it did not create", async () => {
    const scratch = await mkdtemp(path.join(tmpdir(), "s-gw-runtime-existing-backup-"));
    const staged = path.join(scratch, "staged");
    const destination = path.join(scratch, "runtime");
    const backup = path.join(scratch, "backup");

    try {
      await mkdir(staged);
      await mkdir(destination);
      await mkdir(backup);
      await writeFile(path.join(staged, "new.txt"), "new");
      await writeFile(path.join(destination, "current.txt"), "current");
      await writeFile(path.join(backup, "sentinel.txt"), "sentinel");

      await expect(replaceDirectory(staged, destination, {
        backupPath: backup,
        platform: "win32",
        renamePath: async (source: string, target: string) => {
          if (source === destination && target === backup) {
            throw Object.assign(new Error("simulated backup collision"), { code: "EEXIST" });
          }
          await rename(source, target);
        },
        wait: async () => undefined
      })).rejects.toThrow("simulated backup collision");

      await expect(readFile(path.join(backup, "sentinel.txt"), "utf8")).resolves.toBe("sentinel");
      await expect(readFile(path.join(destination, "current.txt"), "utf8")).resolves.toBe("current");
      await expect(readFile(path.join(staged, "new.txt"), "utf8")).resolves.toBe("new");
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }
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
    expect(env.SGW_CONSOLE_URL).toBeUndefined();
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
