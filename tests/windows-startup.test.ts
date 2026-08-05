import { spawnSync } from "node:child_process";
import { realpathSync } from "node:fs";
import { lstat, mkdir, mkdtemp, realpath, rm, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { windowsBackgroundEnvironment } from "../src/install.js";
import { getSgwInstanceKey } from "../src/paths.js";
import {
  applyWindowsStartupConfig,
  buildWindowsStartupConfig,
  decodeWindowsStartupConfig,
  encodeWindowsStartupConfig
} from "../src/windows-startup.js";
import {
  trustedWindowsPowerShellSync,
  trustedWindowsSystemExecutableSync,
  trustedWindowsSystemRootSync,
  windowsSystemEnvironment
} from "../src/windows-system.js";

let root = "";
let previousEnv: NodeJS.ProcessEnv;

beforeEach(async () => {
  previousEnv = { ...process.env };
  root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-windows-startup-")));
  process.env.SGW_TEST_MODE = "1";
  process.env.SGW_TEST_HOME_ROOT = root;
  process.env.SGW_HOME = path.join(root, "authority home 漢字");
  process.env.SGW_RECOVERY_HOME = path.join(root, "recovery home é");
  process.env.SGW_KEYCHAIN_SERVICE = "com.example.sgw.test";
  process.env.SGW_KEYCHAIN_ACCOUNT = "standard user é";
  process.env.SGW_SECRET_KEYCHAIN_SERVICE = "com.example.sgw.secrets";
  process.env.SGW_SECRET_BACKEND = "keychain";
  process.env.SGW_EXECUTION_ENGINE = "rust";
});

afterEach(async () => {
  process.env = previousEnv;
  if (root) {
    const junctionPath = path.join(root, "system-root junction");
    const junctionInfo = await lstat(junctionPath).catch(() => undefined);
    if (junctionInfo) {
      await unlink(junctionPath);
    }
  }
  await rm(root, { recursive: true, force: true });
});

describe("Windows login startup contract", () => {
  it("round-trips alternate authority paths, port, tray, and non-ASCII metadata", () => {
    process.env.SGW_MASTER_PASSPHRASE = "sentinel-master-passphrase";
    process.env.AWS_SECRET_ACCESS_KEY = "sentinel-cloud-secret";
    process.env.NODE_OPTIONS = "--require hostile-preload.js";
    process.env.SGW_WINDOWS_CREDENTIAL_HELPER = path.join(root, "hostile-helper.ps1");
    process.env.SGW_SECRET_BACKEND = "  KEYCHAIN ";
    process.env.SGW_EXECUTION_ENGINE = "  RUST ";

    const config = buildWindowsStartupConfig("S-1-5-21-100-200-300-1001", 29_871, true);
    const payload = encodeWindowsStartupConfig(config);
    const decoded = decodeWindowsStartupConfig(payload);

    expect(decoded).toEqual(config);
    expect(decoded.port).toBe(29_871);
    expect(decoded.tray).toBe(true);
    expect(decoded.env.SGW_HOME).toContain("authority home 漢字");
    expect(decoded.env.SGW_RECOVERY_HOME).toContain("recovery home é");
    expect(decoded.env.SGW_EXECUTION_ENGINE).toBe("rust");
    expect(decoded.env.SGW_SECRET_BACKEND).toBe("keychain");
    const serialized = JSON.stringify(decoded);
    expect(serialized).not.toContain("sentinel-master-passphrase");
    expect(serialized).not.toContain("sentinel-cloud-secret");
    expect(serialized).not.toContain("hostile-preload");
    expect(serialized).not.toContain("hostile-helper");
    expect(Object.keys(decoded.env).sort()).toEqual([
      "SGW_EXECUTION_ENGINE",
      "SGW_HOME",
      "SGW_KEYCHAIN_ACCOUNT",
      "SGW_KEYCHAIN_SERVICE",
      "SGW_RECOVERY_HOME",
      "SGW_SECRET_BACKEND",
      "SGW_SECRET_KEYCHAIN_SERVICE"
    ]);
  });

  it("rejects extra fields, credential material, invalid backends, and overlapping homes", () => {
    const valid = buildWindowsStartupConfig("S-1-5-21-100-200-300-1001", 8718, false);
    expect(() => decodeWindowsStartupConfig(encodeRaw({ ...valid, token: "credential" })))
      .toThrow(/invalid schema/i);
    expect(() => decodeWindowsStartupConfig(encodeRaw({
      ...valid,
      env: { ...valid.env, SGW_MASTER_PASSPHRASE: "credential" }
    }))).toThrow(/unsupported environment/i);
    expect(() => decodeWindowsStartupConfig(encodeRaw({
      ...valid,
      env: { ...valid.env, SGW_SECRET_BACKEND: "windows-credential-manager" }
    }))).toThrow(/unsupported secret backend/i);
    expect(() => decodeWindowsStartupConfig(encodeRaw({
      ...valid,
      env: { ...valid.env, SGW_RECOVERY_HOME: path.join(valid.env.SGW_HOME, "recovery") }
    }))).toThrow(/must not overlap/i);
  });

  it("applies only stable authority settings and restores the caller environment", () => {
    const before = getSgwInstanceKey();
    const config = buildWindowsStartupConfig("S-1-5-21-100-200-300-1001", 8718, false);
    process.env.SGW_MASTER_PASSPHRASE = "sentinel-master-passphrase";
    process.env.SGW_DISABLE_KEYCHAIN = "1";
    process.env.SGW_WINDOWS_CREDENTIAL_HELPER = "hostile-helper";
    process.env.SGW_LOGIN_SESSION_ID = "different-login";
    expect(getSgwInstanceKey()).toBe(before);

    const restore = applyWindowsStartupConfig(config);
    expect(process.env.SGW_MASTER_PASSPHRASE).toBeUndefined();
    expect(process.env.SGW_DISABLE_KEYCHAIN).toBeUndefined();
    expect(process.env.SGW_WINDOWS_CREDENTIAL_HELPER).toBeUndefined();
    expect(getSgwInstanceKey()).toBe(before);
    restore();
    expect(process.env.SGW_MASTER_PASSPHRASE).toBe("sentinel-master-passphrase");
    expect(process.env.SGW_DISABLE_KEYCHAIN).toBe("1");
    expect(process.env.SGW_WINDOWS_CREDENTIAL_HELPER).toBe("hostile-helper");
  });

  it.skipIf(process.platform === "win32")(
    "uses the trusted System32 PowerShell and strips hostile inherited environment",
    async () => {
      const systemRoot = path.join(root, "trusted Windows");
      const powershell = path.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
      const hostileDir = path.join(root, "hostile path");
      await mkdir(path.dirname(powershell), { recursive: true });
      await mkdir(hostileDir, { recursive: true });
      await writeFile(powershell, "trusted", "utf8");
      await writeFile(path.join(hostileDir, "powershell.exe"), "hostile", "utf8");
      const directoryExecutable = path.join(path.dirname(powershell), "directory.exe");
      await mkdir(directoryExecutable);
      delete process.env.SystemRoot;
      delete process.env.WINDIR;
      process.env.systemroot = await realpath(systemRoot);
      process.env.windir = process.env.systemroot;
      process.env.PATH = hostileDir;
      process.env.SGW_MASTER_PASSPHRASE = "sentinel-master-passphrase";
      process.env.AWS_SECRET_ACCESS_KEY = "sentinel-cloud-secret";
      process.env.NODE_OPTIONS = "--require hostile-preload.js";

      expect(trustedWindowsPowerShellSync()).toBe(await realpath(powershell));
      expect(() => trustedWindowsSystemExecutableSync(
        "WindowsPowerShell",
        "v1.0",
        "directory.exe"
      )).toThrow(/invalid file type/i);
      const systemEnv = windowsSystemEnvironment();
      expect(systemEnv.PATH).toContain(path.join(process.env.systemroot, "System32"));
      expect(systemEnv.PATH).not.toContain(hostileDir);
      expect(() => windowsSystemEnvironment({ PATH: hostileDir })).toThrow(/cannot override trusted PATH/i);

      const background = windowsBackgroundEnvironment("http://127.0.0.1:8718/");
      expect(background.SGW_HOME).toBe(process.env.SGW_HOME);
      expect(background.SGW_RECOVERY_HOME).toBe(process.env.SGW_RECOVERY_HOME);
      expect(background.SGW_EXECUTION_ENGINE).toBe("rust");
      expect(background.SGW_MASTER_PASSPHRASE).toBeUndefined();
      expect(background.AWS_SECRET_ACCESS_KEY).toBeUndefined();
      expect(background.NODE_OPTIONS).toBeUndefined();
      expect(JSON.stringify(background)).not.toContain("sentinel-");
    }
  );

  it.skipIf(process.platform !== "win32")(
    "validates kernel identity and returns a spawnable normal system path",
    async () => {
      const testMode = process.env.SGW_TEST_MODE;
      let substDrive = "";
      let substExecutable = "";
      let substMapped = false;
      const junctionPath = path.join(root, "system-root junction");
      let junctionExists = false;
      delete process.env.SGW_TEST_MODE;
      try {
        const globalRoot = String.raw`\\?\GLOBALROOT\SystemRoot`;
        const trustedRoot = trustedWindowsSystemRootSync();
        const trustedShell = path.win32.join(
          trustedRoot,
          "System32",
          "WindowsPowerShell",
          "v1.0",
          "powershell.exe"
        );
        const globalShell = path.win32.join(
          globalRoot,
          "System32",
          "WindowsPowerShell",
          "v1.0",
          "powershell.exe"
        );
        expect(trustedRoot).toMatch(/^[A-Za-z]:\\/u);
        expect(trustedRoot).not.toBe(globalRoot);
        expect(trustedWindowsPowerShellSync()).toBe(trustedShell);
        const normalRootInfo = await lstat(trustedRoot, { bigint: true });
        const globalRootInfo = await lstat(globalRoot, { bigint: true });
        const normalShellInfo = await lstat(trustedShell, { bigint: true });
        const globalShellInfo = await lstat(globalShell, { bigint: true });
        expect([normalRootInfo.dev, normalRootInfo.ino]).toEqual([globalRootInfo.dev, globalRootInfo.ino]);
        expect([normalShellInfo.dev, normalShellInfo.ino]).toEqual([globalShellInfo.dev, globalShellInfo.ino]);

        const result = spawnSync(trustedShell, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "exit 0"], {
          env: windowsSystemEnvironment(),
          shell: false,
          stdio: "ignore",
          windowsHide: true
        });
        expect(result.error).toBeUndefined();
        expect(result.status).toBe(0);

        const hostileRoot = path.join(root, "hostile Windows");
        await mkdir(hostileRoot, { recursive: true });
        for (const key of Object.keys(process.env)) {
          if (["systemroot", "windir"].includes(key.toLowerCase())) delete process.env[key];
        }
        expect(trustedWindowsSystemRootSync()).toBe(trustedRoot);
        expect(trustedWindowsPowerShellSync()).toBe(trustedShell);

        process.env.systemroot = hostileRoot;
        process.env.windir = hostileRoot;
        expect(trustedWindowsSystemRootSync()).toBe(trustedRoot);
        expect(trustedWindowsPowerShellSync()).toBe(trustedShell);

        process.env.SystemRoot = hostileRoot;
        process.env.WINDIR = trustedRoot;
        expect(trustedWindowsSystemRootSync()).toBe(trustedRoot);
        expect(trustedWindowsPowerShellSync()).toBe(trustedShell);
        expect(windowsSystemEnvironment()).toMatchObject({
          SystemRoot: trustedRoot,
          WINDIR: trustedRoot
        });

        await symlink(trustedRoot, junctionPath, "junction");
        junctionExists = true;
        expect(windowsPathKey(realpathSync.native(junctionPath))).toBe(windowsPathKey(trustedRoot));
        process.env.SystemRoot = junctionPath;
        process.env.WINDIR = junctionPath;
        expect(trustedWindowsSystemRootSync()).toBe(trustedRoot);
        expect(trustedWindowsPowerShellSync()).toBe(trustedShell);

        await unlink(junctionPath);
        junctionExists = false;
        await symlink(hostileRoot, junctionPath, "junction");
        junctionExists = true;
        expect(windowsPathKey(realpathSync.native(junctionPath))).toBe(windowsPathKey(hostileRoot));
        expect(trustedWindowsSystemRootSync()).toBe(trustedRoot);
        expect(trustedWindowsPowerShellSync()).toBe(trustedShell);
        await unlink(junctionPath);
        junctionExists = false;

        for (let code = "Z".charCodeAt(0); code >= "P".charCodeAt(0); code -= 1) {
          const candidate = `${String.fromCharCode(code)}:`;
          const exists = await lstat(`${candidate}\\`).then(() => true, () => false);
          if (!exists) {
            substDrive = candidate;
            break;
          }
        }
        expect(substDrive).not.toBe("");
        substExecutable = trustedWindowsSystemExecutableSync("subst.exe");
        const mapResult = spawnSync(substExecutable, [substDrive, trustedRoot], {
          env: windowsSystemEnvironment(),
          shell: false,
          stdio: "ignore",
          windowsHide: true
        });
        expect(mapResult.error).toBeUndefined();
        expect(mapResult.status).toBe(0);
        substMapped = true;

        const substRoot = `${substDrive}\\`;
        expect(windowsPathKey(realpathSync.native(substRoot))).toBe(windowsPathKey(trustedRoot));
        process.env.SystemRoot = substRoot;
        process.env.WINDIR = substRoot;
        expect(trustedWindowsSystemRootSync()).toBe(trustedRoot);
        expect(trustedWindowsPowerShellSync()).toBe(trustedShell);

        const finalSpawn = spawnSync(trustedWindowsPowerShellSync(), [
          "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "exit 0"
        ], {
          env: windowsSystemEnvironment(),
          shell: false,
          stdio: "ignore",
          windowsHide: true
        });
        expect(finalSpawn.error).toBeUndefined();
        expect(finalSpawn.status).toBe(0);
      } finally {
        if (junctionExists) {
          await unlink(junctionPath).catch(() => undefined);
        }
        if (substMapped) {
          spawnSync(substExecutable, [substDrive, "/D"], {
            env: previousEnv,
            shell: false,
            stdio: "ignore",
            windowsHide: true
          });
        }
        if (testMode === undefined) delete process.env.SGW_TEST_MODE;
        else process.env.SGW_TEST_MODE = testMode;
      }
    }
  );
});

function encodeRaw(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function windowsPathKey(value: string): string {
  return path.win32.normalize(value).replace(/[\\/]+$/, "").toLowerCase();
}
