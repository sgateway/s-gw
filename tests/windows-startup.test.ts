import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
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

  it("uses the trusted System32 PowerShell and strips hostile inherited environment", async () => {
    const systemRoot = path.join(root, "trusted Windows");
    const powershell = path.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
    const hostileDir = path.join(root, "hostile path");
    await mkdir(path.dirname(powershell), { recursive: true });
    await mkdir(hostileDir, { recursive: true });
    await writeFile(powershell, "trusted", "utf8");
    await writeFile(path.join(hostileDir, "powershell.exe"), "hostile", "utf8");
    process.env.SystemRoot = await realpath(systemRoot);
    process.env.WINDIR = process.env.SystemRoot;
    process.env.PATH = hostileDir;
    process.env.SGW_MASTER_PASSPHRASE = "sentinel-master-passphrase";
    process.env.AWS_SECRET_ACCESS_KEY = "sentinel-cloud-secret";
    process.env.NODE_OPTIONS = "--require hostile-preload.js";

    expect(trustedWindowsPowerShellSync()).toBe(await realpath(powershell));
    const systemEnv = windowsSystemEnvironment();
    expect(systemEnv.PATH).toContain(path.join(process.env.SystemRoot, "System32"));
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
  });
});

function encodeRaw(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}
