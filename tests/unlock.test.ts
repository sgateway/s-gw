import { spawn, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, readdir, rename, rm, stat, symlink, utimes, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { requirePassphrase } from "../src/crypto.js";
import {
  getMacKeychainItem,
  installPersistentKeychainHelper,
  keychainInfo,
  parseKeychainTrustedApplicationPaths,
  persistentKeychainHelperPath,
  pinPackagedKeychainHelper,
  repairMacKeychainItemAccess,
  setKeychainPassphrase,
  unlockStatus,
  windowsCredentialHelperTimeoutMs
} from "../src/unlock.js";

let tmpDir = "";

beforeEach(async () => {
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-unlock-test-"));
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  process.env.SGW_KEYCHAIN_SERVICE = "com.s-gw.test";
  process.env.SGW_KEYCHAIN_ACCOUNT = "unit-test";
});

afterEach(async () => {
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  delete process.env.SGW_KEYCHAIN_SERVICE;
  delete process.env.SGW_KEYCHAIN_ACCOUNT;
  delete process.env.SGW_KEYCHAIN_HELPER;
  delete process.env.SGW_KEYCHAIN_INSPECTOR;
  delete process.env.SGW_KEYCHAIN_LEGACY_HELPERS;
  delete process.env.SGW_KEYCHAIN_STATUS_CLI;
  delete process.env.SGW_FAKE_KEYCHAIN_VALUE;
  delete process.env.SGW_FAKE_KEYCHAIN_CAPTURE;
  delete process.env.SGW_FAKE_KEYCHAIN_GET_DENIED;
  delete process.env.SGW_FAKE_INSPECTOR_CAPTURE;
  delete process.env.SGW_FAKE_INSPECTOR_FAILURE;
  delete process.env.SGW_ALLOW_SECURITY_CLI;
  delete process.env.SGW_FAKE_KEYCHAIN_DB;
  delete process.env.SGW_TEST_KEYCHAIN_REPAIR_LOCK_TIMEOUT_MS;
  delete process.env.SGW_REQUIRE_MARKED_KEYCHAIN_REPAIR_LOCK;
  delete process.env.SGW_MAC_KEYCHAIN_SUBPROCESS_TIMEOUT_MS;
  delete process.env.SGW_FAKE_KEYCHAIN_GET_WAIT_MS;
  delete process.env.SGW_FAKE_KEYCHAIN_SET_WAIT_MS;
  delete process.env.SGW_FAKE_INSPECTOR_WAIT_MS;
  delete process.env.SGW_HOME;
  delete process.env.SGW_RECOVERY_HOME;
  if (tmpDir) {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

describe("unlock passphrase provider", () => {
  it("allows a bounded Windows helper timeout only in isolated tests", () => {
    const oldTestMode = process.env.SGW_TEST_MODE;
    const oldTimeout = process.env.SGW_WINDOWS_CREDENTIAL_HELPER_TIMEOUT_MS;
    try {
      delete process.env.SGW_TEST_MODE;
      process.env.SGW_WINDOWS_CREDENTIAL_HELPER_TIMEOUT_MS = "120000";
      expect(windowsCredentialHelperTimeoutMs()).toBe(30_000);

      process.env.SGW_TEST_MODE = "1";
      expect(windowsCredentialHelperTimeoutMs()).toBe(120_000);
      process.env.SGW_WINDOWS_CREDENTIAL_HELPER_TIMEOUT_MS = "120001";
      expect(windowsCredentialHelperTimeoutMs()).toBe(30_000);
    } finally {
      if (oldTestMode === undefined) delete process.env.SGW_TEST_MODE;
      else process.env.SGW_TEST_MODE = oldTestMode;
      if (oldTimeout === undefined) delete process.env.SGW_WINDOWS_CREDENTIAL_HELPER_TIMEOUT_MS;
      else process.env.SGW_WINDOWS_CREDENTIAL_HELPER_TIMEOUT_MS = oldTimeout;
    }
  });

  it.skipIf(process.platform !== "darwin")("refuses raw helper overrides outside isolated test mode", async () => {
    const helper = path.join(tmpDir, "s-gw-keychain-helper");
    await writeFile(helper, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await chmod(helper, 0o700);
    const oldTestMode = process.env.SGW_TEST_MODE;
    process.env.SGW_KEYCHAIN_HELPER = helper;
    delete process.env.SGW_TEST_MODE;
    try {
      expect(() => keychainInfo()).toThrow(/SGW_KEYCHAIN_HELPER.*restricted to isolated s-gw tests/i);
    } finally {
      if (oldTestMode === undefined) delete process.env.SGW_TEST_MODE;
      else process.env.SGW_TEST_MODE = oldTestMode;
    }
  });

  it("prefers the explicit environment passphrase", () => {
    process.env.SGW_MASTER_PASSPHRASE = "env passphrase";

    expect(requirePassphrase()).toBe("env passphrase");
    expect(unlockStatus().activeSource).toBe("env");
  }, process.platform === "win32" ? 60_000 : 5_000);

  it("can fall back to a local macOS Keychain passphrase", async () => {
    if (process.platform !== "darwin") {
      return;
    }

    await installFakeHelper("keychain passphrase");
    expect(requirePassphrase()).toBe("keychain passphrase");

    const status = unlockStatus();
    expect(status.activeSource).toBe("macos-keychain");
    expect(status.keychain.configured).toBe(true);
    expect(status.keychain.service).toBe("com.s-gw.test");
    expect(status.keychain.provider).toBe("native-helper");
  });

  it.skipIf(process.platform !== "darwin")("times out a stalled native Keychain helper when opted in", async () => {
    await installFakeHelper("synthetic passphrase");
    process.env.SGW_MAC_KEYCHAIN_SUBPROCESS_TIMEOUT_MS = "200";
    process.env.SGW_FAKE_KEYCHAIN_GET_WAIT_MS = "3000";

    expect(() => getMacKeychainItem({ service: "com.s-gw.test", account: "unit-test" }))
      .toThrow("Native Keychain helper timed out after 200 ms.");
  });

  it.skipIf(process.platform !== "darwin")("reports a stalled metadata inspector as unavailable when opted in", async () => {
    await installFakeHelper("synthetic passphrase");
    process.env.SGW_MAC_KEYCHAIN_SUBPROCESS_TIMEOUT_MS = "200";
    process.env.SGW_FAKE_INSPECTOR_WAIT_MS = "3000";

    const status = unlockStatus();
    expect(status.keychain.state).toBe("unavailable");
    expect(status.keychain.error).toBe("Keychain inspector timed out after 200 ms.");
  });

  it.skipIf(process.platform !== "darwin")("rejects an invalid Keychain subprocess timeout", async () => {
    await installFakeHelper("synthetic passphrase");
    process.env.SGW_MAC_KEYCHAIN_SUBPROCESS_TIMEOUT_MS = "120001";

    expect(() => getMacKeychainItem({ service: "com.s-gw.test", account: "unit-test" }))
      .toThrow("SGW_MAC_KEYCHAIN_SUBPROCESS_TIMEOUT_MS must be an integer from 100 to 120000.");
  });

  it.skipIf(process.platform !== "darwin")("does not interrupt a Keychain write with an uncertain outcome", async () => {
    await installFakeHelper("");
    process.env.SGW_MAC_KEYCHAIN_SUBPROCESS_TIMEOUT_MS = "100";
    process.env.SGW_FAKE_KEYCHAIN_SET_WAIT_MS = "300";

    expect(() => setKeychainPassphrase("synthetic passphrase")).not.toThrow();
  });

  it("sets the Keychain passphrase through helper stdin instead of command arguments", async () => {
    if (process.platform !== "darwin") {
      return;
    }

    const capturePath = path.join(tmpDir, "capture.json");
    process.env.SGW_FAKE_KEYCHAIN_CAPTURE = capturePath;
    await installFakeHelper("");

    setKeychainPassphrase("native helper passphrase");

    const captured = JSON.parse(await readText(capturePath));
    expect(captured.stdin).toBe("native helper passphrase");
    expect(captured.args.join(" ")).not.toContain("native helper passphrase");
  });

  it("checks Keychain status through the metadata-only inspector", async () => {
    if (process.platform !== "darwin") {
      return;
    }

    const capturePath = path.join(tmpDir, "inspector-args.json");
    process.env.SGW_FAKE_INSPECTOR_CAPTURE = capturePath;
    process.env.SGW_FAKE_KEYCHAIN_GET_DENIED = "1";
    await installFakeHelper("configured keychain passphrase");
    process.env.SGW_KEYCHAIN_STATUS_CLI = await installSecurityStatusTrap();

    const status = unlockStatus();
    expect(status.activeSource).toBe("macos-keychain");
    expect(status.keychain.configured).toBe(true);

    const args = JSON.parse(await readText(capturePath)) as string[];
    expect(args).toEqual([
      "exists",
      "--service",
      "com.s-gw.test",
      "--account",
      "unit-test"
    ]);
  });

  it("uses the security CLI only when its compatibility fallback is explicit", async () => {
    if (process.platform !== "darwin") return;

    const capturePath = path.join(tmpDir, "security-fallback-args.json");
    process.env.SGW_FAKE_KEYCHAIN_GET_DENIED = "1";
    await installFakeHelper("configured keychain passphrase");
    process.env.SGW_KEYCHAIN_INSPECTOR = path.join(tmpDir, "missing-inspector");
    process.env.SGW_ALLOW_SECURITY_CLI = "1";
    process.env.SGW_KEYCHAIN_STATUS_CLI = await installFakeSecurityStatus(capturePath);

    const status = unlockStatus();
    expect(status.activeSource).toBe("macos-keychain");
    expect(status.keychain.state).toBe("configured");
    expect(JSON.parse(await readText(capturePath))).toEqual([
      "find-generic-password",
      "-a",
      "unit-test",
      "-s",
      "com.s-gw.test"
    ]);
  });

  it("reports a missing Keychain item when the inspector exits 44", async () => {
    if (process.platform !== "darwin") return;

    process.env.SGW_FAKE_KEYCHAIN_GET_DENIED = "1";
    await installFakeHelper("");

    const status = unlockStatus();
    expect(status.activeSource).toBe("none");
    expect(status.keychain.configured).toBe(false);
    expect(status.keychain.state).toBe("missing");
    expect(status.keychain.error).toBeUndefined();
  });

  it("fails closed when the Keychain inspector cannot determine status", async () => {
    if (process.platform !== "darwin") return;

    process.env.SGW_FAKE_KEYCHAIN_GET_DENIED = "1";
    process.env.SGW_FAKE_INSPECTOR_FAILURE = "Synthetic inspector failure";
    await installFakeHelper("configured keychain passphrase");

    const status = unlockStatus();
    expect(status.activeSource).toBe("none");
    expect(status.keychain.configured).toBe(false);
    expect(status.keychain.state).toBe("unavailable");
    expect(status.keychain.error).toContain("Synthetic inspector failure");
  });

  it("keeps the first installed helper identity in the s-gw data directory", async () => {
    if (process.platform !== "darwin") {
      return;
    }

    const sgwHome = path.join(tmpDir, "home");
    const original = path.join(tmpDir, "original-helper");
    const replacement = path.join(tmpDir, "replacement-helper");
    await writeFile(original, "trusted helper\n");
    await writeFile(replacement, "new helper\n");
    await chmod(original, 0o755);
    await chmod(replacement, 0o755);

    const first = installPersistentKeychainHelper({ sourcePath: original, sgwHome });
    const second = installPersistentKeychainHelper({ sourcePath: replacement, sgwHome });
    const helperPath = persistentKeychainHelperPath(sgwHome);

    expect(first).toMatchObject({ helperPath, sourcePath: original, changed: true });
    expect(second).toMatchObject({ helperPath, changed: false });
    expect(await readFile(helperPath, "utf8")).toBe("trusted helper\n");
    expect((await stat(helperPath)).mode & 0o777).toBe(0o700);
    const replacementHash = createHash("sha256").update("new helper\n").digest("hex");
    const archivedReplacement = path.join(
      sgwHome,
      "native",
      "legacy",
      replacementHash,
      "s-gw-keychain-helper"
    );
    expect(await readFile(archivedReplacement, "utf8")).toBe("new helper\n");
    expect((await stat(archivedReplacement)).mode & 0o777).toBe(0o700);

    process.env.SGW_HOME = sgwHome;
    process.env.SGW_RECOVERY_HOME = `${sgwHome}-recovery`;
    expect(keychainInfo().helperPath).toBe(helperPath);
  });

  it("pins the persistent identity at the package path used by stale agent sessions", async () => {
    if (process.platform !== "darwin") return;

    const sgwHome = path.join(tmpDir, "home");
    const packageRoot = path.join(tmpDir, "package");
    const original = path.join(tmpDir, "original-helper");
    const packageHelper = path.join(
      packageRoot,
      "dist",
      "native",
      `${process.platform}-${process.arch}`,
      "s-gw-keychain-helper"
    );
    await writeFile(original, "stable helper identity\n");
    await chmod(original, 0o755);
    await mkdir(path.dirname(packageHelper), { recursive: true });
    await writeFile(packageHelper, "replacement helper identity\n");
    await chmod(packageHelper, 0o755);
    process.env.SGW_HOME = sgwHome;
    process.env.SGW_RECOVERY_HOME = `${sgwHome}-recovery`;
    installPersistentKeychainHelper({ sourcePath: original, sgwHome });

    expect(pinPackagedKeychainHelper(packageRoot)).toMatchObject({
      sourcePath: persistentKeychainHelperPath(sgwHome),
      packagePath: packageHelper,
      changed: true
    });
    expect(await readFile(packageHelper, "utf8")).toBe("stable helper identity\n");
    expect((await stat(packageHelper)).mode & 0o777).toBe(0o755);
    const packageHash = createHash("sha256").update("replacement helper identity\n").digest("hex");
    const archivedPackageHelper = path.join(
      sgwHome,
      "native",
      "legacy",
      packageHash,
      "s-gw-keychain-helper"
    );
    expect(await readFile(archivedPackageHelper, "utf8")).toBe("replacement helper identity\n");
    expect((await stat(archivedPackageHelper)).mode & 0o777).toBe(0o700);
  });

  it("never rewrites a signed self-contained app runtime", async () => {
    if (process.platform !== "darwin") return;

    const app = path.join(tmpDir, "s-gw.app");
    const runtime = path.join(app, "Contents", "Resources", "s-gw-runtime");
    const packageRoot = path.join(runtime, "package");
    const helper = path.join(
      packageRoot,
      "dist",
      "native",
      `${process.platform}-${process.arch}`,
      "s-gw-keychain-helper"
    );
    await mkdir(path.join(app, "Contents", "MacOS"), { recursive: true });
    await writeFile(path.join(app, "Contents", "MacOS", "s-gw"), "app\n");
    await chmod(path.join(app, "Contents", "MacOS", "s-gw"), 0o755);
    await mkdir(path.join(runtime, "node", "bin"), { recursive: true });
    await writeFile(path.join(runtime, "runtime.json"), "{}\n");
    await writeFile(path.join(runtime, "node", "bin", "node"), "node\n");
    await chmod(path.join(runtime, "node", "bin", "node"), 0o755);
    await mkdir(path.join(packageRoot, "dist"), { recursive: true });
    await writeFile(path.join(packageRoot, "dist", "cli.js"), "export {};\n");
    await writeFile(path.join(packageRoot, "dist", "mcp-server.js"), "export {};\n");
    await mkdir(path.dirname(helper), { recursive: true });
    await writeFile(helper, "sealed helper identity\n");
    await chmod(helper, 0o755);

    expect(pinPackagedKeychainHelper(packageRoot)).toBeUndefined();
    expect(await readFile(helper, "utf8")).toBe("sealed helper identity\n");
  });

  it("rebinds a legacy Keychain item to the persistent helper without prompting", async () => {
    if (process.platform !== "darwin") return;

    const service = "com.s-gw.test.secret";
    const account = "s-gw:test:legacy";
    const value = "disposable-keychain-value";
    const harness = await installRepairHarness({ service, account, value });

    const result = repairMacKeychainItemAccess({ service, account, label: "test secret" });
    expect(result).toEqual({ state: "migrated", helperPath: harness.persistent });
    expect(getMacKeychainItem({ service, account })).toBe(value);

    const db = JSON.parse(await readText(harness.dbPath));
    expect(db.items[`${service}\u0000${account}`].trustedIdentity).toBe(await helperIdentity(harness.persistent));
    expect(Object.keys(db.items).some((key) => key.startsWith("com.s-gw.sgw.keychain-repair\u0000"))).toBe(false);
  });

  it("recovers an original item from a verified repair backup", async () => {
    if (process.platform !== "darwin") return;

    const service = "com.s-gw.test.secret";
    const account = "s-gw:test:interrupted";
    const value = "recoverable-keychain-value";
    const harness = await installRepairHarness({ service, account, value });
    const db = JSON.parse(await readText(harness.dbPath));
    delete db.items[`${service}\u0000${account}`];
    const backupAccount = createHash("sha256").update(service).update("\0").update(account).digest("hex");
    db.items[`com.s-gw.sgw.keychain-repair\u0000${backupAccount}`] = {
      value,
      trustedIdentity: await helperIdentity(harness.persistent)
    };
    await writeFile(harness.dbPath, JSON.stringify(db));

    expect(repairMacKeychainItemAccess({ service, account, label: "recovered secret" })).toEqual({
      state: "recovered",
      helperPath: harness.persistent
    });
    expect(getMacKeychainItem({ service, account })).toBe(value);

    const repaired = JSON.parse(await readText(harness.dbPath));
    expect(repaired.items[`${service}\u0000${account}`].trustedIdentity).toBe(await helperIdentity(harness.persistent));
    expect(repaired.items[`com.s-gw.sgw.keychain-repair\u0000${backupAccount}`]).toBeUndefined();
  });

  it("keeps an old live repair owner locked while another process waits", async () => {
    if (process.platform !== "darwin") return;

    const ref = { service: "com.s-gw.test.secret", account: "s-gw:test:concurrent" };
    await installRepairHarness({ ...ref, value: "concurrent-value" });
    const paused = path.join(tmpDir, "helper-paused");
    const child = await startRepairChild(ref, {
      SGW_FAKE_KEYCHAIN_HOLD_MS: "1000",
      SGW_FAKE_KEYCHAIN_HOLD_MARKER: paused
    });
    try {
      await waitForFile(paused);
      const lockPath = path.join(process.env.SGW_HOME!, ".keychain-repair.lock");
      const entries = await readdir(lockPath);
      expect(entries).toHaveLength(1);
      expect(entries[0]).toMatch(/^owner-[0-9a-f-]{36}\.json$/u);
      const stale = new Date(Date.now() - 60_000);
      await utimes(lockPath, stale, stale);
      process.env.SGW_TEST_KEYCHAIN_REPAIR_LOCK_TIMEOUT_MS = "150";

      expect(() => repairMacKeychainItemAccess(ref)).toThrow(/Timed out waiting for Keychain repair lock/u);
      expect(await readdir(lockPath)).toEqual(entries);
      expect((await child.exit).code).toBe(0);
      expect(getMacKeychainItem(ref)).toBe("concurrent-value");
    } finally {
      child.process.kill("SIGKILL");
    }
  }, 10_000);

  it("reclaims a repair lock left by a crashed owner", async () => {
    if (process.platform !== "darwin") return;

    const ref = { service: "com.s-gw.test.secret", account: "s-gw:test:crashed" };
    await installRepairHarness({ ...ref, value: "crash-value" });
    const paused = path.join(tmpDir, "crashed-helper-paused");
    const child = await startRepairChild(ref, {
      SGW_FAKE_KEYCHAIN_HOLD_MS: "5000",
      SGW_FAKE_KEYCHAIN_HOLD_MARKER: paused
    });
    try {
      await waitForFile(paused);
      child.process.kill("SIGKILL");
      await child.exit;
      const helperPid = Number(await readFile(paused, "utf8"));
      try { process.kill(helperPid, "SIGKILL"); } catch { /* The fake helper already exited. */ }

      expect(repairMacKeychainItemAccess(ref).state).toBe("migrated");
      expect(getMacKeychainItem(ref)).toBe("crash-value");
      await expect(stat(path.join(process.env.SGW_HOME!, ".keychain-repair.lock"))).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      child.process.kill("SIGKILL");
    }
  }, 10_000);

  it("reclaims a dead marked owner and a stale legacy empty lock", async () => {
    if (process.platform !== "darwin") return;

    const ref = { service: "com.s-gw.test.secret", account: "s-gw:test:stale" };
    await installRepairHarness({ ...ref, value: "stale-value" });
    const lockPath = path.join(process.env.SGW_HOME!, ".keychain-repair.lock");
    const dead = spawnSync(process.execPath, ["-e", ""]);
    expect(dead.status).toBe(0);
    const token = randomUUID();
    await mkdir(lockPath);
    await writeFile(path.join(lockPath, `owner-${token}.json`), JSON.stringify({ version: 1, pid: dead.pid, token }));
    expect(repairMacKeychainItemAccess(ref).state).toBe("migrated");

    await mkdir(lockPath);
    const stale = new Date(Date.now() - 60_000);
    await utimes(lockPath, stale, stale);
    expect(getMacKeychainItem(ref)).toBe("stale-value");
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("can refuse stale empty repair locks without disabling marked-owner recovery", async () => {
    if (process.platform !== "darwin") return;

    const ref = { service: "com.s-gw.test.secret", account: "s-gw:test:marked-only" };
    await installRepairHarness({ ...ref, value: "marked-only-value" });
    const lockPath = path.join(process.env.SGW_HOME!, ".keychain-repair.lock");
    process.env.SGW_REQUIRE_MARKED_KEYCHAIN_REPAIR_LOCK = "1";
    process.env.SGW_TEST_KEYCHAIN_REPAIR_LOCK_TIMEOUT_MS = "150";
    await mkdir(lockPath);
    const stale = new Date(Date.now() - 60_000);
    await utimes(lockPath, stale, stale);

    expect(() => repairMacKeychainItemAccess(ref)).toThrow(/Timed out waiting for Keychain repair lock/u);
    expect(await readdir(lockPath)).toEqual([]);
    await rm(lockPath, { recursive: true });

    const dead = spawnSync(process.execPath, ["-e", ""]);
    expect(dead.status).toBe(0);
    const token = randomUUID();
    await mkdir(lockPath);
    await writeFile(path.join(lockPath, `owner-${token}.json`), JSON.stringify({ version: 1, pid: dead.pid, token }));
    expect(repairMacKeychainItemAccess(ref).state).toBe("migrated");
    await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("does not silently ignore an invalid marked-owner setting", async () => {
    if (process.platform !== "darwin") return;

    const ref = { service: "com.s-gw.test.secret", account: "s-gw:test:invalid-lock-setting" };
    await installRepairHarness({ ...ref, value: "unused" });
    process.env.SGW_REQUIRE_MARKED_KEYCHAIN_REPAIR_LOCK = "yes";
    expect(() => repairMacKeychainItemAccess(ref)).toThrow(/must be 0 or 1/u);
  });

  it("refuses a symlink at the repair lock path", async () => {
    if (process.platform !== "darwin") return;

    const ref = { service: "com.s-gw.test.secret", account: "s-gw:test:symlink" };
    await installRepairHarness({ ...ref, value: "symlink-value" });
    const lockPath = path.join(process.env.SGW_HOME!, ".keychain-repair.lock");
    const outside = path.join(tmpDir, "outside");
    await mkdir(outside);
    await writeFile(path.join(outside, "sentinel"), "keep");
    await symlink(outside, lockPath);

    expect(() => repairMacKeychainItemAccess(ref)).toThrow(/repair lock is not a directory/u);
    expect(await readFile(path.join(outside, "sentinel"), "utf8")).toBe("keep");
  });

  it("does not release a replacement repair lock", async () => {
    if (process.platform !== "darwin") return;

    const ref = { service: "com.s-gw.test.secret", account: "s-gw:test:replaced" };
    await installRepairHarness({ ...ref, value: "replacement-value" });
    const paused = path.join(tmpDir, "replacement-helper-paused");
    const child = await startRepairChild(ref, {
      SGW_FAKE_KEYCHAIN_HOLD_MS: "650",
      SGW_FAKE_KEYCHAIN_HOLD_MARKER: paused
    });
    try {
      await waitForFile(paused);
      const lockPath = path.join(process.env.SGW_HOME!, ".keychain-repair.lock");
      await rename(lockPath, `${lockPath}.old`);
      await mkdir(lockPath);
      const token = randomUUID();
      const marker = path.join(lockPath, `owner-${token}.json`);
      await writeFile(marker, JSON.stringify({ version: 1, pid: process.pid, token }));

      const result = await child.exit;
      expect(result.code).not.toBe(0);
      expect(result.stderr).toMatch(/Keychain repair lock ownership was lost/u);
      expect(JSON.parse(await readFile(marker, "utf8"))).toMatchObject({ token, pid: process.pid });
    } finally {
      child.process.kill("SIGKILL");
    }
  }, 10_000);

  it("does not release a replayed owner marker", async () => {
    if (process.platform !== "darwin") return;

    const ref = { service: "com.s-gw.test.secret", account: "s-gw:test:replayed" };
    await installRepairHarness({ ...ref, value: "replay-value" });
    const paused = path.join(tmpDir, "replayed-helper-paused");
    const child = await startRepairChild(ref, {
      SGW_FAKE_KEYCHAIN_HOLD_MS: "650",
      SGW_FAKE_KEYCHAIN_HOLD_MARKER: paused
    });
    try {
      await waitForFile(paused);
      const lockPath = path.join(process.env.SGW_HOME!, ".keychain-repair.lock");
      const marker = path.join(lockPath, (await readdir(lockPath))[0]);
      const copy = `${marker}.old`;
      const contents = await readFile(marker);
      await rename(marker, copy);
      await writeFile(marker, contents);

      const result = await child.exit;
      expect(result.code).not.toBe(0);
      expect(result.stderr).toMatch(/Keychain repair lock ownership was lost/u);
      expect(await readFile(marker)).toEqual(contents);
    } finally {
      child.process.kill("SIGKILL");
    }
  }, 10_000);

  it("stops before running a helper when no trusted application can be verified", async () => {
    if (process.platform !== "darwin") return;

    const service = "com.s-gw.test.secret";
    const account = "s-gw:test:untrusted";
    const harness = await installRepairHarness({ service, account, value: "do-not-read" });
    const db = JSON.parse(await readText(harness.dbPath));
    db.items[`${service}\u0000${account}`].trustedIdentity = "unavailable-helper-identity";
    await writeFile(harness.dbPath, JSON.stringify(db));

    expect(() => getMacKeychainItem({ service, account })).toThrow(/stopped before requesting your login password/i);
  });

  it("reports a blocked master-passphrase ACL instead of hiding it as missing", async () => {
    if (process.platform !== "darwin") return;

    const harness = await installRepairHarness({
      service: "com.s-gw.test",
      account: "unit-test",
      value: "valid master passphrase"
    });
    const db = JSON.parse(await readText(harness.dbPath));
    db.items["com.s-gw.test\u0000unit-test"].trustedIdentity = "unavailable-helper-identity";
    await writeFile(harness.dbPath, JSON.stringify(db));

    expect(() => requirePassphrase()).toThrow(/stopped before requesting your login password/i);
  });

  it.skipIf(process.platform !== "darwin")("parses only the requested Keychain item's trusted application paths", () => {
    const dump = `keychain: "/Users/test/login.keychain-db"
attributes:
    "acct"<blob>="s-gw:first"
    "svce"<blob>="com.s-gw.secret"
access: 1 entries
    entry 0:
        applications (1):
            0: /tmp/first/s-gw-keychain-helper (OK)
keychain: "/Users/test/login.keychain-db"
attributes:
    "acct"<blob>="s-gw:second"
    "svce"<blob>="com.s-gw.secret"
access: 1 entries
    entry 0:
        applications (2):
            0: /tmp/second/s-gw-keychain-helper (status -67068)
            1: /tmp/second copy/s-gw-keychain-helper (OK)
`;

    expect(parseKeychainTrustedApplicationPaths(dump, "com.s-gw.secret", "s-gw:second")).toEqual([
      "/tmp/second/s-gw-keychain-helper",
      "/tmp/second copy/s-gw-keychain-helper"
    ]);
  });

  it("reports a clear unlock error when no provider is configured", async () => {
    if (process.platform === "darwin") {
      await installFakeHelper("");
    }

    expect(() => requirePassphrase()).toThrow(/unlock passphrase/i);
  }, process.platform === "win32" ? 60_000 : 5_000);
});

async function startRepairChild(ref: { service: string; account: string }, extraEnv: Record<string, string>) {
  const script = path.join(tmpDir, `repair-${randomUUID()}.ts`);
  const source = pathToFileURL(path.resolve("src/unlock.ts")).href;
  await writeFile(script, `import { getMacKeychainItem } from ${JSON.stringify(source)};\ngetMacKeychainItem(${JSON.stringify(ref)});\n`);
  const child = spawn(process.execPath, ["--import", "tsx", script], {
    env: { ...process.env, ...extraEnv },
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  child.stderr.on("data", (data) => { stderr += String(data); });
  const exit = new Promise<{ code: number | null; stderr: string }>((resolve) => {
    child.once("close", (code) => resolve({ code, stderr }));
  });
  return { process: child, exit };
}

async function waitForFile(filePath: string): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < 5_000) {
    try {
      await stat(filePath);
      return;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error(`Timed out waiting for disposable test marker ${filePath}.`);
}

async function installFakeHelper(passphrase: string): Promise<void> {
  process.env.SGW_FAKE_KEYCHAIN_VALUE = passphrase;
  const fakePath = path.join(tmpDir, "s-gw-keychain-helper");
  await writeFile(
    fakePath,
    `#!/usr/bin/env node
const fs = require("fs");
const passphrase = process.env.SGW_FAKE_KEYCHAIN_VALUE || "";
const command = process.argv[2];
if (command === "get") {
  if (process.env.SGW_FAKE_KEYCHAIN_GET_WAIT_MS) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Number(process.env.SGW_FAKE_KEYCHAIN_GET_WAIT_MS));
  }
  if (process.env.SGW_FAKE_KEYCHAIN_GET_DENIED === "1") process.exit(70);
  if (!passphrase) process.exit(44);
  process.stdout.write(passphrase + "\\n");
  process.exit(0);
}

if (command === "set") {
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", chunk => input += chunk);
  process.stdin.on("end", () => {
    if (process.env.SGW_FAKE_KEYCHAIN_SET_WAIT_MS) {
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Number(process.env.SGW_FAKE_KEYCHAIN_SET_WAIT_MS));
    }
    if (process.env.SGW_FAKE_KEYCHAIN_CAPTURE) {
      fs.writeFileSync(process.env.SGW_FAKE_KEYCHAIN_CAPTURE, JSON.stringify({
        args: process.argv.slice(2),
        stdin: input
      }));
    }
    process.exit(0);
  });
} else if (command === "delete") {
  process.exit(0);
} else {
process.exit(2);
}
`
  );
  await chmod(fakePath, 0o700);
  process.env.SGW_KEYCHAIN_HELPER = fakePath;

  const fakeInspector = path.join(tmpDir, "s-gw-keychain-inspector");
  await writeFile(
    fakeInspector,
    `#!/usr/bin/env node
const fs = require("fs");
const args = process.argv.slice(2);
if (process.env.SGW_FAKE_INSPECTOR_CAPTURE) {
  fs.writeFileSync(process.env.SGW_FAKE_INSPECTOR_CAPTURE, JSON.stringify(args));
}
if (args[0] !== "exists") process.exit(64);
if (process.env.SGW_FAKE_INSPECTOR_FAILURE) {
  process.stderr.write(process.env.SGW_FAKE_INSPECTOR_FAILURE + "\\n");
  process.exit(70);
}
if (process.env.SGW_FAKE_INSPECTOR_WAIT_MS) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Number(process.env.SGW_FAKE_INSPECTOR_WAIT_MS));
}
process.exit(process.env.SGW_FAKE_KEYCHAIN_VALUE ? 0 : 44);
`
  );
  await chmod(fakeInspector, 0o700);
  process.env.SGW_KEYCHAIN_INSPECTOR = fakeInspector;
}

async function installSecurityStatusTrap(): Promise<string> {
  const trapPath = path.join(tmpDir, "security-status-trap");
  await writeFile(trapPath, "#!/bin/sh\nexit 91\n");
  await chmod(trapPath, 0o700);
  return trapPath;
}

async function installFakeSecurityStatus(capturePath: string): Promise<string> {
  const fakePath = path.join(tmpDir, "security-status-fallback");
  await writeFile(
    fakePath,
    `#!/usr/bin/env node
const fs = require("fs");
fs.writeFileSync(${JSON.stringify(capturePath)}, JSON.stringify(process.argv.slice(2)));
process.exit(0);
`
  );
  await chmod(fakePath, 0o700);
  return fakePath;
}

async function installRepairHarness(input: { service: string; account: string; value: string }): Promise<{
  dbPath: string;
  legacy: string;
  persistent: string;
}> {
  const sgwHome = path.join(tmpDir, "repair-home");
  const dbPath = path.join(tmpDir, "repair-keychain.json");
  const legacy = path.join(tmpDir, "legacy", "s-gw-keychain-helper");
  const current = path.join(tmpDir, "current", "s-gw-keychain-helper");
  const inspector = path.join(tmpDir, "s-gw-keychain-inspector");
  const security = path.join(tmpDir, "security");
  const itemKey = `${input.service}\u0000${input.account}`;
  const legacySource = fakeRepairHelperSource();
  await writeFile(dbPath, JSON.stringify({
    items: {
      [itemKey]: {
        value: input.value,
        trustedIdentity: createHash("sha256").update(legacySource).digest("hex")
      }
    }
  }));
  await mkdir(path.dirname(legacy), { recursive: true });
  await mkdir(path.dirname(current), { recursive: true });
  await writeFile(legacy, legacySource);
  await writeFile(current, `${legacySource}\n// current helper identity\n`);
  await chmod(legacy, 0o700);
  await chmod(current, 0o700);

  await writeFile(inspector, `#!/usr/bin/env node
const crypto = require("crypto");
const fs = require("fs");
const args = process.argv.slice(2);
const command = args[0];
const value = name => args[args.indexOf(name) + 1];
const candidates = [];
for (let i = 0; i < args.length; i++) if (args[i] === "--candidate") candidates.push(args[i + 1]);
const db = JSON.parse(fs.readFileSync(process.env.SGW_FAKE_KEYCHAIN_DB, "utf8"));
const item = db.items[value("--service") + "\\0" + value("--account")];
if (!item) process.exit(44);
if (command === "exists") process.exit(0);
if (command !== "trusted-helper") process.exit(64);
const identity = path => {
  try { return crypto.createHash("sha256").update(fs.readFileSync(path)).digest("hex"); }
  catch { return ""; }
};
process.stdout.write(JSON.stringify({ trustedHelpers: candidates.filter(path => identity(path) === item.trustedIdentity) }) + "\\n");
`);
  await chmod(inspector, 0o700);

  await writeFile(security, `#!/usr/bin/env node
const fs = require("fs");
const args = process.argv.slice(2);
const db = JSON.parse(fs.readFileSync(process.env.SGW_FAKE_KEYCHAIN_DB, "utf8"));
if (args[0] === "dump-keychain") {
  for (const [key, item] of Object.entries(db.items)) {
    const split = key.indexOf("\\0");
    const service = key.slice(0, split);
    const account = key.slice(split + 1);
    process.stdout.write('keychain: "test"\\nattributes:\\n');
    process.stdout.write('    "acct"<blob>="' + account + '"\\n');
    process.stdout.write('    "svce"<blob>="' + service + '"\\n');
    process.stdout.write('access: 1 entries\\n    entry 0:\\n        applications (1):\\n');
    process.stdout.write('            0: /unavailable/s-gw-keychain-helper (status -67068)\\n');
  }
  process.exit(0);
}
process.exit(2);
`);
  await chmod(security, 0o700);

  process.env.SGW_HOME = sgwHome;
  process.env.SGW_RECOVERY_HOME = `${sgwHome}-recovery`;
  process.env.SGW_FAKE_KEYCHAIN_DB = dbPath;
  process.env.SGW_KEYCHAIN_INSPECTOR = inspector;
  process.env.SGW_KEYCHAIN_LEGACY_HELPERS = legacy;
  process.env.SGW_KEYCHAIN_STATUS_CLI = security;
  const persistent = installPersistentKeychainHelper({ sourcePath: current, sgwHome }).helperPath;
  return { dbPath, legacy, persistent };
}

function fakeRepairHelperSource(): string {
  return `#!/usr/bin/env node
const crypto = require("crypto");
const fs = require("fs");
const args = process.argv.slice(2);
const command = args[0];
const value = name => args[args.indexOf(name) + 1];
const key = value("--service") + "\\0" + value("--account");
const dbPath = process.env.SGW_FAKE_KEYCHAIN_DB;
const db = JSON.parse(fs.readFileSync(dbPath, "utf8"));
const item = db.items[key];
const ownIdentity = crypto.createHash("sha256").update(fs.readFileSync(process.argv[1])).digest("hex");
if (command === "get") {
  if (!item) process.exit(44);
  if (item.trustedIdentity !== ownIdentity) process.exit(70);
  if (process.env.SGW_FAKE_KEYCHAIN_HOLD_MARKER) {
    fs.writeFileSync(process.env.SGW_FAKE_KEYCHAIN_HOLD_MARKER, String(process.pid));
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Number(process.env.SGW_FAKE_KEYCHAIN_HOLD_MS || 0));
  }
  process.stdout.write(item.value + "\\n");
  process.exit(0);
}
if (command === "delete") {
  if (!item) process.exit(44);
  if (item.trustedIdentity !== ownIdentity) process.exit(70);
  delete db.items[key];
  fs.writeFileSync(dbPath, JSON.stringify(db));
  process.exit(0);
}
if (command === "set") {
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", chunk => input += chunk);
  process.stdin.on("end", () => {
    if (item && item.trustedIdentity !== ownIdentity) process.exit(70);
    db.items[key] = { value: input, trustedIdentity: ownIdentity };
    fs.writeFileSync(dbPath, JSON.stringify(db));
    process.exit(0);
  });
} else {
  process.exit(2);
}
`;
}

async function helperIdentity(filePath: string): Promise<string> {
  return createHash("sha256").update(await readFile(filePath)).digest("hex");
}

async function readText(filePath: string): Promise<string> {
  return readFile(filePath, "utf8");
}
