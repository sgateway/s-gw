import { mkdtemp, readdir, rm, stat, utimes } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const rmdirFault = vi.hoisted(() => ({
  code: "EPERM",
  enabled: false,
  lockPath: "",
  attempts: 0
}));

vi.mock("node:fs/promises", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs/promises")>();
  return {
    ...actual,
    rmdir: async (
      target: Parameters<typeof actual.rmdir>[0],
      options?: Parameters<typeof actual.rmdir>[1]
    ) => {
      if (rmdirFault.enabled && String(target) === rmdirFault.lockPath) {
        rmdirFault.attempts += 1;
        throw Object.assign(new Error("simulated lock directory cleanup failure"), { code: rmdirFault.code });
      }
      return actual.rmdir(target, options);
    }
  };
});

const originalPlatform = process.platform;
let testHome = "";
let originalTemp: string | undefined;
let originalTmp: string | undefined;

beforeEach(async () => {
  originalTemp = process.env.TEMP;
  originalTmp = process.env.TMP;
  testHome = await mkdtemp(path.join(os.tmpdir(), "sgw-lock-windows-"));
  process.env.TEMP = testHome;
  process.env.TMP = testHome;
  process.env.SGW_HOME = testHome;
  process.env.SGW_RECOVERY_HOME = `${testHome}-recovery`;
  process.env.SGW_MASTER_PASSPHRASE = "local test passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
  Object.defineProperty(process, "platform", { value: "win32" });
  rmdirFault.code = "EPERM";
  rmdirFault.enabled = false;
  rmdirFault.lockPath = "";
  rmdirFault.attempts = 0;
});

afterEach(async () => {
  Object.defineProperty(process, "platform", { value: originalPlatform });
  delete process.env.SGW_HOME;
  delete process.env.SGW_RECOVERY_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  delete process.env.SGW_DISABLE_ONEPASSWORD_BACKUP;
  if (originalTemp === undefined) {
    delete process.env.TEMP;
  } else {
    process.env.TEMP = originalTemp;
  }
  if (originalTmp === undefined) {
    delete process.env.TMP;
  } else {
    process.env.TMP = originalTmp;
  }
  rmdirFault.enabled = false;
  await rm(testHome, { recursive: true, force: true });
  await rm(`${testHome}-recovery`, { recursive: true, force: true });
});

describe("Windows store lock cleanup", () => {
  it("keeps a committed mutation successful after transient rmdir retries are exhausted", async () => {
    const { SecretStore } = await import("../src/store.js");
    const store = new SecretStore();
    await store.init();
    rmdirFault.lockPath = `${store.storePath}.lock`;
    rmdirFault.enabled = true;

    const first = await store.addApprovalPolicyRule({
      name: "Committed before delayed cleanup",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });

    expect(first.name).toBe("Committed before delayed cleanup");
    expect(rmdirFault.attempts).toBe(20);
    expect(await readdir(rmdirFault.lockPath)).toEqual([]);
    expect((await store.listApprovalPolicyRules()).map((rule) => rule.id)).toContain(first.id);

    rmdirFault.enabled = false;
    const stale = new Date(Date.now() - 5_000);
    await utimes(rmdirFault.lockPath, stale, stale);
    const second = await store.addApprovalPolicyRule({
      name: "Recovered after delayed cleanup",
      decision: "allow",
      conditions: { agents: ["claude"] }
    });

    expect(second.name).toBe("Recovered after delayed cleanup");
    await expect(stat(rmdirFault.lockPath)).rejects.toMatchObject({ code: "ENOENT" });
    expect((await store.listApprovalPolicyRules()).map((rule) => rule.id)).toEqual(
      expect.arrayContaining([first.id, second.id])
    );
  });

  it("does not reject a committed mutation after nontransient release cleanup failure", async () => {
    const { SecretStore } = await import("../src/store.js");
    const store = new SecretStore();
    await store.init();
    rmdirFault.lockPath = `${store.storePath}.lock`;
    rmdirFault.code = "EIO";
    rmdirFault.enabled = true;

    const rule = await store.addApprovalPolicyRule({
      name: "Committed before cleanup error",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });

    expect(rule.name).toBe("Committed before cleanup error");
    expect(rmdirFault.attempts).toBe(1);
    expect(await readdir(rmdirFault.lockPath)).toEqual([]);
    expect((await store.listApprovalPolicyRules()).map((item) => item.id)).toContain(rule.id);
  });
});
