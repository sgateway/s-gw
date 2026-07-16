import { chmod, mkdir, mkdtemp, readFile, readdir, rm, stat, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeApprovedRequest, executeReusablePermit } from "../src/executor.js";
import { buildEnvCommandAction, scanLocalText } from "../src/gateway.js";
import { tokenForHandle } from "../src/scanner.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";

function fakeAwsAccessKey(): string {
  return ["A", "KIA", "IOSFODNN7EXAMPLE"].join("");
}

function fakeOpenAiToken(label: string): string {
  return ["sk", "-proj-", label, "_1234567890abcdef"].join("");
}

function onePasswordFixtureRef(): string {
  return ["op://", "Example", "/e2e-token/credential"].join("");
}

async function writeStoreLock(lockPath: string, state: { pid: number; token: string; createdAt: string }): Promise<void> {
  await mkdir(lockPath, { mode: 0o700 });
  await writeFile(path.join(lockPath, `owner-${state.token}.json`), `${JSON.stringify({ version: 1, ...state })}\n`);
}

async function externalControlPlaneDir(home = tmpHome, recoveryHome = `${home}-recovery`): Promise<string> {
  const root = path.join(recoveryHome, "control-plane");
  const entries = await readdir(root);
  const namespaces: string[] = [];
  for (const entry of entries) {
    if ((await stat(path.join(root, entry))).isDirectory()) {
      namespaces.push(entry);
    }
  }
  if (namespaces.length !== 1) {
    throw new Error(`Expected one recovery namespace in ${root}.`);
  }
  return path.join(root, namespaces[0]);
}

beforeEach(async () => {
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-test-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_RECOVERY_HOME = `${tmpHome}-recovery`;
  process.env.SGW_MASTER_PASSPHRASE = "local test passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
});

afterEach(async () => {
  delete process.env.SGW_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  delete process.env.SGW_DISABLE_ONEPASSWORD_BACKUP;
  delete process.env.SGW_OP_CLI;
  delete process.env.SGW_ONEPASSWORD_TIMEOUT_MS;
  delete process.env.SGW_KEYCHAIN_HELPER;
  delete process.env.SGW_SECRET_KEYCHAIN_SERVICE;
  delete process.env.SGW_LOGIN_SESSION_ID;
  delete process.env.SGW_RECOVERY_HOME;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
  }
});

describe("SecretStore", () => {
  it("stores encrypted secret values and lists only handle metadata", async () => {
    const store = new SecretStore();
    await store.init();

    const rawSecret = fakeOpenAiToken("test_secret");
    const record = await store.addSecret({
      name: "openai test",
      type: "api-token",
      value: rawSecret,
      policy: {
        injectEnv: "API_TOKEN",
        allowedCommands: [process.execPath]
      }
    });

    const storeText = await readFile(store.storePath, "utf8");
    expect(storeText).not.toContain(rawSecret);
    expect(record.handle).toMatch(/^s-gw:api-token:/);

    const handles = await store.listHandles();
    expect(handles).toHaveLength(1);
    expect(JSON.stringify(handles)).not.toContain(rawSecret);
    expect(handles[0].policy.injectEnv).toBe("API_TOKEN");
  });

  it("updates the injection environment without reading the secret", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "policy update token",
      type: "api-token",
      value: fakeOpenAiToken("policy_update"),
      policy: { injectEnv: "OLD_TOKEN" }
    });

    const updated = await store.setInjectEnv(record.handle, "NODE_AUTH_TOKEN");
    expect(updated.policy.injectEnv).toBe("NODE_AUTH_TOKEN");
    await expect(store.setInjectEnv(record.handle, "invalid-name")).rejects.toThrow(/invalid environment/i);

    const stored = await store.getHandle(record.handle);
    expect(stored?.policy.injectEnv).toBe("NODE_AUTH_TOKEN");
  });

  it("rejects invalid injection environment names during enrollment", async () => {
    const store = new SecretStore();
    await expect(store.addSecret({
      name: "invalid env token",
      type: "api-token",
      value: fakeOpenAiToken("invalid_env"),
      policy: { injectEnv: "invalid-name" }
    })).rejects.toThrow(/invalid environment/i);
  });

  it("keeps encrypted store backups before ledger overwrites", async () => {
    const store = new SecretStore();
    const firstSecret = "first-backup-secret-value-123456789";
    const secondSecret = "second-backup-secret-value-123456789";
    await store.addSecret({
      name: "first backup token",
      type: "credential",
      value: firstSecret,
      policy: { injectEnv: "FIRST_BACKUP_TOKEN", allowedCommands: [process.execPath] }
    });
    await store.addSecret({
      name: "second backup token",
      type: "credential",
      value: secondSecret,
      policy: { injectEnv: "SECOND_BACKUP_TOKEN", allowedCommands: [process.execPath] }
    });

    const backups = await store.listStoreBackups();
    expect(backups.length).toBeGreaterThan(0);
    const backupText = await readFile(backups[0].path, "utf8");
    expect(backupText).not.toContain(firstSecret);
    expect(backupText).not.toContain(secondSecret);
    expect(backupText).not.toContain("op://");
  });

  it("seals the next control state before replacing the primary ledger", async () => {
    if (process.platform === "win32") return;

    const store = new SecretStore();
    await store.addSecret({
      name: "preseal candidate token",
      type: "credential",
      value: "preseal-candidate-secret-value-123456789",
      policy: { injectEnv: "PRESEAL_CANDIDATE_TOKEN", allowedCommands: [process.execPath] }
    });
    const primaryBefore = await readFile(store.storePath, "utf8");
    const manifestBefore = await readFile(path.join(tmpHome, ".store-control.json"), "utf8");
    const externalDir = await externalControlPlaneDir();

    await chmod(externalDir, 0o500);
    try {
      await expect(store.addApprovalPolicyRule({
        name: "This write cannot be sealed",
        decision: "allow",
        conditions: { agents: ["codex"] }
      })).rejects.toThrow(/EACCES|permission denied|operation not permitted/i);
    } finally {
      await chmod(externalDir, 0o700);
    }

    expect(await readFile(store.storePath, "utf8")).toBe(primaryBefore);
    expect(await readFile(path.join(tmpHome, ".store-control.json"), "utf8")).toBe(manifestBefore);
  });

  it("recovers a missing ledger without losing credentials or approval policies", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "recovery token",
      type: "api-token",
      value: fakeOpenAiToken("missing_store_recovery"),
      policy: { injectEnv: "RECOVERY_TOKEN", allowedCommands: [process.execPath] }
    });
    const rule = await store.addApprovalPolicyRule({
      name: "Allow Codex recovery test",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });

    await rm(store.storePath);

    const recovered = new SecretStore();
    expect((await recovered.listHandles()).map((item) => item.handle)).toContain(secret.handle);
    expect((await recovered.listApprovalPolicyRules()).map((item) => item.id)).toContain(rule.id);
    expect((await recovered.auditLog()).some((event) => event.type === "store.recovered")).toBe(true);
  });

  it("recovers credentials and policies after the entire primary home is removed", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "external recovery token",
      type: "api-token",
      value: fakeOpenAiToken("external_recovery"),
      policy: { injectEnv: "EXTERNAL_RECOVERY_TOKEN", allowedCommands: [process.execPath] }
    });
    const rule = await store.addApprovalPolicyRule({
      name: "External recovery policy",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });

    await rm(tmpHome, { recursive: true, force: true });

    const recovered = new SecretStore();
    expect((await recovered.listHandles()).map((item) => item.handle)).toContain(secret.handle);
    expect((await recovered.listApprovalPolicyRules()).map((item) => item.id)).toContain(rule.id);
  });

  it("rejects an externally replaced ledger and restores the verified control state", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "replacement guard token",
      type: "api-token",
      value: fakeOpenAiToken("replacement_guard"),
      policy: { injectEnv: "REPLACEMENT_GUARD_TOKEN", allowedCommands: [process.execPath] }
    });
    const rule = await store.addApprovalPolicyRule({
      name: "Replacement guard policy",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });
    await writeFile(store.storePath, `${JSON.stringify({
      version: 1,
      secrets: [],
      requests: [],
      audit: [],
      approvalSettings: { mode: "per-transaction", durationMs: 15 * 60 * 1000 },
      approvalGrants: [],
      approvalPolicyRules: []
    }, null, 2)}\n`);

    const recovered = new SecretStore();
    expect((await recovered.listHandles()).map((item) => item.handle)).toContain(secret.handle);
    expect((await recovered.listApprovalPolicyRules()).map((item) => item.id)).toContain(rule.id);

    const preserved = await readdir(path.join(tmpHome, "recovery", "automatic"));
    expect(preserved.some((name) => name.includes("control-mismatch"))).toBe(true);
  });

  it("recovers a corrupt ledger and preserves it for investigation", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "corrupt recovery token",
      type: "api-token",
      value: fakeOpenAiToken("corrupt_recovery"),
      policy: { injectEnv: "CORRUPT_RECOVERY_TOKEN" }
    });
    await writeFile(store.storePath, "{not valid json\n");

    const recovered = new SecretStore();
    expect((await recovered.listHandles()).map((item) => item.handle)).toContain(secret.handle);
    const preserved = await readdir(path.join(tmpHome, "recovery", "automatic"));
    expect(preserved.some((name) => name.includes("store-invalid"))).toBe(true);
  });

  it("rebuilds a missing control manifest only from a matching checkpoint", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "manifest recovery token",
      type: "api-token",
      value: fakeOpenAiToken("manifest_recovery"),
      policy: { injectEnv: "MANIFEST_RECOVERY_TOKEN" }
    });
    await rm(path.join(tmpHome, ".store-control.json"));

    const recovered = new SecretStore();
    expect((await recovered.listHandles()).map((item) => item.handle)).toContain(secret.handle);
    expect(JSON.parse(await readFile(path.join(tmpHome, ".store-control.json"), "utf8"))).toMatchObject({
      version: 1,
      secrets: 1
    });
  });

  it("does not rotate control-plane checkpoints for request-only traffic", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "request traffic token",
      type: "api-token",
      value: fakeOpenAiToken("request_traffic"),
      policy: { injectEnv: "REQUEST_TRAFFIC_TOKEN", allowedCommands: [process.execPath] }
    });
    const checkpointDir = path.join(tmpHome, "backups", "control-plane");
    const before = (await readdir(checkpointDir)).length;
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "0"],
      injectEnv: "REQUEST_TRAFFIC_TOKEN"
    });

    for (let index = 0; index < 8; index += 1) {
      await store.createRequest(secret.handle, action, `request traffic ${index}`);
    }

    expect((await readdir(checkpointDir)).length).toBe(before);
    await store.addApprovalPolicyRule({
      name: "New durable policy",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });
    expect((await readdir(checkpointDir)).length).toBeGreaterThan(before);
  });

  it("does not churn rolling backups for high-frequency request traffic", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "request backup cadence token",
      type: "api-token",
      value: fakeOpenAiToken("request_backup_cadence"),
      policy: { injectEnv: "REQUEST_BACKUP_CADENCE_TOKEN", allowedCommands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "0"],
      injectEnv: "REQUEST_BACKUP_CADENCE_TOKEN"
    });
    const before = await store.listStoreBackups();

    for (let index = 0; index < 8; index += 1) {
      await store.createRequest(secret.handle, action, `request backup cadence ${index}`);
    }

    expect(await store.listStoreBackups()).toHaveLength(before.length);
    await store.addApprovalPolicyRule({
      name: "Durable backup cadence policy",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });
    expect(await store.listStoreBackups()).toHaveLength(before.length + 1);
  });

  it("does not churn durable backups for reusable approval traffic", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "reusable request backup token",
      type: "api-token",
      value: fakeOpenAiToken("reusable_request_backup"),
      policy: { injectEnv: "REUSABLE_REQUEST_BACKUP_TOKEN", allowedCommands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "0"],
      injectEnv: "REUSABLE_REQUEST_BACKUP_TOKEN"
    });
    const context = { agentName: "codex" };
    const first = await store.createRequest(secret.handle, action, "reusable request backup", context);
    await store.approveRequest(first.id, { mode: "timed-session", durationMs: 60 * 60 * 1000 });

    const backupCount = (await store.listStoreBackups()).length;
    const externalDir = await externalControlPlaneDir();
    const checkpointCount = (await readdir(externalDir)).filter((entry) => entry.startsWith("checkpoint-")).length;

    for (let index = 0; index < 8; index += 1) {
      const request = await store.createRequest(secret.handle, action, `reusable request backup ${index}`, context);
      expect(request.state).toBe("approved");
    }

    expect(await store.listStoreBackups()).toHaveLength(backupCount);
    expect((await readdir(externalDir)).filter((entry) => entry.startsWith("checkpoint-"))).toHaveLength(checkpointCount);
  });

  it("keeps an append-only control-plane history instead of pruning it", async () => {
    const store = new SecretStore();
    await store.addSecret({
      name: "checkpoint history token",
      type: "api-token",
      value: fakeOpenAiToken("checkpoint_history"),
      policy: { injectEnv: "CHECKPOINT_HISTORY_TOKEN" }
    });

    for (let index = 0; index < 52; index += 1) {
      await store.addApprovalPolicyRule({
        name: `Checkpoint policy ${index}`,
        decision: "allow",
        conditions: { agents: ["codex"] }
      });
    }

    const externalDir = await externalControlPlaneDir();
    const checkpoints = (await readdir(externalDir)).filter((entry) => entry.startsWith("checkpoint-"));
    expect(checkpoints.length).toBeGreaterThan(50);
    expect((await stat(path.join(externalDir, checkpoints[0]))).mode & 0o200).toBe(0);
  }, 15_000);

  it("keeps the newest sealed checkpoint when the clock moves backwards", async () => {
    const store = new SecretStore();
    await store.addSecret({
      name: "clock-safe checkpoint token",
      type: "api-token",
      value: fakeOpenAiToken("clock_safe_checkpoint"),
      policy: { injectEnv: "CLOCK_SAFE_CHECKPOINT_TOKEN" }
    });

    const now = Date.now();
    const dateNow = vi.spyOn(Date, "now").mockReturnValue(now - 60 * 60 * 1000);
    try {
      await store.addApprovalPolicyRule({
        name: "Clock-safe durable policy",
        decision: "allow",
        conditions: { agents: ["codex"] }
      });
    } finally {
      dateNow.mockRestore();
    }

    expect((await store.listApprovalPolicyRules()).some((rule) => rule.name === "Clock-safe durable policy")).toBe(true);
  });

  it("keeps separate recovery namespaces when ledgers share one recovery home", async () => {
    const firstHome = await mkdtemp(path.join(os.tmpdir(), "sgw-first-ledger-"));
    const secondHome = await mkdtemp(path.join(os.tmpdir(), "sgw-second-ledger-"));
    const sharedRecoveryHome = await mkdtemp(path.join(os.tmpdir(), "sgw-shared-recovery-"));
    const originalHome = process.env.SGW_HOME;
    const originalRecoveryHome = process.env.SGW_RECOVERY_HOME;
    try {
      process.env.SGW_HOME = firstHome;
      process.env.SGW_RECOVERY_HOME = sharedRecoveryHome;
      const first = await new SecretStore(firstHome).addSecret({
        name: "first shared recovery token",
        type: "api-token",
        value: fakeOpenAiToken("first_shared_recovery"),
        policy: { injectEnv: "FIRST_SHARED_RECOVERY_TOKEN" }
      });

      process.env.SGW_HOME = secondHome;
      const second = await new SecretStore(secondHome).addSecret({
        name: "second shared recovery token",
        type: "api-token",
        value: fakeOpenAiToken("second_shared_recovery"),
        policy: { injectEnv: "SECOND_SHARED_RECOVERY_TOKEN" }
      });

      const namespaces = await readdir(path.join(sharedRecoveryHome, "control-plane"));
      expect(namespaces).toHaveLength(2);

      process.env.SGW_HOME = firstHome;
      expect((await new SecretStore(firstHome).listHandles()).map((item) => item.handle)).toEqual([first.handle]);
      process.env.SGW_HOME = secondHome;
      expect((await new SecretStore(secondHome).listHandles()).map((item) => item.handle)).toEqual([second.handle]);
    } finally {
      process.env.SGW_HOME = originalHome;
      process.env.SGW_RECOVERY_HOME = originalRecoveryHome;
      await rm(firstHome, { recursive: true, force: true });
      await rm(secondHome, { recursive: true, force: true });
      await rm(sharedRecoveryHome, { recursive: true, force: true });
    }
  });

  it("does not cross-restore an unanchored legacy checkpoint from a shared recovery home", async () => {
    const firstHome = await mkdtemp(path.join(os.tmpdir(), "sgw-first-legacy-ledger-"));
    const secondHome = await mkdtemp(path.join(os.tmpdir(), "sgw-second-legacy-ledger-"));
    const sharedRecoveryHome = await mkdtemp(path.join(os.tmpdir(), "sgw-shared-legacy-recovery-"));
    const originalHome = process.env.SGW_HOME;
    const originalRecoveryHome = process.env.SGW_RECOVERY_HOME;
    try {
      process.env.SGW_HOME = firstHome;
      process.env.SGW_RECOVERY_HOME = sharedRecoveryHome;
      const first = new SecretStore(firstHome);
      await first.addSecret({
        name: "legacy source token",
        type: "api-token",
        value: fakeOpenAiToken("legacy_shared_source"),
        policy: { injectEnv: "LEGACY_SHARED_SOURCE" }
      });

      const firstRecoveryDir = await externalControlPlaneDir(firstHome, sharedRecoveryHome);
      const head = JSON.parse(await readFile(path.join(firstRecoveryDir, "head.json"), "utf8"));
      const snapshot = await readFile(path.join(firstRecoveryDir, head.checkpoint), "utf8");
      await writeFile(
        path.join(sharedRecoveryHome, "control-plane", "store-20260715T000000-legacy-1.json"),
        snapshot
      );

      process.env.SGW_HOME = secondHome;
      await expect(new SecretStore(secondHome).listHandles()).rejects.toThrow(/refusing to create an empty ledger/i);
    } finally {
      process.env.SGW_HOME = originalHome;
      process.env.SGW_RECOVERY_HOME = originalRecoveryHome;
      await rm(firstHome, { recursive: true, force: true });
      await rm(secondHome, { recursive: true, force: true });
      await rm(sharedRecoveryHome, { recursive: true, force: true });
    }
  });

  it("fails closed when the configured recovery home changes after sealing", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "recovery vault binding token",
      type: "api-token",
      value: fakeOpenAiToken("recovery_vault_binding"),
      policy: { injectEnv: "RECOVERY_VAULT_BINDING" }
    });
    const originalRecoveryHome = process.env.SGW_RECOVERY_HOME;
    const alternateRecoveryHome = await mkdtemp(path.join(os.tmpdir(), "sgw-alternate-recovery-"));

    try {
      process.env.SGW_RECOVERY_HOME = alternateRecoveryHome;
      await expect(new SecretStore().listHandles()).rejects.toThrow(/recovery home changed/i);

      const sourceDir = await externalControlPlaneDir();
      const targetDir = path.join(alternateRecoveryHome, "control-plane", path.basename(sourceDir));
      await mkdir(targetDir, { recursive: true, mode: 0o700 });
      for (const entry of await readdir(sourceDir)) {
        const source = path.join(sourceDir, entry);
        const target = path.join(targetDir, entry);
        if (!(await stat(source)).isFile()) {
          continue;
        }
        await writeFile(target, await readFile(source));
        if (entry.startsWith("checkpoint-")) {
          await chmod(target, 0o400);
        }
      }

      expect((await new SecretStore().listHandles()).map((item) => item.handle)).toEqual([secret.handle]);
    } finally {
      process.env.SGW_RECOVERY_HOME = originalRecoveryHome;
      await rm(alternateRecoveryHome, { recursive: true, force: true });
    }

    expect((await new SecretStore().listHandles()).map((item) => item.handle)).toEqual([secret.handle]);
  });

  it("restores the sealed external checkpoint when the primary and manifest are both replaced", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "sealed checkpoint token",
      type: "api-token",
      value: fakeOpenAiToken("sealed_checkpoint"),
      policy: { injectEnv: "SEALED_CHECKPOINT_TOKEN" }
    });
    const rule = await store.addApprovalPolicyRule({
      name: "Sealed checkpoint policy",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });

    const fixtureHome = await mkdtemp(path.join(os.tmpdir(), "sgw-empty-ledger-"));
    const fixtureRecoveryHome = `${tmpHome}-recovery`;
    const originalHome = process.env.SGW_HOME;
    const originalRecoveryHome = process.env.SGW_RECOVERY_HOME;
    let emptyStore = "";
    let emptyManifest = "";
    try {
      process.env.SGW_HOME = fixtureHome;
      process.env.SGW_RECOVERY_HOME = fixtureRecoveryHome;
      await new SecretStore().init();
      emptyStore = await readFile(path.join(fixtureHome, "store.json"), "utf8");
      emptyManifest = await readFile(path.join(fixtureHome, ".store-control.json"), "utf8");
    } finally {
      process.env.SGW_HOME = originalHome;
      process.env.SGW_RECOVERY_HOME = originalRecoveryHome;
      await rm(fixtureHome, { recursive: true, force: true });
    }

    await writeFile(store.storePath, emptyStore);
    await writeFile(path.join(tmpHome, ".store-control.json"), emptyManifest);

    const recovered = new SecretStore();
    expect((await recovered.listHandles()).map((item) => item.handle)).toContain(secret.handle);
    expect((await recovered.listApprovalPolicyRules()).map((item) => item.id)).toContain(rule.id);
  });

  it("fails closed when the manifest-pinned sealed checkpoint disappears", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "pinned checkpoint token",
      type: "api-token",
      value: fakeOpenAiToken("pinned_checkpoint"),
      policy: { injectEnv: "PINNED_CHECKPOINT_TOKEN" }
    });
    const rule = await store.addApprovalPolicyRule({
      name: "Pinned checkpoint policy",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });
    const primaryBefore = await readFile(store.storePath, "utf8");
    const manifest = JSON.parse(await readFile(path.join(tmpHome, ".store-control.json"), "utf8"));
    const externalDir = await externalControlPlaneDir();

    expect(manifest).toMatchObject({ recoverySealed: true });
    expect(typeof manifest.recoveryCheckpoint).toBe("string");
    expect((await readdir(externalDir)).filter((entry) => entry.startsWith("checkpoint-")).length).toBeGreaterThan(1);
    await rm(path.join(externalDir, manifest.recoveryCheckpoint));

    await expect(new SecretStore().listHandles()).rejects.toThrow(
      /sealed recovery anchor is unavailable or does not match.*refusing to roll back credentials or policies/i
    );
    expect(await readFile(store.storePath, "utf8")).toBe(primaryBefore);

    const primary = JSON.parse(primaryBefore);
    expect(primary.secrets.map((item: { handle: string }) => item.handle)).toContain(secret.handle);
    expect(primary.approvalPolicyRules.map((item: { id: string }) => item.id)).toContain(rule.id);
  });

  it("fails closed when a sealed manifest is missing its recovery anchors", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "incomplete sealed manifest token",
      type: "api-token",
      value: fakeOpenAiToken("incomplete_sealed_manifest"),
      policy: { injectEnv: "INCOMPLETE_SEALED_MANIFEST_TOKEN" }
    });
    const primaryBefore = await readFile(store.storePath, "utf8");
    const controlPath = path.join(tmpHome, ".store-control.json");
    const manifest = JSON.parse(await readFile(controlPath, "utf8"));
    delete manifest.recoveryCheckpoint;
    delete manifest.recoveryVaultId;
    delete manifest.recoveryNamespace;
    await writeFile(controlPath, `${JSON.stringify(manifest, null, 2)}\n`);

    await expect(new SecretStore().listHandles()).rejects.toThrow(/control manifest is invalid/i);
    expect(await readFile(store.storePath, "utf8")).toBe(primaryBefore);
    expect(JSON.parse(primaryBefore).secrets.map((item: { handle: string }) => item.handle)).toContain(secret.handle);
  });

  it("does not bootstrap a replacement ledger after its manifest and marker disappear", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "manifestless replacement token",
      type: "api-token",
      value: fakeOpenAiToken("manifestless_replacement"),
      policy: { injectEnv: "MANIFESTLESS_REPLACEMENT_TOKEN" }
    });

    const fixtureHome = await mkdtemp(path.join(os.tmpdir(), "sgw-empty-ledger-"));
    const fixtureRecoveryHome = `${fixtureHome}-recovery`;
    const originalHome = process.env.SGW_HOME;
    const originalRecoveryHome = process.env.SGW_RECOVERY_HOME;
    let emptyStore = "";
    try {
      process.env.SGW_HOME = fixtureHome;
      process.env.SGW_RECOVERY_HOME = fixtureRecoveryHome;
      await new SecretStore().init();
      emptyStore = await readFile(path.join(fixtureHome, "store.json"), "utf8");
    } finally {
      process.env.SGW_HOME = originalHome;
      process.env.SGW_RECOVERY_HOME = originalRecoveryHome;
      await rm(fixtureHome, { recursive: true, force: true });
      await rm(fixtureRecoveryHome, { recursive: true, force: true });
    }

    await writeFile(store.storePath, emptyStore);
    await rm(path.join(tmpHome, ".store-control.json"));
    await rm(path.join(tmpHome, ".store-initialized"));

    expect((await new SecretStore().listHandles()).map((item) => item.handle)).toContain(secret.handle);
  });

  it("migrates a legacy external control-plane checkpoint into a sealed anchor", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "legacy checkpoint token",
      type: "api-token",
      value: fakeOpenAiToken("legacy_checkpoint"),
      policy: { injectEnv: "LEGACY_CHECKPOINT_TOKEN" }
    });
    const externalDir = await externalControlPlaneDir();
    const head = JSON.parse(await readFile(path.join(externalDir, "head.json"), "utf8"));
    const snapshot = await readFile(path.join(externalDir, head.checkpoint), "utf8");
    const legacyDir = path.join(`${tmpHome}-recovery`, "control-plane");
    await writeFile(path.join(legacyDir, "store-20260715T000000-legacy-1.json"), snapshot);
    await rm(externalDir, { recursive: true, force: true });

    const controlPath = path.join(tmpHome, ".store-control.json");
    const legacyManifest = JSON.parse(await readFile(controlPath, "utf8"));
    delete legacyManifest.recoverySealed;
    await writeFile(controlPath, `${JSON.stringify(legacyManifest, null, 2)}\n`);

    const migrated = new SecretStore();
    expect((await migrated.listHandles()).map((item) => item.handle)).toContain(secret.handle);
    expect(JSON.parse(await readFile(controlPath, "utf8"))).toMatchObject({ recoverySealed: true });
    const migratedDir = await externalControlPlaneDir();
    expect((await readdir(migratedDir)).some((entry) => entry.startsWith("checkpoint-"))).toBe(true);
  });

  it("does not commit a pending state with the wrong predecessor fingerprint", async () => {
    const store = new SecretStore();
    const original = await store.addSecret({
      name: "known control state",
      type: "api-token",
      value: fakeOpenAiToken("known_control_state"),
      policy: { injectEnv: "KNOWN_CONTROL_STATE" }
    });

    const fixtureHome = await mkdtemp(path.join(os.tmpdir(), "sgw-pending-fixture-"));
    const fixtureRecoveryHome = `${fixtureHome}-recovery`;
    const originalHome = process.env.SGW_HOME;
    const originalRecoveryHome = process.env.SGW_RECOVERY_HOME;
    let replacementStore = "";
    let replacementFingerprint = "";
    let replacementHandle = "";
    try {
      process.env.SGW_HOME = fixtureHome;
      process.env.SGW_RECOVERY_HOME = fixtureRecoveryHome;
      const replacement = await new SecretStore().addSecret({
        name: "untrusted pending state",
        type: "api-token",
        value: fakeOpenAiToken("untrusted_pending_state"),
        policy: { injectEnv: "UNTRUSTED_PENDING_STATE" }
      });
      replacementHandle = replacement.handle;
      replacementStore = await readFile(path.join(fixtureHome, "store.json"), "utf8");
      replacementFingerprint = JSON.parse(
        await readFile(path.join(fixtureHome, ".store-control.json"), "utf8")
      ).fingerprint;
    } finally {
      process.env.SGW_HOME = originalHome;
      process.env.SGW_RECOVERY_HOME = originalRecoveryHome;
      await rm(fixtureHome, { recursive: true, force: true });
      await rm(fixtureRecoveryHome, { recursive: true, force: true });
    }

    await writeFile(store.storePath, replacementStore);
    await writeFile(path.join(tmpHome, ".store-control.pending.json"), `${JSON.stringify({
      version: 1,
      previousFingerprint: "0".repeat(64),
      nextFingerprint: replacementFingerprint,
      createdAt: new Date().toISOString()
    })}\n`);

    const recovered = new SecretStore();
    const handles = (await recovered.listHandles()).map((item) => item.handle);
    expect(handles).toContain(original.handle);
    expect(handles).not.toContain(replacementHandle);
  });

  it("does not replace the ledger when the external checkpoint cannot be written", async () => {
    const store = new SecretStore();
    const first = await store.addSecret({
      name: "durable before failure",
      type: "api-token",
      value: fakeOpenAiToken("durable_before_failure"),
      policy: { injectEnv: "DURABLE_BEFORE_FAILURE" }
    });
    const recoveryHome = process.env.SGW_RECOVERY_HOME;
    const unavailableRecoveryHome = path.join(tmpHome, "unavailable-recovery");
    await writeFile(unavailableRecoveryHome, "not a directory\n");
    process.env.SGW_RECOVERY_HOME = unavailableRecoveryHome;

    await expect(store.addSecret({
      name: "must not commit",
      type: "api-token",
      value: fakeOpenAiToken("must_not_commit"),
      policy: { injectEnv: "MUST_NOT_COMMIT" }
    })).rejects.toThrow();

    process.env.SGW_RECOVERY_HOME = recoveryHome;
    const recovered = new SecretStore();
    expect((await recovered.listHandles()).map((item) => item.handle)).toEqual([first.handle]);
  });

  it("fails closed instead of trusting a rolling backup when sealed recovery is unavailable", async () => {
    const store = new SecretStore();
    await store.addSecret({
      name: "sealed recovery required token",
      type: "api-token",
      value: fakeOpenAiToken("sealed_recovery_required"),
      policy: { injectEnv: "SEALED_RECOVERY_REQUIRED_TOKEN" }
    });
    const current = await readFile(store.storePath, "utf8");
    await writeFile(
      path.join(tmpHome, "backups", "store-20260715T000000-999-1.json"),
      current
    );
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
    await writeFile(store.storePath, "not valid json\n");

    await expect(new SecretStore().listHandles()).rejects.toThrow(/invalid and no verified recovery copy/i);
  });

  it("does not steal a lock held by a live process", async () => {
    const store = new SecretStore();
    await store.init();
    const lockPath = `${store.storePath}.lock`;
    const previousTimeout = process.env.SGW_TEST_LOCK_TIMEOUT_MS;
    await writeStoreLock(lockPath, {
      pid: process.pid,
      token: "live-process-lock-token-1234567890",
      createdAt: "2000-01-01T00:00:00.000Z"
    });
    process.env.SGW_TEST_LOCK_TIMEOUT_MS = "30";

    try {
      await expect(store.addApprovalPolicyRule({
        name: "Blocked by live lock",
        decision: "allow",
        conditions: { agents: ["codex"] }
      })).rejects.toThrow(/timed out waiting/i);
    } finally {
      if (previousTimeout === undefined) {
        delete process.env.SGW_TEST_LOCK_TIMEOUT_MS;
      } else {
        process.env.SGW_TEST_LOCK_TIMEOUT_MS = previousTimeout;
      }
      await rm(lockPath, { recursive: true, force: true });
    }
  });

  it("reclaims a lock only after its owner is definitely dead", async () => {
    const store = new SecretStore();
    await store.init();
    await writeStoreLock(`${store.storePath}.lock`, {
      pid: 2147483647,
      token: "dead-process-lock-token-1234567890",
      createdAt: "2000-01-01T00:00:00.000Z"
    });

    const rule = await store.addApprovalPolicyRule({
      name: "Recovered dead lock",
      decision: "allow",
      conditions: { agents: ["codex"] }
    });
    expect(rule.name).toBe("Recovered dead lock");
  });

  it("fails closed when recovery evidence exists but no valid ledger remains", async () => {
    const store = new SecretStore();
    await store.addSecret({
      name: "fail closed token",
      type: "api-token",
      value: fakeOpenAiToken("fail_closed"),
      policy: { injectEnv: "FAIL_CLOSED_TOKEN" }
    });
    await rm(store.storePath);
    await rm(path.join(tmpHome, "backups"), { recursive: true, force: true });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });

    await expect(new SecretStore().listHandles()).rejects.toThrow(/refusing to (create an empty ledger|initialize from an unanchored ledger)/i);
    await expect(readFile(store.storePath, "utf8")).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("serializes concurrent recovery so every reader gets the same ledger", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "concurrent recovery token",
      type: "api-token",
      value: fakeOpenAiToken("concurrent_recovery"),
      policy: { injectEnv: "CONCURRENT_RECOVERY_TOKEN" }
    });
    await rm(store.storePath);

    const results = await Promise.all(
      Array.from({ length: 20 }, () => new SecretStore().listHandles())
    );
    for (const handles of results) {
      expect(handles.map((item) => item.handle)).toContain(secret.handle);
    }
  });

  it("refuses to use the live s-gw home while running tests", () => {
    const oldHome = process.env.SGW_HOME;
    const oldLiveHome = process.env.SGW_TEST_LIVE_HOME;
    const guardedHome = path.join(tmpHome, "pretend-live-home");
    process.env.SGW_HOME = guardedHome;
    process.env.SGW_TEST_LIVE_HOME = guardedHome;

    try {
      expect(() => new SecretStore()).toThrow(/refusing to use the live s-gw home/i);
    } finally {
      process.env.SGW_HOME = oldHome;
      if (oldLiveHome === undefined) {
        delete process.env.SGW_TEST_LIVE_HOME;
      } else {
        process.env.SGW_TEST_LIVE_HOME = oldLiveHome;
      }
    }
  });

  it("tokenizes local text with a unique handle representation", async () => {
    const store = new SecretStore();
    const secret = fakeOpenAiToken("local_scan");
    const result = await scanLocalText(store, `OPENAI_API_KEY=${secret}\n`, { persist: true, source: "unit-test" });

    expect(result.findings).toHaveLength(1);
    expect(result.tokenizedText).not.toContain(secret);
    expect(result.tokenizedText).toContain(tokenForHandle(result.findings[0].handle));

    const handles = await store.listHandles();
    expect(handles).toHaveLength(1);
    expect(handles[0].source).toBe("unit-test");
    expect(handles[0].provider).toBe("openai");
    expect(handles[0].ruleId).toBe("SEC-OPENAI-PROJECT");
    expect(handles[0].severity).toBe("critical");
  });

  it("requires local approval before executing a secret-backed command", async () => {
    const store = new SecretStore();
    const secret = "super-secret-value-123456789";
    const record = await store.addSecret({
      name: "exec token",
      type: "api-token",
      value: secret,
      policy: {
        injectEnv: "SGW_TEST_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "console.log(process.env.SGW_TEST_TOKEN)"],
        injectEnv: "SGW_TEST_TOKEN"
      }),
      "unit test"
    );

    await expect(executeApprovedRequest(store, request.id)).rejects.toThrow(/local approval/i);
    await store.approveRequest(request.id);

    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).not.toContain(secret);
    expect(summary.stdout).toContain(tokenForHandle(record.handle));
    expect(summary.proof).toMatch(/^s-gw-proof:/);
  });

  it("treats repeated approval as the same decision", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "repeat approval token",
      type: "api-token",
      value: "repeat-approval-secret-value-123456789",
      policy: {
        injectEnv: "SGW_REPEAT_APPROVAL_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "0"],
        injectEnv: "SGW_REPEAT_APPROVAL_TOKEN"
      }),
      "repeat approval test"
    );

    const first = await store.approveRequest(request.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    const repeated = await store.approveRequest(request.id, {
      mode: "per-transaction",
      agentScope: "same-agent"
    });

    expect(repeated.state).toBe("approved");
    expect(repeated.approvalGrantId).toBe(first.approvalGrantId);
    expect(await store.listApprovalGrants()).toHaveLength(1);
    expect((await store.auditLog()).filter((event) => event.type === "request.approved")).toHaveLength(1);
  });

  it("records the runtime agent for generic local CLI requests", async () => {
    const oldCodexShell = process.env.CODEX_SHELL;
    process.env.CODEX_SHELL = "1";

    try {
      const store = new SecretStore();
      const record = await store.addSecret({
        name: "generic cli token",
        type: "api-token",
        value: "generic-cli-secret-value-123456789",
        policy: {
          injectEnv: "SGW_GENERIC_TOKEN",
          allowedCommands: [process.execPath]
        }
      });
      const request = await store.createRequest(
        record.handle,
        buildEnvCommandAction({
          command: process.execPath,
          args: ["-e", "console.log(process.env.SGW_GENERIC_TOKEN)"],
          injectEnv: "SGW_GENERIC_TOKEN"
        }),
        "Local CLI request"
      );

      expect(request.agentName).toBe("Codex");
      expect((await store.getRequest(request.id)).agentName).toBe("Codex");
    } finally {
      if (oldCodexShell === undefined) {
        delete process.env.CODEX_SHELL;
      } else {
        process.env.CODEX_SHELL = oldCodexShell;
      }
    }
  });

  it("stores Keychain-backed secret values outside the encrypted ledger", async () => {
    if (process.platform !== "darwin") {
      return;
    }

    const fakeDb = path.join(tmpHome, "fake-keychain.json");
    process.env.SGW_KEYCHAIN_HELPER = await writeFakeKeychainHelper(fakeDb);
    process.env.SGW_SECRET_KEYCHAIN_SERVICE = "com.s-gw.test.secret";

    const store = new SecretStore();
    const secret = "keychain-secret-value-1234567890";
    const record = await store.addKeychainSecret({
      name: "keychain token",
      type: "api-token",
      value: secret,
      policy: {
        injectEnv: "SGW_KEYCHAIN_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const storeText = await readFile(store.storePath, "utf8");
    expect(storeText).not.toContain(secret);
    expect(record.backend).toBe("keychain");
    expect(record.provider).toBe("macos-keychain");

    const handles = await store.listHandles();
    expect(handles[0].backend).toBe("keychain");
    expect(handles[0].provider).toBe("macos-keychain");

    expect(await store.repairKeychainAccess()).toMatchObject({
      checked: 1,
      unsupported: 1,
      failed: []
    });

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "console.log(process.env.SGW_KEYCHAIN_TOKEN)"],
        injectEnv: "SGW_KEYCHAIN_TOKEN"
      }),
      "Keychain unit test"
    );

    await store.approveRequest(request.id);
    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).not.toContain(secret);
    expect(summary.stdout).toContain(tokenForHandle(record.handle));

    const dbBeforeDelete = JSON.parse(await readFile(fakeDb, "utf8"));
    expect(Object.keys(dbBeforeDelete)).toHaveLength(1);

    await store.deleteSecret(record.handle);
    const dbAfterDelete = JSON.parse(await readFile(fakeDb, "utf8"));
    expect(Object.keys(dbAfterDelete)).toHaveLength(0);
  });

  it("does not pass unrelated parent-process secrets into approved commands", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "master-passphrase-should-not-leak";
    process.env.AWS_SECRET_ACCESS_KEY = "aws-parent-secret-should-not-leak";

    const store = new SecretStore();
    const secret = "approved-command-secret-123456789";
    const record = await store.addSecret({
      name: "env isolation",
      type: "api-token",
      value: secret,
      policy: {
        injectEnv: "SGW_ALLOWED_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: [
          "-e",
          [
            "console.log(process.env.SGW_MASTER_PASSPHRASE || 'missing-master')",
            "console.log(process.env.AWS_SECRET_ACCESS_KEY || 'missing-aws')",
            "console.log(process.env.SGW_ALLOWED_TOKEN)"
          ].join(";")
        ],
        injectEnv: "SGW_ALLOWED_TOKEN"
      }),
      "env isolation test"
    );

    await store.approveRequest(request.id);
    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.stdout).toContain("missing-master");
    expect(summary.stdout).toContain("missing-aws");
    expect(summary.stdout).not.toContain("master-passphrase-should-not-leak");
    expect(summary.stdout).not.toContain("aws-parent-secret-should-not-leak");
    expect(summary.stdout).not.toContain(secret);
    expect(summary.stdout).toContain(tokenForHandle(record.handle));
  });

  it("injects multiple approved handles into one env-command and sanitizes each value", async () => {
    const store = new SecretStore();
    const accessKey = fakeAwsAccessKey();
    const secretKey = "aws-secret-access-key-value-123456789";
    const access = await store.addSecret({
      name: "aws access key id",
      type: "access-key",
      value: accessKey,
      policy: {
        injectEnv: "AWS_ACCESS_KEY_ID",
        allowedCommands: [process.execPath]
      }
    });
    const secret = await store.addSecret({
      name: "aws secret access key",
      type: "credential",
      value: secretKey,
      policy: {
        injectEnv: "AWS_SECRET_ACCESS_KEY",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const request = await store.createRequest(
      secret.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: [
          "-e",
          [
            "console.log(process.env.AWS_ACCESS_KEY_ID)",
            "console.log(process.env.AWS_SECRET_ACCESS_KEY)"
          ].join(";")
        ],
        injectEnv: "AWS_SECRET_ACCESS_KEY",
        env: [{ handle: access.handle, injectEnv: "AWS_ACCESS_KEY_ID" }]
      }),
      "Codex AWS credential pair"
    );

    await store.approveRequest(request.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).not.toContain(accessKey);
    expect(summary.stdout).not.toContain(secretKey);
    expect(summary.stdout).toContain(tokenForHandle(access.handle));
    expect(summary.stdout).toContain(tokenForHandle(secret.handle));
  });

  it("keeps long timeout requests explicit and supports no child-process timer", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "timeout token",
      type: "credential",
      value: "timeout-secret-value-123456789",
      policy: {
        injectEnv: "SGW_TIMEOUT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });

    const longRequest = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "0"],
        injectEnv: "SGW_TIMEOUT_TOKEN",
        timeoutMs: 1_800_000
      }),
      "Codex long EICE helper"
    );
    expect(longRequest.action.timeoutMs).toBe(1_800_000);

    const sessionRequest = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "0"],
        injectEnv: "SGW_TIMEOUT_TOKEN",
        timeoutMs: 0
      }),
      "Codex no timeout helper"
    );
    expect(sessionRequest.action.timeoutMs).toBe(0);
  });

  it("never leaks a partial secret when output is truncated across the byte cap", async () => {
    const store = new SecretStore();
    // A secret with no detector-recognizable shape, so only the exact-value
    // sanitizer can remove it — this is what protects us, not the scanner.
    const secret = "ZxQveryLongOpaqueCredentialValue1234567890abcdefXY";
    const record = await store.addSecret({
      name: "truncation leak",
      type: "credential",
      value: secret,
      policy: {
        injectEnv: "SGW_LEAK_TOKEN",
        allowedCommands: [process.execPath],
        // Tiny cap so the printed secret lands across the truncation boundary.
        maxOutputBytes: 24
      }
    });

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        // Pad before the secret so the cut falls in the middle of it.
        args: ["-e", "process.stdout.write('p'.repeat(18) + process.env.SGW_LEAK_TOKEN)"],
        injectEnv: "SGW_LEAK_TOKEN"
      }),
      "truncation leak test"
    );

    await store.approveRequest(request.id);
    const summary = await executeApprovedRequest(store, request.id);

    // No run of the secret (down to short prefixes) may survive the cap.
    for (let len = secret.length; len >= 6; len--) {
      for (let i = 0; i + len <= secret.length; i++) {
        expect(summary.stdout).not.toContain(secret.slice(i, i + len));
      }
    }
    expect(summary.stdout).not.toContain(secret);
  });

  it("recovers a request stranded in executing when the runner never reported back", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "stranded token",
      type: "api-token",
      value: "stranded-secret-value-123456789",
      policy: { injectEnv: "SGW_STRANDED_TOKEN", allowedCommands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_STRANDED_TOKEN)"],
      injectEnv: "SGW_STRANDED_TOKEN"
    });

    const request = await store.createRequest(record.handle, action, "stranded test");
    await store.approveRequest(request.id);
    await store.claimApprovedRequest(request.id);

    // Pretend the runner died ~20 minutes ago, well past the stale window.
    await backdateRequest(request.id, 20 * 60 * 1000);

    const recovered = await store.recoverStaleExecutions();
    expect(recovered.map((item) => item.id)).toEqual([request.id]);

    const after = await store.getRequest(request.id);
    expect(after.state).toBe("failed");
    expect(after.error).toMatch(/interrupted/i);

    // A stale executing request must not be claimable again.
    await expect(store.claimApprovedRequest(request.id)).rejects.toThrow(/failed/);
  });

  it("leaves a freshly executing request alone", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "fresh token",
      type: "api-token",
      value: "fresh-secret-value-123456789",
      policy: { injectEnv: "SGW_FRESH_TOKEN", allowedCommands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_FRESH_TOKEN)"],
      injectEnv: "SGW_FRESH_TOKEN"
    });

    const request = await store.createRequest(record.handle, action, "fresh test");
    await store.approveRequest(request.id);
    await store.claimApprovedRequest(request.id);

    const recovered = await store.recoverStaleExecutions();
    expect(recovered).toHaveLength(0);
    expect((await store.getRequest(request.id)).state).toBe("executing");
  });

  it("supersedes older duplicate pending requests and can clean stale approved work", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "duplicate pending token",
      type: "api-token",
      value: "duplicate-pending-secret-123456789",
      policy: {
        injectEnv: "SGW_DUP_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_DUP_TOKEN)"],
      injectEnv: "SGW_DUP_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex duplicate pending");
    const second = await store.createRequest(record.handle, action, "Codex duplicate pending");
    expect((await store.getRequest(first.id)).state).toBe("failed");
    expect((await store.getRequest(first.id)).error).toContain(second.id);
    expect(second.state).toBe("pending");

    await store.approveRequest(second.id);
    await backdateRequest(second.id, 2 * 60 * 60 * 1000, ["approvedAt", "createdAt"]);

    const cleaned = await store.cleanupRequests({
      approvedOlderThanMs: 60 * 60 * 1000,
      pendingOlderThanMs: 24 * 60 * 60 * 1000
    });
    expect(cleaned.requests.map((item) => item.id)).toContain(second.id);
    const after = await store.getRequest(second.id);
    expect(after.state).toBe("failed");
    expect(after.error).toMatch(/expired before execution/i);
  });

  it("force-recovers a freshly executing request on explicit user action", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "force recover token",
      type: "api-token",
      value: "force-recover-secret-123456789",
      policy: { injectEnv: "SGW_FORCE_TOKEN", allowedCommands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_FORCE_TOKEN)"],
      injectEnv: "SGW_FORCE_TOKEN"
    });

    const request = await store.createRequest(record.handle, action, "force recover test");
    await store.approveRequest(request.id);
    await store.claimApprovedRequest(request.id);

    // No backdating: the request is still well inside the stale window, so the automatic
    // sweep would leave it. The explicit user-driven recovery should still clear it.
    const recovered = await store.forceRecoverExecutions(request.id);
    expect(recovered.map((item) => item.id)).toEqual([request.id]);

    const after = await store.getRequest(request.id);
    expect(after.state).toBe("failed");
    expect(after.error).toMatch(/recovered manually/i);
    await expect(store.claimApprovedRequest(request.id)).rejects.toThrow(/failed/);
  });

  it("refuses to force-recover a request that is not executing", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "non-executing token",
      type: "api-token",
      value: "non-executing-secret-123456789",
      policy: { injectEnv: "SGW_PENDING_TOKEN", allowedCommands: [process.execPath] }
    });
    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "0"],
        injectEnv: "SGW_PENDING_TOKEN"
      }),
      "still pending"
    );

    await expect(store.forceRecoverExecutions(request.id)).rejects.toThrow(/not executing/i);
    await expect(store.forceRecoverExecutions("req_missing")).rejects.toThrow(/unknown request/i);
  });

  it("claims an approved request before execution so concurrent calls run it once", async () => {
    const store = new SecretStore();
    const hitFile = path.join(tmpHome, "race-hits.txt");
    const record = await store.addSecret({
      name: "race token",
      type: "api-token",
      value: "race-secret-value-123456789",
      policy: {
        injectEnv: "SGW_RACE_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: [
          "-e",
          "require('node:fs').appendFileSync(process.argv[1], 'hit\\n'); console.log(process.env.SGW_RACE_TOKEN)",
          hitFile
        ],
        injectEnv: "SGW_RACE_TOKEN"
      }),
      "race test"
    );

    await store.approveRequest(request.id);
    const results = await Promise.allSettled([
      executeApprovedRequest(store, request.id),
      executeApprovedRequest(store, request.id)
    ]);

    expect(results.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((item) => item.status === "rejected")).toHaveLength(1);
    const hits = await readFile(hitFile, "utf8");
    expect(hits.trim().split("\n")).toHaveLength(1);
  });

  it("auto-approves the same action inside a timed approval session", async () => {
    const store = new SecretStore();
    await store.setApprovalSettings({ mode: "timed-session", durationMs: 15 * 60 * 1000 });
    const record = await store.addSecret({
      name: "timed token",
      type: "api-token",
      value: "timed-secret-value-123456789",
      policy: {
        injectEnv: "SGW_TIMED_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_TIMED_TOKEN)"],
      injectEnv: "SGW_TIMED_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "timed session first");
    expect(first.state).toBe("pending");
    const approved = await store.approveRequest(first.id);
    expect(approved.approvalGrantId).toMatch(/^grant_/);

    const second = await store.createRequest(record.handle, action, "timed session second");
    expect(second.state).toBe("approved");
    expect(second.approvalGrantId).toBe(approved.approvalGrantId);
  });

  it("blocks a revoked grant's auto-approved request but keeps the manual approval valid", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "revoked auto-approved request token",
      type: "api-token",
      value: "revoked-auto-approved-request-secret-value-123456789",
      policy: {
        injectEnv: "SGW_REVOKED_AUTO_APPROVED_REQUEST",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "process.stdout.write('approved')"],
      injectEnv: "SGW_REVOKED_AUTO_APPROVED_REQUEST"
    });
    const manual = await store.createRequest(record.handle, action, "Codex manual approval");
    const approved = await store.approveRequest(manual.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000
    });
    const automatic = await store.createRequest(record.handle, action, "Codex reusable approval");
    expect(manual.approvalSource).toBeUndefined();
    expect(approved.approvalSource).toBe("manual");
    expect(automatic.approvalSource).toBe("grant");

    const raw = JSON.parse(await readFile(store.storePath, "utf8"));
    delete raw.requests.find((request: { id: string }) => request.id === automatic.id).approvalSource;
    await writeFile(store.storePath, `${JSON.stringify(raw, null, 2)}\n`);

    const reloaded = new SecretStore();
    await reloaded.revokeApprovalGrant(approved.approvalGrantId!);
    await expect(executeApprovedRequest(reloaded, automatic.id, { engine: "typescript" })).rejects.toThrow(/revoked or expired/i);
    expect((await reloaded.getRequest(automatic.id)).state).toBe("denied");

    const summary = await executeApprovedRequest(reloaded, manual.id, { engine: "typescript" });
    expect(summary.stdout).toBe("approved");
  });

  it("scopes login-session approval reuse to the current login session id", async () => {
    process.env.SGW_LOGIN_SESSION_ID = "login-session-a";
    const store = new SecretStore();
    await store.setApprovalSettings({ mode: "login-session" });
    const record = await store.addSecret({
      name: "login token",
      type: "api-token",
      value: "login-secret-value-123456789",
      policy: {
        injectEnv: "SGW_LOGIN_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_LOGIN_TOKEN)"],
      injectEnv: "SGW_LOGIN_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "login session first");
    await store.approveRequest(first.id);
    const sameLogin = await store.createRequest(record.handle, action, "same login");
    expect(sameLogin.state).toBe("approved");

    process.env.SGW_LOGIN_SESSION_ID = "login-session-b";
    const differentLogin = await store.createRequest(record.handle, action, "different login");
    expect(differentLogin.state).toBe("pending");
  });

  it("can reuse an approval for the same agent and duration from the approval choice", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "codex timed token",
      type: "api-token",
      value: "codex-timed-secret-value-123456789",
      policy: {
        injectEnv: "SGW_CODEX_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_CODEX_TOKEN)"],
      injectEnv: "SGW_CODEX_TOKEN"
    });

    const first = await store.createRequest(
      record.handle,
      action,
      "Agent requested local secret-backed execution.",
      { mcpClientName: "codex-mcp-client", env: {} }
    );
    expect(first.agentName).toBe("Codex");
    expect(first.agentSource).toBe("mcp-client");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    expect(approved.approvalGrantId).toMatch(/^grant_/);

    const sameAgent = await store.createRequest(
      record.handle,
      action,
      "Agent requested local secret-backed execution.",
      { mcpClientName: "Codex", env: {} }
    );
    expect(sameAgent.state).toBe("approved");
    expect(sameAgent.approvalGrantId).toBe(approved.approvalGrantId);

    const otherAgent = await store.createRequest(
      record.handle,
      action,
      "Agent requested local secret-backed execution.",
      { mcpClientName: "Claude Code", env: {} }
    );
    expect(otherAgent.state).toBe("pending");
  });

  it("runs policy-authorized one-shot commands without rewriting the ledger", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "one-shot policy token",
      type: "api-token",
      value: "one-shot-policy-secret-value-123456789",
      policy: {
        injectEnv: "SGW_ONE_SHOT_POLICY_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const rule = await store.addApprovalPolicyRule({
      name: "Allow one-shot policy execution",
      decision: "allow",
      conditions: {
        handles: [record.handle],
        agents: ["Codex"],
        commands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "process.stdout.write('ok')"],
      injectEnv: "SGW_ONE_SHOT_POLICY_TOKEN"
    });
    const before = await readFile(store.storePath, "utf8");
    const beforeMtime = (await stat(store.storePath)).mtimeMs;
    const headPath = path.join(await externalControlPlaneDir(), "head.json");
    const headBefore = await readFile(headPath, "utf8");
    const headBeforeMtime = (await stat(headPath)).mtimeMs;

    for (let index = 0; index < 12; index += 1) {
      const admission = await store.prepareOneShotExecution(record.handle, action, "Codex one-shot policy run");
      expect(admission.kind).toBe("reusable");
      if (admission.kind !== "reusable") throw new Error("Expected reusable one-shot admission.");
      const summary = await executeReusablePermit(store, admission.permit, { engine: "typescript" });
      expect(summary.stdout).toBe("ok");
    }

    expect(await readFile(store.storePath, "utf8")).toBe(before);
    expect((await stat(store.storePath)).mtimeMs).toBe(beforeMtime);
    expect(await readFile(headPath, "utf8")).toBe(headBefore);
    expect((await stat(headPath)).mtimeMs).toBe(headBeforeMtime);
    await store.setApprovalPolicyRuleEnabled(rule.id, false);

    const invalidated = await store.prepareOneShotExecution(record.handle, action, "Codex one-shot policy run");
    expect(invalidated.kind).toBe("request");
  }, 15_000);

  it("rejects a serialized reusable execution permit", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "opaque one-shot permit token",
      type: "api-token",
      value: "opaque-one-shot-permit-secret-value-123456789",
      policy: {
        injectEnv: "SGW_OPAQUE_ONE_SHOT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    await store.addApprovalPolicyRule({
      name: "Allow opaque permit execution",
      decision: "allow",
      conditions: { handles: [record.handle], commands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "process.stdout.write('opaque')"],
      injectEnv: "SGW_OPAQUE_ONE_SHOT_TOKEN"
    });
    const admission = await store.prepareOneShotExecution(record.handle, action, "Codex opaque permit run");
    expect(admission.kind).toBe("reusable");
    if (admission.kind !== "reusable") throw new Error("Expected reusable one-shot admission.");

    const copiedPermit = JSON.parse(JSON.stringify(admission.permit));
    await expect(executeReusablePermit(store, copiedPermit)).rejects.toThrow(/invalid s-gw reusable execution permit/i);

    const summary = await executeReusablePermit(store, admission.permit, { engine: "typescript" });
    expect(summary.stdout).toBe("opaque");
  });

  it("revalidates a reusable permit after delayed secret materialization", async () => {
    const enteredPath = path.join(tmpHome, "op-read-entered");
    const releasePath = path.join(tmpHome, "op-read-release");
    process.env.SGW_OP_CLI = await writeGatedFakeOp(
      "gated-one-shot-secret-value-123456789",
      enteredPath,
      releasePath
    );

    const store = new SecretStore();
    const record = await store.addOnePasswordReference({
      name: "gated one-shot permit token",
      type: "api-token",
      reference: onePasswordFixtureRef(),
      policy: {
        injectEnv: "SGW_GATED_ONE_SHOT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const rule = await store.addApprovalPolicyRule({
      name: "Allow gated one-shot permit execution",
      decision: "allow",
      conditions: { handles: [record.handle], commands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "process.stdout.write('must-not-run')"],
      injectEnv: "SGW_GATED_ONE_SHOT_TOKEN"
    });
    const admission = await store.prepareOneShotExecution(record.handle, action, "Codex gated permit run");
    expect(admission.kind).toBe("reusable");
    if (admission.kind !== "reusable") throw new Error("Expected reusable one-shot admission.");

    const execution = executeReusablePermit(store, admission.permit, { engine: "typescript" });
    try {
      await waitForFile(enteredPath);
      await store.setApprovalPolicyRuleEnabled(rule.id, false);
    } finally {
      await writeFile(releasePath, "release\n");
    }

    await expect(execution).rejects.toThrow(/authorization changed|approval policy changed/i);
  });

  it("caches policy-authorized 1Password one-shot execution after the first run", async () => {
    const counterPath = path.join(tmpHome, "op-policy-read-count.txt");
    process.env.SGW_OP_CLI = await writeCountingFakeOp("op-policy-cache-secret-value-1234567890", counterPath);

    const store = new SecretStore();
    const record = await store.addOnePasswordReference({
      name: "1password policy-cached token",
      type: "api-token",
      reference: onePasswordFixtureRef(),
      policy: {
        injectEnv: "SGW_OP_POLICY_CACHED_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const rule = await store.addApprovalPolicyRule({
      name: "Allow policy-cached 1Password execution",
      decision: "allow",
      conditions: { handles: [record.handle], commands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_OP_POLICY_CACHED_TOKEN)"],
      injectEnv: "SGW_OP_POLICY_CACHED_TOKEN"
    });

    const first = await store.prepareOneShotExecution(record.handle, action, "Codex policy-cached one-shot run");
    expect(first.kind).toBe("reusable");
    if (first.kind !== "reusable") throw new Error("Expected reusable one-shot admission.");
    const firstSummary = await executeReusablePermit(store, first.permit, { engine: "typescript" });
    expect(firstSummary.stdout).toContain(tokenForHandle(record.handle));
    const afterFirst = await readFile(store.storePath, "utf8");

    const second = await store.prepareOneShotExecution(record.handle, action, "Codex policy-cached one-shot run");
    expect(second.kind).toBe("reusable");
    if (second.kind !== "reusable") throw new Error("Expected reusable one-shot admission.");
    const secondSummary = await executeReusablePermit(store, second.permit, { engine: "typescript" });
    expect(secondSummary.stdout).toContain(tokenForHandle(record.handle));

    expect(await readCount(counterPath)).toBe(1);
    expect(await readFile(store.storePath, "utf8")).toBe(afterFirst);
    expect(JSON.parse(afterFirst).secrets[0].cache.approvalPolicyRuleId).toBe(rule.id);

    await store.setApprovalPolicyRuleEnabled(rule.id, false);
    expect(JSON.parse(await readFile(store.storePath, "utf8")).secrets[0].cache).toBeUndefined();
  });

  it("runs grant-authorized one-shot commands without changing grant usage metadata", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "one-shot grant token",
      type: "api-token",
      value: "one-shot-grant-secret-value-123456789",
      policy: {
        injectEnv: "SGW_ONE_SHOT_GRANT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "process.stdout.write('grant')"],
      injectEnv: "SGW_ONE_SHOT_GRANT_TOKEN"
    });
    const context = { agentName: "Codex", env: {} };
    const first = await store.createRequest(record.handle, action, "Codex one-shot grant run", context);
    await store.approveRequest(first.id, { mode: "timed-session", durationMs: 60 * 60 * 1000 });
    const before = await readFile(store.storePath, "utf8");

    for (let index = 0; index < 12; index += 1) {
      const admission = await store.prepareOneShotExecution(record.handle, action, "Codex one-shot grant run", context);
      expect(admission.kind).toBe("reusable");
      if (admission.kind !== "reusable") throw new Error("Expected reusable one-shot admission.");
      const summary = await executeReusablePermit(store, admission.permit, { engine: "typescript" });
      expect(summary.stdout).toBe("grant");
    }

    expect(await readFile(store.storePath, "utf8")).toBe(before);
    const admission = await store.prepareOneShotExecution(record.handle, action, "Codex one-shot grant run", context);
    if (admission.kind !== "reusable") throw new Error("Expected reusable one-shot admission.");
    await store.clearApprovalGrants();
    await expect(executeReusablePermit(store, admission.permit)).rejects.toThrow(/authorization changed|grant is no longer valid/i);
  });

  it("coalesces repeated unapproved one-shot commands into one pending request", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "one-shot pending token",
      type: "api-token",
      value: "one-shot-pending-secret-value-123456789",
      policy: {
        injectEnv: "SGW_ONE_SHOT_PENDING_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "0"],
      injectEnv: "SGW_ONE_SHOT_PENDING_TOKEN"
    });
    const admissions = await Promise.all(Array.from({ length: 16 }, () => {
      return new SecretStore().prepareOneShotExecution(record.handle, action, "Codex repeated pending run");
    }));
    const ids = new Set<string>();

    for (const admission of admissions) {
      expect(admission.kind).toBe("request");
      if (admission.kind !== "request") throw new Error("Expected a pending approval request.");
      ids.add(admission.request.id);
    }

    expect(ids.size).toBe(1);
    expect((await store.listRequests("pending")).filter((request) => request.handle === record.handle)).toHaveLength(1);
  }, 15_000);

  it("coalesces repeated policy denials into one durable record", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "one-shot denied token",
      type: "api-token",
      value: "one-shot-denied-secret-value-123456789",
      policy: {
        injectEnv: "SGW_ONE_SHOT_DENIED_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    await store.addApprovalPolicyRule({
      name: "Deny repeated one-shot execution",
      decision: "deny",
      conditions: { handles: [record.handle], commands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "0"],
      injectEnv: "SGW_ONE_SHOT_DENIED_TOKEN"
    });
    const admissions = await Promise.all(Array.from({ length: 16 }, () => {
      return new SecretStore().prepareOneShotExecution(record.handle, action, "Codex repeated denied run");
    }));
    const ids = new Set<string>();

    for (const admission of admissions) {
      expect(admission.kind).toBe("request");
      if (admission.kind !== "request") throw new Error("Expected a denied request.");
      expect(admission.request.state).toBe("denied");
      ids.add(admission.request.id);
    }

    expect(ids.size).toBe(1);
    expect((await store.listRequests("denied")).filter((request) => request.handle === record.handle)).toHaveLength(1);
  }, 15_000);

  it("requires one matching allow policy for every injected secret", async () => {
    const store = new SecretStore();
    const primary = await store.addSecret({
      name: "multi-handle primary token",
      type: "api-token",
      value: "multi-handle-primary-secret-value-123456789",
      policy: {
        injectEnv: "SGW_MULTI_PRIMARY_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const extra = await store.addSecret({
      name: "multi-handle extra token",
      type: "api-token",
      value: "multi-handle-extra-secret-value-123456789",
      policy: {
        injectEnv: "SGW_MULTI_EXTRA_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "0"],
      injectEnv: "SGW_MULTI_PRIMARY_TOKEN",
      env: [{ handle: extra.handle, injectEnv: "SGW_MULTI_EXTRA_TOKEN" }]
    });
    await store.addApprovalPolicyRule({
      name: "Allow only the primary secret",
      priority: 200,
      decision: "allow",
      conditions: { handles: [primary.handle], commands: [process.execPath] }
    });

    const incomplete = await store.prepareOneShotExecution(primary.handle, action, "Codex multi-handle policy run");
    expect(incomplete.kind).toBe("request");
    if (incomplete.kind !== "request") throw new Error("Expected a pending approval request.");
    expect(incomplete.request.state).toBe("pending");

    await store.addApprovalPolicyRule({
      name: "Allow both injected secrets",
      priority: 100,
      decision: "allow",
      conditions: { handles: [primary.handle, extra.handle], commands: [process.execPath] }
    });
    const complete = await store.prepareOneShotExecution(primary.handle, action, "Codex multi-handle policy run");
    expect(complete.kind).toBe("reusable");
  });

  it("matches each injected secret against its own policy environment binding", async () => {
    const store = new SecretStore();
    const primary = await store.addSecret({
      name: "binding scoped primary token",
      type: "api-token",
      value: "binding-scoped-primary-secret-value-123456789",
      policy: {
        injectEnv: "SGW_BINDING_SCOPED_PRIMARY",
        allowedCommands: [process.execPath]
      }
    });
    const extra = await store.addSecret({
      name: "binding scoped extra token",
      type: "api-token",
      value: "binding-scoped-extra-secret-value-123456789",
      policy: {
        injectEnv: "SGW_BINDING_SCOPED_EXTRA",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "0"],
      injectEnv: "SGW_BINDING_SCOPED_PRIMARY",
      env: [{ handle: extra.handle, injectEnv: "SGW_BINDING_SCOPED_EXTRA" }]
    });
    await store.addApprovalPolicyRule({
      name: "Allow only the primary environment binding",
      decision: "allow",
      conditions: {
        handles: [primary.handle, extra.handle],
        commands: [process.execPath],
        injectEnvs: ["SGW_BINDING_SCOPED_PRIMARY"]
      }
    });

    const admission = await store.prepareOneShotExecution(primary.handle, action, "Codex binding scoped policy run");
    expect(admission.kind).toBe("request");
    if (admission.kind !== "request") throw new Error("Expected a durable approval request.");
    expect(admission.request.state).toBe("pending");
  });

  it("lets a deny policy for an injected secret override a reusable grant", async () => {
    const store = new SecretStore();
    const primary = await store.addSecret({
      name: "grant primary token",
      type: "api-token",
      value: "grant-primary-secret-value-123456789",
      policy: {
        injectEnv: "SGW_GRANT_PRIMARY_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const extra = await store.addSecret({
      name: "grant extra token",
      type: "api-token",
      value: "grant-extra-secret-value-123456789",
      policy: {
        injectEnv: "SGW_GRANT_EXTRA_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "0"],
      injectEnv: "SGW_GRANT_PRIMARY_TOKEN",
      env: [{ handle: extra.handle, injectEnv: "SGW_GRANT_EXTRA_TOKEN" }]
    });
    const context = { agentName: "Codex", env: {} };
    const request = await store.createRequest(primary.handle, action, "Codex multi-handle grant run", context);
    await store.approveRequest(request.id, { mode: "timed-session", durationMs: 60 * 60 * 1000 });
    await store.addApprovalPolicyRule({
      name: "Deny the extra injected secret",
      decision: "deny",
      conditions: { handles: [extra.handle], commands: [process.execPath] }
    });

    const admission = await store.prepareOneShotExecution(primary.handle, action, "Codex multi-handle grant run", context);
    expect(admission.kind).toBe("request");
    if (admission.kind !== "request") throw new Error("Expected a denied request.");
    expect(admission.request.state).toBe("denied");
  });

  it("auto-approves a matching request from an approval policy rule", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "policy codex token",
      type: "api-token",
      value: "policy-codex-secret-value-123456789",
      provider: "github",
      policy: {
        injectEnv: "SGW_POLICY_CODEX_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    await store.addApprovalPolicyRule({
      name: "Codex may use this GitHub token",
      decision: "allow",
      conditions: {
        handles: [record.handle],
        agents: ["Codex"],
        providers: ["github"],
        commands: [process.execPath],
        injectEnvs: ["SGW_POLICY_CODEX_TOKEN"]
      }
    });

    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_POLICY_CODEX_TOKEN)"],
      injectEnv: "SGW_POLICY_CODEX_TOKEN"
    });
    const request = await store.createRequest(record.handle, action, "Codex policy run");
    expect(request.state).toBe("approved");
    expect(request.approvalPolicyRuleId).toMatch(/^policy_/);
    expect(request.approvalGrantId).toBeUndefined();

    const result = await executeApprovedRequest(store, request.id);
    expect(result.stdout).toContain(`<<SGW_SECRET:${record.handle}>>`);
    expect(result.stdout).not.toContain("policy-codex-secret-value");
  });

  it("blocks an auto-approved request after its policy is disabled", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "revoked policy request token",
      type: "api-token",
      value: "revoked-policy-request-secret-value-123456789",
      policy: {
        injectEnv: "SGW_REVOKED_POLICY_REQUEST",
        allowedCommands: [process.execPath]
      }
    });
    const rule = await store.addApprovalPolicyRule({
      name: "Allow revocable policy request",
      decision: "allow",
      conditions: { handles: [record.handle], commands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "process.stdout.write('must-not-run')"],
      injectEnv: "SGW_REVOKED_POLICY_REQUEST"
    });
    const automatic = await store.createRequest(record.handle, action, "Codex revocable policy request");
    expect(automatic.approvalSource).toBe("policy");

    await store.setApprovalPolicyRuleEnabled(rule.id, false);
    await expect(executeApprovedRequest(store, automatic.id, { engine: "typescript" })).rejects.toThrow(/policy.*changed|no longer allows/i);
    expect((await store.getRequest(automatic.id)).state).toBe("denied");
  });

  it("lets a higher-priority ask policy override a broader allow policy", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "policy ask token",
      type: "api-token",
      value: "policy-ask-secret-value-123456789",
      policy: {
        injectEnv: "SGW_POLICY_ASK_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    await store.addApprovalPolicyRule({
      name: "Allow Codex broadly",
      decision: "allow",
      priority: 200,
      conditions: { agents: ["Codex"], commands: [process.execPath] }
    });
    await store.addApprovalPolicyRule({
      name: "Ask for this handle",
      decision: "ask",
      priority: 50,
      conditions: { handles: [record.handle] }
    });

    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_POLICY_ASK_TOKEN)"],
      injectEnv: "SGW_POLICY_ASK_TOKEN"
    });
    const request = await store.createRequest(record.handle, action, "Codex should be asked");
    expect(request.state).toBe("pending");
    expect(request.approvalPolicyRuleId).toMatch(/^policy_/);
  });

  it("denies a matching policy even when an approval grant exists", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "policy deny token",
      type: "api-token",
      value: "policy-deny-secret-value-123456789",
      severity: "critical",
      policy: {
        injectEnv: "SGW_POLICY_DENY_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_POLICY_DENY_TOKEN)"],
      injectEnv: "SGW_POLICY_DENY_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex first approval");
    await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    await store.addApprovalPolicyRule({
      name: "Block critical token",
      decision: "deny",
      priority: 10,
      conditions: {
        minSeverity: "critical",
        agents: ["Codex"]
      }
    });

    const denied = await store.createRequest(record.handle, action, "Codex after deny policy");
    expect(denied.state).toBe("denied");
    expect(denied.error).toContain("Denied by approval policy");
  });

  it("reuses a timed approval when the same agent changes command arguments", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "codex wrapper credential",
      type: "password",
      value: "codex-wrapper-secret-value-123456789",
      policy: {
        injectEnv: "SGW_WRAPPER_PASSWORD",
        allowedCommands: [process.execPath]
      }
    });
    const firstAction = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log('first', process.env.SGW_WRAPPER_PASSWORD)"],
      injectEnv: "SGW_WRAPPER_PASSWORD"
    });
    const secondAction = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log('second', process.env.SGW_WRAPPER_PASSWORD)"],
      injectEnv: "SGW_WRAPPER_PASSWORD"
    });

    const first = await store.createRequest(record.handle, firstAction, "Codex wrapper first run");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });

    const next = await store.createRequest(record.handle, secondAction, "Codex wrapper follow-up");
    expect(next.state).toBe("approved");
    expect(next.approvalGrantId).toBe(approved.approvalGrantId);
  });

  it("migrates old approval grants that were keyed to command arguments", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "legacy wrapper credential",
      type: "password",
      value: "legacy-wrapper-secret-value-123456789",
      policy: {
        injectEnv: "SGW_LEGACY_WRAPPER_PASSWORD",
        allowedCommands: [process.execPath]
      }
    });
    const firstAction = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log('legacy first', process.env.SGW_LEGACY_WRAPPER_PASSWORD)"],
      injectEnv: "SGW_LEGACY_WRAPPER_PASSWORD"
    });
    const secondAction = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log('legacy second', process.env.SGW_LEGACY_WRAPPER_PASSWORD)"],
      injectEnv: "SGW_LEGACY_WRAPPER_PASSWORD"
    });

    const first = await store.createRequest(record.handle, firstAction, "Codex legacy wrapper first run");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    const legacyKey = legacyApprovalActionKey(record.handle, firstAction);

    const raw = JSON.parse(await readFile(store.storePath, "utf8"));
    raw.approvalGrants[0].actionKey = legacyKey;
    await writeFile(store.storePath, `${JSON.stringify(raw, null, 2)}\n`);

    const direct = await store.prepareOneShotExecution(record.handle, secondAction, "Codex legacy wrapper follow-up");
    expect(direct.kind).toBe("reusable");

    const next = await store.createRequest(record.handle, secondAction, "Codex legacy wrapper follow-up");
    expect(next.state).toBe("approved");
    expect(next.approvalGrantId).toBe(approved.approvalGrantId);

    const grants = await store.listApprovalGrants();
    expect(grants).toHaveLength(1);
    expect(grants[0].actionKey).not.toBe(legacyKey);
  });

  it("can reuse an approval across agents when explicitly scoped that way", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "any-agent token",
      type: "api-token",
      value: "any-agent-secret-value-123456789",
      policy: {
        injectEnv: "SGW_ANY_AGENT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_ANY_AGENT_TOKEN)"],
      injectEnv: "SGW_ANY_AGENT_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex initial approval");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000,
      agentScope: "any-agent"
    });

    const claude = await store.createRequest(record.handle, action, "Claude follow-up approval");
    expect(claude.state).toBe("approved");
    expect(claude.approvalGrantId).toBe(approved.approvalGrantId);
  });

  it("revokes reusable approval grants before the next matching request", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "revoke grant token",
      type: "api-token",
      value: "revoke-grant-secret-value-123456789",
      policy: {
        injectEnv: "SGW_REVOKE_GRANT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_REVOKE_GRANT_TOKEN)"],
      injectEnv: "SGW_REVOKE_GRANT_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex grant first");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    expect(approved.approvalGrantId).toMatch(/^grant_/);

    const grants = await store.listApprovalGrants();
    expect(grants.map((grant) => grant.id)).toEqual([approved.approvalGrantId]);

    const revoked = await store.revokeApprovalGrant(approved.approvalGrantId!);
    expect(revoked.id).toBe(approved.approvalGrantId);
    expect(await store.listApprovalGrants()).toHaveLength(0);

    const next = await store.createRequest(record.handle, action, "Codex grant after revoke");
    expect(next.state).toBe("pending");
  });

  it("clears every reusable approval grant", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "clear grants token",
      type: "api-token",
      value: "clear-grants-secret-value-123456789",
      policy: {
        injectEnv: "SGW_CLEAR_GRANTS_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_CLEAR_GRANTS_TOKEN)"],
      injectEnv: "SGW_CLEAR_GRANTS_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex clear grants");
    await store.approveRequest(first.id, { mode: "timed-session", agentScope: "same-agent" });

    const cleared = await store.clearApprovalGrants();
    expect(cleared.revokedCount).toBe(1);
    expect(await store.listApprovalGrants()).toHaveLength(0);
  });

  it("deletes a handle, revokes reusable grants, and fails unfinished requests", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "delete token",
      type: "api-token",
      value: "delete-secret-value-123456789",
      policy: {
        injectEnv: "SGW_DELETE_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_DELETE_TOKEN)"],
      injectEnv: "SGW_DELETE_TOKEN"
    });

    const approved = await store.createRequest(record.handle, action, "Codex approved before delete");
    await store.approveRequest(approved.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    const pending = await store.createRequest(record.handle, action, "Claude pending before delete");
    await store.addApprovalPolicyRule({
      name: "Delete scoped policy",
      decision: "allow",
      conditions: { handles: [record.handle], agents: ["Codex"] }
    });

    const deleted = await store.deleteSecret(record.handle);
    expect(deleted.handle).toBe(record.handle);
    expect(deleted.revokedApprovalGrants).toBe(1);
    expect(deleted.revokedApprovalPolicies).toBe(1);
    expect(deleted.failedRequests.map((request) => request.id).sort()).toEqual([approved.id, pending.id].sort());
    expect(await store.listApprovalPolicyRules()).toHaveLength(0);

    await expect(store.getSecretRecord(record.handle)).rejects.toThrow(/unknown secret handle/i);
    await expect(store.createRequest(record.handle, action, "Codex after delete")).rejects.toThrow(/unknown secret handle/i);
    await expect(executeApprovedRequest(store, approved.id)).rejects.toThrow(/failed/);

    const audit = await store.auditLog();
    expect(audit.some((event) => event.type === "secret.deleted" && event.handle === record.handle)).toBe(true);
  });

  it("can create an unlimited approval that survives login-session changes", async () => {
    process.env.SGW_LOGIN_SESSION_ID = "login-session-a";
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "unlimited token",
      type: "api-token",
      value: "unlimited-secret-value-123456789",
      policy: {
        injectEnv: "SGW_UNLIMITED_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_UNLIMITED_TOKEN)"],
      injectEnv: "SGW_UNLIMITED_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex persistent approval");
    const approved = await store.approveRequest(first.id, {
      mode: "always",
      agentScope: "same-agent"
    });

    process.env.SGW_LOGIN_SESSION_ID = "login-session-b";
    const afterLoginChange = await store.createRequest(record.handle, action, "Codex after login switch");
    expect(afterLoginChange.state).toBe("approved");
    expect(afterLoginChange.approvalGrantId).toBe(approved.approvalGrantId);
  });

  it("resolves 1Password-backed handles only during approved local execution", async () => {
    const fakeOp = await writeFakeOp("op-e2e-secret-value-1234567890");
    process.env.SGW_OP_CLI = fakeOp;

    const store = new SecretStore();
    const reference = onePasswordFixtureRef();
    const record = await store.addOnePasswordReference({
      name: "1password e2e token",
      type: "api-token",
      reference,
      policy: {
        injectEnv: "SGW_OP_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const storeText = await readFile(store.storePath, "utf8");
    expect(storeText).not.toContain(reference);
    expect(storeText).not.toContain("op-e2e-secret-value");

    const handles = await store.listHandles();
    expect(handles[0].backend).toBe("onepassword");
    expect(handles[0].provider).toBe("1password");
    expect(handles[0].source).toBe("onepassword");

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "console.log(process.env.SGW_OP_TOKEN)"],
        injectEnv: "SGW_OP_TOKEN"
      }),
      "1Password unit test"
    );

    await store.approveRequest(request.id);
    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).not.toContain("op-e2e-secret-value");
    expect(summary.stdout).toContain(tokenForHandle(record.handle));
    expect(summary.sanitized).toBe(true);

    const afterExecute = JSON.parse(await readFile(store.storePath, "utf8"));
    expect(afterExecute.secrets[0].cache).toBeUndefined();
  });

  it("caches 1Password reads in the encrypted store for a reusable approval TTL", async () => {
    const counterPath = path.join(tmpHome, "op-read-count.txt");
    process.env.SGW_OP_CLI = await writeCountingFakeOp("op-cached-secret-value-1234567890", counterPath);

    const store = new SecretStore();
    const reference = onePasswordFixtureRef();
    const record = await store.addOnePasswordReference({
      name: "1password cached token",
      type: "api-token",
      reference,
      policy: {
        injectEnv: "SGW_OP_CACHED_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_OP_CACHED_TOKEN)"],
      injectEnv: "SGW_OP_CACHED_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex cached 1Password first run");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    const firstSummary = await executeApprovedRequest(store, first.id);
    expect(firstSummary.stdout).toContain(tokenForHandle(record.handle));

    const second = await store.createRequest(record.handle, action, "Codex cached 1Password second run");
    expect(second.state).toBe("approved");
    expect(second.approvalGrantId).toBe(approved.approvalGrantId);
    const secondSummary = await executeApprovedRequest(store, second.id);
    expect(secondSummary.stdout).toContain(tokenForHandle(record.handle));

    expect(await readCount(counterPath)).toBe(1);
    const storeText = await readFile(store.storePath, "utf8");
    expect(storeText).not.toContain(reference);
    expect(storeText).not.toContain("op-cached-secret-value");

    const raw = JSON.parse(storeText);
    expect(raw.secrets[0].cache.approvalGrantId).toBe(approved.approvalGrantId);
    expect(raw.secrets[0].cache.expiresAt).toBeTruthy();
  });

  it("drops cached 1Password values when the reusable approval is revoked", async () => {
    const counterPath = path.join(tmpHome, "op-revoke-count.txt");
    process.env.SGW_OP_CLI = await writeCountingFakeOp("op-revoked-cache-secret-1234567890", counterPath);

    const store = new SecretStore();
    const record = await store.addOnePasswordReference({
      name: "1password revoked cache token",
      type: "api-token",
      reference: onePasswordFixtureRef(),
      policy: {
        injectEnv: "SGW_OP_REVOKE_CACHE",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_OP_REVOKE_CACHE)"],
      injectEnv: "SGW_OP_REVOKE_CACHE"
    });

    const first = await store.createRequest(record.handle, action, "Codex cached revoke first run");
    const approved = await store.approveRequest(first.id, { mode: "timed-session", agentScope: "same-agent" });
    await executeApprovedRequest(store, first.id);

    let raw = JSON.parse(await readFile(store.storePath, "utf8"));
    expect(raw.secrets[0].cache.approvalGrantId).toBe(approved.approvalGrantId);

    await store.revokeApprovalGrant(approved.approvalGrantId!);
    raw = JSON.parse(await readFile(store.storePath, "utf8"));
    expect(raw.secrets[0].cache).toBeUndefined();

    const next = await store.createRequest(record.handle, action, "Codex cached revoke after revoke");
    expect(next.state).toBe("pending");
  });

  it("rejects commands outside the handle policy", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "restricted",
      type: "api-token",
      value: "another-secret-value-123456789",
      policy: {
        injectEnv: "TOKEN",
        allowedCommands: ["ssh"]
      }
    });

    await expect(
      store.createRequest(
        record.handle,
        buildEnvCommandAction({
          command: process.execPath,
          args: ["-v"],
          injectEnv: "TOKEN"
        }),
        "wrong command"
      )
    ).rejects.toThrow(/not allowed/i);
  });

  it("does not treat an absolute command as allowed by a bare basename grant", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "basename restricted",
      type: "api-token",
      value: "basename-secret-value-123456789",
      policy: {
        injectEnv: "TOKEN",
        allowedCommands: ["node"]
      }
    });

    await expect(
      store.createRequest(
        record.handle,
        buildEnvCommandAction({
          command: process.execPath,
          args: ["-v"],
          injectEnv: "TOKEN"
        }),
        "absolute request"
      )
    ).rejects.toThrow(/not allowed/i);
  });
});

async function backdateRequest(requestId: string, agoMs: number, fields = ["updatedAt"]): Promise<void> {
  const storePath = path.join(tmpHome, "store.json");
  const store = JSON.parse(await readFile(storePath, "utf8"));
  const request = store.requests.find((item: { id: string }) => item.id === requestId);
  const value = new Date(Date.now() - agoMs).toISOString();
  for (const field of fields) {
    request[field] = value;
  }
  await writeFile(storePath, `${JSON.stringify(store, null, 2)}\n`);
}

function legacyApprovalActionKey(handle: string, action: ReturnType<typeof buildEnvCommandAction>): string {
  const command = path.isAbsolute(action.command) ? path.normalize(action.command) : action.command.trim();
  const payload = {
    handle,
    kind: action.kind,
    command,
    args: action.args,
    injectEnv: action.injectEnv,
    workingDir: action.workingDir ? path.resolve(action.workingDir) : ""
  };

  return createHash("sha256").update(JSON.stringify(payload)).digest("base64url");
}

async function writeFakeOp(secret: string): Promise<string> {
  const fakeOp = path.join(tmpHome, "op");
  const reference = onePasswordFixtureRef();
  await writeFile(fakeOp, `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '2.34.0\\n'
  exit 0
fi
if [ "$1" = "read" ] && [ "$2" = "${reference}" ]; then
  printf '%s' '${secret}'
  exit 0
fi
printf 'unexpected op call: %s %s\\n' "$1" "$2" >&2
exit 2
`);
  await chmod(fakeOp, 0o755);
  return fakeOp;
}

async function writeCountingFakeOp(secret: string, counterPath: string): Promise<string> {
  const fakeOp = path.join(tmpHome, `op-counting-${path.basename(counterPath)}`);
  const reference = onePasswordFixtureRef();
  await writeFile(fakeOp, `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '2.34.0\\n'
  exit 0
fi
if [ "$1" = "read" ] && [ "$2" = "${reference}" ]; then
  count="$(cat '${counterPath}' 2>/dev/null || printf 0)"
  count="$((count + 1))"
  printf '%s' "$count" > '${counterPath}'
  printf '%s' '${secret}'
  exit 0
fi
printf 'unexpected op call: %s %s\\n' "$1" "$2" >&2
exit 2
`);
  await chmod(fakeOp, 0o755);
  return fakeOp;
}

async function writeGatedFakeOp(secret: string, enteredPath: string, releasePath: string): Promise<string> {
  const fakeOp = path.join(tmpHome, "op-gated");
  const reference = onePasswordFixtureRef();
  await writeFile(fakeOp, `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '2.34.0\\n'
  exit 0
fi
if [ "$1" = "read" ] && [ "$2" = "${reference}" ]; then
  : > '${enteredPath}'
  while [ ! -f '${releasePath}' ]; do
    sleep 0.01
  done
  printf '%s' '${secret}'
  exit 0
fi
printf 'unexpected op call: %s %s\\n' "$1" "$2" >&2
exit 2
`);
  await chmod(fakeOp, 0o755);
  return fakeOp;
}

async function waitForFile(file: string): Promise<void> {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (await stat(file).catch(() => undefined)) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for ${file}.`);
}

async function writeFakeKeychainHelper(dbPath: string): Promise<string> {
  const helper = path.join(tmpHome, "s-gw-keychain-helper");
  await writeFile(helper, `#!/usr/bin/env node
const fs = require("fs");
const dbPath = ${JSON.stringify(dbPath)};

function arg(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || index + 1 >= process.argv.length) {
    return "";
  }
  return process.argv[index + 1];
}

function readDb() {
  try {
    return JSON.parse(fs.readFileSync(dbPath, "utf8"));
  } catch {
    return {};
  }
}

function writeDb(db) {
  fs.writeFileSync(dbPath, JSON.stringify(db, null, 2) + "\\n");
}

const command = process.argv[2];
const service = arg("--service");
const account = arg("--account");
const key = service + "\\u0000" + account;

if (!service || !account) {
  process.stderr.write("missing service/account\\n");
  process.exit(64);
}

if (command === "get") {
  const db = readDb();
  if (!Object.prototype.hasOwnProperty.call(db, key)) {
    process.exit(44);
  }
  process.stdout.write(db[key] + "\\n");
  process.exit(0);
}

if (command === "set") {
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", chunk => input += chunk);
  process.stdin.on("end", () => {
    const db = readDb();
    db[key] = input;
    writeDb(db);
  });
  return;
}

if (command === "delete") {
  const db = readDb();
  delete db[key];
  writeDb(db);
  process.exit(0);
}

process.stderr.write("unexpected command\\n");
process.exit(2);
`);
  await chmod(helper, 0o755);
  return helper;
}

async function readCount(file: string): Promise<number> {
  const text = await readFile(file, "utf8").catch(() => "0");
  return Number.parseInt(text.trim() || "0", 10);
}
