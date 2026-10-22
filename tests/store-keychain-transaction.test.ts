import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { SecretStore } from "../src/store.js";

const worker = path.join(process.cwd(), "tests", "fixtures", "keychain-lock-worker.ts");
const tsx = path.join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs");

function startWorker(operation: string, env: NodeJS.ProcessEnv) {
  const child = spawn(process.execPath, [tsx, worker, operation], {
    cwd: process.cwd(), env, stdio: ["ignore", "ignore", "pipe"]
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => { stderr += chunk; });
  const done = new Promise<{ code: number | null; stderr: string }>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stderr }));
  });
  return { child, done };
}

function childEnv(root: string): NodeJS.ProcessEnv {
  return {
    PATH: `${path.dirname(process.execPath)}:/usr/bin:/bin`,
    HOME: root,
    TMPDIR: root
  };
}

async function waitForFile(filePath: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (!existsSync(filePath)) {
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${filePath}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function withDeadline<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => { timer = setTimeout(() => reject(new Error("Worker timed out")), ms); })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function fakeKeychainHelper(helper: string): Promise<void> {
  await writeFile(helper, `#!/usr/bin/env node
const fs = require("node:fs");
const args = process.argv.slice(2);
const command = args[0];
const account = args[args.indexOf("--account") + 1];
const service = args[args.indexOf("--service") + 1];
const key = service + "\\u0000" + account;
const dbPath = process.env.SGW_TEST_KEYCHAIN_DB;
const db = fs.existsSync(dbPath) ? JSON.parse(fs.readFileSync(dbPath, "utf8")) : {};
if (command === "set") {
  if (process.env.SGW_TEST_BLOCK_SET === "1") {
    fs.writeFileSync(process.env.SGW_TEST_WAITING, String(process.pid));
    const pause = new Int32Array(new SharedArrayBuffer(4));
    while (!fs.existsSync(process.env.SGW_TEST_RELEASE)) Atomics.wait(pause, 0, 0, 20);
  }
  db[key] = fs.readFileSync(0, "utf8");
  fs.writeFileSync(dbPath, JSON.stringify(db), { mode: 0o600 });
  process.exit(0);
}
if (command === "get") {
  if (!(key in db)) process.exit(44);
  process.stdout.write((process.env.SGW_TEST_WRONG_READ === "1" ? "synthetic wrong value" : db[key]) + "\\n");
  process.exit(0);
}
process.exit(44);
`, { mode: 0o700 });
  await chmod(helper, 0o700);
}

describe.skipIf(process.platform !== "darwin").sequential("staged credential-store add", () => {
  it("lets an unrelated writer commit while the provider is blocked, then publishes only after readback", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "sgw-staged-keychain-"));
    const home = path.join(root, "home");
    const helper = path.join(root, "keychain-helper");
    const waiting = path.join(root, "waiting");
    const release = path.join(root, "release");
    await fakeKeychainHelper(helper);
    const env = {
      ...childEnv(root),
      SGW_HOME: home,
      SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_TEST_MODE: "1",
      SGW_TEST_HOME_ROOT: root,
      SGW_KEYCHAIN_HELPER: helper,
      SGW_TEST_KEYCHAIN_DB: path.join(root, "provider.json"),
      SGW_MASTER_PASSPHRASE: "synthetic master passphrase",
      SGW_DISABLE_KEYCHAIN: "1",
      SGW_DISABLE_ONEPASSWORD_BACKUP: "1",
      SGW_TEST_BLOCK_SET: "1",
      SGW_TEST_WAITING: waiting,
      SGW_TEST_RELEASE: release
    };
    let adding: ReturnType<typeof startWorker> | undefined;
    let concurrent: ReturnType<typeof startWorker> | undefined;
    try {
      adding = startWorker("add-keychain-staged", env);
      await waitForFile(waiting);
      const pending = JSON.parse(await readFile(path.join(home, "store.json"), "utf8"));
      expect(pending.secrets).toHaveLength(0);
      expect(pending.credentialOps).toHaveLength(1);
      expect(JSON.stringify(pending)).not.toContain("synthetic-staged-value-123456789");

      concurrent = startWorker("add-policy", { ...env, SGW_TEST_BLOCK_SET: "0", SGW_TEST_LOCK_TIMEOUT_MS: "300" });
      const policy = await withDeadline(concurrent.done, 10_000);
      expect(policy, policy.stderr).toMatchObject({ code: 0 });

      await writeFile(release, "");
      const result = await withDeadline(adding.done, 10_000);
      expect(result, result.stderr).toMatchObject({ code: 0 });
      const committed = JSON.parse(await readFile(path.join(home, "store.json"), "utf8"));
      expect(committed.secrets).toHaveLength(1);
      expect(committed.credentialOps).toHaveLength(0);
      expect(committed.approvalPolicyRules).toHaveLength(1);
      expect(JSON.stringify(committed)).not.toContain("synthetic-staged-value-123456789");
    } finally {
      await writeFile(release, "").catch(() => undefined);
      if (adding?.child.exitCode === null) adding.child.kill();
      if (concurrent?.child.exitCode === null) concurrent.child.kill();
      await adding?.done.catch(() => undefined);
      await concurrent?.done.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);

  it("resumes the prepared operation after the writer dies before the provider call completes", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "sgw-staged-crash-"));
    const home = path.join(root, "home");
    const helper = path.join(root, "keychain-helper");
    const waiting = path.join(root, "waiting");
    const release = path.join(root, "release");
    await fakeKeychainHelper(helper);
    const env = {
      ...childEnv(root),
      SGW_HOME: home,
      SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_TEST_MODE: "1",
      SGW_TEST_HOME_ROOT: root,
      SGW_KEYCHAIN_HELPER: helper,
      SGW_TEST_KEYCHAIN_DB: path.join(root, "provider.json"),
      SGW_MASTER_PASSPHRASE: "synthetic master passphrase",
      SGW_DISABLE_KEYCHAIN: "1",
      SGW_DISABLE_ONEPASSWORD_BACKUP: "1",
      SGW_TEST_BLOCK_SET: "1",
      SGW_TEST_WAITING: waiting,
      SGW_TEST_RELEASE: release
    };
    let first: ReturnType<typeof startWorker> | undefined;
    let resumed: ReturnType<typeof startWorker> | undefined;
    try {
      first = startWorker("add-keychain-staged", env);
      await waitForFile(waiting);
      const before = JSON.parse(await readFile(path.join(home, "store.json"), "utf8"));
      const opId = before.credentialOps[0].id;
      process.kill(Number(await readFile(waiting, "utf8")), "SIGKILL");
      first.child.kill("SIGKILL");
      await withDeadline(first.done, 10_000);
      expect(before.secrets).toHaveLength(0);

      resumed = startWorker("add-keychain-staged", { ...env, SGW_TEST_BLOCK_SET: "0" });
      const result = await withDeadline(resumed.done, 10_000);
      expect(result, result.stderr).toMatchObject({ code: 0 });
      const after = JSON.parse(await readFile(path.join(home, "store.json"), "utf8"));
      expect(after.credentialOps).toHaveLength(0);
      expect(after.secrets).toHaveLength(1);
      const db = JSON.parse(await readFile(env.SGW_TEST_KEYCHAIN_DB, "utf8"));
      expect(Object.keys(db)).toEqual([expect.stringContaining(opId)]);
    } finally {
      await writeFile(release, "").catch(() => undefined);
      if (first?.child.exitCode === null) first.child.kill();
      if (resumed?.child.exitCode === null) resumed.child.kill();
      await first?.done.catch(() => undefined);
      await resumed?.done.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);

  it("keeps a failed readback pending across sealed recovery and retries the same staging account", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "sgw-staged-retry-"));
    const home = path.join(root, "home");
    const helper = path.join(root, "keychain-helper");
    await fakeKeychainHelper(helper);
    const names = [
      "SGW_HOME", "SGW_RECOVERY_HOME", "SGW_TEST_MODE", "SGW_KEYCHAIN_HELPER",
      "SGW_TEST_KEYCHAIN_DB", "SGW_MASTER_PASSPHRASE", "SGW_DISABLE_KEYCHAIN",
      "SGW_DISABLE_ONEPASSWORD_BACKUP", "SGW_TEST_WRONG_READ"
    ] as const;
    const old = Object.fromEntries(names.map((name) => [name, process.env[name]]));
    Object.assign(process.env, {
      SGW_HOME: home,
      SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_TEST_MODE: "1",
      SGW_KEYCHAIN_HELPER: helper,
      SGW_TEST_KEYCHAIN_DB: path.join(root, "provider.json"),
      SGW_MASTER_PASSPHRASE: "synthetic master passphrase",
      SGW_DISABLE_KEYCHAIN: "1",
      SGW_DISABLE_ONEPASSWORD_BACKUP: "1",
      SGW_TEST_WRONG_READ: "1"
    });
    const input = { name: "synthetic staged item", type: "api-token" as const, value: "synthetic-staged-value-123456789" };
    try {
      const store = new SecretStore(home);
      await expect(store.addKeychainSecretStaged(input)).rejects.toThrow(/is pending because its staged value was not verified/);
      const [pending] = await store.listPendingCredentialOperations();
      expect(pending).toMatchObject({ name: input.name });
      expect(await store.listHandles()).toHaveLength(0);
      await expect(store.addSecret(input)).rejects.toThrow(/is pending; retry it/);
      await expect(store.addKeychainSecretStaged({
        ...input, policy: { injectEnv: "DIFFERENT_TOKEN" }
      })).rejects.toThrow(/requires its original metadata and policy/);

      await rm(store.storePath);
      const recovered = new SecretStore(home);
      expect(await recovered.listPendingCredentialOperations()).toEqual([pending]);
      delete process.env.SGW_TEST_WRONG_READ;
      const record = await recovered.addKeychainSecretStaged(input);
      expect(record.handle).toBe(pending.handle);
      expect(await recovered.listPendingCredentialOperations()).toEqual([]);
      expect(await recovered.listHandles()).toEqual([expect.objectContaining({ handle: pending.handle })]);
      const db = JSON.parse(await readFile(process.env.SGW_TEST_KEYCHAIN_DB!, "utf8"));
      expect(Object.keys(db)).toHaveLength(1);
      expect(Object.keys(db)[0]).toContain(pending.id);
    } finally {
      for (const name of names) {
        if (old[name] === undefined) delete process.env[name];
        else process.env[name] = old[name];
      }
      await rm(root, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);
});
