import { spawn } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { SecretStore } from "../src/store.js";

const worker = path.join(process.cwd(), "tests", "fixtures", "keychain-lock-worker.ts");
const tsx = path.join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs");

function startWorker(operation: string, env: NodeJS.ProcessEnv) {
  const child = spawn(process.execPath, [tsx, worker, operation], {
    cwd: process.cwd(), env, stdio: ["ignore", "pipe", "pipe"]
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

async function waitForFile(filePath: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (!existsSync(filePath)) {
    if (Date.now() > deadline) throw new Error(`Timed out waiting for test helper at ${filePath}`);
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
}

async function withDeadline<T>(promise: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`Test worker exceeded ${ms} ms`)), ms);
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

async function writeFakeHelper(helper: string): Promise<void> {
  await writeFile(helper, `#!/usr/bin/env node
const fs = require("node:fs");
const command = process.argv[2];
let getCount = 0;
if (command === "get" && process.env.SGW_TEST_HELPER_GET_LOG) {
  const prior = fs.existsSync(process.env.SGW_TEST_HELPER_GET_LOG)
    ? fs.readFileSync(process.env.SGW_TEST_HELPER_GET_LOG, "utf8") : "";
  getCount = prior.split("\\n").filter(Boolean).length + 1;
  fs.appendFileSync(process.env.SGW_TEST_HELPER_GET_LOG, "get\\n");
}
if (command === process.env.SGW_TEST_HELPER_BLOCK_OP) {
  const waiting = process.env.SGW_TEST_HELPER_WAITING + (getCount ? "-" + getCount : "");
  const release = process.env.SGW_TEST_HELPER_RELEASE + (getCount ? "-" + getCount : "");
  fs.writeFileSync(waiting, "");
  const pause = new Int32Array(new SharedArrayBuffer(4));
  while (!fs.existsSync(release)) Atomics.wait(pause, 0, 0, 20);
}
if (command === "get") process.stdout.write("synthetic master passphrase\\n");
if (command !== "get" && command !== "set" && command !== "delete") process.exit(44);
`, { mode: 0o700 });
  await chmod(helper, 0o700);
}

describe.skipIf(process.platform !== "darwin")("Keychain unlock and store lock", () => {
  it.each(["add-secret", "add-keychain", "add-onepassword", "delete-keychain"])(
    "allows another store writer while %s waits for Keychain unlock",
    async (operation) => {
      const root = await mkdtemp(path.join(os.tmpdir(), "sgw-keychain-lock-"));
      const home = path.join(root, "store");
      const waiting = path.join(root, "helper-waiting");
      const release = path.join(root, "release-helper");
      const helper = path.join(root, "s-gw-keychain-helper");
      await writeFakeHelper(helper);

      const baseEnv = {
        ...process.env,
        SGW_HOME: home,
        SGW_RECOVERY_HOME: `${home}-recovery`,
        SGW_TEST_MODE: "1",
        SGW_KEYCHAIN_HELPER: helper,
        SGW_TEST_HELPER_BLOCK_OP: "get",
        SGW_TEST_HELPER_WAITING: waiting,
        SGW_TEST_HELPER_RELEASE: release,
        SGW_DISABLE_ONEPASSWORD_BACKUP: "1"
      };
      delete baseEnv.SGW_MASTER_PASSPHRASE;
      delete baseEnv.SGW_DISABLE_KEYCHAIN;
      let first: ReturnType<typeof startWorker> | undefined;
      let second: ReturnType<typeof startWorker> | undefined;
      try {
        if (operation === "delete-keychain") {
          const seeded = startWorker("add-keychain", {
            ...baseEnv,
            SGW_MASTER_PASSPHRASE: "synthetic master passphrase",
            SGW_TEST_HELPER_BLOCK_OP: "none"
          });
          const result = await withDeadline(seeded.done, 10_000);
          expect(result, result.stderr).toMatchObject({ code: 0 });
        }
        first = startWorker(operation, baseEnv);
        await waitForFile(waiting);
        expect(first.child.exitCode).toBeNull();

        const writerEnv = { ...baseEnv, SGW_MASTER_PASSPHRASE: "synthetic master passphrase", SGW_DISABLE_KEYCHAIN: "1", SGW_TEST_LOCK_TIMEOUT_MS: "300" };
        second = startWorker("add-policy", writerEnv);
        const concurrent = await withDeadline(second.done, 10_000);
        expect(concurrent, concurrent.stderr).toMatchObject({ code: 0 });

        await writeFile(release, "");
        const completed = await withDeadline(first.done, 10_000);
        expect(completed, completed.stderr).toMatchObject({ code: 0 });

        const previousRecoveryHome = process.env.SGW_RECOVERY_HOME;
        process.env.SGW_RECOVERY_HOME = `${home}-recovery`;
        try {
          const store = new SecretStore(home);
          expect(await store.listHandles()).toHaveLength(operation === "delete-keychain" ? 0 : 1);
        } finally {
          if (previousRecoveryHome === undefined) delete process.env.SGW_RECOVERY_HOME;
          else process.env.SGW_RECOVERY_HOME = previousRecoveryHome;
        }
        const raw = await readFile(path.join(home, "store.json"), "utf8");
        expect(raw).not.toContain("synthetic-local-value");
        expect(raw).not.toContain("synthetic-keychain-value");
        expect(raw).not.toContain("synthetic master passphrase");
        expect(raw).toContain("Concurrent synthetic writer");
      } finally {
        await writeFile(release, "").catch(() => undefined);
        if (second?.child.exitCode === null) second.child.kill();
        await second?.done.catch(() => undefined);
        if (first?.child.exitCode === null) first.child.kill();
        await first?.done.catch(() => undefined);
        await rm(root, { recursive: true, force: true });
        await rm(`${home}-recovery`, { recursive: true, force: true });
      }
    },
    30_000
  );

  it.each(["set", "delete"])("shows the remaining store-lock stall during Keychain %s", async (blockedOp) => {
    const root = await mkdtemp(path.join(os.tmpdir(), "sgw-keychain-side-effect-"));
    const home = path.join(root, "store");
    const waiting = path.join(root, "helper-waiting");
    const release = path.join(root, "release-helper");
    const helper = path.join(root, "s-gw-keychain-helper");
    await writeFakeHelper(helper);
    const baseEnv = {
      ...process.env,
      SGW_HOME: home,
      SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_TEST_MODE: "1",
      SGW_KEYCHAIN_HELPER: helper,
      SGW_MASTER_PASSPHRASE: "synthetic master passphrase",
      SGW_DISABLE_KEYCHAIN: "1",
      SGW_DISABLE_ONEPASSWORD_BACKUP: "1",
      SGW_TEST_HELPER_WAITING: waiting,
      SGW_TEST_HELPER_RELEASE: release
    };
    let first: ReturnType<typeof startWorker> | undefined;
    let second: ReturnType<typeof startWorker> | undefined;
    try {
      if (blockedOp === "delete") {
        const seeded = startWorker("add-keychain", baseEnv);
        expect(await withDeadline(seeded.done, 10_000)).toMatchObject({ code: 0 });
      }
      first = startWorker(blockedOp === "set" ? "add-keychain" : "delete-keychain", {
        ...baseEnv,
        SGW_TEST_HELPER_BLOCK_OP: blockedOp
      });
      await waitForFile(waiting);
      expect(first.child.exitCode).toBeNull();

      second = startWorker("add-policy", { ...baseEnv, SGW_TEST_LOCK_TIMEOUT_MS: "300" });
      const concurrent = await withDeadline(second.done, 10_000);
      expect(concurrent.code).not.toBe(0);
      expect(concurrent.stderr).toMatch(/Timed out waiting for s-gw store lock/);

      await writeFile(release, "");
      const completed = await withDeadline(first.done, 10_000);
      expect(completed, completed.stderr).toMatchObject({ code: 0 });
      expect(existsSync(path.join(home, "store.json.lock"))).toBe(false);
    } finally {
      await writeFile(release, "").catch(() => undefined);
      if (second?.child.exitCode === null) second.child.kill();
      await second?.done.catch(() => undefined);
      if (first?.child.exitCode === null) first.child.kill();
      await first?.done.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 30_000);

  it("retries a changed Keychain reference without reading it under the store lock", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "sgw-keychain-retry-"));
    const home = path.join(root, "store");
    const helper = path.join(root, "s-gw-keychain-helper");
    const waiting = path.join(root, "helper-waiting");
    const release = path.join(root, "release-helper");
    await writeFakeHelper(helper);
    const baseEnv = {
      ...process.env,
      SGW_HOME: home,
      SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_TEST_MODE: "1",
      SGW_KEYCHAIN_HELPER: helper,
      SGW_TEST_HELPER_BLOCK_OP: "get",
      SGW_TEST_HELPER_WAITING: waiting,
      SGW_TEST_HELPER_RELEASE: release,
      SGW_TEST_HELPER_GET_LOG: path.join(root, "helper-gets"),
      SGW_DISABLE_ONEPASSWORD_BACKUP: "1"
    };
    delete baseEnv.SGW_MASTER_PASSPHRASE;
    delete baseEnv.SGW_DISABLE_KEYCHAIN;
    const writerEnv = { ...baseEnv, SGW_MASTER_PASSPHRASE: "synthetic master passphrase", SGW_DISABLE_KEYCHAIN: "1", SGW_TEST_HELPER_BLOCK_OP: "none" };
    let deleting: ReturnType<typeof startWorker> | undefined;
    let updating: ReturnType<typeof startWorker> | undefined;
    let concurrent: ReturnType<typeof startWorker> | undefined;
    try {
      const seeded = startWorker("add-keychain", writerEnv);
      const seedResult = await withDeadline(seeded.done, 10_000);
      expect(seedResult, seedResult.stderr).toMatchObject({ code: 0 });
      const original = JSON.parse(await readFile(path.join(home, "store.json"), "utf8"));

      deleting = startWorker("delete-keychain", baseEnv);
      await waitForFile(`${waiting}-1`);
      updating = startWorker("add-keychain", writerEnv);
      const updateResult = await withDeadline(updating.done, 10_000);
      expect(updateResult, updateResult.stderr).toMatchObject({ code: 0 });
      const changed = JSON.parse(await readFile(path.join(home, "store.json"), "utf8"));
      expect(changed.secrets[0].encrypted).not.toEqual(original.secrets[0].encrypted);

      await writeFile(`${release}-1`, "");
      await waitForFile(`${waiting}-2`);
      concurrent = startWorker("add-policy", { ...writerEnv, SGW_TEST_LOCK_TIMEOUT_MS: "300" });
      const writerResult = await withDeadline(concurrent.done, 10_000);
      expect(writerResult, writerResult.stderr).toMatchObject({ code: 0 });

      await writeFile(`${release}-2`, "");
      const deleted = await withDeadline(deleting.done, 10_000);
      expect(deleted, deleted.stderr).toMatchObject({ code: 0 });
      const finalStore = JSON.parse(await readFile(path.join(home, "store.json"), "utf8"));
      expect(finalStore.secrets).toHaveLength(0);
      expect(finalStore.approvalPolicyRules).toHaveLength(1);
    } finally {
      await writeFile(`${release}-1`, "").catch(() => undefined);
      await writeFile(`${release}-2`, "").catch(() => undefined);
      if (concurrent?.child.exitCode === null) concurrent.child.kill();
      await concurrent?.done.catch(() => undefined);
      if (updating?.child.exitCode === null) updating.child.kill();
      await updating?.done.catch(() => undefined);
      if (deleting?.child.exitCode === null) deleting.child.kill();
      await deleting?.done.catch(() => undefined);
      await rm(root, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 40_000);
});
