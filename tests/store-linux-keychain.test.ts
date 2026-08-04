import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SecretStore } from "../src/store.js";

const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
let tmpDir = "";

beforeEach(async () => {
  Object.defineProperty(process, "platform", { configurable: true, value: "linux" });
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-linux-store-"));
  process.env.SGW_HOME = path.join(tmpDir, "home");
  process.env.SGW_RECOVERY_HOME = path.join(tmpDir, "recovery");
  process.env.SGW_MASTER_PASSPHRASE = "synthetic-linux-store-unlock";
  process.env.SGW_SECRET_KEYCHAIN_SERVICE = "com.s-gw.linux-store-test";
  process.env.SGW_FAKE_SECRET_DB = path.join(tmpDir, "secret-db.json");
  process.env.SGW_SECRET_TOOL = await installFakeSecretTool();
  delete process.env.SGW_DISABLE_KEYCHAIN;
});

afterEach(async () => {
  if (originalPlatform) Object.defineProperty(process, "platform", originalPlatform);
  for (const key of [
    "SGW_HOME",
    "SGW_RECOVERY_HOME",
    "SGW_MASTER_PASSPHRASE",
    "SGW_SECRET_KEYCHAIN_SERVICE",
    "SGW_FAKE_SECRET_DB",
    "SGW_FAKE_SECRET_CLEAR_ERROR",
    "SGW_SECRET_TOOL",
    "SGW_DISABLE_KEYCHAIN"
  ]) {
    delete process.env[key];
  }
  await rm(tmpDir, { recursive: true, force: true });
});

describe.sequential("Linux Secret Service store", () => {
  it("retains a retryable handle when credential deletion fails", async () => {
    const store = new SecretStore();
    const record = await store.addKeychainSecret({
      name: "Linux deletion canary",
      type: "api-token",
      value: "synthetic-linux-delete-canary",
      policy: { allowedCommands: [] }
    });

    process.env.SGW_FAKE_SECRET_CLEAR_ERROR = "1";
    await expect(store.deleteSecret(record.handle)).rejects.toThrow(/synthetic Secret Service clear failure/);
    expect(await store.listHandles()).toEqual([
      expect.objectContaining({ handle: record.handle, backend: "keychain", provider: "linux-secret-service" })
    ]);
    expect(Object.keys(await readDb())).toHaveLength(1);

    delete process.env.SGW_FAKE_SECRET_CLEAR_ERROR;
    await expect(store.deleteSecret(record.handle)).resolves.toMatchObject({ handle: record.handle });
    expect(await store.listHandles()).toHaveLength(0);
    expect(Object.keys(await readDb())).toHaveLength(0);
  });
});

async function readDb(): Promise<Record<string, string>> {
  return JSON.parse(await readFile(process.env.SGW_FAKE_SECRET_DB!, "utf8").catch(() => "{}"));
}

async function installFakeSecretTool(): Promise<string> {
  const helper = path.join(tmpDir, "secret-tool");
  await writeFile(helper, `#!/usr/bin/env node
const { existsSync, readFileSync, writeFileSync } = require("node:fs");
const [command, ...args] = process.argv.slice(2);
const dbPath = process.env.SGW_FAKE_SECRET_DB;
if (!dbPath) process.exit(2);
const attrs = {};
for (let i = 0; i + 1 < args.length; i += 2) {
  if (args[i].startsWith("--")) {
    i -= 1;
    continue;
  }
  attrs[args[i]] = args[i + 1];
}
const key = String(attrs.service || "") + "\\u0000" + String(attrs.account || "");
const db = existsSync(dbPath) ? JSON.parse(readFileSync(dbPath, "utf8")) : {};
if (command === "store") {
  db[key] = readFileSync(0, "utf8");
  writeFileSync(dbPath, JSON.stringify(db), { mode: 0o600 });
  process.exit(0);
}
if (command === "lookup") {
  if (!Object.prototype.hasOwnProperty.call(db, key)) process.exit(1);
  process.stdout.write(db[key] + "\\n");
  process.exit(0);
}
if (command === "clear") {
  if (process.env.SGW_FAKE_SECRET_CLEAR_ERROR === "1") {
    process.stderr.write("synthetic Secret Service clear failure\\n");
    process.exit(2);
  }
  delete db[key];
  writeFileSync(dbPath, JSON.stringify(db), { mode: 0o600 });
  process.exit(0);
}
process.exit(2);
`);
  await chmod(helper, 0o700);
  return helper;
}
