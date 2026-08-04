import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { requirePassphrase } from "../src/crypto.js";
import {
  deleteKeychainPassphrase,
  keychainInfo,
  setKeychainPassphrase,
  unlockStatus
} from "../src/unlock.js";

const originalPlatform = Object.getOwnPropertyDescriptor(process, "platform");
let tmpDir = "";

beforeEach(async () => {
  Object.defineProperty(process, "platform", { configurable: true, value: "linux" });
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-linux-unlock-"));
  process.env.SGW_HOME = path.join(tmpDir, "home");
  process.env.SGW_RECOVERY_HOME = path.join(tmpDir, "recovery");
  process.env.SGW_KEYCHAIN_SERVICE = "com.s-gw.linux-test";
  process.env.SGW_KEYCHAIN_ACCOUNT = "ordinary-user";
  process.env.SGW_FAKE_SECRET_DB = path.join(tmpDir, "secret.txt");
  process.env.SGW_FAKE_SECRET_CAPTURE = path.join(tmpDir, "capture.json");
  process.env.SGW_SECRET_TOOL = await installFakeSecretTool();
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
});

afterEach(async () => {
  if (originalPlatform) Object.defineProperty(process, "platform", originalPlatform);
  for (const key of [
    "SGW_KEYCHAIN_SERVICE",
    "SGW_KEYCHAIN_ACCOUNT",
    "SGW_FAKE_SECRET_DB",
    "SGW_FAKE_SECRET_CAPTURE",
    "SGW_SECRET_TOOL",
    "SGW_MASTER_PASSPHRASE",
    "SGW_DISABLE_KEYCHAIN"
  ]) {
    delete process.env[key];
  }
  await rm(tmpDir, { recursive: true, force: true });
});

describe.sequential("Linux Secret Service unlock", () => {
  it("stores generated unlock material on stdin and reads it back", async () => {
    const passphrase = "synthetic-linux-secret-service-passphrase";
    setKeychainPassphrase(passphrase);

    const capture = JSON.parse(await readFile(process.env.SGW_FAKE_SECRET_CAPTURE!, "utf8"));
    expect(capture.command).toBe("store");
    expect(capture.stdin).toBe(passphrase);
    expect(capture.args.join(" ")).not.toContain(passphrase);

    expect(requirePassphrase()).toBe(passphrase);
    expect(unlockStatus()).toMatchObject({
      envConfigured: false,
      activeSource: "linux-secret-service",
      keychain: {
        supported: true,
        configured: true,
        provider: "secret-service-cli"
      }
    });
  });

  it("deletes the Secret Service unlock item without exposing it", async () => {
    setKeychainPassphrase("synthetic-linux-delete-passphrase");

    expect(deleteKeychainPassphrase()).toBe(true);
    expect(unlockStatus().activeSource).toBe("none");
  });

  it("rejects a writable test helper", async () => {
    await chmod(process.env.SGW_SECRET_TOOL!, 0o777);

    expect(keychainInfo()).toMatchObject({ supported: true, provider: "none" });
    expect(() => setKeychainPassphrase("synthetic-linux-rejected-helper")).toThrow(/Secret Service is unavailable/);
  });
});

async function installFakeSecretTool(): Promise<string> {
  const helper = path.join(tmpDir, "secret-tool");
  await writeFile(helper, `#!/usr/bin/env node
const { existsSync, readFileSync, rmSync, writeFileSync } = require("node:fs");
const [command, ...args] = process.argv.slice(2);
const db = process.env.SGW_FAKE_SECRET_DB;
const capture = process.env.SGW_FAKE_SECRET_CAPTURE;
if (!db || !capture) process.exit(2);
if (command === "store") {
  const value = readFileSync(0, "utf8");
  writeFileSync(db, value, { mode: 0o600 });
  writeFileSync(capture, JSON.stringify({ command, args, stdin: value }), { mode: 0o600 });
  process.exit(0);
}
if (command === "lookup") {
  if (!existsSync(db)) process.exit(1);
  process.stdout.write(readFileSync(db, "utf8") + "\\n");
  process.exit(0);
}
if (command === "clear") {
  rmSync(db, { force: true });
  process.exit(0);
}
process.exit(2);
`);
  await chmod(helper, 0o700);
  return helper;
}
