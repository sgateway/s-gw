import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { requirePassphrase } from "../src/crypto.js";
import { setKeychainPassphrase, unlockStatus } from "../src/unlock.js";

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
  delete process.env.SGW_FAKE_KEYCHAIN_VALUE;
  delete process.env.SGW_FAKE_KEYCHAIN_CAPTURE;
  if (tmpDir) {
    await rm(tmpDir, { recursive: true, force: true });
  }
});

describe("unlock passphrase provider", () => {
  it("prefers the explicit environment passphrase", () => {
    process.env.SGW_MASTER_PASSPHRASE = "env passphrase";

    expect(requirePassphrase()).toBe("env passphrase");
    expect(unlockStatus().activeSource).toBe("env");
  });

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

  it("reports a clear unlock error when no provider is configured", async () => {
    if (process.platform === "darwin") {
      await installFakeHelper("");
    }

    expect(() => requirePassphrase()).toThrow(/unlock passphrase/i);
  });
});

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
  if (!passphrase) process.exit(44);
  process.stdout.write(passphrase + "\\n");
  process.exit(0);
}
if (command === "set") {
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", chunk => input += chunk);
  process.stdin.on("end", () => {
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
}

async function readText(filePath: string): Promise<string> {
  return readFile(filePath, "utf8");
}
