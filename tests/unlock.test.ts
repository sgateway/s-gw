import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { requirePassphrase } from "../src/crypto.js";
import {
  installPersistentKeychainHelper,
  keychainInfo,
  persistentKeychainHelperPath,
  setKeychainPassphrase,
  unlockStatus
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
  delete process.env.SGW_KEYCHAIN_STATUS_CLI;
  delete process.env.SGW_FAKE_KEYCHAIN_VALUE;
  delete process.env.SGW_FAKE_KEYCHAIN_CAPTURE;
  delete process.env.SGW_FAKE_KEYCHAIN_GET_DENIED;
  delete process.env.SGW_FAKE_SECURITY_CAPTURE;
  delete process.env.SGW_HOME;
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

  it("checks Keychain status without asking the helper to reveal the passphrase", async () => {
    if (process.platform !== "darwin") {
      return;
    }

    const capturePath = path.join(tmpDir, "security-args.json");
    process.env.SGW_FAKE_SECURITY_CAPTURE = capturePath;
    process.env.SGW_FAKE_KEYCHAIN_GET_DENIED = "1";
    await installFakeHelper("configured keychain passphrase");

    const status = unlockStatus();
    expect(status.activeSource).toBe("macos-keychain");
    expect(status.keychain.configured).toBe(true);

    const args = JSON.parse(await readText(capturePath)) as string[];
    expect(args).toEqual([
      "find-generic-password",
      "-a",
      "unit-test",
      "-s",
      "com.s-gw.test"
    ]);
    expect(args).not.toContain("-w");
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

    process.env.SGW_HOME = sgwHome;
    expect(keychainInfo().helperPath).toBe(helperPath);
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

  const fakeSecurity = path.join(tmpDir, "security");
  await writeFile(
    fakeSecurity,
    `#!/usr/bin/env node
const fs = require("fs");
const args = process.argv.slice(2);
if (process.env.SGW_FAKE_SECURITY_CAPTURE) {
  fs.writeFileSync(process.env.SGW_FAKE_SECURITY_CAPTURE, JSON.stringify(args));
}
if (args[0] !== "find-generic-password" || args.includes("-w")) process.exit(2);
process.exit(process.env.SGW_FAKE_KEYCHAIN_VALUE ? 0 : 44);
`
  );
  await chmod(fakeSecurity, 0o700);
  process.env.SGW_KEYCHAIN_STATUS_CLI = fakeSecurity;
}

async function readText(filePath: string): Promise<string> {
  return readFile(filePath, "utf8");
}
