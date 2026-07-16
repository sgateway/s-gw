import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
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
  delete process.env.SGW_KEYCHAIN_INSPECTOR;
  delete process.env.SGW_KEYCHAIN_LEGACY_HELPERS;
  delete process.env.SGW_KEYCHAIN_STATUS_CLI;
  delete process.env.SGW_FAKE_KEYCHAIN_VALUE;
  delete process.env.SGW_FAKE_KEYCHAIN_CAPTURE;
  delete process.env.SGW_FAKE_KEYCHAIN_GET_DENIED;
  delete process.env.SGW_FAKE_SECURITY_CAPTURE;
  delete process.env.SGW_FAKE_KEYCHAIN_DB;
  delete process.env.SGW_HOME;
  delete process.env.SGW_RECOVERY_HOME;
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

  it("parses only the requested Keychain item's trusted application paths", () => {
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
const value = name => args[args.indexOf(name) + 1];
const candidates = [];
for (let i = 0; i < args.length; i++) if (args[i] === "--candidate") candidates.push(args[i + 1]);
const db = JSON.parse(fs.readFileSync(process.env.SGW_FAKE_KEYCHAIN_DB, "utf8"));
const item = db.items[value("--service") + "\\0" + value("--account")];
if (!item) process.exit(44);
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
if (args[0] === "find-generic-password") {
  const account = args[args.indexOf("-a") + 1];
  const service = args[args.indexOf("-s") + 1];
  process.exit(db.items[service + "\\0" + account] ? 0 : 44);
}
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
