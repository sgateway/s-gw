import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assertNoMacAclAllow } from "../src/macos-path-acl.js";

let root = "";

afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
  root = "";
});

async function testFile(): Promise<string> {
  root = await mkdtemp(path.join(os.homedir(), ".sgw-acl-test-"));
  const file = path.join(root, "trusted");
  await writeFile(file, "test");
  return file;
}

describe.skipIf(process.platform !== "darwin")("macOS broker path ACLs", () => {
  it("accepts ordinary paths and deny-only ACL entries", async () => {
    const file = await testFile();
    await expect(assertNoMacAclAllow(file)).resolves.toBeUndefined();
    const deny = spawnSync("/bin/chmod", ["+a", "everyone deny read", file], { encoding: "utf8" });
    expect(deny.status, deny.stderr).toBe(0);
    await expect(assertNoMacAclAllow(file)).resolves.toBeUndefined();
  });

  it("rejects an allow entry even when POSIX mode grants no agent access", async () => {
    const file = await testFile();
    const allow = spawnSync("/bin/chmod", ["+a", "everyone allow read,write", file], { encoding: "utf8" });
    expect(allow.status, allow.stderr).toBe(0);
    await expect(assertNoMacAclAllow(file)).rejects.toThrow("extended ACL allow");
  });

  it("fails closed if ACL inspection fails or a path could forge the listing format", async () => {
    const file = await testFile();
    await expect(assertNoMacAclAllow(`${file}-missing`)).rejects.toThrow("Could not verify");
    await expect(assertNoMacAclAllow(`${file}\n 0: everyone deny all`)).rejects.toThrow("control character");
  });
});
