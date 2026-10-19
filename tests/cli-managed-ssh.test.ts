import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { managedSshHostFingerprint } from "../src/managed-ssh.js";
import { SecretStore } from "../src/store.js";

let root = "";
afterEach(async () => { if (root) await rm(root, { recursive: true, force: true }); });

function publicHostKey(): string {
  const { publicKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" });
  const name = Buffer.from("ssh-ed25519");
  const length = (value: Buffer) => {
    const prefix = Buffer.alloc(4);
    prefix.writeUInt32BE(value.length);
    return Buffer.concat([prefix, value]);
  };
  return `ssh-ed25519 ${Buffer.concat([length(name), length(der.subarray(-32))]).toString("base64")}`;
}

it("manages trusted SSH routes and requests one by ID through the CLI", async () => {
  root = await mkdtemp(path.join(os.tmpdir(), "sgw-route-cli-"));
  const env = { ...process.env, SGW_HOME: path.join(root, "store"), SGW_RECOVERY_HOME: path.join(root, "recovery"),
    SGW_MASTER_PASSPHRASE: "synthetic route CLI passphrase", SGW_DISABLE_KEYCHAIN: "1",
    SGW_DISABLE_ONEPASSWORD_BACKUP: "1", SGW_DISABLE_UPDATE_CHECK: "1" };
  const original = { ...process.env };
  process.env = { ...env };
  let handle: string;
  try {
    const store = new SecretStore();
    await store.init();
    handle = (await store.addSecret({ name: "SSH route fixture", type: "password", value: "synthetic password",
      policy: { allowedCommands: ["s-gw:ssh-session"], allowedDestinations: ["127.0.0.1:2222"] } })).handle;
  } finally { process.env = original; }
  const run = (args: string[]) => JSON.parse(execFileSync(process.execPath,
    [path.join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs"), "src/cli.ts", ...args],
    { cwd: process.cwd(), env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }));
  const added = run(["ssh", "route", "add", "--name", "fixture", "--host", "127.0.0.1", "--user", "runner",
    "--port", "2222", "--host-public-key", publicHostKey()]);
  expect(added.id).toMatch(/^route_/);
  expect(run(["ssh", "route", "show", "--id", added.id])).toMatchObject({ name: "fixture", route: { user: "runner", port: 2222 } });
  expect(run(["ssh", "route", "list"])).toHaveLength(1);
  const request = run(["ssh", "request", handle, "--route", added.id, "--arg", "hostname"]);
  expect(request.request.action.ssh).toMatchObject({ managedRouteId: added.id,
    managed: { host: "127.0.0.1", user: "runner", port: 2222 } });
  expect(request.request.state).toBe("pending");
  try {
    run(["approve", request.request.id]);
    throw new Error("Managed SSH approval unexpectedly succeeded without route review.");
  } catch (error) {
    expect(String((error as { stderr?: string }).stderr)).toContain("Managed SSH approval requires review");
  }
  const reviewed = `runner@127.0.0.1:2222 ${managedSshHostFingerprint(added.route)}`;
  expect(run(["approve", request.request.id, "--confirm-route", reviewed]).state).toBe("approved");
  expect(run(["ssh", "route", "update", "--id", added.id, "--name", "renamed"]).name).toBe("renamed");
  expect(run(["ssh", "route", "delete", "--id", added.id]).id).toBe(added.id);
  expect(run(["ssh", "route", "list"])).toEqual([]);
});
