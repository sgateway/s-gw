import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import { managedSshArgs, managedSshHostFingerprint, managedSshKnownHostsLine, normalizeManagedSshRoute } from "../src/managed-ssh.js";

let dir = "";
afterEach(async () => { if (dir) await rm(dir, { recursive: true, force: true }); });

async function route() {
  dir = await mkdtemp(path.join(os.tmpdir(), "sgw-managed-ssh-test-"));
  const keyFile = path.join(dir, "host-key");
  execFileSync("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keyFile]);
  const publicKey = (await readFile(`${keyFile}.pub`, "utf8")).trim().split(/\s+/).slice(0, 2).join(" ");
  return { host: "127.0.0.1", user: "fixture", port: 2222, hostPublicKey: publicKey };
}

it.skipIf(process.platform === "win32")("pins one route and ignores OpenSSH user configuration", async () => {
  const managed = await route();
  const knownHosts = path.join(dir, "known_hosts");
  const { alias, line } = managedSshKnownHostsLine(managed);
  expect(line).toBe(`${alias} ${managed.hostPublicKey}\n`);
  expect(managedSshHostFingerprint(managed)).toMatch(/^SHA256:[A-Za-z0-9+/]+$/);

  const args = managedSshArgs(managed, knownHosts, ["-i", path.join(dir, "host-key")], ["hostname"], true);
  expect(args).toContain("-F"); expect(args[args.indexOf("-F") + 1]).toBe("none");
  expect(args).toContain("ProxyCommand=none"); expect(args).toContain("ProxyJump=none");
  expect(args).toContain("StrictHostKeyChecking=yes");
  expect(args).toContain(`UserKnownHostsFile=${knownHosts}`);
  expect(args.slice(-6)).toEqual(["-l", "fixture", "-p", "2222", "127.0.0.1", "hostname"]);

  const output = execFileSync("/usr/bin/ssh", ["-G", ...args.slice(0, -1)], { encoding: "utf8" });
  expect(output).toMatch(/^hostname 127\.0\.0\.1$/m);
  expect(output).toMatch(/^user fixture$/m);
  expect(output).toMatch(/^port 2222$/m);
  expect(output).toMatch(/^stricthostkeychecking true$/m);
  expect(output).toMatch(new RegExp(`^hostkeyalias ${alias}$`, "m"));
  expect(output).not.toMatch(/^proxycommand .+$/m);
  expect(output).toMatch(/^identityfile none$/m);
  expect(output).toMatch(new RegExp(`^identityfile ${path.join(dir, "host-key")}$`, "m"));
});

it.skipIf(process.platform === "win32")("rejects malformed or option-like managed routes", async () => {
  const valid = await route();
  for (const changed of [
    { host: "-oProxyCommand=evil" }, { host: "other host" }, { host: "host\nmalicious" },
    { user: "-oProxyJump=evil" }, { user: "fixture another" },
    { port: 0 }, { port: 65536 }, { port: 22.5 },
    { hostPublicKey: "ssh-ed25519 AAAA" },
    { hostPublicKey: valid.hostPublicKey.replace("ssh-ed25519", "ssh-rsa") },
    { hostPublicKey: `${valid.hostPublicKey} malicious` }
  ]) {
    expect(() => normalizeManagedSshRoute({ ...valid, ...changed })).toThrow();
  }
  expect(normalizeManagedSshRoute(valid)).toEqual(valid);
});
