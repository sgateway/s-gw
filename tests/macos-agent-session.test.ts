import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, realpath, rm, symlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { MacAgentSessionLeases } from "../src/macos-agent-session.js";
import type { PeerSession } from "../src/peer-identity.js";

let root = "";

afterEach(async () => {
  if (root) await rm(root, { recursive: true, force: true });
  root = "";
});

async function leaseDir(): Promise<string> {
  root = await realpath(await mkdtemp(path.join(os.homedir(), ".sgw-mac-lease-")));
  await chmod(root, 0o700);
  return root;
}

function session(uid = 231_000): PeerSession {
  return { uid, gid: 231_000, sessionId: `test-${uid}`, name: "Agent" };
}

describe.skipIf(process.platform !== "darwin")("macOS agent UID leases", () => {
  it("burns a UID across broker restarts after ending its peer session", async () => {
    const location = await leaseDir();
    const register = vi.fn(() => vi.fn());
    const stop = await new MacAgentSessionLeases(location).register(session(), register);
    expect(register).toHaveBeenCalledOnce();
    stop();
    stop();
    expect(register.mock.results[0]?.value).toHaveBeenCalledOnce();
    await expect(new MacAgentSessionLeases(location).register(session(), register))
      .rejects.toThrow("already used");
    expect(register).toHaveBeenCalledOnce();
  });

  it("rejects reuse even if peer registration fails", async () => {
    const location = await leaseDir();
    await expect(new MacAgentSessionLeases(location).register(session(), () => {
      throw new Error("registry unavailable");
    })).rejects.toThrow("registry unavailable");
    await expect(new MacAgentSessionLeases(location).register(session(), () => () => {}))
      .rejects.toThrow("already used");
  });

  it("allows only one of two concurrent registrations for the same UID", async () => {
    const location = await leaseDir();
    const leases = new MacAgentSessionLeases(location);
    const outcomes = await Promise.allSettled([
      leases.register(session(), () => () => {}), leases.register(session(), () => () => {})
    ]);
    expect(outcomes.filter(item => item.status === "fulfilled")).toHaveLength(1);
    expect(outcomes.filter(item => item.status === "rejected")).toHaveLength(1);
  });

  it("rejects broker identity, shared group, and writable lease storage", async () => {
    const location = await leaseDir();
    const leases = new MacAgentSessionLeases(location);
    const register = vi.fn(() => () => {});
    await expect(leases.register(session(process.getuid!()), register)).rejects.toThrow("dedicated UID");
    await expect(leases.register({ ...session(), gid: process.getgid!() }, register)).rejects.toThrow("dedicated UID");
    await chmod(location, 0o750);
    await expect(leases.register(session(), register)).rejects.toThrow("private to the broker");
    expect(register).not.toHaveBeenCalled();
  });

  it("rejects a symlinked lease directory", async () => {
    const location = await leaseDir();
    const link = `${location}-link`;
    await symlink(location, link);
    try {
      await expect(new MacAgentSessionLeases(link).register(session(), () => () => {}))
        .rejects.toThrow("private to the broker");
    } finally { await rm(link); }
  });

  it("rejects an extended ACL grant on the lease directory before reserving a UID", async () => {
    const location = await leaseDir();
    const acl = spawnSync("/bin/chmod", ["+a", "everyone allow read,write,execute", location], { encoding: "utf8" });
    expect(acl.status, acl.stderr).toBe(0);
    const register = vi.fn(() => () => {});
    await expect(new MacAgentSessionLeases(location).register(session(), register))
      .rejects.toThrow("extended ACL allow");
    expect(register).not.toHaveBeenCalled();
  });

  it("rejects an ACL grant or write bit on an ancestor", async () => {
    const parent = await leaseDir();
    const location = path.join(parent, "leases");
    await mkdir(location, { mode: 0o700 });
    const acl = spawnSync("/bin/chmod", ["+a", "everyone allow read,write,execute", parent], { encoding: "utf8" });
    expect(acl.status, acl.stderr).toBe(0);
    await expect(new MacAgentSessionLeases(location).register(session(), () => () => {}))
      .rejects.toThrow("extended ACL allow");
    const clear = spawnSync("/bin/chmod", ["-a#", "0", parent], { encoding: "utf8" });
    expect(clear.status, clear.stderr).toBe(0);
    await chmod(parent, 0o777);
    await expect(new MacAgentSessionLeases(location).register(session(), () => () => {}))
      .rejects.toThrow("untrusted parent");
  });

  it("accepts a lease directory below a root-owned sticky parent", async () => {
    root = await realpath(await mkdtemp(path.join("/private/tmp", "sgw-mac-lease-sticky-")));
    await chmod(root, 0o700);
    const stopped = await new MacAgentSessionLeases(root).register(session(), () => () => {});
    stopped();
  });
});
