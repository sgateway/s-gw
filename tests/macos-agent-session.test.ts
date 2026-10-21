import { chmod, mkdtemp, realpath, rm, symlink } from "node:fs/promises";
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
  root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-mac-lease-")));
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
});
