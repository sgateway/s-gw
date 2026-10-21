import { chmod, mkdtemp, readFile, readdir, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LinuxAgentSessionLeases } from "../src/linux-agent-session.js";
import { linuxAgentUnitName, type LinuxAgentUnitManager, type LinuxAgentUnitPlan,
  type LinuxAgentUnitState } from "../src/linux-agent-unit.js";
import type { PeerSession } from "../src/peer-identity.js";

let leasePath = "";

afterEach(async () => {
  if (leasePath) await rm(leasePath, { recursive: true, force: true });
  leasePath = "";
});

async function leases(): Promise<string> {
  leasePath = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-linux-lease-")));
  await chmod(leasePath, 0o700);
  return leasePath;
}

function plan(uid = 231001): LinuxAgentUnitPlan {
  return {
    sessionId: `session-${uid}`, uid, gid: uid, brokerUid: process.getuid!(),
    rootDirectory: `/var/lib/s-gw/agent-roots/session-${uid}`,
    brokerSocket: `/run/s-gw/agents/session-${uid}/broker.sock`,
    executable: "/usr/bin/node", args: ["/app/agent.js"]
  };
}

function manager(p: LinuxAgentUnitPlan) {
  const state: LinuxAgentUnitState = {
    unit: linuxAgentUnitName(p.sessionId), uid: p.uid, gid: p.gid,
    cgroup: `/system.slice/${linuxAgentUnitName(p.sessionId)}`, mainPid: 4567,
    invocationId: "0123456789abcdef0123456789abcdef"
  };
  return { start: vi.fn(async () => {}), inspect: vi.fn(async () => state),
    release: vi.fn(async () => {}),
    stop: vi.fn(async () => {}) } satisfies LinuxAgentUnitManager;
}

describe("Linux broker agent leases", () => {
  it("persists unique UID and GID tombstones before registering the attested cgroup", async () => {
    const location = await leases();
    const p = plan();
    const units = manager(p);
    const events: string[] = [];
    units.start.mockImplementation(async () => { events.push("start"); });
    units.inspect.mockImplementation(async () => { events.push("inspect"); return {
      unit: linuxAgentUnitName(p.sessionId), uid: p.uid, gid: p.gid,
      cgroup: `/system.slice/${linuxAgentUnitName(p.sessionId)}`, mainPid: 4567,
      invocationId: "0123456789abcdef0123456789abcdef"
    }; });
    let registered: PeerSession | undefined;
    const stop = await new LinuxAgentSessionLeases(location, units).launch(p, "Test agent", session => {
      events.push("register"); registered = session; return () => { events.push("revoke"); };
    });
    expect(events).toEqual(["start", "inspect", "register"]);
    expect(registered).toMatchObject({ uid: p.uid, gid: p.gid, linuxCgroup: `/system.slice/${linuxAgentUnitName(p.sessionId)}` });
    expect(await readdir(location)).toEqual([`gid-${p.gid}`, `session-${p.sessionId}`, `uid-${p.uid}`]);
    expect(JSON.parse(await readFile(path.join(location, `uid-${p.uid}`), "utf8"))).toMatchObject({ sessionId: p.sessionId });
    await stop();
    expect(events.at(-1)).toBe("revoke");
    expect(units.stop).toHaveBeenCalledOnce();
    await expect(new LinuxAgentSessionLeases(location, units).launch(p, "Test agent", () => () => {}))
      .rejects.toThrow("already used");
  });

  it("registers the attested peer before releasing the gated executable", async () => {
    const location = await leases();
    const p = { ...plan(), launchGate: true };
    const units = manager(p);
    const events: string[] = [];
    units.start.mockImplementation(async () => { events.push("start"); });
    units.inspect.mockImplementation(async () => { events.push("inspect"); return {
      unit: linuxAgentUnitName(p.sessionId), uid: p.uid, gid: p.gid,
      cgroup: `/system.slice/${linuxAgentUnitName(p.sessionId)}`, mainPid: 4567,
      invocationId: "0123456789abcdef0123456789abcdef"
    }; });
    units.release.mockImplementation(async () => { events.push("release"); });
    const stop = await new LinuxAgentSessionLeases(location, units).launch(p, "A", () => {
      events.push("register"); return () => { events.push("revoke"); };
    });
    expect(events).toEqual(["start", "inspect", "register", "release"]);
    expect(units.release).toHaveBeenCalledWith(p, expect.objectContaining({ mainPid: 4567 }));
    await stop();
    expect(events.at(-1)).toBe("revoke");
  });

  it("passes an opted-in generation through the attested Linux launch", async () => {
    const location = await leases();
    const p = { ...plan(), launchGate: true, activatedSocket: true,
      isolatedSharedMemory: true, serializedLifecycle: true, sealedStdio: true,
      supervisedControlUnit: true, logicalAgentId: "codex-main",
      identityGeneration: "a".repeat(32) };
    const units = manager(p);
    let registered: PeerSession | undefined;
    const stop = await new LinuxAgentSessionLeases(location, units).launch(p, "Codex", session => {
      registered = session;
      return () => {};
    }, async () => {});
    expect(registered).toMatchObject({ uid: p.uid, gid: p.gid,
      linuxIdentityGeneration: p.identityGeneration,
      linuxCgroup: `/system.slice/${linuxAgentUnitName(p.sessionId)}` });
    await stop();
  });

  it("checks an activated listener's live binding before registration and gate release", async () => {
    const location = await leases();
    const p = { ...plan(), activatedSocket: true, launchGate: true };
    const units = manager(p);
    const events: string[] = [];
    const check = vi.fn(async () => { events.push("binding"); });
    units.start.mockImplementation(async () => { events.push("start"); });
    units.inspect.mockImplementation(async () => { events.push("inspect"); return {
      unit: linuxAgentUnitName(p.sessionId), uid: p.uid, gid: p.gid,
      cgroup: `/system.slice/${linuxAgentUnitName(p.sessionId)}`, mainPid: 4567,
      invocationId: "0123456789abcdef0123456789abcdef"
    }; });
    units.release.mockImplementation(async () => { events.push("release"); });
    const stop = await new LinuxAgentSessionLeases(location, units).launch(p, "A", () => {
      events.push("register"); return () => { events.push("revoke"); };
    }, check);
    expect(events).toEqual(["start", "inspect", "binding", "register", "binding", "release"]);
    expect(check).toHaveBeenCalledTimes(2);
    await stop();
  });

  it("rejects an activated launch without a binding check and revokes after a rebind", async () => {
    const location = await leases();
    const p = { ...plan(), activatedSocket: true, launchGate: true };
    const units = manager(p);
    await expect(new LinuxAgentSessionLeases(location, units).launch(p, "A", () => () => {}))
      .rejects.toThrow("live broker FD binding check");
    expect(units.start).not.toHaveBeenCalled();

    const events: string[] = [];
    const check = vi.fn()
      .mockImplementationOnce(async () => { events.push("binding"); })
      .mockRejectedValueOnce(new Error("socket rebound"));
    await expect(new LinuxAgentSessionLeases(location, units).launch(p, "A", () => {
      events.push("register"); return () => { events.push("revoke"); };
    }, check)).rejects.toThrow("socket rebound");
    expect(events).toEqual(["binding", "register", "revoke"]);
    expect(units.release).not.toHaveBeenCalled();
    expect(units.stop).toHaveBeenCalledOnce();
  });

  it("revokes and stops when a gated launch cannot be released", async () => {
    const location = await leases();
    const p = { ...plan(), launchGate: true };
    const units = manager(p);
    const events: string[] = [];
    units.release.mockRejectedValue(new Error("gate marker not written"));
    units.stop.mockImplementation(async () => { events.push("stop"); });
    await expect(new LinuxAgentSessionLeases(location, units).launch(p, "A", () => {
      events.push("register"); return () => { events.push("revoke"); };
    })).rejects.toThrow("gate marker not written");
    expect(events).toEqual(["register", "revoke", "stop"]);
    await expect(new LinuxAgentSessionLeases(location, units).launch(p, "A", () => () => {}))
      .rejects.toThrow("already used");
  });

  it("fails closed if a gated unit manager has no release method", async () => {
    const location = await leases();
    const p = { ...plan(), launchGate: true };
    const units = manager(p);
    const withoutRelease: LinuxAgentUnitManager = { start: units.start, inspect: units.inspect, stop: units.stop };
    const revoke = vi.fn();
    await expect(new LinuxAgentSessionLeases(location, withoutRelease).launch(p, "A", () => revoke))
      .rejects.toThrow("cannot be released");
    expect(revoke).toHaveBeenCalledOnce();
    expect(units.stop).toHaveBeenCalledOnce();
  });

  it("only one concurrent launch reserves the same identity", async () => {
    const location = await leases();
    const p = plan();
    const units = manager(p);
    const managerA = new LinuxAgentSessionLeases(location, units);
    const managerB = new LinuxAgentSessionLeases(location, units);
    const result = await Promise.allSettled([
      managerA.launch(p, "A", () => () => {}), managerB.launch(p, "B", () => () => {})
    ]);
    expect(result.filter(item => item.status === "fulfilled")).toHaveLength(1);
    expect(units.start).toHaveBeenCalledOnce();
  });

  it("rejects a reused session ID before starting a second unit with another UID", async () => {
    const location = await leases();
    const p = plan();
    const units = manager(p);
    await new LinuxAgentSessionLeases(location, units).launch(p, "A", () => () => {});
    const second = { ...plan(231002), sessionId: p.sessionId,
      rootDirectory: p.rootDirectory, brokerSocket: p.brokerSocket };
    await expect(new LinuxAgentSessionLeases(location, units).launch(second, "B", () => () => {}))
      .rejects.toThrow("already used");
    expect(units.start).toHaveBeenCalledOnce();
    expect(units.stop).not.toHaveBeenCalled();
  });

  it("does not stop a preexisting unit when systemd refuses a new start", async () => {
    const location = await leases();
    const p = plan();
    const units = manager(p);
    units.start.mockRejectedValue(new Error("unit already exists"));
    await expect(new LinuxAgentSessionLeases(location, units).launch(p, "A", () => () => {}))
      .rejects.toThrow("unit already exists");
    expect(units.stop).not.toHaveBeenCalled();
    expect(await readdir(location)).toContain(`session-${p.sessionId}`);
  });

  it("stops an unregistered unit and burns its UID if attestation fails", async () => {
    const location = await leases();
    const p = plan();
    const units = manager(p);
    units.inspect.mockResolvedValue({ ...await units.inspect(p), uid: 99999 });
    const register = vi.fn(() => () => {});
    const controller = new LinuxAgentSessionLeases(location, units);
    await expect(controller.launch(p, "A", register)).rejects.toThrow("identity changed");
    expect(units.stop).toHaveBeenCalledOnce();
    expect(register).not.toHaveBeenCalled();
    await expect(controller.launch(p, "A", register)).rejects.toThrow("already used");
  });

  it("revokes broker access before stopping and allows a failed stop to be retried", async () => {
    const location = await leases();
    const p = plan();
    const units = manager(p);
    const events: string[] = [];
    let attempts = 0;
    units.stop.mockImplementation(async () => {
      events.push("stop");
      if (++attempts === 1) throw new Error("unit still running");
    });
    const stop = await new LinuxAgentSessionLeases(location, units).launch(p, "A", () => () => {
      events.push("revoke");
    });
    await expect(stop()).rejects.toThrow("unit still running");
    await stop();
    expect(events).toEqual(["revoke", "stop", "stop"]);
  });

  it("rejects writable lease storage before calling systemd", async () => {
    const location = await leases();
    const p = plan();
    const units = manager(p);
    await chmod(location, 0o750);
    await expect(new LinuxAgentSessionLeases(location, units).launch(p, "A", () => () => {}))
      .rejects.toThrow("private to the broker");
    expect(units.start).not.toHaveBeenCalled();
  });
});
