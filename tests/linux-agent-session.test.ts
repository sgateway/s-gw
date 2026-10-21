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
