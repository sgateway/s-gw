import { describe, expect, it, vi } from "vitest";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { brokerUnitInvocation, claimIdentityMarkers, sendControlReply, startTrackedManagedUnit,
  stopTrackedManagedUnit, validateLinuxManagedPlan,
  validateLinuxManagedPlanRecord, type LinuxManagedPlanRecord } from "../src/linux-agent-control.js";
import { validateLinuxManagedMcpConfig } from "../src/linux-managed-mcp.js";
import type { LinuxAgentUnitPlan } from "../src/linux-agent-unit.js";

function plan(): LinuxAgentUnitPlan {
  const brokerUid = process.getuid?.() ?? 1000;
  const brokerGid = process.getgid?.() ?? 1000;
  return {
    sessionId: "managed-session", uid: 230001, gid: 230001, brokerUid,
    rootDirectory: "/var/lib/s-gw/agent-roots/managed-session",
    brokerSocket: "/run/s-gw/agents/managed-session/broker.sock",
    executable: "/usr/bin/agent", args: [],
    launchGate: true, activatedSocket: true, isolatedSharedMemory: true,
    serializedLifecycle: true, sealedStdio: true, supervisedControlUnit: true
  };
}

function record(sessionId = "managed-session"): LinuxManagedPlanRecord {
  const agentPlan = { ...plan(), sessionId,
    rootDirectory: `/var/lib/s-gw/agent-roots/${sessionId}`,
    brokerSocket: `/run/s-gw/agents/${sessionId}/broker.sock` };
  const brokerUnit = `s-gw-managed-mcp-${sessionId}.service`;
  return { plan: agentPlan, brokerUnit,
    brokerUnitFile: `/run/systemd/system/${brokerUnit}`,
    brokerEntry: "/opt/s-gw/dist/linux-managed-mcp.js",
    brokerConfig: `/run/s-gw/${sessionId}.json` };
}

function brokerState(item: LinuxManagedPlanRecord, pid = 4123,
  invocation = "a".repeat(32)): string {
  return [`Id=${item.brokerUnit}`, "ActiveState=active", `MainPID=${pid}`,
    `ControlGroup=/system.slice/${item.brokerUnit}`, `InvocationID=${invocation}`,
    `FragmentPath=${item.brokerUnitFile}`, "BindsTo=s-gw-agent-control.service",
    "After=network.target s-gw-agent-control.service"].join("\n") + "\n";
}

describe("Linux managed MCP control", () => {
  it("requires the full supervised profile and a separate agent identity", () => {
    const good = plan();
    expect(() => validateLinuxManagedPlan(good, good.brokerUid, process.getgid?.() ?? 1000)).not.toThrow();
    for (const changed of [
      { launchGate: false }, { activatedSocket: false }, { isolatedSharedMemory: false },
      { serializedLifecycle: false }, { sealedStdio: false }, { supervisedControlUnit: false },
      { uid: good.brokerUid }, { gid: process.getgid?.() ?? 1000 }
    ]) {
      expect(() => validateLinuxManagedPlan({ ...good, ...changed },
        good.brokerUid, process.getgid?.() ?? 1000)).toThrow();
    }
  });

  it("requires one explicit absolute lease directory and a bounded display name", () => {
    const good = { name: "Managed agent", leaseDir: "/run/s-gw/managed-leases", plan: plan() };
    expect(() => validateLinuxManagedMcpConfig(good)).not.toThrow();
    expect(() => validateLinuxManagedMcpConfig({ ...good, leaseDir: "relative" })).toThrow();
    expect(() => validateLinuxManagedMcpConfig({ ...good, name: " " })).toThrow();
  });

  it("pins each broker unit and exact launch plan to a root registration", () => {
    const first = record();
    const second = record("another-session");
    const gid = process.getgid?.() ?? 1000;
    for (const item of [first, second]) {
      expect(() => validateLinuxManagedPlanRecord(item, item.plan.sessionId,
        item.plan.brokerUid, gid)).not.toThrow();
    }
    expect(() => validateLinuxManagedPlanRecord(first, second.plan.sessionId,
      first.plan.brokerUid, gid)).toThrow();
    expect(() => validateLinuxManagedPlanRecord({ ...first, brokerUnit: second.brokerUnit },
      first.plan.sessionId, first.plan.brokerUid, gid)).toThrow();
    expect(() => validateLinuxManagedPlanRecord({ ...first, brokerUnitFile: "/tmp/agent.service" },
      first.plan.sessionId, first.plan.brokerUid, gid)).toThrow();
    expect(() => validateLinuxManagedPlanRecord({ ...first, plan: { ...first.plan, uid: first.plan.brokerUid } },
      first.plan.sessionId, first.plan.brokerUid, gid)).toThrow();
  });

  it("rejects broker unit replacement, a foreign PID, and a new invocation", () => {
    const item = record();
    const attested = brokerState(item);
    const id = "a".repeat(32);
    expect(brokerUnitInvocation(item, 4123, attested, id)).toBe(id);
    for (const changed of [
      attested.replace("MainPID=4123", "MainPID=9999"),
      attested.replace("ActiveState=active", "ActiveState=inactive"),
      attested.replace(`FragmentPath=${item.brokerUnitFile}`, "FragmentPath=/tmp/forged.service"),
      attested.replace(`ControlGroup=/system.slice/${item.brokerUnit}`, "ControlGroup=/user.slice/other"),
      attested.replace("BindsTo=s-gw-agent-control.service", "BindsTo="),
      attested + "MainPID=4123\n"
    ]) {
      expect(() => brokerUnitInvocation(item, 4123, changed, id)).toThrow();
    }
    expect(() => brokerUnitInvocation(item, 4123, brokerState(item, 4123, "b".repeat(32)), id)).toThrow();
  });

  it("reserves UID and GID independently and rolls back only new pre-launch markers", async () => {
    const directory = await mkdtemp(path.join(tmpdir(), "s-gw-identity-"));
    try {
      const first = plan();
      await claimIdentityMarkers(first, directory);
      const initial = (await readdir(directory)).sort();
      expect(initial).toEqual([`gid-${first.gid}.used`, `session-${first.sessionId}.used`,
        `uid-${first.uid}.used`].sort());
      expect(await readFile(path.join(directory, `uid-${first.uid}.used`), "utf8"))
        .toBe(`${first.sessionId} ${first.uid} ${first.gid}\n`);

      await expect(claimIdentityMarkers({ ...first, sessionId: "same-uid", gid: first.gid + 1 },
        directory)).rejects.toThrow();
      await expect(claimIdentityMarkers({ ...first, sessionId: "same-gid", uid: first.uid + 1 },
        directory)).rejects.toThrow();
      await expect(claimIdentityMarkers({ ...first, uid: first.uid + 2, gid: first.gid + 2 },
        directory)).rejects.toThrow();
      expect((await readdir(directory)).sort()).toEqual(initial);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  it("does not stop another session after a verified pre-launch failure", async () => {
    const failure = new Error("preflight rejected the agent account");
    const manager = {
      start: vi.fn(async () => { throw failure; }),
      hasActiveLease: vi.fn(() => false),
      stop: vi.fn(async () => {})
    };
    const state = { started: false };
    await expect(startTrackedManagedUnit(manager, plan(), state)).rejects.toBe(failure);
    await stopTrackedManagedUnit(manager, plan(), state);
    expect(manager.hasActiveLease).toHaveBeenCalledWith(plan().sessionId);
    expect(manager.stop).not.toHaveBeenCalled();
  });

  it("retains cleanup responsibility after an uncertain start and failed stop", async () => {
    const failure = new Error("launch result is uncertain");
    const stopFailure = new Error("owned stop failed");
    const manager = {
      start: vi.fn(async () => { throw failure; }),
      hasActiveLease: vi.fn(() => true),
      stop: vi.fn(async () => { throw stopFailure; })
    };
    const state = { started: false };
    await expect(startTrackedManagedUnit(manager, plan(), state)).rejects.toBe(failure);
    expect(state.started).toBe(true);
    await expect(stopTrackedManagedUnit(manager, plan(), state)).rejects.toBe(stopFailure);
    expect(manager.stop).toHaveBeenCalledOnce();
    expect(state.started).toBe(true);
  });

  it("closes only the bad control connection when a reply cannot fit", () => {
    const write = vi.fn();
    const destroy = vi.fn();
    const socket = { destroyed: false, write, destroy } as unknown as Socket;

    expect(() => sendControlReply(socket, "x".repeat(32_000),
      { ok: false, error: "invalid call" })).not.toThrow();
    expect(write).not.toHaveBeenCalled();
    expect(destroy).toHaveBeenCalledOnce();

    destroy.mockClear();
    expect(() => sendControlReply(socket, 1,
      { ok: false, error: "x".repeat(33_000) })).not.toThrow();
    expect(write).not.toHaveBeenCalled();
    expect(destroy).toHaveBeenCalledOnce();
  });
});
