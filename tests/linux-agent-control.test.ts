import { describe, expect, it } from "vitest";
import { validateLinuxManagedPlan } from "../src/linux-agent-control.js";
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
});
