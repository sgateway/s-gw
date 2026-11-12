import { describe, expect, it } from "vitest";
import { renderLinuxAgentControlUnit, renderLinuxManagedUnitBundle } from "../src/linux-agent-provision.js";
import type { LinuxManagedMcpConfig } from "../src/linux-managed-mcp.js";
import type { LinuxManagedPlanRecord } from "../src/linux-agent-control.js";

function setup(relay = true): { config: LinuxManagedMcpConfig; record: LinuxManagedPlanRecord } {
  const sessionId = "example-agent";
  const plan = {
    sessionId, uid: 230101, gid: 230102, brokerUid: 230100,
    rootDirectory: `/var/lib/s-gw/agent-roots/${sessionId}`,
    brokerSocket: `/run/s-gw/agents/${sessionId}/broker.sock`,
    ...(relay ? { modelRelaySocket: `/run/s-gw/agents/${sessionId}/model.sock` } : {}),
    executable: "/usr/bin/agent", args: [], launchGate: true, activatedSocket: true,
    isolatedSharedMemory: true, serializedLifecycle: true, sealedStdio: true,
    supervisedControlUnit: true, restrictedSocketFamilies: true,
    requirePtracePolicy: true, logicalAgentId: sessionId,
    identityGeneration: "a".repeat(32)
  };
  const config: LinuxManagedMcpConfig = {
    name: "Example agent", leaseDir: "/run/s-gw/managed-leases", plan,
    ...(relay ? { relay: { grant: { handle: "s-gw:api-token:fixture", provider: "anthropic",
      routes: ["POST /v1/messages"], ttlMs: 30_000, payloadProfile: "strict" },
    requestId: "req_approved" } } : {})
  };
  const brokerUnit = `s-gw-managed-mcp-${sessionId}.service`;
  const record: LinuxManagedPlanRecord = {
    plan, brokerUnit,
    brokerUnitFile: `/run/systemd/system/${brokerUnit}`,
    mcpSocketUnitFile: `/run/systemd/system/s-gw-managed-mcp-${sessionId}.socket`,
    ...(relay ? { modelRelaySocketUnitFile:
      `/run/systemd/system/s-gw-managed-model-${sessionId}.socket` } : {}),
    brokerEntry: "/usr/libexec/s-gw/dist/linux-managed-mcp.js",
    brokerConfig: `/run/s-gw/${sessionId}.json`,
    brokerNode: "/usr/libexec/s-gw/node", brokerRuntimeRoot: "/usr/libexec/s-gw",
    brokerPreflight: "/usr/libexec/s-gw/s-gw-linux-broker-runtime",
    brokerEnvironmentFile: "/run/s-gw/broker.env", brokerCa: null
  };
  return { config, record };
}

describe.skipIf(process.platform === "win32")("Linux managed unit provisioning", () => {
  it("renders a pinned root control service without a startup environment file", () => {
    const text = renderLinuxAgentControlUnit({
      unitFile: "/run/systemd/system/s-gw-agent-control.service",
      runtimeRoot: "/usr/libexec/s-gw", preflight: "/usr/libexec/s-gw/s-gw-linux-broker-runtime",
      node: "/usr/libexec/s-gw/node", entry: "/usr/libexec/s-gw/control/linux-agent-control.js",
      brokerUid: 230100, brokerGid: 230103
    });
    expect(text).toContain("User=root\nGroup=root\n");
    expect(text).toContain("verify /usr/libexec/s-gw /usr/libexec/s-gw/node " +
      "/usr/libexec/s-gw/control/linux-agent-control.js " +
      "/run/systemd/system/s-gw-agent-control.service - -\n");
    expect(text).toContain("-- --serve 230100 230103\n");
    expect(text).toContain("UnsetEnvironment=NODE_OPTIONS NODE_PATH");
    expect(text).toContain(" NODE_EXTRA_CA_CERTS\n");
    expect(text).not.toContain("EnvironmentFile=");
    expect(() => renderLinuxAgentControlUnit({
      unitFile: "/run/systemd/system/s-gw-agent-control.service",
      runtimeRoot: "/usr/libexec/s-gw", preflight: "/usr/libexec/s-gw/s-gw-linux-broker-runtime",
      node: "/usr/libexec/s-gw/node", entry: "/tmp/linux-agent-control.js",
      brokerUid: 230100, brokerGid: 230103
    })).toThrow(/trusted runtime/);
    expect(() => renderLinuxAgentControlUnit({
      unitFile: "/run/systemd/system/s-gw-agent-control.service",
      runtimeRoot: "/usr/libexec/s-gw", preflight: "/usr/libexec/s-gw/s-gw-linux-broker-runtime",
      node: "/usr/libexec/s-gw/node", entry: undefined as unknown as string,
      brokerUid: 230100, brokerGid: 230103
    })).toThrow(/trusted runtime/);
    expect(() => renderLinuxAgentControlUnit({
      unitFile: "/run/systemd/system/s-gw-agent-control.service",
      runtimeRoot: "/usr/libexec/s-gw", preflight: "/usr/libexec/s-gw/../untrusted/verify",
      node: "/usr/libexec/s-gw/node", entry: "/usr/libexec/s-gw/control/linux-agent-control.js",
      brokerUid: 230100, brokerGid: 230103
    })).toThrow(/trusted runtime/);
  });

  it("renders a sealed, two-socket runtime bound to root control", () => {
    const { config, record } = setup();
    const files = renderLinuxManagedUnitBundle(config, record, 230103, "runtime");
    expect(JSON.parse(files.brokerConfig)).toEqual(config);
    expect(JSON.parse(files.planRecord)).toEqual(record);
    expect(files.mcpSocketUnit).toContain("ListenStream=/run/s-gw/agents/example-agent/broker.sock\n");
    expect(files.mcpSocketUnit).toContain("SocketGroup=230102\n");
    expect(files.mcpSocketUnit).toContain("PassCredentials=yes\n");
    expect(files.mcpSocketUnit).toContain("BindsTo=s-gw-agent-control.service\n");
    expect(files.modelSocketUnit).toContain("FileDescriptorName=s-gw-model-example-agent\n");
    expect(files.modelSocketUnit).toContain(`Service=${record.brokerUnit}\n`);
    expect(files.brokerUnit).toContain("User=230100\nGroup=230103\n");
    expect(files.brokerUnit).toContain("verify-exec /usr/libexec/s-gw /usr/libexec/s-gw/node");
    expect(files.brokerUnit).toContain("UnsetEnvironment=NODE_OPTIONS NODE_PATH");
  });

  it("preserves an opt-in client-only relay grant in the sealed broker config", () => {
    const { config, record } = setup();
    config.relay!.grant.toolBoundary = "client-only";
    const files = renderLinuxManagedUnitBundle(config, record, 230103, "runtime");
    expect(JSON.parse(files.brokerConfig).relay.grant.toolBoundary).toBe("client-only");
  });

  it("renders an unsealed preparation bundle without activating either socket", () => {
    const { config, record } = setup();
    config.relay!.requestId = undefined;
    const files = renderLinuxManagedUnitBundle(config, record, 230103, "prepare");
    expect(files.modelSocketUnit).toContain("ListenStream=/run/s-gw/agents/example-agent/model.sock\n");
    expect(JSON.parse(files.brokerConfig).relay.requestId).toBeUndefined();
    expect(() => renderLinuxManagedUnitBundle(config, record, 230103, "runtime"))
      .toThrow(/sealed request ID/);
  });

  it("keeps MCP-only provisioning available", () => {
    const { config, record } = setup(false);
    const files = renderLinuxManagedUnitBundle(config, record, 230103, "runtime");
    expect(files.modelSocketUnit).toBeUndefined();
    expect(files.mcpSocketUnit).toContain("FileDescriptorName=s-gw-agent-example-agent\n");
    expect(() => renderLinuxManagedUnitBundle(config, record, 230103, "prepare"))
      .toThrow(/model relay/);
  });

  it("assigns an opt-in MCP listener to the root-registered forwarder group", () => {
    const { config, record } = setup();
    config.mcpForwarder = { uid: 230104, gid: 230105 };
    record.mcpForwarder = { ...config.mcpForwarder,
      unitFile: "/run/systemd/system/s-gw-forwarder-example-agent.service",
      rootDirectory: "/var/lib/s-gw/forwarder-roots/example-agent",
      networkNamespacePath: "/run/s-gw/netns/example-agent" };
    const files = renderLinuxManagedUnitBundle(config, record, 230103, "runtime");
    expect(files.mcpSocketUnit).toContain("SocketGroup=230105\n");
    expect(files.modelSocketUnit).toContain("SocketGroup=230102\n");
    expect(() => renderLinuxManagedUnitBundle({ ...config,
      mcpForwarder: { uid: 230104, gid: 230106 } }, record, 230103, "runtime"))
      .toThrow(/forwarder differs/);
  });

  it("rejects mismatched, untrusted, and loose relay plans", () => {
    const { config, record } = setup();
    expect(() => renderLinuxManagedUnitBundle({ ...config,
      plan: { ...config.plan, uid: 230104 } }, record, 230103, "runtime"))
      .toThrow(/differs/);
    expect(() => renderLinuxManagedUnitBundle({ ...config,
      relay: { ...config.relay!, grant: { ...config.relay!.grant, payloadProfile: undefined } } },
    record, 230103, "runtime")).toThrow(/strict/);
    expect(() => renderLinuxManagedUnitBundle(config, { ...record,
      brokerEnvironmentFile: "/run/s-gw/broker.env\nExecStart=/bin/sh" }, 230103, "runtime"))
      .toThrow(/unsafe systemd/);
    expect(() => renderLinuxManagedUnitBundle(config, record, config.plan.gid, "runtime"))
      .toThrow(/dedicated/);
    const mcpOnly = setup(false);
    expect(() => renderLinuxManagedUnitBundle({ ...mcpOnly.config,
      plan: { ...mcpOnly.config.plan, logicalAgentId: undefined, identityGeneration: undefined } },
    { ...mcpOnly.record, plan: { ...mcpOnly.record.plan, logicalAgentId: undefined,
      identityGeneration: undefined } }, 230103, "runtime")).toThrow(/durable identity/);
    expect(() => renderLinuxManagedUnitBundle({ ...config,
      plan: { ...config.plan, requirePtracePolicy: false } }, { ...record,
      plan: { ...record.plan, requirePtracePolicy: false } }, 230103, "runtime"))
      .toThrow(/strict isolation/);
  });
});
