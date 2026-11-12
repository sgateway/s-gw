import { describe, expect, it } from "vitest";
import { collectRootManagedForwarderSession,
  type LinuxForwarderAttestationHost } from "../src/linux-managed-forwarder-attestation.js";
import type { LinuxManagedPlanRecord } from "../src/linux-agent-control.js";
import type { LinuxAgentUnitState } from "../src/linux-agent-unit.js";

interface FakeFile {
  uid: number; gid: number; mode: number; nlink: number; dev: number; ino: number;
  isFile(): boolean; isSocket(): boolean; isDirectory(): boolean;
}

function file(kind: "file" | "socket" | "directory", uid: number, gid: number,
  mode: number, dev = 1, ino = 1): FakeFile {
  return { uid, gid, mode, dev, ino, nlink: 1,
    isFile: () => kind === "file", isSocket: () => kind === "socket",
    isDirectory: () => kind === "directory" };
}

function fixture() {
  const sessionId = "managed-a";
  const agentInvocation = "a".repeat(32), forwarderInvocation = "b".repeat(32);
  const record: LinuxManagedPlanRecord = {
    plan: {
      sessionId, uid: 31001, gid: 31001, brokerUid: 30001,
      rootDirectory: `/var/lib/s-gw/agent-roots/${sessionId}`,
      brokerSocket: `/run/s-gw/agents/${sessionId}/broker.sock`,
      executable: "/usr/bin/agent", args: [], launchGate: true, activatedSocket: true,
      isolatedSharedMemory: true, serializedLifecycle: true, sealedStdio: true,
      supervisedControlUnit: true, logicalAgentId: "claude", identityGeneration: "c".repeat(32)
    },
    brokerUnit: `s-gw-managed-mcp-${sessionId}.service`,
    brokerUnitFile: `/run/systemd/system/s-gw-managed-mcp-${sessionId}.service`,
    mcpSocketUnitFile: `/run/systemd/system/s-gw-managed-mcp-${sessionId}.socket`,
    brokerEntry: "/opt/s-gw/dist/linux-managed-mcp.js", brokerConfig: `/run/s-gw/${sessionId}.json`,
    brokerNode: "/opt/s-gw/node", brokerRuntimeRoot: "/opt/s-gw",
    brokerPreflight: "/opt/s-gw/s-gw-linux-broker-runtime",
    brokerEnvironmentFile: "/run/s-gw/broker.env", brokerCa: null,
    mcpForwarder: { uid: 32001, gid: 32001,
      unitFile: `/run/systemd/system/s-gw-forwarder-${sessionId}.service`,
      rootDirectory: `/var/lib/s-gw/forwarder-roots/${sessionId}`,
      networkNamespacePath: `/run/s-gw/netns/${sessionId}` }
  };
  const agentUnit: LinuxAgentUnitState = { unit: `s-gw-agent-${sessionId}.service`,
    uid: 31001, gid: 31001, cgroup: `/system.slice/s-gw-agent-${sessionId}.service`,
    mainPid: 101, invocationId: agentInvocation };
  const unitText = [
    `Id=s-gw-forwarder-${sessionId}.service`, "LoadState=loaded", "ActiveState=active",
    `FragmentPath=${record.mcpForwarder!.unitFile}`, "DropInPaths=", "User=32001", "Group=32001",
    "SupplementaryGroups=", `RootDirectory=${record.mcpForwarder!.rootDirectory}`,
    `NetworkNamespacePath=${record.mcpForwarder!.networkNamespacePath}`, "PrivateIPC=yes",
    "PrivateTmp=yes", "ProtectHome=yes", "ProtectSystem=strict", "NoNewPrivileges=yes",
    "CapabilityBoundingSet=0", "AmbientCapabilities=0", "RestrictNamespaces=yes",
    "SystemCallArchitectures=native", "KillMode=control-group",
    `BindsTo=s-gw-agent-control.service ${agentUnit.unit}`,
    `After=s-gw-agent-control.service ${agentUnit.unit}`,
    "ExecStart={ path=/opt/s-gw/node ; argv[]=/opt/s-gw/node /opt/s-gw/dist/linux-managed-mcp-forwarder.js ; ignore_errors=no ; }",
    `ControlGroup=/system.slice/s-gw-forwarder-${sessionId}.service`, "MainPID=202",
    `InvocationID=${forwarderInvocation}`
  ].join("\n") + "\n";
  const reads = new Map<string, string>([
    ["/proc/101/status", "Uid:\t31001\t31001\t31001\t31001\nGid:\t31001\t31001\t31001\t31001\nGroups:\t31001\n"],
    ["/proc/101/cgroup", `0::${agentUnit.cgroup}\n`],
    ["/proc/101/environ", `INVOCATION_ID=${agentInvocation}\0`],
    ["/proc/202/status", "Uid:\t32001\t32001\t32001\t32001\nGid:\t32001\t32001\t32001\t32001\nGroups:\t32001\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"],
    ["/proc/202/cgroup", `0::/system.slice/s-gw-forwarder-${sessionId}.service\n`],
    ["/proc/202/environ", `INVOCATION_ID=${forwarderInvocation}\0`]
  ]);
  const links = new Map<string, string>([
    ["/proc/101/ns/net", "net:[777]"], ["/proc/202/ns/net", "net:[777]"],
    ["/proc/self/ns/net", "net:[99]"],
    ["/proc/self/ns/pid", "pid:[200]"],
    ["/proc/101/ns/pid", "pid:[100]"], ["/proc/202/ns/pid", "pid:[200]"],
    ["/proc/101/ns/ipc", "ipc:[101]"], ["/proc/202/ns/ipc", "ipc:[201]"],
    ["/proc/101/ns/mnt", "mnt:[102]"], ["/proc/202/ns/mnt", "mnt:[202]"]
  ]);
  const files = new Map<string, FakeFile>([
    [record.mcpForwarder!.unitFile, file("file", 0, 0, 0o100644)],
    ["/opt/s-gw/dist/linux-managed-mcp-forwarder.js", file("file", 0, 0, 0o100644)],
    [record.brokerNode, file("file", 0, 0, 0o100755)],
    [record.plan.brokerSocket, file("socket", 0, 32001, 0o140660, 10, 20)],
    ["/proc/202/root/run/s-gw/broker.sock", file("socket", 0, 32001, 0o140660, 10, 20)],
    ["/proc/202/root", file("directory", 0, 0, 0o40755, 4, 40)],
    [record.mcpForwarder!.rootDirectory, file("directory", 0, 0, 0o40755, 4, 40)],
    ["/proc/202/ns/net", file("file", 0, 0, 0o100444, 5, 50)],
    [record.mcpForwarder!.networkNamespacePath, file("file", 0, 0, 0o100444, 5, 50)]
  ]);
  for (const name of [record.mcpForwarder!.unitFile,
    "/opt/s-gw/dist/linux-managed-mcp-forwarder.js", record.brokerNode,
    record.mcpForwarder!.networkNamespacePath]) {
    let parent = name.slice(0, name.lastIndexOf("/")) || "/";
    while (!files.has(parent)) {
      files.set(parent, file("directory", 0, 0, 0o40755));
      if (parent === "/") break;
      parent = parent.slice(0, parent.lastIndexOf("/")) || "/";
    }
  }
  const host: LinuxForwarderAttestationHost = {
    assertRoot: async () => {}, attestIdentity: async () => {}, attestAgentIsolation: async () => {},
    unit: async () => unitText,
    read: async name => { const value = reads.get(name); if (value === undefined) throw Error(name); return value; },
    readlink: async name => { const value = links.get(name); if (!value) throw Error(name); return value; },
    lstat: async name => { const value = files.get(name); if (!value) throw Object.assign(Error(name), { code: "ENOENT" }); return value; },
    stat: async name => { const value = files.get(name); if (!value) throw Error(name); return value; },
    realpath: async name => name
  };
  return { record, agentUnit, host, files, reads, links, unitText };
}

describe("product Linux MCP forwarder attestation", () => {
  it("registers only a root-collected live forwarder identity and agent generation", async () => {
    const { record, agentUnit, host } = fixture();
    const binding = await collectRootManagedForwarderSession(record, agentUnit, "Claude", host);
    expect(binding.peer).toEqual({ uid: 32001, gid: 32001, sessionId: "managed-a", name: "Claude",
      linuxCgroup: "/system.slice/s-gw-forwarder-managed-a.service",
      linuxIdentityGeneration: "c".repeat(32) });
    expect(binding.proof.forwarderMainPid).toBe(202);
    expect(binding.proof.brokerSocketInode).toBe("20");
  });

  it("fails closed on a changed invocation, supplementary group, namespace, and socket inode", async () => {
    const changed = [
      (x: ReturnType<typeof fixture>) => x.reads.set("/proc/202/environ", `INVOCATION_ID=${"d".repeat(32)}\0`),
      (x: ReturnType<typeof fixture>) => x.reads.set("/proc/202/status",
        x.reads.get("/proc/202/status")!.replace("Groups:\t32001", "Groups:\t32001 30001")),
      (x: ReturnType<typeof fixture>) => x.reads.set("/proc/202/status",
        x.reads.get("/proc/202/status")!.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001")),
      (x: ReturnType<typeof fixture>) => x.links.set("/proc/202/ns/net", "net:[778]"),
      (x: ReturnType<typeof fixture>) => x.files.set("/proc/202/root/run/s-gw/broker.sock",
        file("socket", 0, 32001, 0o140660, 10, 21))
    ];
    for (const mutate of changed) {
      const x = fixture(); mutate(x);
      await expect(collectRootManagedForwarderSession(x.record, x.agentUnit, "Claude", x.host))
        .rejects.toThrow();
    }
  });

  it("refuses an agent-visible broker socket and a replaced unit", async () => {
    const direct = fixture();
    direct.files.set("/proc/101/root/run/s-gw/broker.sock",
      file("socket", 0, 32001, 0o140660, 10, 20));
    await expect(collectRootManagedForwarderSession(direct.record, direct.agentUnit, "Claude", direct.host))
      .rejects.toThrow(/direct broker socket/);
    const unit = fixture();
    unit.host.unit = async () => unit.unitText.replace("DropInPaths=", "DropInPaths=/tmp/override.conf");
    await expect(collectRootManagedForwarderSession(unit.record, unit.agentUnit, "Claude", unit.host))
      .rejects.toThrow(/unit differs/);
  });

  it("cannot register when the agent mount and FD gate has no trusted proof", async () => {
    const x = fixture();
    x.host.attestAgentIsolation = async () => {
      throw new Error("Managed MCP forwarder agent mount and inherited-FD isolation is not attested.");
    };
    await expect(collectRootManagedForwarderSession(x.record, x.agentUnit, "Claude", x.host))
      .rejects.toThrow(/inherited-FD isolation is not attested/);
  });
});
