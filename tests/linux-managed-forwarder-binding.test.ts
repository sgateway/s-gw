import { describe, expect, it } from "vitest";
import { bindLinuxManagedForwarderSession,
  type LinuxManagedForwarderBindingInput } from "../src/linux-managed-forwarder-binding.js";

function fixture(): LinuxManagedForwarderBindingInput {
  const sessionId = "session-a";
  const generation = "a".repeat(32);
  const agentInvocation = "b".repeat(32);
  const forwarderInvocation = "c".repeat(32);
  const agentCgroup = `/system.slice/s-gw-agent-${sessionId}.service`;
  const forwarderCgroup = `/system.slice/s-gw-forwarder-${sessionId}.service`;
  const networkNamespace = "net:[777]";
  const hostNetworkNamespace = "net:[99]";
  const agentPidNamespace = "pid:[100]", forwarderPidNamespace = "pid:[200]";
  const agentIpcNamespace = "ipc:[101]", forwarderIpcNamespace = "ipc:[201]";
  const agentMountNamespace = "mnt:[102]", forwarderMountNamespace = "mnt:[202]";
  return {
    plan: {
      sessionId, uid: 31001, gid: 31001, brokerUid: 30001,
      rootDirectory: `/var/lib/s-gw/agent-roots/${sessionId}`,
      brokerSocket: `/run/s-gw/agents/${sessionId}/broker.sock`,
      modelRelaySocket: `/run/s-gw/agents/${sessionId}/model.sock`,
      executable: "/usr/bin/true", args: [], launchGate: true,
      activatedSocket: true, serializedLifecycle: true,
      sealedStdio: true, isolatedSharedMemory: true, supervisedControlUnit: true,
      logicalAgentId: "claude", identityGeneration: generation
    },
    name: "Claude",
    brokerUid: 30001,
    hostNetworkNamespace,
    durableIdentity: {
      logicalAgentId: "claude", identityGeneration: generation, uid: 31001, gid: 31001
    },
    agentUnit: {
      unit: `s-gw-agent-${sessionId}.service`, uid: 31001, gid: 31001,
      cgroup: agentCgroup, mainPid: 101, invocationId: agentInvocation
    },
    agentProcess: {
      pid: 101, uids: [31001, 31001, 31001, 31001],
      gids: [31001, 31001, 31001, 31001],
      procStatus: "Groups:\t31001\n",
      cgroup: agentCgroup, invocationId: agentInvocation, networkNamespace,
      pidNamespace: agentPidNamespace, ipcNamespace: agentIpcNamespace,
      mountNamespace: agentMountNamespace
    },
    forwarderUnit: {
      unit: `s-gw-forwarder-${sessionId}.service`, uid: 32001, gid: 32001,
      cgroup: forwarderCgroup, mainPid: 202, invocationId: forwarderInvocation
    },
    forwarderProcess: {
      pid: 202, uids: [32001, 32001, 32001, 32001],
      gids: [32001, 32001, 32001, 32001],
      procStatus: "Groups:\t32001\n",
      cgroup: forwarderCgroup, invocationId: forwarderInvocation, networkNamespace,
      pidNamespace: forwarderPidNamespace, ipcNamespace: forwarderIpcNamespace,
      mountNamespace: forwarderMountNamespace
    },
    brokerSocket: { kind: "socket", device: "10", inode: "20", uid: 0, gid: 32001, mode: 0o660 },
    mountedBrokerSocket: { kind: "socket", device: "10", inode: "20", uid: 0, gid: 32001, mode: 0o660 },
    rootAttestation: {
      version: 1, sessionId, logicalAgentId: "claude", identityGeneration: generation,
      agentUid: 31001, agentGid: 31001, agentMainPid: 101,
      agentInvocationId: agentInvocation,
      forwarderUid: 32001, forwarderGid: 32001, forwarderMainPid: 202,
      forwarderInvocationId: forwarderInvocation,
      brokerUid: 30001, networkNamespace, hostNetworkNamespace,
      agentPidNamespace, agentIpcNamespace, agentMountNamespace,
      forwarderPidNamespace, forwarderIpcNamespace, forwarderMountNamespace,
      brokerSocketDevice: "10", brokerSocketInode: "20"
    }
  };
}

describe("root-attested Linux forwarder binding", () => {
  it("registers only the forwarder peer while preserving the agent generation principal", () => {
    const input = fixture();
    expect(bindLinuxManagedForwarderSession(input)).toEqual({
      uid: 32001, gid: 32001, sessionId: "session-a", name: "Claude",
      linuxCgroup: "/system.slice/s-gw-forwarder-session-a.service",
      linuxIdentityGeneration: "a".repeat(32)
    });
  });

  it("rejects a different or host network namespace", () => {
    const separate = fixture();
    separate.forwarderProcess.networkNamespace = "net:[778]";
    expect(() => bindLinuxManagedForwarderSession(separate)).toThrow();
    const host = fixture();
    host.hostNetworkNamespace = "net:[777]";
    host.rootAttestation.hostNetworkNamespace = "net:[777]";
    expect(() => bindLinuxManagedForwarderSession(host)).toThrow();
  });

  it("requires separate PID, IPC, and mount namespaces with matching root proof", () => {
    for (const field of ["pidNamespace", "ipcNamespace", "mountNamespace"] as const) {
      const shared = fixture();
      shared.forwarderProcess[field] = shared.agentProcess[field];
      expect(() => bindLinuxManagedForwarderSession(shared)).toThrow();
      const stale = fixture();
      stale.forwarderProcess[field] = field === "pidNamespace" ? "pid:[999]" :
        field === "ipcNamespace" ? "ipc:[999]" : "mnt:[999]";
      expect(() => bindLinuxManagedForwarderSession(stale)).toThrow();
    }
  });

  it("rejects a replaced or incorrectly owned broker socket in the forwarder mount", () => {
    const replaced = fixture();
    replaced.mountedBrokerSocket.inode = "21";
    expect(() => bindLinuxManagedForwarderSession(replaced)).toThrow();
    const wrongGroup = fixture();
    wrongGroup.brokerSocket.gid = 31001;
    expect(() => bindLinuxManagedForwarderSession(wrongGroup)).toThrow();
    const staleProof = fixture();
    staleProof.rootAttestation.brokerSocketInode = "21";
    expect(() => bindLinuxManagedForwarderSession(staleProof)).toThrow();
    const wrongKind = fixture();
    (wrongKind.mountedBrokerSocket as { kind: string }).kind = "symlink";
    expect(() => bindLinuxManagedForwarderSession(wrongKind)).toThrow();
  });

  it("rejects forwarder identity reuse and changed process credentials", () => {
    const sharedUid = fixture();
    sharedUid.forwarderUnit.uid = 31001;
    sharedUid.forwarderProcess.uids = [31001, 31001, 31001, 31001];
    sharedUid.rootAttestation.forwarderUid = 31001;
    expect(() => bindLinuxManagedForwarderSession(sharedUid)).toThrow();
    const sharedGid = fixture();
    sharedGid.forwarderUnit.gid = 31001;
    sharedGid.forwarderProcess.gids = [31001, 31001, 31001, 31001];
    sharedGid.rootAttestation.forwarderGid = 31001;
    expect(() => bindLinuxManagedForwarderSession(sharedGid)).toThrow();
    const changedFsUid = fixture();
    changedFsUid.forwarderProcess.uids = [32001, 32001, 32001, 30001];
    expect(() => bindLinuxManagedForwarderSession(changedFsUid)).toThrow();
  });

  it("rejects supplementary groups on either process", () => {
    const agentExtra = fixture();
    agentExtra.agentProcess.procStatus = "Groups:\t31001 32001\n";
    expect(() => bindLinuxManagedForwarderSession(agentExtra)).toThrow();
    const forwarderExtra = fixture();
    forwarderExtra.forwarderProcess.procStatus = "Groups:\t32001 30001\n";
    expect(() => bindLinuxManagedForwarderSession(forwarderExtra)).toThrow();
    const missingGroups = fixture();
    missingGroups.forwarderProcess.procStatus = "Name:\tforwarder\n";
    expect(() => bindLinuxManagedForwarderSession(missingGroups)).toThrow();
    const emptyGroups = fixture();
    emptyGroups.forwarderProcess.procStatus = "Groups:\t\n";
    expect(() => bindLinuxManagedForwarderSession(emptyGroups)).not.toThrow();
  });

  it("rejects stale process, cgroup, invocation, and root generation", () => {
    const stalePid = fixture();
    stalePid.forwarderProcess.pid = 203;
    expect(() => bindLinuxManagedForwarderSession(stalePid)).toThrow();
    const wrongCgroup = fixture();
    wrongCgroup.forwarderProcess.cgroup = "/system.slice/other.service";
    expect(() => bindLinuxManagedForwarderSession(wrongCgroup)).toThrow();
    const wrongInvocation = fixture();
    wrongInvocation.rootAttestation.agentInvocationId = "d".repeat(32);
    expect(() => bindLinuxManagedForwarderSession(wrongInvocation)).toThrow();
    const staleForwarder = fixture();
    staleForwarder.forwarderProcess.invocationId = "d".repeat(32);
    expect(() => bindLinuxManagedForwarderSession(staleForwarder)).toThrow();
    const wrongGeneration = fixture();
    wrongGeneration.rootAttestation.identityGeneration = "d".repeat(32);
    expect(() => bindLinuxManagedForwarderSession(wrongGeneration)).toThrow();
    const missingDurableGeneration = fixture();
    missingDurableGeneration.durableIdentity.identityGeneration = "d".repeat(32);
    expect(() => bindLinuxManagedForwarderSession(missingDurableGeneration)).toThrow();
  });

  it("requires a durable managed plan and exact root-attested session", () => {
    const noGeneration = fixture();
    delete noGeneration.plan.identityGeneration;
    expect(() => bindLinuxManagedForwarderSession(noGeneration)).toThrow();
    const wrongSession = fixture();
    wrongSession.rootAttestation.sessionId = "session-b";
    expect(() => bindLinuxManagedForwarderSession(wrongSession)).toThrow();
  });
});
