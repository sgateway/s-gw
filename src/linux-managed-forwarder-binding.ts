import {
  linuxAgentUnitName, validateLinuxAgentPlan,
  type LinuxAgentUnitPlan, type LinuxAgentUnitState
} from "./linux-agent-unit.js";
import type { PeerSession } from "./peer-identity.js";

export interface LinuxUnitProcessEvidence {
  pid: number;
  uids: readonly [number, number, number, number];
  gids: readonly [number, number, number, number];
  cgroup: string;
  invocationId: string;
  networkNamespace: string;
  pidNamespace: string;
  ipcNamespace: string;
  mountNamespace: string;
}

export interface LinuxBrokerSocketEvidence {
  kind: "socket";
  device: string;
  inode: string;
  uid: number;
  gid: number;
  mode: number;
}

export interface RootAttestedForwarderBinding {
  version: 1;
  sessionId: string;
  logicalAgentId: string;
  identityGeneration: string;
  agentUid: number;
  agentGid: number;
  agentMainPid: number;
  agentInvocationId: string;
  forwarderUid: number;
  forwarderGid: number;
  forwarderMainPid: number;
  forwarderInvocationId: string;
  brokerUid: number;
  networkNamespace: string;
  hostNetworkNamespace: string;
  agentPidNamespace: string;
  agentIpcNamespace: string;
  agentMountNamespace: string;
  forwarderPidNamespace: string;
  forwarderIpcNamespace: string;
  forwarderMountNamespace: string;
  brokerSocketDevice: string;
  brokerSocketInode: string;
}

export interface LinuxManagedForwarderBindingInput {
  plan: LinuxAgentUnitPlan;
  name: string;
  brokerUid: number;
  hostNetworkNamespace: string;
  durableIdentity: {
    logicalAgentId: string;
    identityGeneration: string;
    uid: number;
    gid: number;
  };
  agentUnit: LinuxAgentUnitState;
  agentProcess: LinuxUnitProcessEvidence;
  forwarderUnit: LinuxAgentUnitState;
  forwarderProcess: LinuxUnitProcessEvidence;
  brokerSocket: LinuxBrokerSocketEvidence;
  mountedBrokerSocket: LinuxBrokerSocketEvidence;
  rootAttestation: RootAttestedForwarderBinding;
}

const invocationId = /^[a-f0-9]{32}$/;
const netNamespace = /^net:\[\d+\]$/;
const pidNamespace = /^pid:\[\d+\]$/;
const ipcNamespace = /^ipc:\[\d+\]$/;
const mountNamespace = /^mnt:\[\d+\]$/;
const decimal = /^[1-9][0-9]*$/;

// Only a root control service that has checked both live units should call this before registration.
export function bindLinuxManagedForwarderSession(input: LinuxManagedForwarderBindingInput): PeerSession {
  const plan = input.plan;
  validateLinuxAgentPlan(plan);
  if (!plan.launchGate || !plan.activatedSocket || !plan.serializedLifecycle ||
      !plan.sealedStdio || !plan.supervisedControlUnit || !plan.logicalAgentId ||
      !plan.identityGeneration || typeof input.name !== "string" ||
      !input.name.trim() || input.name.length > 120 ||
      input.brokerUid !== plan.brokerUid) {
    throw new Error("A durable root-managed agent plan is required for forwarder binding.");
  }
  const identity = input.durableIdentity;
  if (!identity || identity.logicalAgentId !== plan.logicalAgentId ||
      identity.identityGeneration !== plan.identityGeneration ||
      identity.uid !== plan.uid || identity.gid !== plan.gid) {
    throw new Error("The durable agent identity record differs from the managed plan.");
  }

  const agent = input.agentUnit;
  const forwarder = input.forwarderUnit;
  const agentName = linuxAgentUnitName(plan.sessionId);
  const forwarderName = `s-gw-forwarder-${plan.sessionId}.service`;
  assertLiveUnit(agent, input.agentProcess, agentName, plan.uid, plan.gid);
  assertLiveUnit(forwarder, input.forwarderProcess, forwarderName, forwarder.uid, forwarder.gid);
  if (forwarder.uid === plan.uid || forwarder.uid === plan.brokerUid ||
      forwarder.gid === plan.gid || agent.cgroup === forwarder.cgroup ||
      !netNamespace.test(input.hostNetworkNamespace) ||
      input.agentProcess.networkNamespace !== input.forwarderProcess.networkNamespace ||
      input.agentProcess.networkNamespace === input.hostNetworkNamespace ||
      input.agentProcess.pidNamespace === input.forwarderProcess.pidNamespace ||
      input.agentProcess.ipcNamespace === input.forwarderProcess.ipcNamespace ||
      input.agentProcess.mountNamespace === input.forwarderProcess.mountNamespace) {
    throw new Error("Forwarder and agent do not have separate identities in one private network namespace.");
  }

  const socket = input.brokerSocket;
  const mountedSocket = input.mountedBrokerSocket;
  if (!socket || !mountedSocket || socket.kind !== "socket" || mountedSocket.kind !== "socket" ||
      !decimal.test(socket.device) || !decimal.test(socket.inode) ||
      socket.uid !== 0 || socket.gid !== forwarder.gid || socket.mode !== 0o660 ||
      mountedSocket.device !== socket.device || mountedSocket.inode !== socket.inode ||
      mountedSocket.uid !== socket.uid || mountedSocket.gid !== socket.gid ||
      mountedSocket.mode !== socket.mode) {
    throw new Error("Forwarder mount does not contain the activated broker socket.");
  }

  const proof = input.rootAttestation;
  if (!proof || proof.version !== 1 || proof.sessionId !== plan.sessionId ||
      proof.logicalAgentId !== plan.logicalAgentId ||
      proof.identityGeneration !== plan.identityGeneration ||
      proof.agentUid !== agent.uid || proof.agentGid !== agent.gid ||
      proof.agentMainPid !== agent.mainPid || proof.agentInvocationId !== agent.invocationId ||
      proof.forwarderUid !== forwarder.uid || proof.forwarderGid !== forwarder.gid ||
      proof.forwarderMainPid !== forwarder.mainPid ||
      proof.forwarderInvocationId !== forwarder.invocationId ||
      proof.brokerUid !== input.brokerUid ||
      proof.networkNamespace !== input.agentProcess.networkNamespace ||
      proof.hostNetworkNamespace !== input.hostNetworkNamespace ||
      proof.agentPidNamespace !== input.agentProcess.pidNamespace ||
      proof.agentIpcNamespace !== input.agentProcess.ipcNamespace ||
      proof.agentMountNamespace !== input.agentProcess.mountNamespace ||
      proof.forwarderPidNamespace !== input.forwarderProcess.pidNamespace ||
      proof.forwarderIpcNamespace !== input.forwarderProcess.ipcNamespace ||
      proof.forwarderMountNamespace !== input.forwarderProcess.mountNamespace ||
      proof.brokerSocketDevice !== socket.device || proof.brokerSocketInode !== socket.inode) {
    throw new Error("Root forwarder attestation differs from live agent or forwarder evidence.");
  }

  return {
    uid: forwarder.uid, gid: forwarder.gid,
    sessionId: plan.sessionId, name: input.name,
    linuxCgroup: forwarder.cgroup,
    linuxIdentityGeneration: plan.identityGeneration
  };
}

function assertLiveUnit(unit: LinuxAgentUnitState, process: LinuxUnitProcessEvidence,
    expectedName: string, uid: number, gid: number): void {
  if (!Number.isSafeInteger(uid) || uid < 1 || !Number.isSafeInteger(gid) || gid < 1 ||
      unit.unit !== expectedName || unit.uid !== uid || unit.gid !== gid ||
      unit.cgroup !== `/system.slice/${expectedName}` ||
      !Number.isSafeInteger(unit.mainPid) || unit.mainPid < 1 ||
      !invocationId.test(unit.invocationId) ||
      !process || process.pid !== unit.mainPid ||
      !Array.isArray(process.uids) || process.uids.length !== 4 ||
      process.uids.some(value => value !== uid) ||
      !Array.isArray(process.gids) || process.gids.length !== 4 ||
      process.gids.some(value => value !== gid) ||
      process.cgroup !== unit.cgroup || process.invocationId !== unit.invocationId ||
      !netNamespace.test(process.networkNamespace) ||
      !pidNamespace.test(process.pidNamespace) ||
      !ipcNamespace.test(process.ipcNamespace) ||
      !mountNamespace.test(process.mountNamespace)) {
    throw new Error("Live unit process differs from its root-managed systemd identity.");
  }
}
