import { execFile } from "node:child_process";
import { lstat, readFile, readlink, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { attestDurableLinuxAgentIdentity } from "./linux-agent-identity.js";
import type { LinuxManagedPlanRecord } from "./linux-agent-control.js";
import type { LinuxAgentUnitPlan, LinuxAgentUnitState } from "./linux-agent-unit.js";
import { bindLinuxManagedForwarderSession, type LinuxBrokerSocketEvidence,
  type LinuxUnitProcessEvidence, type RootAttestedForwarderBinding } from "./linux-managed-forwarder-binding.js";
import type { PeerSession } from "./peer-identity.js";

const run = promisify(execFile);
const unitFields = ["Id", "LoadState", "ActiveState", "FragmentPath", "DropInPaths", "User", "Group",
  "SupplementaryGroups", "RootDirectory", "NetworkNamespacePath", "PrivateIPC", "PrivateTmp",
  "ProtectHome", "ProtectSystem", "NoNewPrivileges", "CapabilityBoundingSet", "AmbientCapabilities",
  "RestrictNamespaces", "SystemCallArchitectures", "KillMode", "BindsTo", "After", "ExecStart",
  "ControlGroup", "MainPID", "InvocationID"];

interface FileInfo {
  uid: number; gid: number; mode: number; nlink: number; dev: number; ino: number;
  isFile(): boolean; isSocket(): boolean; isDirectory(): boolean;
}

export interface LinuxForwarderAttestationHost {
  assertRoot(): Promise<void>;
  attestIdentity(plan: LinuxAgentUnitPlan): Promise<void>;
  attestAgentIsolation(pid: number): Promise<void>;
  unit(name: string, fields: string[]): Promise<string>;
  read(filename: string): Promise<string>;
  readlink(filename: string): Promise<string>;
  lstat(filename: string): Promise<FileInfo>;
  stat(filename: string): Promise<FileInfo>;
  realpath(filename: string): Promise<string>;
}

const nativeHost: LinuxForwarderAttestationHost = {
  async assertRoot() {
    if (process.platform !== "linux" || process.geteuid?.() !== 0) {
      throw new Error("Only Linux root control can attest a managed MCP forwarder.");
    }
  },
  attestIdentity: attestDurableLinuxAgentIdentity,
  async attestAgentIsolation() {
    throw new Error("Managed MCP forwarder agent mount and inherited-FD isolation is not attested.");
  },
  async unit(name, fields) {
    const { stdout } = await run("/usr/bin/systemctl", ["--system", "--no-pager", "--all", "show", name,
      ...fields.flatMap(field => ["-p", field])], { maxBuffer: 32 * 1024 });
    return stdout;
  },
  read: filename => readFile(filename, "utf8"),
  readlink, lstat, stat, realpath
};

function properties(output: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const line of output.trimEnd().split("\n")) {
    const split = line.indexOf("=");
    if (split < 1 || values.has(line.slice(0, split))) {
      throw new Error("Invalid live Linux forwarder unit properties.");
    }
    values.set(line.slice(0, split), line.slice(split + 1));
  }
  return values;
}

function assertUnit(record: LinuxManagedPlanRecord, values: Map<string, string>): LinuxAgentUnitState {
  const forwarder = record.mcpForwarder!;
  const name = path.basename(forwarder.unitFile);
  const entry = path.join(path.dirname(record.brokerEntry), "linux-managed-mcp-forwarder.js");
  const exec = values.get("ExecStart") || "";
  const command = `{ path=${record.brokerNode} ; argv[]=${record.brokerNode} ${entry} ; ignore_errors=no ; }`;
  const unit = [`Id=${name}`, "LoadState=loaded", "ActiveState=active",
    `FragmentPath=${forwarder.unitFile}`, "DropInPaths=", `User=${forwarder.uid}`,
    `Group=${forwarder.gid}`, "SupplementaryGroups=", `RootDirectory=${forwarder.rootDirectory}`,
    `NetworkNamespacePath=${forwarder.networkNamespacePath}`, "PrivateIPC=yes", "PrivateTmp=yes",
    "ProtectHome=yes", "ProtectSystem=strict", "NoNewPrivileges=yes", "CapabilityBoundingSet=0",
    "AmbientCapabilities=0", "RestrictNamespaces=yes", "SystemCallArchitectures=native",
    "KillMode=control-group"];
  for (const item of unit) {
    const split = item.indexOf("=");
    const expected = item.slice(split + 1);
    const actual = values.get(item.slice(0, split));
    if (actual !== expected && !(expected === "0" && actual === "")) {
      throw new Error("Live Linux forwarder unit differs from its root registration.");
    }
  }
  if (exec !== command) {
    throw new Error("Live Linux forwarder command differs from its trusted runtime.");
  }
  for (const field of ["BindsTo", "After"]) {
    const entries = new Set((values.get(field) || "").split(/\s+/));
    if (!entries.has("s-gw-agent-control.service") ||
        !entries.has(`s-gw-agent-${record.plan.sessionId}.service`)) {
      throw new Error("Linux forwarder does not share the agent and control lifecycle.");
    }
  }
  const mainPid = Number(values.get("MainPID"));
  const invocationId = values.get("InvocationID") || "";
  const cgroup = values.get("ControlGroup") || "";
  if (!Number.isSafeInteger(mainPid) || mainPid < 1 || !/^[a-f0-9]{32}$/.test(invocationId) ||
      cgroup !== `/system.slice/${name}`) {
    throw new Error("Linux forwarder has no stable live process identity.");
  }
  return { unit: name, uid: forwarder.uid, gid: forwarder.gid, cgroup, mainPid, invocationId };
}

function ids(status: string, field: "Uid" | "Gid"): [number, number, number, number] {
  const found = new RegExp(`^${field}:\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)$`, "m").exec(status);
  if (!found) throw new Error(`Live Linux process has no ${field} identity.`);
  return found.slice(1).map(Number) as [number, number, number, number];
}

function assertNoPrivileges(status: string): void {
  for (const field of ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]) {
    const value = new RegExp(`^${field}:\\s+([0-9a-fA-F]+)$`, "m").exec(status)?.[1];
    if (!value || !/^0+$/.test(value)) {
      throw new Error("Live Linux forwarder retains a capability.");
    }
  }
  if (!/^NoNewPrivs:\s+1$/m.test(status) || !/^Seccomp:\s+2$/m.test(status)) {
    throw new Error("Live Linux forwarder is missing its process restrictions.");
  }
}

async function processEvidence(host: LinuxForwarderAttestationHost,
  state: LinuxAgentUnitState): Promise<LinuxUnitProcessEvidence> {
  const pid = state.mainPid;
  const root = `/proc/${pid}`;
  const [procStatus, cgroup, environ, networkNamespace, pidNamespace, ipcNamespace, mountNamespace] =
    await Promise.all([host.read(`${root}/status`), host.read(`${root}/cgroup`),
      host.read(`${root}/environ`), host.readlink(`${root}/ns/net`), host.readlink(`${root}/ns/pid`),
      host.readlink(`${root}/ns/ipc`), host.readlink(`${root}/ns/mnt`)]);
  const invocation = environ.split("\0").filter(value => value.startsWith("INVOCATION_ID="));
  if (invocation.length !== 1 || invocation[0] !== `INVOCATION_ID=${state.invocationId}`) {
    throw new Error("Live Linux process invocation differs from systemd.");
  }
  const cgroupPath = cgroup.split("\n").filter(line => line.startsWith("0::"));
  if (cgroupPath.length !== 1) throw new Error("Live Linux process has no unique cgroup v2 path.");
  if (state.unit.startsWith("s-gw-forwarder-")) assertNoPrivileges(procStatus);
  return { pid, uids: ids(procStatus, "Uid"), gids: ids(procStatus, "Gid"), procStatus,
    cgroup: cgroupPath[0].slice(3), invocationId: state.invocationId,
    networkNamespace, pidNamespace, ipcNamespace, mountNamespace };
}

async function socketEvidence(host: LinuxForwarderAttestationHost,
  filename: string): Promise<LinuxBrokerSocketEvidence> {
  const item = await host.lstat(filename);
  if (!item.isSocket()) throw new Error("Linux forwarder broker endpoint is not a socket.");
  return { kind: "socket", uid: item.uid, gid: item.gid, mode: item.mode & 0o777,
    device: String(item.dev), inode: String(item.ino) };
}

async function rootOwnedFile(host: LinuxForwarderAttestationHost, filename: string): Promise<void> {
  const item = await host.lstat(filename);
  if (!item.isFile() || item.uid !== 0 || item.nlink !== 1 ||
      (item.mode & 0o022) !== 0 || await host.realpath(filename) !== filename) {
    throw new Error(`Linux forwarder unit or runtime is not root controlled: ${filename}`);
  }
  let parent = path.dirname(filename);
  while (true) {
    const dir = await host.lstat(parent);
    if (!dir.isDirectory() || dir.uid !== 0 || (dir.mode & 0o022) !== 0 ||
        await host.realpath(parent) !== parent) {
      throw new Error(`Linux forwarder runtime has an untrusted parent: ${parent}`);
    }
    const next = path.dirname(parent);
    if (next === parent) break;
    parent = next;
  }
}

async function absent(host: LinuxForwarderAttestationHost, filename: string): Promise<void> {
  try { await host.lstat(filename); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new Error("Agent root exposes a direct broker socket path in forwarder mode.");
}

export async function collectRootManagedForwarderSession(record: LinuxManagedPlanRecord,
  agentUnit: LinuxAgentUnitState, name: string,
  host: LinuxForwarderAttestationHost = nativeHost): Promise<{
    peer: PeerSession; proof: RootAttestedForwarderBinding;
  }> {
  await host.assertRoot();
  const forwarder = record.mcpForwarder;
  if (!forwarder) throw new Error("No root-registered Linux MCP forwarder is selected.");
  await host.attestIdentity(record.plan);
  const entry = path.join(path.dirname(record.brokerEntry), "linux-managed-mcp-forwarder.js");
  await rootOwnedFile(host, forwarder.unitFile);
  await rootOwnedFile(host, entry);
  await rootOwnedFile(host, record.brokerNode);
  await rootOwnedFile(host, forwarder.networkNamespacePath);
  const unit = assertUnit(record, properties(await host.unit(path.basename(forwarder.unitFile), unitFields)));
  const [agentProcess, forwarderProcess, brokerSocket, mountedBrokerSocket,
    hostNetworkNamespace, hostPidNamespace, forwarderRoot, configuredRoot,
    namespaceFile, configuredNamespace] = await Promise.all([
      processEvidence(host, agentUnit), processEvidence(host, unit),
      socketEvidence(host, record.plan.brokerSocket),
      socketEvidence(host, `/proc/${unit.mainPid}/root/run/s-gw/broker.sock`),
      host.readlink("/proc/self/ns/net"), host.readlink("/proc/self/ns/pid"),
      host.stat(`/proc/${unit.mainPid}/root`),
      host.stat(forwarder.rootDirectory), host.stat(`/proc/${unit.mainPid}/ns/net`),
      host.stat(forwarder.networkNamespacePath)
    ]);
  if (forwarderProcess.pidNamespace !== hostPidNamespace ||
      !forwarderRoot.isDirectory() || forwarderRoot.dev !== configuredRoot.dev ||
      forwarderRoot.ino !== configuredRoot.ino || namespaceFile.dev !== configuredNamespace.dev ||
      namespaceFile.ino !== configuredNamespace.ino) {
    throw new Error("Linux forwarder root or pinned network namespace changed.");
  }
  await absent(host, `/proc/${agentUnit.mainPid}/root/run/s-gw/broker.sock`);
  if (record.plan.modelRelaySocket) {
    await absent(host, `/proc/${agentUnit.mainPid}/root/run/s-gw/model.sock`);
  }
  await host.attestAgentIsolation(agentUnit.mainPid);
  const proof: RootAttestedForwarderBinding = {
    version: 1, sessionId: record.plan.sessionId, logicalAgentId: record.plan.logicalAgentId!,
    identityGeneration: record.plan.identityGeneration!, agentUid: agentUnit.uid, agentGid: agentUnit.gid,
    agentMainPid: agentUnit.mainPid, agentInvocationId: agentUnit.invocationId,
    forwarderUid: unit.uid, forwarderGid: unit.gid, forwarderMainPid: unit.mainPid,
    forwarderInvocationId: unit.invocationId, brokerUid: record.plan.brokerUid,
    networkNamespace: agentProcess.networkNamespace, hostNetworkNamespace,
    agentPidNamespace: agentProcess.pidNamespace, agentIpcNamespace: agentProcess.ipcNamespace,
    agentMountNamespace: agentProcess.mountNamespace,
    forwarderPidNamespace: forwarderProcess.pidNamespace,
    forwarderIpcNamespace: forwarderProcess.ipcNamespace,
    forwarderMountNamespace: forwarderProcess.mountNamespace,
    brokerSocketDevice: brokerSocket.device, brokerSocketInode: brokerSocket.inode
  };
  const peer = bindLinuxManagedForwarderSession({ plan: record.plan, name, brokerUid: record.plan.brokerUid,
    hostNetworkNamespace, durableIdentity: {
      logicalAgentId: record.plan.logicalAgentId!, identityGeneration: record.plan.identityGeneration!,
      uid: record.plan.uid, gid: record.plan.gid
    }, agentUnit, agentProcess, forwarderUnit: unit, forwarderProcess,
    brokerSocket, mountedBrokerSocket, rootAttestation: proof });
  return { peer, proof };
}
