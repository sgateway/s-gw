import { spawn, type StdioOptions } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants } from "node:fs";
import { chmod, lstat, mkdir, open, readFile, readlink, readdir, realpath, rename, rmdir, stat, unlink } from "node:fs/promises";
import path from "node:path";
import { validLinuxCgroupPath } from "./linux-peer-identity.js";

export interface LinuxAgentUnitPlan {
  sessionId: string;
  uid: number;
  gid: number;
  brokerUid: number;
  rootDirectory: string;
  brokerSocket: string;
  executable: string;
  args: readonly string[];
  launchGate?: boolean;
  activatedSocket?: boolean;
  isolatedSharedMemory?: boolean;
  serializedLifecycle?: boolean;
  launchAttemptFence?: boolean;
  sealedStdio?: boolean;
  supervisedControlUnit?: boolean;
  logicalAgentId?: string;
  identityGeneration?: string;
}

export interface LinuxAgentUnitState {
  unit: string;
  uid: number;
  gid: number;
  cgroup: string;
  mainPid: number;
  invocationId: string;
}

export interface LinuxAgentUnitManager {
  start(plan: LinuxAgentUnitPlan): Promise<void>;
  inspect(plan: LinuxAgentUnitPlan): Promise<LinuxAgentUnitState>;
  release?(plan: LinuxAgentUnitPlan, state: LinuxAgentUnitState): Promise<void>;
  stop(plan: LinuxAgentUnitPlan): Promise<void>;
}

const rootPrefix = "/var/lib/s-gw/agent-roots/";
const socketPrefix = "/run/s-gw/agents/";
const gatePrefix = "/run/s-gw/launch-gates/";
const lifecycleRoot = "/run/s-gw/agent-unit-lifecycle";
const gateExecutable = "/usr/libexec/s-gw/agent-launch-gate";
const gateMount = "/run/s-gw/launch-gate";
const privateSharedMemoryMount = "/dev/shm:rw,nosuid,nodev,noexec,mode=1777";
const unitProperties = [
  "Type=exec", "Restart=no", "KillMode=control-group", "SendSIGKILL=yes", "Delegate=no",
  "DynamicUser=no", "PrivateUsers=no",
  "PrivateNetwork=yes", "PrivateIPC=yes", "PrivateTmp=yes",
  "ProtectSystem=strict", "ProtectHome=yes", "PrivateDevices=yes",
  "NoNewPrivileges=yes", "CapabilityBoundingSet=", "AmbientCapabilities=",
  "ProtectKernelTunables=yes", "ProtectKernelModules=yes", "ProtectControlGroups=yes",
  "RestrictNamespaces=yes", "RestrictSUIDSGID=yes"
];

export function linuxAgentUnitName(sessionId: string): string {
  if (!/^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(sessionId)) {
    throw new Error("Linux agent session ID is invalid for a dedicated unit.");
  }
  return `s-gw-agent-${sessionId}.service`;
}

export function validateLinuxAgentPlan(plan: LinuxAgentUnitPlan): void {
  linuxAgentUnitName(plan.sessionId);
  const durableIdentity = plan.logicalAgentId !== undefined || plan.identityGeneration !== undefined;
  if (!Number.isSafeInteger(plan.uid) || plan.uid < 1 ||
      !Number.isSafeInteger(plan.gid) || plan.gid < 1 ||
      !Number.isSafeInteger(plan.brokerUid) || plan.brokerUid < 1 || plan.uid === plan.brokerUid) {
    throw new Error("Linux agent needs a dedicated UID and GID.");
  }
  if (!canonicalPath(plan.rootDirectory) || plan.rootDirectory !== `${rootPrefix}${plan.sessionId}` ||
      !canonicalPath(plan.brokerSocket) ||
      plan.brokerSocket !== `${socketPrefix}${plan.sessionId}/broker.sock`) {
    throw new Error("Linux agent root and broker socket must use managed paths.");
  }
  if (!canonicalPath(plan.executable) || !plan.executable.startsWith("/usr/") ||
      (plan.launchGate !== undefined && typeof plan.launchGate !== "boolean") ||
      (plan.activatedSocket !== undefined && typeof plan.activatedSocket !== "boolean") ||
      (plan.isolatedSharedMemory !== undefined && typeof plan.isolatedSharedMemory !== "boolean") ||
      (plan.isolatedSharedMemory === true && plan.launchGate !== true) ||
      (plan.serializedLifecycle !== undefined && typeof plan.serializedLifecycle !== "boolean") ||
      (plan.serializedLifecycle === true && plan.launchGate !== true) ||
      (plan.launchAttemptFence !== undefined && typeof plan.launchAttemptFence !== "boolean") ||
      (plan.serializedLifecycle === true && plan.launchAttemptFence === false) ||
      (plan.sealedStdio !== undefined && typeof plan.sealedStdio !== "boolean") ||
      (plan.sealedStdio === true && plan.launchGate !== true) ||
      (plan.supervisedControlUnit !== undefined && typeof plan.supervisedControlUnit !== "boolean") ||
      (plan.supervisedControlUnit === true && (!plan.launchGate || !plan.activatedSocket ||
        !plan.serializedLifecycle || !plan.sealedStdio || !plan.isolatedSharedMemory)) ||
      (durableIdentity && (typeof plan.logicalAgentId !== "string" ||
        !/^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(plan.logicalAgentId) ||
        typeof plan.identityGeneration !== "string" ||
        !/^[a-f0-9]{32}$/.test(plan.identityGeneration) || !plan.supervisedControlUnit)) ||
      !Array.isArray(plan.args) || plan.args.length > 128 ||
      plan.args.some(arg => typeof arg !== "string" || arg.includes("\0") || arg.length > 4096)) {
    throw new Error("Linux agent executable or arguments are invalid.");
  }
}

export function linuxLaunchAttemptFenceEnabled(plan: LinuxAgentUnitPlan): boolean {
  validateLinuxAgentPlan(plan);
  return plan.serializedLifecycle === true || plan.launchAttemptFence === true;
}

export function systemdRunArgs(plan: LinuxAgentUnitPlan, attemptId?: string): string[] {
  validateLinuxAgentPlan(plan);
  if (attemptId !== undefined && !/^[a-f0-9]{32}$/.test(attemptId)) {
    throw new Error("Invalid Linux agent launch attempt ID.");
  }
  const unit = linuxAgentUnitName(plan.sessionId);
  const properties = [
    ...unitProperties,
    `User=${plan.uid}`, `Group=${plan.gid}`,
    `RootDirectory=${plan.rootDirectory}`,
    "WorkingDirectory=/workspace",
    `ReadWritePaths=${plan.rootDirectory}/workspace`,
    `BindReadOnlyPaths=${bindReadOnlyPaths(plan)}`,
    ...(plan.isolatedSharedMemory ? [`TemporaryFileSystem=${privateSharedMemoryMount}`] : []),
    ...(plan.sealedStdio ? ["StandardInput=null", "StandardOutput=null", "StandardError=null"] : []),
    ...(plan.supervisedControlUnit ? ["BindsTo=s-gw-agent-control.service", "After=s-gw-agent-control.service"] : []),
    "Environment=SGW_BROKER_SOCKET=/run/s-gw/broker.sock"
  ];
  return ["--system", "--no-ask-password", `--unit=${unit}`,
    ...(attemptId ? [`--description=s-gw-agent-start:${attemptId}`] : []),
    ...properties.map(value => `--property=${value}`),
    "--", ...(plan.launchGate ? [gateExecutable, "--"] : []), plan.executable, ...plan.args];
}

export function linuxUnitOwnedByStartAttempt(plan: LinuxAgentUnitPlan, attemptId: string, output: string): boolean {
  validateLinuxAgentPlan(plan);
  if (!/^[a-f0-9]{32}$/.test(attemptId)) return false;
  const fields = new Map<string, string>();
  for (const line of output.trimEnd().split("\n")) {
    const index = line.indexOf("=");
    if (index < 1 || fields.has(line.slice(0, index))) return false;
    fields.set(line.slice(0, index), line.slice(index + 1));
  }
  return fields.get("Id") === linuxAgentUnitName(plan.sessionId) &&
    fields.get("Description") === `s-gw-agent-start:${attemptId}` &&
    fields.get("User") === String(plan.uid) && fields.get("Group") === String(plan.gid) &&
    fields.get("RootDirectory") === plan.rootDirectory;
}

interface PreparedLinuxUnitStart {
  launch(): Promise<void>;
  inspectOwnership(): Promise<string>;
  verify(): Promise<void>;
  stopOwned(): Promise<void>;
}

interface LinuxUnitLifecycleLease {
  attemptId: string;
  planKey: string;
  directory: string;
  marker: string;
  dev: number;
  ino: number;
  busy: boolean;
  invocationId?: string;
}

export interface LinuxUnitLaunchFence {
  filename: string;
  marker: string;
  attemptId: string;
  dev: number;
  ino: number;
}

export function lifecyclePlanKey(plan: LinuxAgentUnitPlan): string {
  const fields = [plan.sessionId, plan.uid, plan.gid, plan.brokerUid,
    plan.rootDirectory, plan.brokerSocket, plan.executable, plan.args,
    plan.launchGate === true, plan.activatedSocket === true,
    plan.isolatedSharedMemory === true, plan.serializedLifecycle === true,
    linuxLaunchAttemptFenceEnabled(plan), plan.sealedStdio === true,
    plan.supervisedControlUnit === true];
  if (plan.identityGeneration) fields.push(plan.logicalAgentId!, plan.identityGeneration);
  return JSON.stringify(fields);
}

export async function stopOwnedLinuxAgentUnit(plan: LinuxAgentUnitPlan, attemptId: string,
  invocationId: string | undefined, operations: {
    inspectOwnership(): Promise<string>;
    stopOwned(): Promise<void>;
  }): Promise<void> {
  const output = await operations.inspectOwnership();
  if (!linuxUnitOwnedByStartAttempt(plan, attemptId, output) ||
      (invocationId !== undefined && !output.split("\n").includes(`InvocationID=${invocationId}`))) {
    throw new Error("Linux agent unit changed before its owned stop.");
  }
  await operations.stopOwned();
}

export async function startPreparedLinuxAgentUnit(plan: LinuxAgentUnitPlan, attemptId: string,
  operations: PreparedLinuxUnitStart): Promise<void> {
  const stopAttempt = async () => {
    const output = await operations.inspectOwnership();
    if (!linuxUnitOwnedByStartAttempt(plan, attemptId, output)) return false;
    await operations.stopOwned();
    return true;
  };
  try {
    await operations.launch();
  } catch (error) {
    try { await stopAttempt(); }
    catch (cleanupError) {
      throw new AggregateError([error, cleanupError], "Linux agent start and teardown failed.");
    }
    throw error;
  }
  try {
    await operations.verify();
  } catch (error) {
    try {
      if (!await stopAttempt()) throw new Error("Could not prove ownership of the failed Linux agent start.");
    } catch (stopError) {
      throw new AggregateError([error, stopError], "Linux agent start and teardown failed.");
    }
    throw error;
  }
}

function gateDirectory(plan: LinuxAgentUnitPlan): string {
  return `${gatePrefix}${plan.sessionId}`;
}

function bindReadOnlyPaths(plan: LinuxAgentUnitPlan): string {
  const broker = `${plan.brokerSocket}:/run/s-gw/broker.sock`;
  return plan.launchGate ? `${broker} ${gateDirectory(plan)}:${gateMount}` : broker;
}

function attestedReadOnlyPaths(plan: LinuxAgentUnitPlan, value: string | undefined): boolean {
  const expected = bindReadOnlyPaths(plan).split(" ");
  const actual = value?.split(" ") || [];
  return actual.length === expected.length &&
    actual.every((entry, index) => entry === expected[index] || entry === `${expected[index]}:rbind`);
}

export function parseSystemdAgentState(plan: LinuxAgentUnitPlan, output: string): LinuxAgentUnitState {
  validateLinuxAgentPlan(plan);
  const fields = new Map<string, string>();
  for (const line of output.trimEnd().split("\n")) {
    const index = line.indexOf("=");
    if (index < 1) throw new Error("Invalid Linux agent unit attestation.");
    const key = line.slice(0, index);
    if (fields.has(key)) throw new Error("Duplicate Linux agent unit property.");
    fields.set(key, line.slice(index + 1));
  }
  const matches = (name: string, value: string) => fields.get(name) === value;
  const enabled = (name: string) => ["yes", "true", "1"].includes(fields.get(name) || "");
  const disabled = (name: string) => ["no", "false", "0"].includes(fields.get(name) || "");
  const unit = linuxAgentUnitName(plan.sessionId);
  const cgroup = fields.get("ControlGroup") || "";
  const mainPid = Number(fields.get("MainPID"));
  const invocationId = fields.get("InvocationID") || "";
  if (!matches("Id", unit) || !matches("ActiveState", "active") || !matches("Type", "exec") ||
      !matches("User", String(plan.uid)) || !matches("Group", String(plan.gid)) ||
      !matches("SupplementaryGroups", "") ||
      !matches("RootDirectory", plan.rootDirectory) || !matches("WorkingDirectory", "/workspace") ||
      !matches("ReadWritePaths", `${plan.rootDirectory}/workspace`) ||
      !attestedReadOnlyPaths(plan, fields.get("BindReadOnlyPaths")) ||
      (plan.isolatedSharedMemory && !matches("TemporaryFileSystem", privateSharedMemoryMount)) ||
      (plan.sealedStdio && (!matches("StandardInput", "null") ||
        !matches("StandardOutput", "null") || !matches("StandardError", "null"))) ||
      !matches("BindPaths", "") ||
      !matches("Environment", "SGW_BROKER_SOCKET=/run/s-gw/broker.sock") ||
      !matches("Restart", "no") || !matches("KillMode", "control-group") ||
      !enabled("SendSIGKILL") || !disabled("Delegate") || !disabled("DynamicUser") ||
      !disabled("PrivateUsers") || !enabled("PrivateNetwork") ||
      !enabled("PrivateIPC") || !enabled("PrivateTmp") ||
      !matches("ProtectSystem", "strict") || !enabled("ProtectHome") ||
      !enabled("PrivateDevices") || !enabled("NoNewPrivileges") ||
      !["", "0"].includes(fields.get("CapabilityBoundingSet") ?? "missing") ||
      !["", "0"].includes(fields.get("AmbientCapabilities") ?? "missing") ||
      !enabled("ProtectKernelTunables") || !enabled("ProtectKernelModules") ||
      !enabled("ProtectControlGroups") || !enabled("RestrictNamespaces") ||
      !enabled("RestrictSUIDSGID") || !matches("NetworkNamespacePath", "") ||
      (plan.supervisedControlUnit && (!fields.get("BindsTo")?.split(/\s+/).includes("s-gw-agent-control.service") ||
        !fields.get("After")?.split(/\s+/).includes("s-gw-agent-control.service"))) ||
      !matches("IPCNamespacePath", "") || !matches("JoinsNamespaceOf", "") ||
      !validLinuxCgroupPath(cgroup) || cgroup !== `/system.slice/${unit}` ||
      !Number.isSafeInteger(mainPid) || mainPid < 1 || !/^[a-f0-9]{32}$/.test(invocationId)) {
    throw new Error("Linux agent unit did not attest its required identity and isolation.");
  }
  return { unit, uid: plan.uid, gid: plan.gid, cgroup, mainPid, invocationId };
}

export class SystemdRunAgentUnitManager implements LinuxAgentUnitManager {
  private readonly gates = new Map<string, { dev: number; ino: number }>();
  private readonly launchPaths = new Map<string, string>();
  private readonly lifecycleLeases = new Map<string, LinuxUnitLifecycleLease>();
  private readonly launchFences = new Map<string, { fence: LinuxUnitLaunchFence; planKey: string }>();

  hasActiveLease(sessionId: string): boolean {
    linuxAgentUnitName(sessionId);
    return this.lifecycleLeases.has(sessionId);
  }

  async start(plan: LinuxAgentUnitPlan): Promise<void> {
    this.requireRoot();
    validateLinuxAgentPlan(plan);
    await this.withUnitOperationLock(plan, () => this.startLocked(plan));
  }

  private async startLocked(plan: LinuxAgentUnitPlan): Promise<void> {
    this.rejectLaunchFenceDowngrade(plan);
    const fenced = linuxLaunchAttemptFenceEnabled(plan);
    if (fenced) await rejectUnresolvedUnitLaunchFences(lifecycleRoot, linuxAgentUnitName(plan.sessionId));
    if (plan.serializedLifecycle) await assertUnitNotPresent(plan);
    else await rejectExistingUnitLifecycleLease(plan);
    if (this.lifecycleLeases.has(plan.sessionId)) {
      throw new Error("This Linux agent unit already has a lifecycle lease in this manager.");
    }
    const attemptId = randomBytes(16).toString("hex");
    const args = systemdRunArgs(plan, attemptId);
    await checkedAgentAccount(plan);
    if (plan.launchGate) await assertNoUidProcesses(plan.uid);
    const before = await checkedHostPaths(plan);
    const unit = linuxAgentUnitName(plan.sessionId);
    const lease = plan.serializedLifecycle ? await acquireUnitLifecycleLease(plan, attemptId) : undefined;
    if (lease) this.lifecycleLeases.set(plan.sessionId, lease);
    let launchAttempted = false;
    let launchSucceeded = false;
    let safeTeardown = false;
    let fence: LinuxUnitLaunchFence | undefined;
    try {
      if (plan.launchGate) this.gates.set(plan.sessionId, await prepareGate(plan));
      await startPreparedLinuxAgentUnit(plan, attemptId, {
        launch: async () => {
          if (!lease) await rejectExistingUnitLifecycleLease(plan);
          fence = await beginLinuxUnitLaunchAttempt(plan, attemptId, lifecycleRoot, 0);
          launchAttempted = true;
          await run("/usr/bin/systemd-run", args);
          launchSucceeded = true;
        },
        inspectOwnership: () => run("/usr/bin/systemctl", ["--system", "--no-pager", "show", unit,
          "-p", "Id", "-p", "Description", "-p", "User", "-p", "Group", "-p", "RootDirectory"]),
        verify: async () => {
          if (await checkedHostPaths(plan) !== before) {
            throw new Error("Linux agent launch paths changed while starting the unit.");
          }
          if (plan.launchGate) await checkedGateFiles(plan);
          if (plan.launchGate && plan.activatedSocket) this.launchPaths.set(plan.sessionId, before);
        },
        stopOwned: async () => {
          if (lease) await verifyUnitLifecycleLease(lease);
          else await rejectExistingUnitLifecycleLease(plan);
          await run("/usr/bin/systemctl", ["--system", "--no-ask-password", "stop", unit]);
          await assertNoUidProcesses(plan.uid);
          if (plan.launchGate) await this.cleanGate(plan);
          safeTeardown = true;
        }
      });
      if (fence) this.launchFences.set(plan.sessionId, { fence, planKey: lifecyclePlanKey(plan) });
    } catch (error) {
      if (fence && launchSucceeded && safeTeardown) {
        try { await releaseLinuxUnitLaunchFence(fence, 0); }
        catch (cleanupError) {
          throw new AggregateError([error, cleanupError], "Linux agent start and launch-fence cleanup failed.");
        }
      }
      if (lease && (!launchAttempted || safeTeardown)) {
        try {
          await releaseUnitLifecycleLease(lease);
          this.lifecycleLeases.delete(plan.sessionId);
        } catch (cleanupError) {
          throw new AggregateError([error, cleanupError], "Linux agent start and lifecycle cleanup failed.");
        }
      }
      throw error;
    } finally {
      if (lease) lease.busy = false;
    }
  }

  async inspect(plan: LinuxAgentUnitPlan): Promise<LinuxAgentUnitState> {
    this.requireRoot();
    validateLinuxAgentPlan(plan);
    return this.withUnitOperationLock(plan, () => this.inspectLocked(plan));
  }

  private async inspectLocked(plan: LinuxAgentUnitPlan): Promise<LinuxAgentUnitState> {
    this.rejectLifecycleDowngrade(plan);
    this.rejectLaunchFenceDowngrade(plan);
    if (!plan.serializedLifecycle) {
      await rejectExistingUnitLifecycleLease(plan);
      return this.inspectUnit(plan);
    }
    const lease = this.checkedLease(plan);
    lease.busy = true;
    try {
      await verifyUnitLifecycleLease(lease);
      return await this.inspectUnit(plan, lease);
    } finally { lease.busy = false; }
  }

  private async inspectUnit(plan: LinuxAgentUnitPlan,
    lease?: LinuxUnitLifecycleLease): Promise<LinuxAgentUnitState> {
    const output = await run("/usr/bin/systemctl", ["--system", "--no-pager", "show", linuxAgentUnitName(plan.sessionId),
      "-p", "Id", "-p", "Description", "-p", "ActiveState", "-p", "Type", "-p", "User", "-p", "Group",
      "-p", "RootDirectory", "-p", "WorkingDirectory", "-p", "ReadWritePaths", "-p", "BindReadOnlyPaths", "-p", "BindPaths",
      "-p", "TemporaryFileSystem", "-p", "StandardInput", "-p", "StandardOutput", "-p", "StandardError",
      "-p", "Environment", "-p", "Restart", "-p", "KillMode", "-p", "SendSIGKILL",
      "-p", "Delegate", "-p", "DynamicUser", "-p", "PrivateUsers", "-p", "PrivateNetwork",
      "-p", "SupplementaryGroups",
      "-p", "PrivateIPC", "-p", "PrivateTmp", "-p", "ProtectSystem", "-p", "ProtectHome",
      "-p", "PrivateDevices", "-p", "NoNewPrivileges", "-p", "CapabilityBoundingSet",
      "-p", "AmbientCapabilities", "-p", "ProtectKernelTunables", "-p", "ProtectKernelModules",
      "-p", "ProtectControlGroups", "-p", "RestrictNamespaces", "-p", "RestrictSUIDSGID",
      "-p", "BindsTo", "-p", "After",
      "-p", "NetworkNamespacePath", "-p", "IPCNamespacePath", "-p", "JoinsNamespaceOf",
      "-p", "ControlGroup", "-p", "MainPID", "-p", "InvocationID"]);
    if (lease && !linuxUnitOwnedByStartAttempt(plan, lease.attemptId, output)) {
      throw new Error("Linux agent unit changed after its leased start.");
    }
    const activeFence = this.launchFences.get(plan.sessionId);
    if (activeFence && !linuxUnitOwnedByStartAttempt(plan, activeFence.fence.attemptId, output)) {
      throw new Error("Linux agent unit changed after its fenced start.");
    }
    const state = parseSystemdAgentState(plan, output);
    if (lease?.invocationId && lease.invocationId !== state.invocationId) {
      throw new Error("Linux agent invocation changed during its lifecycle lease.");
    }
    await assertMainProcess(state, plan);
    if (lease) lease.invocationId = state.invocationId;
    return state;
  }

  async release(plan: LinuxAgentUnitPlan, expected: LinuxAgentUnitState): Promise<void> {
    this.requireRoot();
    validateLinuxAgentPlan(plan);
    await this.withUnitOperationLock(plan, () => this.releaseLocked(plan, expected));
  }

  private async releaseLocked(plan: LinuxAgentUnitPlan, expected: LinuxAgentUnitState): Promise<void> {
    this.rejectLifecycleDowngrade(plan);
    this.rejectLaunchFenceDowngrade(plan);
    if (!plan.serializedLifecycle) {
      await rejectExistingUnitLifecycleLease(plan);
      return this.releaseUnit(plan, expected);
    }
    const lease = this.checkedLease(plan);
    lease.busy = true;
    try {
      await verifyUnitLifecycleLease(lease);
      await this.releaseUnit(plan, expected, lease);
    } finally { lease.busy = false; }
  }

  private async releaseUnit(plan: LinuxAgentUnitPlan, expected: LinuxAgentUnitState,
    lease?: LinuxUnitLifecycleLease): Promise<void> {
    if (!plan.launchGate) throw new Error("This Linux agent unit has no launch gate.");
    const currentPaths = await checkedHostPaths(plan);
    if (plan.activatedSocket && this.launchPaths.get(plan.sessionId) !== currentPaths) {
      throw new Error("Linux activated socket path changed before launch gate release.");
    }
    await checkedGateFiles(plan);
    const current = await this.inspectUnit(plan, lease);
    if (current.unit !== expected.unit || current.uid !== expected.uid || current.gid !== expected.gid ||
        current.cgroup !== expected.cgroup || current.mainPid !== expected.mainPid ||
        current.invocationId !== expected.invocationId) {
      throw new Error("Linux agent unit changed before launch gate release.");
    }
    const dir = gateDirectory(plan);
    if (await readFile(path.join(dir, "release"), "utf8") !== "WAIT\n") {
      throw new Error("Linux agent launch gate was already released or altered.");
    }
    const networkNamespace = await readlink(`/proc/${current.mainPid}/ns/net`);
    const hostNetworkNamespace = await readlink("/proc/self/ns/net");
    const brokerSocket = await lstat(plan.brokerSocket);
    if (!/^net:\[\d+\]$/.test(networkNamespace) || networkNamespace === hostNetworkNamespace ||
        !brokerSocket.isSocket() || brokerSocket.uid !== (plan.activatedSocket ? 0 : plan.brokerUid)) {
      throw new Error("Linux agent forwarder boundary changed before release.");
    }
    const attestation = await open(path.join(dir, "forwarder.tmp"),
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o444);
    try {
      await attestation.chmod(0o444);
      await attestation.writeFile(JSON.stringify({ version: 1, sessionId: plan.sessionId,
        uid: current.uid, gid: current.gid, brokerUid: plan.brokerUid,
        brokerSocketOwnerUid: brokerSocket.uid,
        cgroup: current.cgroup, networkNamespace, hostNetworkNamespace,
        invocationId: current.invocationId, mainPid: current.mainPid,
        brokerSocketDevice: String(brokerSocket.dev), brokerSocketInode: String(brokerSocket.ino) }) + "\n");
      await attestation.sync();
    } finally { await attestation.close(); }
    await rename(path.join(dir, "forwarder.tmp"), path.join(dir, "forwarder-attestation.json"));
    const tmp = path.join(dir, "ready.tmp");
    const file = await open(tmp, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o444);
    try {
      await file.chmod(0o444);
      await file.writeFile(`GO ${current.invocationId} ${current.mainPid}\n`);
      await file.sync();
    } finally { await file.close(); }
    await rename(tmp, path.join(dir, "release"));
    const directory = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await directory.sync(); }
    finally { await directory.close(); }
  }

  async stop(plan: LinuxAgentUnitPlan): Promise<void> {
    this.requireRoot();
    validateLinuxAgentPlan(plan);
    await this.withUnitOperationLock(plan, () => this.stopLocked(plan));
  }

  private async stopLocked(plan: LinuxAgentUnitPlan): Promise<void> {
    this.rejectLifecycleDowngrade(plan);
    this.rejectLaunchFenceDowngrade(plan);
    if (!plan.serializedLifecycle) {
      await rejectExistingUnitLifecycleLease(plan);
      const activeFence = this.launchFences.get(plan.sessionId);
      if (activeFence) {
        const unit = linuxAgentUnitName(plan.sessionId);
        await stopOwnedLinuxAgentUnit(plan, activeFence.fence.attemptId, undefined, {
          inspectOwnership: () => run("/usr/bin/systemctl", ["--system", "--no-pager", "show", unit,
            "-p", "Id", "-p", "Description", "-p", "User", "-p", "Group", "-p", "RootDirectory"]),
          stopOwned: async () => { await run("/usr/bin/systemctl", ["--system", "--no-ask-password", "stop", unit]); }
        });
      } else {
        await run("/usr/bin/systemctl", ["--system", "--no-ask-password", "stop", linuxAgentUnitName(plan.sessionId)]);
      }
      await assertNoUidProcesses(plan.uid);
      if (plan.launchGate) await this.cleanGate(plan);
      await this.releaseLaunchFence(plan);
      this.launchPaths.delete(plan.sessionId);
      return;
    }
    const lease = this.checkedLease(plan);
    lease.busy = true;
    try {
      await verifyUnitLifecycleLease(lease);
      const unit = linuxAgentUnitName(plan.sessionId);
      await stopOwnedLinuxAgentUnit(plan, lease.attemptId, lease.invocationId, {
        inspectOwnership: () => run("/usr/bin/systemctl", ["--system", "--no-pager", "show", unit,
          "-p", "Id", "-p", "Description", "-p", "User", "-p", "Group", "-p", "RootDirectory",
          "-p", "InvocationID"]),
        stopOwned: async () => {
          await verifyUnitLifecycleLease(lease);
          await run("/usr/bin/systemctl", ["--system", "--no-ask-password", "stop", unit]);
        }
      });
      await assertNoUidProcesses(plan.uid);
      if (plan.launchGate) await this.cleanGate(plan);
      await releaseUnitLifecycleLease(lease);
      this.lifecycleLeases.delete(plan.sessionId);
      await this.releaseLaunchFence(plan);
      this.launchPaths.delete(plan.sessionId);
    } finally { lease.busy = false; }
  }

  private checkedLease(plan: LinuxAgentUnitPlan): LinuxUnitLifecycleLease {
    validateLinuxAgentPlan(plan);
    const lease = this.lifecycleLeases.get(plan.sessionId);
    if (!lease || lease.planKey !== lifecyclePlanKey(plan) || lease.busy) {
      throw new Error("Linux agent lifecycle lease is absent, busy, or belongs to another plan.");
    }
    return lease;
  }

  private rejectLifecycleDowngrade(plan: LinuxAgentUnitPlan): void {
    if (!plan.serializedLifecycle && this.lifecycleLeases.has(plan.sessionId)) {
      throw new Error("Linux agent unit has a serialized lifecycle lease in this manager.");
    }
  }

  private rejectLaunchFenceDowngrade(plan: LinuxAgentUnitPlan): void {
    const active = this.launchFences.get(plan.sessionId);
    if (active && active.planKey !== lifecyclePlanKey(plan)) {
      throw new Error("Linux agent launch fence belongs to a different unit plan.");
    }
  }

  private async withUnitOperationLock<T>(plan: LinuxAgentUnitPlan, action: () => Promise<T>): Promise<T> {
    await checkedLifecycleRoot();
    const filename = path.join(lifecycleRoot, `${linuxAgentUnitName(plan.sessionId)}.lock`);
    return withLinuxUnitOperationLock(filename, 0, action);
  }

  private async cleanGate(plan: LinuxAgentUnitPlan): Promise<void> {
    const identity = this.gates.get(plan.sessionId);
    if (!identity) return;
    await cleanupGate(plan, identity);
    this.gates.delete(plan.sessionId);
  }

  private async releaseLaunchFence(plan: LinuxAgentUnitPlan): Promise<void> {
    const active = this.launchFences.get(plan.sessionId);
    if (!active) return;
    this.rejectLaunchFenceDowngrade(plan);
    await releaseLinuxUnitLaunchFence(active.fence, 0);
    this.launchFences.delete(plan.sessionId);
  }

  private requireRoot(): void {
    if (process.platform !== "linux" || process.geteuid?.() !== 0) {
      throw new Error("The Linux systemd launcher requires the privileged system service.");
    }
  }
}

async function checkedLifecycleRoot(): Promise<void> {
  await checkedRootParentChain(path.dirname(lifecycleRoot));
  try { await mkdir(lifecycleRoot, { mode: 0o700 }); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
  }
  const folder = await lstat(lifecycleRoot);
  if (!folder.isDirectory() || folder.uid !== 0 || (folder.mode & 0o077) !== 0 ||
      await realpath(lifecycleRoot) !== lifecycleRoot) {
    throw new Error("Linux agent lifecycle lock root is not private to the privileged manager.");
  }
}

function launchFenceName(unit: string, attemptId: string): string {
  const sessionId = /^s-gw-agent-(.+)\.service$/.exec(unit)?.[1];
  if (!sessionId || linuxAgentUnitName(sessionId) !== unit || !/^[a-f0-9]{32}$/.test(attemptId)) {
    throw new Error("Linux agent launch-fence identity is invalid.");
  }
  return `${unit}.launch-${attemptId}`;
}

async function checkedLaunchFenceDirectory(directory: string, ownerUid: number): Promise<void> {
  if (!path.isAbsolute(directory) || path.resolve(directory) !== directory ||
      !Number.isSafeInteger(ownerUid) || ownerUid < 0) {
    throw new Error("Linux agent launch-fence directory or owner is invalid.");
  }
  const info = await lstat(directory);
  if (!info.isDirectory() || info.uid !== ownerUid || (info.mode & 0o077) !== 0 ||
      await realpath(directory) !== directory) {
    throw new Error("Linux agent launch-fence directory is not private to its owner.");
  }
}

export async function rejectUnresolvedUnitLaunchFences(directory: string, unit: string,
  ownerUid = 0): Promise<void> {
  launchFenceName(unit, "0".repeat(32));
  await checkedLaunchFenceDirectory(directory, ownerUid);
  if ((await readdir(directory)).some(name => name.startsWith(`${unit}.launch-`))) {
    throw new Error("Linux agent unit has an unresolved prior launch attempt.");
  }
}

export async function beginLinuxUnitLaunchAttempt(plan: LinuxAgentUnitPlan, attemptId: string,
  directory: string, ownerUid: number): Promise<LinuxUnitLaunchFence | undefined> {
  if (!linuxLaunchAttemptFenceEnabled(plan)) return undefined;
  const unit = linuxAgentUnitName(plan.sessionId);
  await rejectUnresolvedUnitLaunchFences(directory, unit, ownerUid);
  return reserveLinuxUnitLaunchFence(directory, unit, attemptId, ownerUid);
}

export async function reserveLinuxUnitLaunchFence(directory: string, unit: string, attemptId: string,
  ownerUid: number): Promise<LinuxUnitLaunchFence> {
  const name = launchFenceName(unit, attemptId);
  await checkedLaunchFenceDirectory(directory, ownerUid);
  const filename = path.join(directory, name);
  const marker = `${unit} ${attemptId}\n`;
  const file = await open(filename, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  let dev: number;
  let ino: number;
  try {
    await file.chmod(0o600);
    await file.writeFile(marker);
    await file.sync();
    const info = await file.stat();
    dev = info.dev;
    ino = info.ino;
  } finally { await file.close(); }
  const dir = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await dir.sync(); }
  finally { await dir.close(); }
  return { filename, marker, attemptId, dev, ino };
}

export async function releaseLinuxUnitLaunchFence(fence: LinuxUnitLaunchFence,
  ownerUid: number): Promise<void> {
  const directory = path.dirname(fence.filename);
  await checkedLaunchFenceDirectory(directory, ownerUid);
  const before = await lstat(fence.filename);
  if (!before.isFile() || before.uid !== ownerUid || (before.mode & 0o077) !== 0 ||
      before.nlink !== 1 || before.dev !== fence.dev || before.ino !== fence.ino) {
    throw new Error("Linux agent launch fence changed before release.");
  }
  const file = await open(fence.filename, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const current = await file.stat();
    if (current.dev !== fence.dev || current.ino !== fence.ino ||
        await file.readFile({ encoding: "utf8" }) !== fence.marker) {
      throw new Error("Linux agent launch fence changed before release.");
    }
  } finally { await file.close(); }
  await unlink(fence.filename);
  const dir = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await dir.sync(); }
  finally { await dir.close(); }
}

export async function withLinuxUnitOperationLock<T>(filename: string, ownerUid: number,
  action: () => Promise<T>): Promise<T> {
  if (!path.isAbsolute(filename) || path.resolve(filename) !== filename ||
      !Number.isSafeInteger(ownerUid) || ownerUid < 0) {
    throw new Error("Linux agent operation lock path or owner is invalid.");
  }
  const parentPath = path.dirname(filename);
  const parent = await lstat(parentPath);
  if (!parent.isDirectory() || parent.uid !== ownerUid || (parent.mode & 0o077) !== 0 ||
      await realpath(parentPath) !== parentPath) {
    throw new Error("Linux agent operation lock parent is not private to its owner.");
  }
  const file = await open(filename, constants.O_RDWR | constants.O_CREAT | constants.O_NOFOLLOW, 0o600);
  try {
    const before = await lstat(filename);
    const opened = await file.stat();
    if (!before.isFile() || before.uid !== ownerUid || (before.mode & 0o077) !== 0 ||
        before.nlink !== 1 || before.dev !== opened.dev || before.ino !== opened.ino) {
      throw new Error("Linux agent operation lock file is not privately owned.");
    }
    try { await run("/usr/bin/flock", ["--exclusive", "--nonblock", "3"], file.fd); }
    catch (error) {
      throw new Error("Linux agent operation lock is unavailable or busy.", { cause: error });
    }
    const current = await lstat(filename);
    if (current.dev !== opened.dev || current.ino !== opened.ino ||
        !current.isFile() || current.uid !== ownerUid || (current.mode & 0o077) !== 0 ||
        current.nlink !== 1) {
      throw new Error("Linux agent operation lock file changed during acquisition.");
    }
    return await action();
  } finally { await file.close(); }
}

async function assertUnitNotPresent(plan: LinuxAgentUnitPlan): Promise<void> {
  const output = await run("/usr/bin/systemctl", ["--system", "--no-pager", "show",
    linuxAgentUnitName(plan.sessionId), "-p", "Id", "-p", "LoadState", "-p", "ActiveState"]);
  if (!linuxUnitIsAbsent(plan, output)) {
    throw new Error("Linux agent unit already exists or its presence is ambiguous before serialized start.");
  }
}

export function linuxUnitIsAbsent(plan: LinuxAgentUnitPlan, output: string): boolean {
  validateLinuxAgentPlan(plan);
  const fields = new Map<string, string>();
  for (const line of output.trimEnd().split("\n")) {
    const index = line.indexOf("=");
    if (index < 1 || fields.has(line.slice(0, index))) return false;
    fields.set(line.slice(0, index), line.slice(index + 1));
  }
  return fields.size === 3 && fields.get("Id") === linuxAgentUnitName(plan.sessionId) &&
    fields.get("LoadState") === "not-found" && fields.get("ActiveState") === "inactive";
}

async function rejectExistingUnitLifecycleLease(plan: LinuxAgentUnitPlan): Promise<void> {
  const directory = path.join(lifecycleRoot, linuxAgentUnitName(plan.sessionId));
  try { await lstat(directory); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  throw new Error("Linux agent unit has an active or unreconciled serialized lifecycle lease.");
}

async function acquireUnitLifecycleLease(plan: LinuxAgentUnitPlan,
  attemptId: string): Promise<LinuxUnitLifecycleLease> {
  await checkedLifecycleRoot();
  const directory = path.join(lifecycleRoot, linuxAgentUnitName(plan.sessionId));
  const folder = await reserveLinuxUnitLifecycleDirectory(directory, 0);
  const marker = `${attemptId}:${randomBytes(16).toString("hex")}:${process.pid}\n`;
  const file = await open(path.join(directory, "owner"),
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await file.chmod(0o600);
    await file.writeFile(marker);
    await file.sync();
  } finally { await file.close(); }
  const dir = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await dir.sync(); }
  finally { await dir.close(); }
  return { attemptId, planKey: lifecyclePlanKey(plan), directory, marker,
    dev: folder.dev, ino: folder.ino, busy: true };
}

export async function reserveLinuxUnitLifecycleDirectory(directory: string,
  ownerUid: number): Promise<{ dev: number; ino: number }> {
  if (!path.isAbsolute(directory) || path.resolve(directory) !== directory ||
      !Number.isSafeInteger(ownerUid) || ownerUid < 0) {
    throw new Error("Linux agent lifecycle lock path or owner is invalid.");
  }
  try { await mkdir(directory, { mode: 0o700 }); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error("Linux agent unit has an active or unreconciled lifecycle lease.");
    }
    throw error;
  }
  const folder = await lstat(directory);
  if (!folder.isDirectory() || folder.uid !== ownerUid || (folder.mode & 0o077) !== 0 ||
      await realpath(directory) !== directory) {
    throw new Error("Linux agent lifecycle lease directory changed during acquisition.");
  }
  return { dev: folder.dev, ino: folder.ino };
}

async function verifyUnitLifecycleLease(lease: LinuxUnitLifecycleLease): Promise<void> {
  await checkedLifecycleRoot();
  const folder = await lstat(lease.directory);
  if (!folder.isDirectory() || folder.uid !== 0 || (folder.mode & 0o077) !== 0 ||
      folder.dev !== lease.dev || folder.ino !== lease.ino ||
      await realpath(lease.directory) !== lease.directory) {
    throw new Error("Linux agent lifecycle lease directory changed.");
  }
  const filePath = path.join(lease.directory, "owner");
  const before = await lstat(filePath);
  if (!before.isFile() || before.uid !== 0 || (before.mode & 0o077) !== 0 || before.nlink !== 1) {
    throw new Error("Linux agent lifecycle lease owner changed.");
  }
  const file = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const current = await file.stat();
    if (current.dev !== before.dev || current.ino !== before.ino ||
        await file.readFile({ encoding: "utf8" }) !== lease.marker) {
      throw new Error("Linux agent lifecycle lease owner changed.");
    }
  } finally { await file.close(); }
}

async function releaseUnitLifecycleLease(lease: LinuxUnitLifecycleLease): Promise<void> {
  await verifyUnitLifecycleLease(lease);
  await unlink(path.join(lease.directory, "owner"));
  await rmdir(lease.directory);
}

async function checkedHostPaths(plan: LinuxAgentUnitPlan): Promise<string> {
  validateLinuxAgentPlan(plan);
  const root = await lstat(plan.rootDirectory);
  const workspace = await lstat(path.join(plan.rootDirectory, "workspace"));
  const socket = await lstat(plan.brokerSocket);
  const executable = await lstat(path.join(plan.rootDirectory, plan.executable));
  if (!root.isDirectory() || root.uid !== 0 || (root.mode & 0o022) !== 0 ||
      await realpath(plan.rootDirectory) !== plan.rootDirectory ||
      !workspace.isDirectory() || workspace.uid !== plan.uid || workspace.gid !== plan.gid ||
      (workspace.mode & 0o077) !== 0 || !executable.isFile() || executable.uid !== 0 ||
      (executable.mode & 0o022) !== 0 || (executable.mode & 0o111) === 0 ||
      !socket.isSocket() || socket.uid !== (plan.activatedSocket ? 0 : plan.brokerUid) ||
      socket.gid !== plan.gid ||
      (plan.activatedSocket ? (socket.mode & 0o777) !== 0o660 :
        (socket.mode & 0o007) !== 0 || (socket.mode & 0o060) !== 0o060)) {
    throw new Error("Linux agent root, workspace, or broker socket is not privately staged.");
  }
  const socketParent = await lstat(path.dirname(plan.brokerSocket));
  const activatedParent = plan.activatedSocket && socketParent.uid === 0 &&
    (socketParent.mode & 0o777) === 0o711;
  const brokerParent = !plan.activatedSocket && socketParent.uid === plan.brokerUid &&
    socketParent.gid === plan.gid && (socketParent.mode & 0o027) === 0 &&
    (socketParent.mode & 0o010) !== 0;
  if (!socketParent.isDirectory() || (!activatedParent && !brokerParent)) {
    throw new Error("Linux agent broker socket directory is not controlled by the broker.");
  }
  await checkedRootParentChain(path.dirname(plan.rootDirectory));
  await checkedRootParentChain(path.dirname(path.dirname(plan.brokerSocket)));
  await checkedExecutableParents(plan.rootDirectory, plan.executable);
  const markers = [root.dev, root.ino, workspace.dev, workspace.ino, socket.dev, socket.ino,
    socketParent.dev, socketParent.ino, executable.dev, executable.ino];
  if (plan.launchGate) {
    const binary = await lstat(path.join(plan.rootDirectory, gateExecutable));
    const mount = await lstat(path.join(plan.rootDirectory, gateMount));
    if (!binary.isFile() || binary.uid !== 0 || (binary.mode & 0o022) !== 0 ||
        (binary.mode & 0o111) === 0 || !mount.isDirectory() || mount.uid !== 0 ||
        (mount.mode & 0o022) !== 0 || (await readdir(path.join(plan.rootDirectory, gateMount))).length !== 0) {
      throw new Error("Linux agent launch gate is not privately staged.");
    }
    await checkedExecutableParents(plan.rootDirectory, gateExecutable);
    await checkedRootParentChain(path.join(plan.rootDirectory, "run/s-gw"));
    markers.push(binary.dev, binary.ino, mount.dev, mount.ino);
  }
  return markers.join(":");
}

async function prepareGate(plan: LinuxAgentUnitPlan): Promise<{ dev: number; ino: number }> {
  await checkedRootParentChain(path.dirname(gateDirectory(plan)));
  const dir = gateDirectory(plan);
  await mkdir(dir, { mode: 0o755 });
  const folder = await lstat(dir);
  const identity = { dev: folder.dev, ino: folder.ino };
  try {
    await chmod(dir, 0o755);
    const marker = await open(path.join(dir, "release"),
      constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o444);
    try {
      await marker.chmod(0o444);
      await marker.writeFile("WAIT\n");
      await marker.sync();
    } finally { await marker.close(); }
    const directory = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await directory.sync(); }
    finally { await directory.close(); }
    await checkedGateFiles(plan);
    return identity;
  } catch (error) {
    try { await cleanupGate(plan, identity); }
    catch (cleanupError) {
      throw new AggregateError([error, cleanupError], "Linux agent launch gate preparation and cleanup failed.");
    }
    throw error;
  }
}

async function checkedGateFiles(plan: LinuxAgentUnitPlan): Promise<void> {
  const dir = gateDirectory(plan);
  const [folder, marker] = await Promise.all([lstat(dir), lstat(path.join(dir, "release"))]);
  if (!folder.isDirectory() || folder.uid !== 0 || (folder.mode & 0o022) !== 0 ||
      !marker.isFile() || marker.uid !== 0 || (marker.mode & 0o022) !== 0 ||
      marker.nlink !== 1 || await realpath(dir) !== dir) {
    throw new Error("Linux agent launch gate release path is not root controlled.");
  }
  await checkedRootParentChain(path.dirname(dir));
}

async function cleanupGate(plan: LinuxAgentUnitPlan, identity: { dev: number; ino: number }): Promise<void> {
  const dir = gateDirectory(plan);
  await checkedRootParentChain(path.dirname(dir));
  const folder = await lstat(dir);
  if (!folder.isDirectory() || folder.uid !== 0 || (folder.mode & 0o022) !== 0 ||
      folder.dev !== identity.dev || folder.ino !== identity.ino || await realpath(dir) !== dir) {
    throw new Error("Linux agent launch gate directory changed before cleanup.");
  }
  const names = await readdir(dir);
  if (names.some(name => name !== "release" && name !== "ready.tmp" &&
      name !== "forwarder.tmp" && name !== "forwarder-attestation.json")) {
    throw new Error("Linux agent launch gate directory has unexpected files.");
  }
  for (const name of names) {
    const filePath = path.join(dir, name);
    const before = await lstat(filePath);
    if (!before.isFile() || before.uid !== 0 || before.nlink !== 1 ||
        (before.mode & 0o022) !== 0 ||
        before.size > (name.startsWith("forwarder") ? 1024 : 96)) {
      throw new Error("Linux agent launch gate marker changed before cleanup.");
    }
    const file = await open(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const current = await file.stat();
      if (current.dev !== before.dev || current.ino !== before.ino) {
        throw new Error("Linux agent launch gate marker inode changed before cleanup.");
      }
    } finally { await file.close(); }
    await unlink(filePath);
  }
  const directory = await open(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const current = await directory.stat();
    if (current.dev !== identity.dev || current.ino !== identity.ino) {
      throw new Error("Linux agent launch gate directory inode changed before removal.");
    }
  } finally { await directory.close(); }
  await rmdir(dir);
}

async function checkedAgentAccount(plan: LinuxAgentUnitPlan): Promise<void> {
  validateLinuxAgentPlan(plan);
  const entry = (await run("/usr/bin/getent", ["passwd", String(plan.uid)])).trimEnd();
  const fields = entry.split(":");
  if (fields.length !== 7 || !fields[0] || Number(fields[2]) !== plan.uid || Number(fields[3]) !== plan.gid) {
    throw new Error("Linux agent account does not match its dedicated UID and GID.");
  }
  const groups = await run("/usr/bin/id", ["-G", "--", fields[0]]);
  if (!dedicatedGroups(groups, plan.gid, false)) {
    throw new Error("Linux agent account has supplementary group access.");
  }
}

async function checkedExecutableParents(root: string, executable: string): Promise<void> {
  let current = path.dirname(path.join(root, executable));
  while (current !== root) {
    const info = await lstat(current);
    if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0) {
      throw new Error("Linux agent executable has an untrusted parent directory.");
    }
    current = path.dirname(current);
  }
}

async function assertMainProcess(state: LinuxAgentUnitState, plan: LinuxAgentUnitPlan): Promise<void> {
  const [status, cgroup, procRoot, net, hostNet, ipc, hostIpc, mounts, hostMounts] = await Promise.all([
    readFile(`/proc/${state.mainPid}/status`, "utf8"),
    readFile(`/proc/${state.mainPid}/cgroup`, "utf8"),
    readlink(`/proc/${state.mainPid}/root`),
    readlink(`/proc/${state.mainPid}/ns/net`), readlink("/proc/self/ns/net"),
    readlink(`/proc/${state.mainPid}/ns/ipc`), readlink("/proc/self/ns/ipc"),
    readlink(`/proc/${state.mainPid}/ns/mnt`), readlink("/proc/self/ns/mnt")
  ]);
  const uid = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
  const gid = /^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
  const current = cgroup.split("\n").find(line => line.startsWith("0::"))?.slice(3);
  const caps = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"];
  const noCapabilities = caps.every(name => {
    const value = new RegExp(`^${name}:\\s+([0-9a-fA-F]+)$`, "m").exec(status)?.[1];
    return Boolean(value && /^0+$/.test(value));
  });
  if (!uid || !gid || uid.slice(1).some(value => Number(value) !== state.uid) ||
      gid.slice(1).some(value => Number(value) !== state.gid) ||
      !linuxProcessGroupsAreDedicated(status, state.gid) ||
      (current !== state.cgroup && !current?.startsWith(`${state.cgroup}/`)) ||
      procRoot !== plan.rootDirectory || net === hostNet || ipc === hostIpc || mounts === hostMounts ||
      !noCapabilities || !/^NoNewPrivs:\s+1$/m.test(status) || !/^Seccomp:\s+2$/m.test(status)) {
    throw new Error("Linux agent main process did not attest its OS identity and namespaces.");
  }
  if (plan.launchGate) await assertHeldLaunchGate(plan, state);
  if (plan.isolatedSharedMemory) await assertPrivateSharedMemory(state);
  if (plan.sealedStdio) await assertSealedStandardDescriptors(state.mainPid);
}

async function assertSealedStandardDescriptors(pid: number): Promise<void> {
  const nullDevice = await stat("/dev/null");
  if (!nullDevice.isCharacterDevice()) {
    throw new Error("Linux host null device is not a character device.");
  }
  for (let fd = 0; fd < 3; fd++) {
    const current = await stat(`/proc/${pid}/fd/${fd}`);
    if (!current.isCharacterDevice() || current.rdev !== nullDevice.rdev) {
      throw new Error("Linux agent standard descriptor is not the null device.");
    }
  }
}

async function assertPrivateSharedMemory(state: LinuxAgentUnitState): Promise<void> {
  const [mountinfo, inside, host] = await Promise.all([
    readFile(`/proc/${state.mainPid}/mountinfo`, "utf8"),
    stat(`/proc/${state.mainPid}/root/dev/shm`), stat("/dev/shm")
  ]);
  if (!inside.isDirectory() || (inside.mode & 0o7777) !== 0o1777 ||
      !host.isDirectory() ||
      !linuxPrivateSharedMemoryMount(mountinfo, inside.dev, host.dev)) {
    throw new Error("Linux agent private shared-memory mount did not attest.");
  }
}

export function linuxPrivateSharedMemoryMount(mountinfo: string, agentDev: number,
  hostDev: number): boolean {
  if (!Number.isSafeInteger(agentDev) || !Number.isSafeInteger(hostDev) ||
      agentDev === hostDev) return false;
  const mounts = mountinfo.split("\n").filter(line => line.split(" ")[4] === "/dev/shm");
  if (mounts.length !== 1) return false;
  const fields = mounts[0].split(" ");
  const separator = fields.indexOf("-");
  const options = fields[5]?.split(",") || [];
  return separator >= 0 && fields[separator + 1] === "tmpfs" &&
    options.includes("rw") && options.includes("nosuid") &&
    options.includes("nodev") && options.includes("noexec");
}

async function assertHeldLaunchGate(plan: LinuxAgentUnitPlan, state: LinuxAgentUnitState): Promise<void> {
  const [cmdline, mountinfo, inside, outside, executable, staged] = await Promise.all([
    readFile(`/proc/${state.mainPid}/cmdline`),
    readFile(`/proc/${state.mainPid}/mountinfo`, "utf8"),
    lstat(`/proc/${state.mainPid}/root${gateMount}`),
    lstat(gateDirectory(plan)),
    stat(`/proc/${state.mainPid}/exe`),
    stat(path.join(plan.rootDirectory, gateExecutable))
  ]);
  const expected = [gateExecutable, "--", plan.executable, ...plan.args].join("\0") + "\0";
  const readOnlyMount = mountinfo.split("\n").some(line => {
    const fields = line.split(" ");
    return fields[4] === gateMount && fields[5]?.split(",").includes("ro");
  });
  if (cmdline.toString("utf8") !== expected || !inside.isDirectory() ||
      inside.dev !== outside.dev || inside.ino !== outside.ino || !readOnlyMount ||
      executable.dev !== staged.dev || executable.ino !== staged.ino) {
    throw new Error("Linux agent launch gate did not attest its command and read-only release mount.");
  }
}

export function linuxProcessGroupsAreDedicated(status: string, gid: number): boolean {
  const groups = /^Groups:[ \t]*([0-9 \t]*)$/m.exec(status);
  return Boolean(groups && dedicatedGroups(groups[1], gid, true));
}

function dedicatedGroups(value: string, gid: number, allowEmpty: boolean): boolean {
  const groups = value.trim();
  if (!groups) return allowEmpty;
  return groups.split(/\s+/).every(item => /^\d+$/.test(item) && Number(item) === gid);
}

async function checkedRootParentChain(start: string): Promise<void> {
  let current = start;
  while (true) {
    const info = await lstat(current);
    if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0) {
      throw new Error("Linux agent launch path has an untrusted parent.");
    }
    const next = path.dirname(current);
    if (next === current) return;
    current = next;
  }
}

async function assertNoUidProcesses(uid: number): Promise<void> {
  for (const entry of await readdir("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    let status: string;
    try { status = await readFile(`/proc/${entry}/status`, "utf8"); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
      throw error;
    }
    const ids = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
    if (!ids) throw new Error("Could not verify Linux agent UID teardown.");
    if (ids.slice(1).some(value => Number(value) === uid)) {
      throw new Error("Linux agent UID still has a live process after unit stop.");
    }
  }
}

function canonicalPath(value: string): boolean {
  return typeof value === "string" && value.startsWith("/") && path.posix.normalize(value) === value &&
    !value.endsWith("/") && !value.includes("\0") && !value.includes(":");
}

function run(command: string, args: string[], sharedFd?: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const stdio: StdioOptions = sharedFd === undefined ? ["ignore", "pipe", "pipe"] :
      ["ignore", "pipe", "pipe", sharedFd];
    const child = spawn(command, args, { cwd: "/", env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
      stdio });
    let output = "";
    let errorOutput = "";
    let overflow = false;
    const timeout = setTimeout(() => child.kill("SIGKILL"), 10_000);
    child.stdout!.on("data", chunk => { output += String(chunk); if (output.length > 64_000) { overflow = true; child.kill("SIGKILL"); } });
    child.stderr!.on("data", chunk => { errorOutput += String(chunk); if (errorOutput.length > 64_000) { overflow = true; child.kill("SIGKILL"); } });
    child.once("error", error => { clearTimeout(timeout); reject(error); });
    child.once("close", code => {
      clearTimeout(timeout);
      if (code !== 0 || overflow) { reject(new Error("Linux agent systemd operation failed.")); return; }
      resolve(output);
    });
  });
}
