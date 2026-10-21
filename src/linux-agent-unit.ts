import { spawn } from "node:child_process";
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
const gateExecutable = "/usr/libexec/s-gw/agent-launch-gate";
const gateMount = "/run/s-gw/launch-gate";
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
      !Array.isArray(plan.args) || plan.args.length > 128 ||
      plan.args.some(arg => typeof arg !== "string" || arg.includes("\0") || arg.length > 4096)) {
    throw new Error("Linux agent executable or arguments are invalid.");
  }
}

export function systemdRunArgs(plan: LinuxAgentUnitPlan): string[] {
  validateLinuxAgentPlan(plan);
  const unit = linuxAgentUnitName(plan.sessionId);
  const properties = [
    ...unitProperties,
    `User=${plan.uid}`, `Group=${plan.gid}`,
    `RootDirectory=${plan.rootDirectory}`,
    "WorkingDirectory=/workspace",
    `BindReadOnlyPaths=${bindReadOnlyPaths(plan)}`,
    "Environment=SGW_BROKER_SOCKET=/run/s-gw/broker.sock"
  ];
  return ["--system", "--no-ask-password", `--unit=${unit}`,
    ...properties.map(value => `--property=${value}`),
    "--", ...(plan.launchGate ? [gateExecutable, "--"] : []), plan.executable, ...plan.args];
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
      !attestedReadOnlyPaths(plan, fields.get("BindReadOnlyPaths")) ||
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
      !matches("IPCNamespacePath", "") || !matches("JoinsNamespaceOf", "") ||
      !validLinuxCgroupPath(cgroup) || cgroup !== `/system.slice/${unit}` ||
      !Number.isSafeInteger(mainPid) || mainPid < 1 || !/^[a-f0-9]{32}$/.test(invocationId)) {
    throw new Error("Linux agent unit did not attest its required identity and isolation.");
  }
  return { unit, uid: plan.uid, gid: plan.gid, cgroup, mainPid, invocationId };
}

export class SystemdRunAgentUnitManager implements LinuxAgentUnitManager {
  private readonly gates = new Map<string, { dev: number; ino: number }>();

  async start(plan: LinuxAgentUnitPlan): Promise<void> {
    this.requireRoot();
    await checkedAgentAccount(plan);
    if (plan.launchGate) await assertNoUidProcesses(plan.uid);
    const before = await checkedHostPaths(plan);
    if (plan.launchGate) this.gates.set(plan.sessionId, await prepareGate(plan));
    try {
      await run("/usr/bin/systemd-run", systemdRunArgs(plan));
    } catch (error) {
      if (plan.launchGate) {
        try {
          await assertNoUidProcesses(plan.uid);
          await this.cleanGate(plan);
        } catch (cleanupError) {
          throw new AggregateError([error, cleanupError], "Linux agent start and gate cleanup failed.");
        }
      }
      throw error;
    }
    try {
      if (await checkedHostPaths(plan) !== before) {
        throw new Error("Linux agent launch paths changed while starting the unit.");
      }
      if (plan.launchGate) await checkedGateFiles(plan);
    } catch (error) {
      try {
        await run("/usr/bin/systemctl", ["--system", "--no-ask-password", "stop", linuxAgentUnitName(plan.sessionId)]);
        await assertNoUidProcesses(plan.uid);
        if (plan.launchGate) await this.cleanGate(plan);
      } catch (stopError) {
        throw new AggregateError([error, stopError], "Linux agent start and teardown failed.");
      }
      throw error;
    }
  }

  async inspect(plan: LinuxAgentUnitPlan): Promise<LinuxAgentUnitState> {
    this.requireRoot();
    validateLinuxAgentPlan(plan);
    const output = await run("/usr/bin/systemctl", ["--system", "--no-pager", "show", linuxAgentUnitName(plan.sessionId),
      "-p", "Id", "-p", "ActiveState", "-p", "Type", "-p", "User", "-p", "Group",
      "-p", "RootDirectory", "-p", "WorkingDirectory", "-p", "BindReadOnlyPaths", "-p", "BindPaths",
      "-p", "Environment", "-p", "Restart", "-p", "KillMode", "-p", "SendSIGKILL",
      "-p", "Delegate", "-p", "DynamicUser", "-p", "PrivateUsers", "-p", "PrivateNetwork",
      "-p", "SupplementaryGroups",
      "-p", "PrivateIPC", "-p", "PrivateTmp", "-p", "ProtectSystem", "-p", "ProtectHome",
      "-p", "PrivateDevices", "-p", "NoNewPrivileges", "-p", "CapabilityBoundingSet",
      "-p", "AmbientCapabilities", "-p", "ProtectKernelTunables", "-p", "ProtectKernelModules",
      "-p", "ProtectControlGroups", "-p", "RestrictNamespaces", "-p", "RestrictSUIDSGID",
      "-p", "NetworkNamespacePath", "-p", "IPCNamespacePath", "-p", "JoinsNamespaceOf",
      "-p", "ControlGroup", "-p", "MainPID", "-p", "InvocationID"]);
    const state = parseSystemdAgentState(plan, output);
    await assertMainProcess(state, plan);
    return state;
  }

  async release(plan: LinuxAgentUnitPlan, expected: LinuxAgentUnitState): Promise<void> {
    this.requireRoot();
    if (!plan.launchGate) throw new Error("This Linux agent unit has no launch gate.");
    await checkedHostPaths(plan);
    await checkedGateFiles(plan);
    const current = await this.inspect(plan);
    if (current.unit !== expected.unit || current.uid !== expected.uid || current.gid !== expected.gid ||
        current.cgroup !== expected.cgroup || current.mainPid !== expected.mainPid ||
        current.invocationId !== expected.invocationId) {
      throw new Error("Linux agent unit changed before launch gate release.");
    }
    const dir = gateDirectory(plan);
    if (await readFile(path.join(dir, "release"), "utf8") !== "WAIT\n") {
      throw new Error("Linux agent launch gate was already released or altered.");
    }
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
    await run("/usr/bin/systemctl", ["--system", "--no-ask-password", "stop", linuxAgentUnitName(plan.sessionId)]);
    await assertNoUidProcesses(plan.uid);
    if (plan.launchGate) await this.cleanGate(plan);
  }

  private async cleanGate(plan: LinuxAgentUnitPlan): Promise<void> {
    const identity = this.gates.get(plan.sessionId);
    if (!identity) return;
    await cleanupGate(plan, identity);
    this.gates.delete(plan.sessionId);
  }

  private requireRoot(): void {
    if (process.platform !== "linux" || process.geteuid?.() !== 0) {
      throw new Error("The Linux systemd launcher requires the privileged system service.");
    }
  }
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
      !socket.isSocket() || socket.uid !== plan.brokerUid ||
      socket.gid !== plan.gid ||
      (socket.mode & 0o007) !== 0 || (socket.mode & 0o060) !== 0o060) {
    throw new Error("Linux agent root, workspace, or broker socket is not privately staged.");
  }
  const socketParent = await lstat(path.dirname(plan.brokerSocket));
  if (!socketParent.isDirectory() || socketParent.uid !== plan.brokerUid || socketParent.gid !== plan.gid ||
      (socketParent.mode & 0o027) !== 0 || (socketParent.mode & 0o010) === 0) {
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
  if (names.some(name => name !== "release" && name !== "ready.tmp")) {
    throw new Error("Linux agent launch gate directory has unexpected files.");
  }
  for (const name of names) {
    const filePath = path.join(dir, name);
    const before = await lstat(filePath);
    if (!before.isFile() || before.uid !== 0 || before.nlink !== 1 ||
        (before.mode & 0o022) !== 0 || before.size > 96) {
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

function run(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { cwd: "/", env: { LANG: "C", LC_ALL: "C", PATH: "/usr/bin:/bin" },
      stdio: ["ignore", "pipe", "pipe"] });
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
