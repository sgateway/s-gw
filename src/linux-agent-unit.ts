import { spawn } from "node:child_process";
import { lstat, readFile, readlink, readdir, realpath } from "node:fs/promises";
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
  stop(plan: LinuxAgentUnitPlan): Promise<void>;
}

const rootPrefix = "/var/lib/s-gw/agent-roots/";
const socketPrefix = "/run/s-gw/agents/";
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
    `BindReadOnlyPaths=${plan.brokerSocket}:/run/s-gw/broker.sock`,
    "Environment=SGW_BROKER_SOCKET=/run/s-gw/broker.sock"
  ];
  return ["--system", "--no-ask-password", `--unit=${unit}`,
    ...properties.map(value => `--property=${value}`),
    "--", plan.executable, ...plan.args];
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
      !matches("RootDirectory", plan.rootDirectory) || !matches("WorkingDirectory", "/workspace") ||
      !matches("BindReadOnlyPaths", `${plan.brokerSocket}:/run/s-gw/broker.sock`) ||
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
  async start(plan: LinuxAgentUnitPlan): Promise<void> {
    this.requireRoot();
    const before = await checkedHostPaths(plan);
    await run("/usr/bin/systemd-run", systemdRunArgs(plan));
    try {
      if (await checkedHostPaths(plan) !== before) {
        throw new Error("Linux agent launch paths changed while starting the unit.");
      }
    } catch (error) {
      try {
        await run("/usr/bin/systemctl", ["--system", "--no-ask-password", "stop", linuxAgentUnitName(plan.sessionId)]);
        await assertNoUidProcesses(plan.uid);
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

  async stop(plan: LinuxAgentUnitPlan): Promise<void> {
    this.requireRoot();
    validateLinuxAgentPlan(plan);
    await run("/usr/bin/systemctl", ["--system", "--no-ask-password", "stop", linuxAgentUnitName(plan.sessionId)]);
    await assertNoUidProcesses(plan.uid);
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
  return [root.dev, root.ino, workspace.dev, workspace.ino, socket.dev, socket.ino,
    socketParent.dev, socketParent.ino, executable.dev, executable.ino].join(":");
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
      (current !== state.cgroup && !current?.startsWith(`${state.cgroup}/`)) ||
      procRoot !== plan.rootDirectory || net === hostNet || ipc === hostIpc || mounts === hostMounts ||
      !noCapabilities || !/^NoNewPrivs:\s+1$/m.test(status) || !/^Seccomp:\s+2$/m.test(status)) {
    throw new Error("Linux agent main process did not attest its OS identity and namespaces.");
  }
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
