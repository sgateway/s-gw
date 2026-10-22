#!/usr/bin/env node
import { spawn } from "node:child_process";
import { constants } from "node:fs";
import { chmod, chown, lstat, open, readFile, readlink, realpath, unlink } from "node:fs/promises";
import { createConnection, createServer, type Socket } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { lifecyclePlanKey, SystemdRunAgentUnitManager, validateLinuxAgentPlan,
  linuxAgentUnitName, traceLinuxManagedStart,
  type LinuxAgentUnitManager, type LinuxAgentUnitPlan, type LinuxAgentUnitState } from "./linux-agent-unit.js";
import { attestDurableLinuxAgentIdentity } from "./linux-agent-identity.js";
import { verifyLinuxPeerProcess } from "./linux-peer-identity.js";

const controlSocket = "/run/s-gw/agent-control.sock";
const planDir = "/run/s-gw/agent-plans";
const runtimeDir = path.dirname(fileURLToPath(import.meta.url));
const rootPidfdHelper = fileURLToPath(new URL(`../dist/native/linux-${process.arch}/s-gw-linux-peer-identity`, import.meta.url));
const maxFrame = 32 * 1024;
const unsafeStartupEnv = ["NODE_OPTIONS", "NODE_PATH", "NODE_TLS_REJECT_UNAUTHORIZED",
  "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "OPENSSL_CONF", "SSL_CERT_FILE", "SSL_CERT_DIR",
  "GLIBC_TUNABLES", "MALLOC_CHECK_", "MALLOC_PERTURB_", "TZDIR"];
const handshakeReasons = new Set([
  "Linux agent plan registry is not root-private.",
  "Linux agent plan registration is not root-private.",
  "Invalid root-provisioned Linux managed plan record.",
  "Linux agent identity registry is not root-private.",
  "Linux agent identity registry has an untrusted parent.",
  "Linux agent identity record is not root-private.",
  "Linux agent identity record differs from the root plan.",
  "Linux managed MCP socket unit is not bound to the registered broker service and root control.",
  "Linux model socket unit is not bound to the registered broker service.",
  "Linux broker environment file is not root-private.",
  "Linux broker config is not root-provisioned.",
  "Linux broker config differs from its root plan registration.",
  "Linux broker relay config differs from its root plan registration.",
  "Invalid Linux broker unit attestation.",
  "Could not verify live Linux peer in its cgroup.",
  "Linux control peer has the wrong broker identity.",
  "Linux control peer is not the registered broker unit invocation.",
  "Linux broker command does not match its root registration.",
  "Linux broker Node binary differs from its root registration."
]);

export function controlHandshakeFailure(error: unknown): string {
  if (error instanceof Error && handshakeReasons.has(error.message)) return error.message;
  return "Linux control attestation failed.";
}

export interface LinuxManagedPlanRecord {
  plan: LinuxAgentUnitPlan;
  brokerUnit: string;
  brokerUnitFile: string;
  mcpSocketUnitFile: string;
  modelRelaySocketUnitFile?: string;
  brokerEntry: string;
  brokerConfig: string;
  brokerNode: string;
  brokerRuntimeRoot: string;
  brokerPreflight: string;
  brokerEnvironmentFile: string;
  brokerCa: string | null;
}

type Method = "start" | "inspect" | "release" | "stop";
interface ControlCall {
  id: number;
  method: Method;
  plan: LinuxAgentUnitPlan;
  state?: LinuxAgentUnitState;
}

export function validateLinuxManagedPlan(plan: LinuxAgentUnitPlan, brokerUid: number, brokerGid: number): void {
  validateLinuxAgentPlan(plan);
  if (!Number.isSafeInteger(brokerUid) || brokerUid < 1 ||
      !Number.isSafeInteger(brokerGid) || brokerGid < 1 ||
      plan.brokerUid !== brokerUid || plan.uid === brokerUid || plan.gid === brokerGid ||
      plan.launchGate !== true || plan.activatedSocket !== true ||
      plan.isolatedSharedMemory !== true || plan.serializedLifecycle !== true ||
      plan.sealedStdio !== true || plan.supervisedControlUnit !== true) {
    throw new Error("Managed Linux MCP needs the dedicated, supervised agent profile.");
  }
}

export function validateLinuxManagedPlanRecord(value: LinuxManagedPlanRecord,
  sessionId: string, brokerUid: number, brokerGid: number): void {
  const mcpUnit = `s-gw-managed-mcp-${sessionId}.socket`;
  const modelUnit = `s-gw-managed-model-${sessionId}.socket`;
  const modelFile = value?.modelRelaySocketUnitFile;
  const modelExpected = value?.plan?.modelRelaySocket !== undefined;
  if (!value || typeof value !== "object" || !value.plan ||
      value.plan.sessionId !== sessionId ||
      value.brokerUnit !== `s-gw-managed-mcp-${sessionId}.service` ||
      !["/run/systemd/system", "/etc/systemd/system", "/usr/lib/systemd/system"].includes(path.dirname(value.brokerUnitFile || "")) ||
      path.basename(value.brokerUnitFile) !== value.brokerUnit ||
      !["/run/systemd/system", "/etc/systemd/system", "/usr/lib/systemd/system"].includes(path.dirname(value.mcpSocketUnitFile || "")) ||
      path.basename(value.mcpSocketUnitFile) !== mcpUnit ||
      (modelExpected !== (modelFile !== undefined)) ||
      (modelFile !== undefined &&
        (!["/run/systemd/system", "/etc/systemd/system", "/usr/lib/systemd/system"]
          .includes(path.dirname(modelFile)) || path.basename(modelFile) !== modelUnit)) ||
      !canonicalFile(value.brokerEntry) || path.basename(value.brokerEntry) !== "linux-managed-mcp.js" ||
      !canonicalFile(value.brokerConfig) || !canonicalFile(value.brokerNode) ||
      !canonicalFile(value.brokerRuntimeRoot) || !canonicalFile(value.brokerPreflight) ||
      !canonicalFile(value.brokerEnvironmentFile) ||
      (value.brokerCa !== null && !canonicalFile(value.brokerCa)) ||
      !value.brokerNode.startsWith(`${value.brokerRuntimeRoot}/`) ||
      !value.brokerEntry.startsWith(`${value.brokerRuntimeRoot}/`) ||
      !value.brokerPreflight.startsWith(`${value.brokerRuntimeRoot}/`) ||
      Object.keys(value).sort().join(",") !==
        (modelExpected
          ? "brokerCa,brokerConfig,brokerEntry,brokerEnvironmentFile,brokerNode,brokerPreflight,brokerRuntimeRoot,brokerUnit,brokerUnitFile,mcpSocketUnitFile,modelRelaySocketUnitFile,plan"
          : "brokerCa,brokerConfig,brokerEntry,brokerEnvironmentFile,brokerNode,brokerPreflight,brokerRuntimeRoot,brokerUnit,brokerUnitFile,mcpSocketUnitFile,plan")) {
    throw new Error("Invalid root-provisioned Linux managed plan record.");
  }
  validateLinuxManagedPlan(value.plan, brokerUid, brokerGid);
}

function canonicalFile(value: unknown): value is string {
  return typeof value === "string" && path.isAbsolute(value) && path.resolve(value) === value &&
    !value.includes("\0");
}

async function checkedBrokerFile(filename: string): Promise<void> {
  await checkedRootFile(filename);
  if ((await lstat(filename)).nlink !== 1) {
    throw new Error(`Untrusted Linux broker file: ${filename}`);
  }
}

async function registeredPlan(sessionId: string, brokerUid: number,
  brokerGid: number): Promise<LinuxManagedPlanRecord> {
  linuxAgentUnitName(sessionId);
  const directory = await lstat(planDir);
  if (!directory.isDirectory() || directory.uid !== 0 ||
      (directory.mode & 0o777) !== 0o700 || await realpath(planDir) !== planDir) {
    throw new Error("Linux agent plan registry is not root-private.");
  }
  const filename = path.join(planDir, `${sessionId}.json`);
  const item = await lstat(filename);
  if (!item.isFile() || item.uid !== 0 || (item.mode & 0o777) !== 0o600 ||
      item.nlink !== 1 || item.size > maxFrame || await realpath(filename) !== filename) {
    throw new Error("Linux agent plan registration is not root-private.");
  }
  await checkedRootFile(filename);
  const value = JSON.parse(await readFile(filename, "utf8")) as LinuxManagedPlanRecord;
  validateLinuxManagedPlanRecord(value, sessionId, brokerUid, brokerGid);
  await attestDurableLinuxAgentIdentity(value.plan);
  await checkedRootFile(value.brokerUnitFile);
  await checkedRootFile(value.mcpSocketUnitFile);
  assertManagedMcpSocketUnit(value, await systemctlProperties(
    path.basename(value.mcpSocketUnitFile),
    ["Id", "ActiveState", "FragmentPath", "Triggers", "BindsTo", "After"]));
  if (value.modelRelaySocketUnitFile) {
    await checkedRootFile(value.modelRelaySocketUnitFile);
    assertModelSocketUnit(value, await systemctlProperties(
      path.basename(value.modelRelaySocketUnitFile),
      ["Id", "ActiveState", "FragmentPath", "Triggers", "BindsTo", "After"]));
  }
  await checkedBrokerFile(value.brokerNode);
  await checkedBrokerFile(value.brokerPreflight);
  await checkedRootFile(value.brokerEnvironmentFile);
  if ((await lstat(value.brokerEnvironmentFile)).mode & 0o077) {
    throw new Error("Linux broker environment file is not root-private.");
  }
  if (value.brokerCa) await checkedBrokerFile(value.brokerCa);
  const config = await lstat(value.brokerConfig);
  if (!config.isFile() || config.uid !== 0 || config.gid !== brokerGid ||
      (config.mode & 0o777) !== 0o640 || config.nlink !== 1) {
    throw new Error("Linux broker config is not root-provisioned.");
  }
  await checkedRootFile(value.brokerConfig);
  const brokerConfig = JSON.parse(await readFile(value.brokerConfig, "utf8")) as {
    plan?: LinuxAgentUnitPlan; relay?: { grant?: unknown; requestId?: unknown };
  };
  if (!brokerConfig?.plan || lifecyclePlanKey(brokerConfig.plan) !== lifecyclePlanKey(value.plan)) {
    throw new Error("Linux broker config differs from its root plan registration.");
  }
  if (Boolean(brokerConfig.relay) !== Boolean(value.plan.modelRelaySocket)) {
    throw new Error("Linux broker relay config differs from its root plan registration.");
  }
  await checkedBrokerFile(value.brokerEntry);
  return value;
}

async function reserveManagedIdentity(plan: LinuxAgentUnitPlan): Promise<void> {
  const directory = await lstat(planDir);
  if (!directory.isDirectory() || directory.uid !== 0 ||
      (directory.mode & 0o777) !== 0o700 || await realpath(planDir) !== planDir) {
    throw new Error("Linux agent plan registry changed before identity reservation.");
  }
  await claimIdentityMarkers(plan, planDir);
}

export async function claimIdentityMarkers(plan: LinuxAgentUnitPlan, directory: string): Promise<void> {
  const created: { name: string; dev: number; ino: number }[] = [];
  try {
    for (const name of [`uid-${plan.uid}.used`, `gid-${plan.gid}.used`,
      `session-${plan.sessionId}.used`]) {
      const file = await open(path.join(directory, name),
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try {
        const info = await file.stat();
        created.push({ name, dev: info.dev, ino: info.ino });
        await file.chmod(0o600);
        await file.writeFile(`${plan.sessionId} ${plan.uid} ${plan.gid}\n`);
        await file.sync();
      } finally { await file.close(); }
    }
    const dir = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await dir.sync(); }
    finally { await dir.close(); }
  } catch (error) {
    for (const marker of created.reverse()) {
      const filename = path.join(directory, marker.name);
      const current = await lstat(filename);
      if (!current.isFile() || current.dev !== marker.dev || current.ino !== marker.ino) {
        throw new Error(`Linux identity marker changed during rollback: ${filename}`);
      }
      await unlink(filename);
    }
    const dir = await open(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    try { await dir.sync(); }
    finally { await dir.close(); }
    throw error;
  }
}

async function checkedRootFile(filename: string): Promise<void> {
  const value = await lstat(filename);
  if (!value.isFile() || value.uid !== 0 || (value.mode & 0o022) !== 0 ||
      await realpath(filename) !== filename) {
    throw new Error(`Untrusted privileged Linux file: ${filename}`);
  }
  let parent = path.dirname(filename);
  while (true) {
    const info = await lstat(parent);
    if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0 ||
        await realpath(parent) !== parent) {
      throw new Error(`Untrusted privileged Linux parent: ${parent}`);
    }
    const next = path.dirname(parent);
    if (next === parent) return;
    parent = next;
  }
}

async function checkedRootRuntime(): Promise<void> {
  if (process.platform !== "linux" || process.geteuid?.() !== 0 || process.getuid?.() !== 0) {
    throw new Error("The Linux agent control service must run as root.");
  }
  const cgroup = await readFile("/proc/self/cgroup", "utf8");
  if (!cgroup.split("\n").includes("0::/system.slice/s-gw-agent-control.service")) {
    throw new Error("The Linux agent control service needs its systemd unit.");
  }
  for (const filename of [fileURLToPath(import.meta.url), path.join(runtimeDir, "linux-agent-unit.js"),
    path.join(runtimeDir, "linux-peer-identity.js"), path.join(runtimeDir, "linux-agent-identity.js"),
    path.join(runtimeDir, "package.json"),
    rootPidfdHelper, await realpath(process.execPath)]) {
    await checkedRootFile(filename);
  }
  const runtimeRoot = path.dirname(runtimeDir);
  const preflight = path.join(runtimeRoot, "s-gw-linux-broker-runtime");
  const entry = fileURLToPath(import.meta.url);
  const node = await realpath(process.execPath);
  const output = await systemctlProperties("s-gw-agent-control.service");
  const unitFile = parseUnitProperties(output).get("FragmentPath") || "";
  if (path.basename(unitFile) !== "s-gw-agent-control.service" ||
      !["/run/systemd/system", "/etc/systemd/system", "/usr/lib/systemd/system"].includes(path.dirname(unitFile))) {
    throw new Error("Linux root control has an untrusted systemd unit path.");
  }
  await checkedRootFile(unitFile);
  await checkedRootFile(preflight);
  assertControlUnitPreflight(output,
    { unitFile, runtimeRoot, preflight, node, entry, args: process.argv.slice(2) });
  const parent = await lstat(path.dirname(controlSocket));
  if (!parent.isDirectory() || parent.uid !== 0 || (parent.mode & 0o022) !== 0) {
    throw new Error("The Linux control socket directory must be root-owned.");
  }
}

async function readPeer(socket: Socket, helper: string): Promise<{ uid: number; gid: number; pid: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(helper, [], { stdio: ["ignore", "pipe", "ignore", socket], env: {}, timeout: 1500 });
    let output = "";
    child.stdout!.on("data", chunk => {
      output += String(chunk);
      if (output.length > 80) child.kill();
    });
    child.once("error", reject);
    child.once("close", code => {
      const match = /^(\d+) (\d+) (\d+)\n$/.exec(output);
      if (code !== 0 || !match) { reject(new Error("Could not verify Linux control peer.")); return; }
      const [uid, gid, pid] = match.slice(1).map(Number);
      if (![uid, gid, pid].every(Number.isSafeInteger) || pid < 1) {
        reject(new Error("Invalid Linux control peer."));
        return;
      }
      resolve({ uid, gid, pid });
    });
  });
}

function firstFrame(socket: Socket): Promise<unknown> {
  return new Promise((resolve, reject) => {
    let pending = Buffer.alloc(0);
    const done = (error?: Error, value?: unknown) => {
      socket.pause();
      socket.setTimeout(0);
      socket.off("data", onData);
      socket.off("close", onClose);
      socket.off("error", onError);
      if (error) reject(error);
      else resolve(value);
    };
    const onClose = () => done(new Error("Linux control handshake closed."));
    const onError = (error: Error) => done(error);
    const onData = (chunk: Buffer) => {
      if (chunk.length > 512) {
        done(new Error("Invalid Linux control handshake frame."));
        return;
      }
      pending = Buffer.concat([pending, chunk]);
      const end = pending.indexOf(10);
      if (pending.length > 512 || (end >= 0 && end !== pending.length - 1)) {
        done(new Error("Invalid Linux control handshake frame."));
        return;
      }
      if (end < 0) return;
      try { done(undefined, JSON.parse(pending.subarray(0, end).toString("utf8"))); }
      catch { done(new Error("Invalid Linux control handshake JSON.")); }
    };
    socket.setTimeout(1500, () => done(new Error("Linux control handshake timed out.")));
    socket.on("data", onData);
    socket.once("close", onClose);
    socket.once("error", onError);
    socket.resume();
  });
}

async function systemctlProperties(unit: string, names = ["Id", "ActiveState", "MainPID", "ControlGroup", "InvocationID",
    "FragmentPath", "BindsTo", "After", "ExecStart", "ExecStartPre",
    "EnvironmentFiles", "UnsetEnvironment"]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn("/usr/bin/systemctl", ["--system", "--no-pager", "--all", "show", unit,
      ...names.flatMap(name => ["-p", name])], { stdio: ["ignore", "pipe", "pipe"], env: {}, timeout: 3000 });
    let output = "";
    let errorOutput = "";
    child.stdout!.on("data", chunk => {
      output += String(chunk);
      if (output.length > 16_384) child.kill();
    });
    child.stderr!.on("data", chunk => {
      errorOutput += String(chunk);
      if (errorOutput.length > 4096) child.kill();
    });
    child.once("error", reject);
    child.once("close", code => {
      if (code !== 0 || output.length > 16_384 || errorOutput.length > 4096) {
        reject(new Error("Could not attest Linux broker unit."));
      } else resolve(output);
    });
  });
}

export function assertModelSocketUnit(record: LinuxManagedPlanRecord, output: string): void {
  const file = record.modelRelaySocketUnitFile;
  if (!file) throw new Error("No managed Linux model socket unit is registered.");
  const values = parseUnitProperties(output);
  // systemd exposes the socket's resolved service target as Triggers, not Service.
  if (values.get("Id") !== path.basename(file) || values.get("ActiveState") !== "active" ||
      values.get("FragmentPath") !== file || values.get("Triggers") !== record.brokerUnit ||
      !values.get("BindsTo")?.split(/\s+/).includes("s-gw-agent-control.service") ||
      !values.get("After")?.split(/\s+/).includes("s-gw-agent-control.service")) {
    throw new Error("Linux model socket unit is not bound to the registered broker service.");
  }
}

export function assertManagedMcpSocketUnit(record: LinuxManagedPlanRecord, output: string): void {
  const file = record.mcpSocketUnitFile;
  const values = parseUnitProperties(output);
  if (values.get("Id") !== path.basename(file) || values.get("ActiveState") !== "active" ||
      values.get("FragmentPath") !== file || values.get("Triggers") !== record.brokerUnit ||
      !values.get("BindsTo")?.split(/\s+/).includes("s-gw-agent-control.service") ||
      !values.get("After")?.split(/\s+/).includes("s-gw-agent-control.service")) {
    throw new Error("Linux managed MCP socket unit is not bound to the registered broker service and root control.");
  }
}

function parseUnitProperties(output: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const line of output.trimEnd().split("\n")) {
    const index = line.indexOf("=");
    if (index < 1 || values.has(line.slice(0, index))) {
      throw new Error("Invalid Linux broker unit attestation.");
    }
    values.set(line.slice(0, index), line.slice(index + 1));
  }
  return values;
}

function unitCommand(value: string | undefined, executable: string, args: string[]): boolean {
  if (!value || !/^[\/A-Za-z0-9_.@+-]+$/.test(executable) ||
      args.some(arg => !/^[\/A-Za-z0-9_.@+-]+$/.test(arg))) return false;
  const command = `argv[]=${[executable, ...args].join(" ")} ;`;
  return value.startsWith(`{ path=${executable} ; ${command} ignore_errors=no ;`) &&
    value.endsWith(" }") && value.match(/\{ path=/g)?.length === 1;
}

function safeUnitEnvironment(value: string | undefined): boolean {
  if (!value) return false;
  const removed = new Set(value.split(/\s+/));
  return unsafeStartupEnv.every(name => removed.has(name));
}

export function assertControlUnitPreflight(output: string, runtime: {
  unitFile: string; runtimeRoot: string; preflight: string;
  node: string; entry: string; args: string[];
}): void {
  const unit = parseUnitProperties(output);
  const failed: string[] = [];
  if (unit.get("Id") !== "s-gw-agent-control.service") failed.push("Id");
  if (unit.get("ActiveState") !== "active") failed.push("ActiveState");
  if (unit.get("FragmentPath") !== runtime.unitFile) failed.push("FragmentPath");
  // Some systemd versions omit an unconfigured EnvironmentFiles property, even with --all.
  const environmentFiles = unit.get("EnvironmentFiles");
  if (environmentFiles !== undefined && environmentFiles !== "") failed.push("EnvironmentFiles");
  if (!unitCommand(unit.get("ExecStartPre"), runtime.preflight,
    ["verify", runtime.runtimeRoot, runtime.node, runtime.entry, runtime.unitFile, "-", "-"])) {
    failed.push("ExecStartPre");
  }
  if (!unitCommand(unit.get("ExecStart"), runtime.preflight,
    ["verify-exec", runtime.runtimeRoot, runtime.node, runtime.entry,
      runtime.unitFile, "-", "-", "--", ...runtime.args])) {
    failed.push("ExecStart");
  }
  if (!safeUnitEnvironment(unit.get("UnsetEnvironment")) ||
      !unit.get("UnsetEnvironment")?.split(/\s+/).includes("NODE_EXTRA_CA_CERTS")) {
    failed.push("UnsetEnvironment");
  }
  if (failed.length) throw new Error(`Linux root control did not pass the native pre-exec runtime gate: ${failed.join(", ")}.`);
}

export function brokerUnitInvocation(record: LinuxManagedPlanRecord, pid: number,
  output: string, expected?: string): string {
  const values = parseUnitProperties(output);
  const invocation = values.get("InvocationID") || "";
  if (values.get("Id") !== record.brokerUnit || values.get("ActiveState") !== "active" ||
      values.get("MainPID") !== String(pid) ||
      values.get("ControlGroup") !== `/system.slice/${record.brokerUnit}` ||
      values.get("FragmentPath") !== record.brokerUnitFile ||
      !values.get("BindsTo")?.split(/\s+/).includes("s-gw-agent-control.service") ||
      !values.get("After")?.split(/\s+/).includes("s-gw-agent-control.service") ||
      values.get("EnvironmentFiles") !== `${record.brokerEnvironmentFile} (ignore_errors=no)` ||
      !safeUnitEnvironment(values.get("UnsetEnvironment")) ||
      !unitCommand(values.get("ExecStartPre"), record.brokerPreflight,
        ["verify", record.brokerRuntimeRoot, record.brokerNode, record.brokerEntry,
          record.brokerConfig, record.brokerCa ?? "-", record.brokerEnvironmentFile]) ||
      !unitCommand(values.get("ExecStart"), record.brokerPreflight,
        ["verify-exec", record.brokerRuntimeRoot, record.brokerNode, record.brokerEntry,
          record.brokerConfig, record.brokerCa ?? "-", record.brokerEnvironmentFile,
          "--", record.brokerConfig]) ||
      !/^[a-f0-9]{32}$/.test(invocation) || (expected && invocation !== expected)) {
    throw new Error("Linux control peer is not the registered broker unit invocation.");
  }
  return invocation;
}

async function attestBroker(socket: Socket, record: LinuxManagedPlanRecord,
  brokerUid: number, brokerGid: number, expected?: string): Promise<string> {
  const cgroup = `/system.slice/${record.brokerUnit}`;
  const peer = await verifyLinuxPeerProcess(socket, cgroup);
  if (peer.uid !== brokerUid || peer.gid !== brokerGid) {
    throw new Error("Linux control peer has the wrong broker identity.");
  }
  const invocation = brokerUnitInvocation(record, peer.pid,
    await systemctlProperties(record.brokerUnit), expected);
  const command = (await readFile(`/proc/${peer.pid}/cmdline`)).toString("utf8").split("\0");
  if (command.at(-1) === "") command.pop();
  if (command.length !== 3 || command[1] !== record.brokerEntry ||
      command[2] !== record.brokerConfig) {
    throw new Error("Linux broker command does not match its root registration.");
  }
  const executable = await readlink(`/proc/${peer.pid}/exe`);
  if (executable !== record.brokerNode) {
    throw new Error("Linux broker Node binary differs from its root registration.");
  }
  await checkedBrokerFile(executable);
  return invocation;
}

function readFrames(socket: Socket, onFrame: (value: unknown) => void): void {
  let pending = Buffer.alloc(0);
  socket.on("data", chunk => {
    pending = Buffer.concat([pending, chunk]);
    if (pending.length > maxFrame * 2) { socket.destroy(); return; }
    while (true) {
      const end = pending.indexOf(10);
      if (end < 0) break;
      if (end > maxFrame) { socket.destroy(); return; }
      let value: unknown;
      try { value = JSON.parse(pending.subarray(0, end).toString("utf8")); }
      catch { socket.destroy(); return; }
      pending = pending.subarray(end + 1);
      onFrame(value);
    }
  });
}

function sendFrame(socket: Socket, value: unknown): void {
  const frame = JSON.stringify(value) + "\n";
  if (Buffer.byteLength(frame) > maxFrame) throw new Error("Linux control response is too large.");
  socket.write(frame);
}

export function sendControlReply(socket: Socket, id: unknown,
  result: { ok: true; value: unknown } | { ok: false; error: string }): void {
  if (socket.destroyed) return;
  if (!Number.isSafeInteger(id) || (id as number) < 1) {
    socket.destroy();
    return;
  }
  try { sendFrame(socket, { id, ...result }); }
  catch { socket.destroy(); }
}

function controlCall(value: unknown): ControlCall {
  if (!value || typeof value !== "object") throw new Error("Invalid Linux control call.");
  const call = value as ControlCall;
  if (!Number.isSafeInteger(call.id) || call.id < 1 ||
      !["start", "inspect", "release", "stop"].includes(call.method) || !call.plan) {
    throw new Error("Invalid Linux control call.");
  }
  return call;
}

export interface LinuxAgentControlService {
  close(): Promise<void>;
}

export async function startTrackedManagedUnit(manager: Pick<SystemdRunAgentUnitManager, "start" | "hasActiveLease">,
  plan: LinuxAgentUnitPlan, state: { started: boolean }): Promise<void> {
  try {
    await manager.start(plan);
    state.started = true;
  } catch (error) {
    state.started = manager.hasActiveLease(plan.sessionId);
    throw error;
  }
}

export async function stopTrackedManagedUnit(manager: Pick<SystemdRunAgentUnitManager, "stop">,
  plan: LinuxAgentUnitPlan, state: { started: boolean }): Promise<void> {
  if (!state.started) return;
  await manager.stop(plan);
  state.started = false;
}

export async function startLinuxAgentControlService(brokerUid: number, brokerGid: number): Promise<LinuxAgentControlService> {
  await checkedRootRuntime();
  if (!Number.isSafeInteger(brokerUid) || brokerUid < 1 ||
      !Number.isSafeInteger(brokerGid) || brokerGid < 1) {
    throw new Error("A dedicated broker UID and GID are required.");
  }
  const manager = new SystemdRunAgentUnitManager();
  const owners = new Map<string, Socket>();
  const draining = new Set<string>();
  const usedSessions = new Set<string>();
  const connections = new Set<Socket>();
  const cleanups = new Set<Promise<void>>();
  let closing = false;
  let loggedHandshakes = 0;
  const server = createServer(socket => {
    if (closing || connections.size >= 32) { socket.destroy(); return; }
    connections.add(socket);
    socket.pause();
    socket.on("error", () => socket.destroy());
    socket.once("close", () => connections.delete(socket));
    let stage = "frame";
    void firstFrame(socket).then(async raw => {
      const hello = raw as { sessionId?: unknown };
      if (!hello || typeof hello !== "object" || Object.keys(hello).length !== 1 ||
          typeof hello.sessionId !== "string") {
        throw new Error("Linux control needs one registered session ID.");
      }
      const sessionId = hello.sessionId;
      stage = "registration";
      const record = await registeredPlan(sessionId, brokerUid, brokerGid);
      stage = "broker";
      const invocation = await attestBroker(socket, record, brokerUid, brokerGid);
      stage = "admission";
      if (closing || socket.destroyed || owners.has(sessionId) || draining.has(sessionId) ||
          usedSessions.has(sessionId)) {
        throw new Error("Linux control session is already owned or ended.");
      }
      owners.set(sessionId, socket);
      const plan = record.plan;
      const state = { started: false };
      let used = false;
      let queued = 0;
      let chain = Promise.resolve();
      readFrames(socket, raw => {
        if (++queued > 8) { socket.destroy(); return; }
        chain = chain.then(async () => {
          const call = controlCall(raw);
          if (call.plan.sessionId !== sessionId ||
              lifecyclePlanKey(call.plan) !== lifecyclePlanKey(plan)) {
            throw new Error("Linux control plan differs from its root registration.");
          }
          if (closing) throw new Error("Linux root control service is stopping.");
          await attestBroker(socket, record, brokerUid, brokerGid, invocation);
          if (closing || socket.destroyed) throw new Error("Linux root control service is stopping.");
          if (call.method === "start") {
            if (used) throw new Error("This Linux agent session was already launched.");
            used = true;
            usedSessions.add(sessionId);
            // A root-owned rotation must be visible both before and after the UID claim.
            await attestDurableLinuxAgentIdentity(plan);
            await reserveManagedIdentity(plan);
            await attestDurableLinuxAgentIdentity(plan);
            traceLinuxManagedStart(plan.uid, "control start call");
            await startTrackedManagedUnit(manager, plan, state);
            traceLinuxManagedStart(plan.uid, "control start returned");
            return undefined;
          }
          if (!state.started) throw new Error("This Linux agent session has not started.");
          if (call.method === "inspect") {
            traceLinuxManagedStart(plan.uid, "control inspect call");
            const inspected = await manager.inspect(plan);
            traceLinuxManagedStart(plan.uid, "control inspect returned");
            return inspected;
          }
          if (call.method === "release") {
            if (!call.state) throw new Error("Linux gate release needs its attested unit state.");
            traceLinuxManagedStart(plan.uid, "control release call");
            await manager.release!(plan, call.state);
            traceLinuxManagedStart(plan.uid, "control release returned");
          } else {
            await stopTrackedManagedUnit(manager, plan, state);
          }
          return undefined;
        }).then(value => {
          const id = (raw as ControlCall)?.id;
          traceLinuxManagedStart(plan.uid,
            socket.destroyed ? "control reply socket closed" : "control reply send");
          sendControlReply(socket, id, { ok: true, value });
          traceLinuxManagedStart(plan.uid, "control reply queued");
        }).catch(error => {
          const id = (raw as ControlCall)?.id;
          sendControlReply(socket, id, { ok: false, error: String(error) });
        }).finally(() => { queued--; });
      });
      socket.once("close", () => {
        if (owners.get(sessionId) !== socket) return;
        draining.add(sessionId);
        const cleanup = chain.then(async () => {
          await stopTrackedManagedUnit(manager, plan, state);
          owners.delete(sessionId);
          draining.delete(sessionId);
        }).catch(error => {
          process.stderr.write(`Linux control teardown failed: ${String(error)}\n`);
          process.exit(1);
        });
        cleanups.add(cleanup);
        void cleanup.finally(() => cleanups.delete(cleanup));
      });
      sendFrame(socket, { sessionId, ok: true });
      socket.resume();
    }).catch(error => {
      if (loggedHandshakes++ < 4) {
        process.stderr.write(`Linux control handshake rejected during ${stage}: ${controlHandshakeFailure(error)}\n`);
      }
      socket.destroy();
    });
  });
  const oldMask = process.umask(0o117);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(controlSocket, () => { server.off("error", reject); resolve(); });
    });
  } finally { process.umask(oldMask); }
  await chown(controlSocket, 0, brokerGid);
  await chmod(controlSocket, 0o660);
  const node = await lstat(controlSocket);
  let closed: Promise<void> | undefined;
  return {
    close() {
      if (closed) return closed;
      closing = true;
      closed = (async () => {
        for (const socket of connections) socket.destroy();
        await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
        await Promise.all([...cleanups]);
        try {
          const current = await lstat(controlSocket);
          if (current.dev !== node.dev || current.ino !== node.ino) {
            throw new Error("Linux control socket changed before cleanup.");
          }
          await unlink(controlSocket);
        } catch (error) {
          if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
        }
      })();
      return closed;
    }
  };
}

export interface LinuxAgentControlClient extends LinuxAgentUnitManager {
  signal: AbortSignal;
  close(): Promise<void>;
}

export async function connectLinuxAgentControl(plan: LinuxAgentUnitPlan): Promise<LinuxAgentControlClient> {
  const brokerGid = process.getgid?.();
  if (process.platform !== "linux" || process.geteuid?.() === 0 ||
      brokerGid === undefined || process.getuid?.() !== plan.brokerUid) {
    throw new Error("A separate Linux broker identity is required.");
  }
  validateLinuxManagedPlan(plan, plan.brokerUid, brokerGid);
  const admittedPlan = { ...plan, args: [...plan.args] };
  const node = await lstat(controlSocket);
  if (!node.isSocket() || node.uid !== 0 || node.gid !== brokerGid ||
      (node.mode & 0o777) !== 0o660) {
    throw new Error("Linux root control socket ownership changed.");
  }
  const helper = fileURLToPath(new URL(`../dist/native/linux-${process.arch}/s-gw-peer-credentials`, import.meta.url));
  const binary = await lstat(helper);
  if (!binary.isFile() || (binary.uid !== process.getuid?.() && binary.uid !== 0) ||
      (binary.mode & 0o022) !== 0 || await realpath(helper) !== helper) {
    throw new Error("Untrusted Linux broker peer helper.");
  }
  let parent = path.dirname(helper);
  while (true) {
    const info = await lstat(parent);
    const stickyRoot = info.uid === 0 && (info.mode & 0o1000) !== 0;
    if (!info.isDirectory() || (info.uid !== 0 && info.uid !== process.getuid?.()) ||
        ((info.mode & 0o022) !== 0 && !stickyRoot)) {
      throw new Error("Untrusted Linux broker peer-helper parent.");
    }
    const next = path.dirname(parent);
    if (next === parent) break;
    parent = next;
  }
  const socket = createConnection(controlSocket);
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  socket.pause();
  try {
    const peer = await readPeer(socket, helper);
    if (peer.uid !== 0 || peer.gid !== 0) throw new Error("Linux control server is not root.");
  } catch (error) { socket.destroy(); throw error; }
  try {
    sendFrame(socket, { sessionId: plan.sessionId });
    const hello = await firstFrame(socket) as { sessionId?: unknown; ok?: unknown };
    if (!hello || typeof hello !== "object" || Object.keys(hello).length !== 2 ||
        hello.sessionId !== plan.sessionId || hello.ok !== true) {
      throw new Error("Linux root control did not admit this broker session.");
    }
  } catch (error) { socket.destroy(); throw error; }
  let nextId = 0;
  const lost = new AbortController();
  let pending: { id: number; method: Method; resolve(value: unknown): void; reject(error: Error): void } | undefined;
  readFrames(socket, raw => {
    const reply = raw as { id?: number; ok?: boolean; value?: unknown; error?: string };
    traceLinuxManagedStart(admittedPlan.uid, "broker reply frame received");
    if (!pending || reply.id !== pending.id || typeof reply.ok !== "boolean") {
      traceLinuxManagedStart(admittedPlan.uid, "broker reply frame invalid");
      socket.destroy();
      return;
    }
    const current = pending;
    pending = undefined;
    traceLinuxManagedStart(admittedPlan.uid, `broker ${current.method} reply ${reply.ok ? "ok" : "error"}`);
    if (reply.ok) current.resolve(reply.value);
    else current.reject(new Error(reply.error || "Linux control request failed."));
  });
  socket.once("close", () => {
    traceLinuxManagedStart(admittedPlan.uid, "broker control socket closed");
    lost.abort();
    pending?.reject(new Error("Linux root control service disconnected."));
    pending = undefined;
  });
  socket.resume();
  const call = async (method: Method, plan: LinuxAgentUnitPlan, state?: LinuxAgentUnitState): Promise<unknown> => {
    if (socket.destroyed || pending) throw new Error("Linux root control service is unavailable or busy.");
    if (plan.sessionId !== admittedPlan.sessionId ||
        lifecyclePlanKey(plan) !== lifecyclePlanKey(admittedPlan)) {
      throw new Error("Linux control plan differs from the admitted broker session.");
    }
    const id = ++nextId;
    return new Promise((resolve, reject) => {
      pending = { id, method, resolve, reject };
      traceLinuxManagedStart(admittedPlan.uid, `broker ${method} call send`);
      try { sendFrame(socket, { id, method, plan, state }); }
      catch (error) { pending = undefined; reject(error as Error); }
    });
  };
  return {
    signal: lost.signal,
    start: async plan => { await call("start", plan); },
    inspect: async plan => await call("inspect", plan) as LinuxAgentUnitState,
    release: async (plan, state) => { await call("release", plan, state); },
    stop: async plan => { await call("stop", plan); },
    close: async () => {
      if (socket.destroyed) return;
      socket.end();
      await new Promise<void>(resolve => socket.once("close", resolve));
    }
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 5 || process.argv[2] !== "--serve") {
    throw new Error("Usage: linux-agent-control --serve <broker-uid> <broker-gid>");
  }
  const brokerUid = Number(process.argv[3]);
  const brokerGid = Number(process.argv[4]);
  const service = await startLinuxAgentControlService(brokerUid, brokerGid);
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(signal, () => {
      void service.close().then(() => { process.exitCode = 0; }, error => {
        process.stderr.write(`${String(error)}\n`);
        process.exitCode = 1;
      });
    });
  }
}
