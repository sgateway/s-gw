import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { constants, createReadStream, type Stats } from "node:fs";
import { chmod, chown, link, lstat, mkdir, open, readFile, readdir, realpath, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { assertControlUnitPreflight, assertManagedMcpSocketUnit, assertModelSocketUnit,
  brokerUnitInvocation, linuxManagedControlMaxFrame, unsafeStartupEnv,
  type LinuxManagedPlanRecord } from "./linux-agent-control.js";
import { linuxAgentIdentityDir } from "./linux-agent-identity.js";
import { linuxForwarderIdentityDir, linuxForwarderIdentityRecord } from "./linux-forwarder-identity.js";
import { linuxAgentUnitName } from "./linux-agent-unit.js";
import { renderLinuxAgentControlUnit, renderLinuxManagedUnitBundle,
  type LinuxControlUnitRuntime } from "./linux-agent-provision.js";
import type { LinuxManagedMcpConfig } from "./linux-managed-mcp.js";
import { grantFromModelRelayAction, normalizeModelRelayGrant } from "./model-relay-action.js";
import type { RequestRecord } from "./types.js";

interface FileState {
  kind: "file" | "directory" | "socket" | "other";
  uid: number;
  gid: number;
  mode: number;
  nlink: number;
  size: number;
  dev: number;
  ino: number;
}

interface SavedFile { filename: string; dev: number; ino: number }

export interface LinuxManagedInstallPlan {
  control: LinuxControlUnitRuntime;
  config: LinuxManagedMcpConfig;
  record: LinuxManagedPlanRecord;
  brokerGid: number;
}

export interface LinuxManagedInstallHost {
  assertRoot(): Promise<void>;
  file(filename: string): Promise<FileState | undefined>;
  realpath(filename: string): Promise<string>;
  read(filename: string): Promise<string>;
  list?(directory: string): Promise<string[]>;
  sha256?(filename: string): Promise<string>;
  ensureDirectory(filename: string, uid: number, gid: number, mode: number): Promise<boolean>;
  publish(filename: string, content: string, uid: number, gid: number, mode: number): Promise<SavedFile>;
  replace(filename: string, before: SavedFile, content: string,
    uid: number, gid: number, mode: number): Promise<SavedFile>;
  remove(file: SavedFile): Promise<void>;
  unit(unit: string, fields: string[]): Promise<string>;
  action(action: "daemon-reload" | "start" | "stop", unit?: string): Promise<void>;
  account(uid: number): Promise<{ gid: number; groups: number[] }>;
  networkNamespace?(filename: string, helper: string, operation: "create" | "check"): Promise<void>;
}

export const linuxManagedInstallPayloadMaxBytes = 256 * 1024;

export async function readRootLinuxManagedInstallPlan(filename: string,
  host: LinuxManagedInstallHost = nativeLinuxInstallHost): Promise<LinuxManagedInstallPlan> {
  await host.assertRoot();
  if (!path.isAbsolute(filename) || path.resolve(filename) !== filename) {
    throw new Error("Linux install plan needs an absolute root-owned path.");
  }
  const item = await host.file(filename);
  if (!item || item.size > linuxManagedInstallPayloadMaxBytes) {
    throw new Error("Linux install plan is absent or too large.");
  }
  await checkedFile(host, filename, 0, 0, 0o600);
  const input = JSON.parse(await host.read(filename)) as LinuxManagedInstallPlan;
  validateInstallPlan(input);
  return input;
}

const controlName = "s-gw-agent-control.service";
const controlSocket = "/run/s-gw/agent-control.sock";
const prepareSocket = "/run/s-gw/agent-prepare.sock";
const unitFields = ["Id", "LoadState", "ActiveState", "FragmentPath", "DropInPaths", "User", "Group",
  "EnvironmentFiles", "UnsetEnvironment", "ExecStartPre", "ExecStart", "BindsTo", "After",
  "Triggers", "SocketUser", "SocketGroup", "SocketMode", "DirectoryMode", "PassCredentials",
  "FileDescriptorName", "Accept", "RemoveOnStop"];

function parseProperties(output: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const line of output.trimEnd().split("\n")) {
    const pos = line.indexOf("=");
    if (pos < 1 || values.has(line.slice(0, pos))) {
      throw new Error("Invalid Linux systemd property readback.");
    }
    values.set(line.slice(0, pos), line.slice(pos + 1));
  }
  return values;
}

function sameFile(a: FileState, b: SavedFile): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

async function rootParents(host: LinuxManagedInstallHost, filename: string): Promise<void> {
  let parent = path.dirname(filename);
  while (true) {
    const item = await host.file(parent);
    if (!item || item.kind !== "directory" || item.uid !== 0 || (item.mode & 0o022) !== 0 ||
        await host.realpath(parent) !== parent) {
      throw new Error(`Untrusted Linux provisioner parent: ${parent}`);
    }
    const next = path.dirname(parent);
    if (next === parent) return;
    parent = next;
  }
}

async function checkedFile(host: LinuxManagedInstallHost, filename: string,
  uid: number, gid: number, mode?: number): Promise<SavedFile> {
  await rootParents(host, filename);
  const item = await host.file(filename);
  if (!item || item.kind !== "file" || item.uid !== uid || item.nlink !== 1 ||
      (mode === undefined ? (item.mode & 0o022) !== 0 : item.mode !== mode || item.gid !== gid) ||
      await host.realpath(filename) !== filename) {
    throw new Error(`Untrusted Linux provisioner file: ${filename}`);
  }
  return { filename, dev: item.dev, ino: item.ino };
}

async function checkedDirectory(host: LinuxManagedInstallHost, filename: string,
  uid: number, gid: number, mode: number): Promise<void> {
  await rootParents(host, filename);
  const item = await host.file(filename);
  if (!item || item.kind !== "directory" || item.uid !== uid || item.gid !== gid ||
      item.mode !== mode || await host.realpath(filename) !== filename) {
    throw new Error(`Untrusted Linux provisioner directory: ${filename}`);
  }
}

async function ensureDirectory(host: LinuxManagedInstallHost, filename: string,
  uid: number, gid: number, mode: number): Promise<void> {
  await rootParents(host, filename);
  await host.ensureDirectory(filename, uid, gid, mode);
  await checkedDirectory(host, filename, uid, gid, mode);
}

async function withInstallLock<T>(host: LinuxManagedInstallHost,
  work: () => Promise<T>): Promise<T> {
  await ensureDirectory(host, "/run/s-gw", 0, 0, 0o755);
  const lock = await host.publish("/run/s-gw/managed-install.lock",
    `${process.pid}\n`, 0, 0, 0o600);
  try { return await work(); }
  finally { await host.remove(lock); }
}

async function publishExpected(host: LinuxManagedInstallHost, filename: string,
  content: string, uid: number, gid: number, mode: number,
  created: SavedFile[]): Promise<SavedFile> {
  await rootParents(host, filename);
  const old = await host.file(filename);
  if (old) {
    const saved = await checkedFile(host, filename, uid, gid, mode);
    if (await host.read(filename) !== content) {
      throw new Error(`Linux provisioner file already has different content: ${filename}`);
    }
    return saved;
  }
  const saved = await host.publish(filename, content, uid, gid, mode);
  created.push(saved);
  await checkedFile(host, filename, uid, gid, mode);
  return saved;
}

async function verifyInstalledFiles(host: LinuxManagedInstallHost,
  input: LinuxManagedInstallPlan, configText: string): Promise<void> {
  const { control, record, config } = input;
  const bundle = renderLinuxManagedUnitBundle(config, record, input.brokerGid, "prepare");
  const expected: Array<[string, string, number, number]> = [
    [control.unitFile, renderLinuxAgentControlUnit(control), 0, 0o644],
    [record.brokerConfig, configText, input.brokerGid, 0o640],
    [`/run/s-gw/agent-plans/${record.plan.sessionId}.json`, bundle.planRecord, 0, 0o600],
    [record.brokerUnitFile, bundle.brokerUnit, 0, 0o644],
    [record.mcpSocketUnitFile, bundle.mcpSocketUnit, 0, 0o644]
  ];
  if (record.modelRelaySocketUnitFile) {
    expected.push([record.modelRelaySocketUnitFile, bundle.modelSocketUnit!, 0, 0o644]);
  }
  if (record.mcpForwarder) {
    expected.push([record.mcpForwarder.unitFile, bundle.forwarderUnit!, 0, 0o644]);
    expected.push([`/run/s-gw/forwarder-proofs/${record.plan.sessionId}.json`,
      "PENDING\n", 0, 0o644]);
    expected.push([`${record.mcpForwarder.rootDirectory}/run/s-gw/broker.sock`, "", 0, 0o600]);
    expected.push([`${record.mcpForwarder.rootDirectory}/run/s-gw/forwarder-attestation.json`,
      "", 0, 0o600]);
  }
  for (const [filename, content, gid, mode] of expected) {
    await checkedFile(host, filename, 0, gid, mode);
    if (await host.read(filename) !== content) {
      throw new Error(`Linux provisioner file changed after installation: ${filename}`);
    }
  }
}

function validateInstallPlan(input: LinuxManagedInstallPlan): void {
  const { config, record, control, brokerGid } = input;
  renderLinuxAgentControlUnit(control);
  const bundle = renderLinuxManagedUnitBundle(config, record, brokerGid, "prepare");
  if (Buffer.byteLength(bundle.planRecord) > linuxManagedControlMaxFrame) {
    throw new Error("Linux managed plan record exceeds the root control frame limit.");
  }
  const sessionId = record.plan.sessionId;
  if (control.brokerUid !== record.plan.brokerUid || control.brokerGid !== brokerGid ||
      control.unitFile !== `/run/systemd/system/${controlName}` ||
      record.brokerUnitFile !== `/run/systemd/system/${record.brokerUnit}` ||
      record.mcpSocketUnitFile !== `/run/systemd/system/s-gw-managed-mcp-${sessionId}.socket` ||
      (record.modelRelaySocketUnitFile !== undefined && record.modelRelaySocketUnitFile !==
        `/run/systemd/system/s-gw-managed-model-${sessionId}.socket`) ||
      record.brokerConfig !== `/run/s-gw/${sessionId}.json` ||
      config.leaseDir !== "/run/s-gw/managed-leases" ||
      record.plan.uid === control.brokerUid || record.plan.gid === brokerGid ||
      (record.mcpForwarder && record.mcpForwarder.unitFile !==
        `/run/systemd/system/s-gw-forwarder-${sessionId}.service`)) {
    throw new Error("Linux installer needs the dedicated root control and two-UID runtime layout.");
  }
}

export function assertApprovedLinuxManagedRelay(config: LinuxManagedMcpConfig,
  request: RequestRecord, now = Date.now()): void {
  const relay = config.relay;
  if (!relay?.requestId || request?.id !== relay.requestId ||
      request.state !== "approved" || request.approvalSource !== "manual" ||
      request.agentSource !== "managed-peer" ||
      request.principalId !== `linux:managed:${config.plan.identityGeneration}` ||
      request.agentSessionId !== config.plan.sessionId || request.agentName !== config.name ||
      request.action?.kind !== "model_relay") {
    throw new Error("Linux installer needs the exact manually approved model relay request.");
  }
  const approvedAt = Date.parse(request.approvedAt || "");
  if (!Number.isFinite(approvedAt) || approvedAt > now || now - approvedAt > 5 * 60_000 ||
      JSON.stringify(grantFromModelRelayAction(request.handle, request.action)) !==
        JSON.stringify(normalizeModelRelayGrant(relay.grant))) {
    throw new Error("Linux model relay approval is stale or differs from the sealed grant.");
  }
}

async function assertAccountIsolation(host: LinuxManagedInstallHost,
  input: LinuxManagedInstallPlan): Promise<void> {
  const plan = input.record.plan;
  const agent = await host.account(plan.uid);
  const broker = await host.account(plan.brokerUid);
  if (agent.gid !== plan.gid || agent.groups.length !== 1 || agent.groups[0] !== plan.gid ||
      broker.gid !== input.brokerGid || broker.groups.length !== 1 ||
      broker.groups[0] !== input.brokerGid || plan.uid === plan.brokerUid ||
      plan.gid === input.brokerGid) {
    throw new Error("Linux installer needs separate agent and broker accounts with dedicated groups.");
  }
  const forwarder = input.record.mcpForwarder;
  if (forwarder) {
    const account = await host.account(forwarder.uid);
    if (account.gid !== forwarder.gid || account.groups.length !== 1 ||
        account.groups[0] !== forwarder.gid) {
      throw new Error("Linux installer needs a separate dedicated MCP forwarder account.");
    }
  }
}

function forwarderEntry(input: LinuxManagedInstallPlan): string {
  return path.join(path.dirname(input.record.brokerEntry), "linux-managed-mcp-forwarder.js");
}

async function checkForwarderRoot(host: LinuxManagedInstallHost,
  input: LinuxManagedInstallPlan): Promise<void> {
  const forwarder = input.record.mcpForwarder;
  if (!forwarder) return;
  await checkedDirectory(host, forwarder.rootDirectory, 0, 0, 0o755);
  await checkedDirectory(host, `${forwarder.rootDirectory}/run/s-gw`, 0, 0, 0o755);
  const packageFile = `${forwarder.rootDirectory}${input.record.brokerRuntimeRoot}/package.json`;
  const packageState = await host.file(packageFile);
  await checkedFile(host, packageFile, 0, 0, 0o644);
  if (!packageState || packageState.size > 128 ||
      await host.read(packageFile) !== '{"type":"module"}\n') {
    throw new Error("Linux forwarder root needs sealed ES module metadata.");
  }
  if (!host.sha256) throw new Error("Linux forwarder root needs a trusted runtime digest check.");
  for (const filename of [input.record.brokerNode, forwarderEntry(input)]) {
    const hostFile = await checkedFile(host, filename, 0, 0);
    const inside = await checkedFile(host, `${forwarder.rootDirectory}${filename}`, 0, 0);
    const hostState = await host.file(hostFile.filename);
    const insideState = await host.file(inside.filename);
    if (!hostState || !insideState || hostState.size !== insideState.size ||
        await host.sha256(hostFile.filename) !== await host.sha256(inside.filename)) {
      throw new Error("Linux forwarder root does not contain its trusted runtime.");
    }
  }
}

async function checkForwarderNamespace(host: LinuxManagedInstallHost,
  input: LinuxManagedInstallPlan, operation: "create" | "check"): Promise<void> {
  const forwarder = input.record.mcpForwarder;
  if (!forwarder) return;
  const helper = `${input.control.runtimeRoot}/s-gw-linux-netns`;
  const item = await host.file(helper);
  await checkedFile(host, helper, 0, 0);
  if (!item || (item.mode & 0o111) === 0 || !host.networkNamespace) {
    throw new Error("Linux forwarder needs its trusted namespace helper.");
  }
  if (operation === "create") {
    if (await host.file(forwarder.networkNamespacePath)) {
      throw new Error("Linux forwarder needs a fresh private network namespace.");
    }
    await host.networkNamespace(forwarder.networkNamespacePath, helper, "create");
  }
  await checkedFile(host, forwarder.networkNamespacePath, 0, 0);
  await host.networkNamespace(forwarder.networkNamespacePath, helper, "check");
}

async function rejectAgentIdentityReuse(host: LinuxManagedInstallHost,
  forwarder: NonNullable<LinuxManagedPlanRecord["mcpForwarder"]>): Promise<void> {
  if (!host.list) throw new Error("Linux forwarder needs the durable agent identity inventory.");
  for (const name of await host.list(linuxAgentIdentityDir)) {
    if (!name.startsWith("generation-")) continue;
    if (!/^generation-[a-f0-9]{32}\.json$/.test(name)) {
      throw new Error("Linux agent identity registry has an invalid generation receipt.");
    }
    const filename = `${linuxAgentIdentityDir}/${name}`;
    await checkedFile(host, filename, 0, 0, 0o600);
    const value = JSON.parse(await host.read(filename)) as Record<string, unknown>;
    if (!value || typeof value !== "object" ||
        value.identityGeneration !== name.slice("generation-".length, -".json".length) ||
        !Number.isSafeInteger(value.uid) || !Number.isSafeInteger(value.gid)) {
      throw new Error("Linux agent identity history cannot be verified.");
    }
    if (value.uid === forwarder.uid || value.gid === forwarder.gid) {
      throw new Error("Linux agent and forwarder identity histories overlap.");
    }
  }
}

async function readbackForwarder(host: LinuxManagedInstallHost,
  input: LinuxManagedInstallPlan): Promise<void> {
  const forwarder = input.record.mcpForwarder;
  if (!forwarder) return;
  const name = path.basename(forwarder.unitFile);
  const values = parseProperties(await host.unit(name, ["Id", "LoadState", "ActiveState",
    "FragmentPath", "DropInPaths", "User", "Group", "RootDirectory", "NetworkNamespacePath",
    "PrivateNetwork", "PrivateIPC", "PrivateTmp", "PrivatePIDs", "MountFlags", "BindLogSockets",
    "ProtectHome", "ProtectSystem",
    "NoNewPrivileges", "CapabilityBoundingSet", "AmbientCapabilities", "RestrictNamespaces",
    "SystemCallArchitectures", "KillMode", "BindReadOnlyPaths", "BindsTo", "After", "ExecStart"]));
  const wanted = new Map([
    ["Id", name], ["LoadState", "loaded"], ["ActiveState", "inactive"],
    ["FragmentPath", forwarder.unitFile], ["DropInPaths", ""],
    ["User", String(forwarder.uid)], ["Group", String(forwarder.gid)],
    ["RootDirectory", forwarder.rootDirectory],
    ["NetworkNamespacePath", forwarder.networkNamespacePath],
    ["PrivateNetwork", "yes"], ["PrivateIPC", "yes"], ["PrivateTmp", "yes"],
    ["PrivatePIDs", "no"], ["MountFlags", "private"], ["BindLogSockets", "no"],
    ["ProtectHome", "yes"], ["ProtectSystem", "strict"],
    ["NoNewPrivileges", "yes"], ["RestrictNamespaces", "yes"],
    ["SystemCallArchitectures", "native"], ["KillMode", "control-group"],
    ["BindReadOnlyPaths", `${input.record.plan.brokerSocket}:/run/s-gw/broker.sock ` +
      `/run/s-gw/forwarder-proofs/${input.record.plan.sessionId}.json:/run/s-gw/forwarder-attestation.json`]
  ]);
  for (const [key, expected] of wanted) {
    const actual = values.get(key);
    const validBind = key === "BindReadOnlyPaths" && actual?.split(" ").length === 2 &&
      actual.split(" ").every((entry, index) => {
        const source = expected.split(" ")[index];
        return entry === source || entry === `${source}:rbind`;
      });
    if (actual !== expected && !validBind) {
      throw new Error(`Linux forwarder unit property changed: ${key}`);
    }
  }
  for (const key of ["CapabilityBoundingSet", "AmbientCapabilities"]) {
    if (!["", "0"].includes(values.get(key) ?? "missing")) {
      throw new Error(`Linux forwarder retained ${key}.`);
    }
  }
  const expectedDeps = ["s-gw-agent-control.service",
    `s-gw-agent-${input.record.plan.sessionId}.service`];
  for (const key of ["BindsTo", "After"]) {
    const deps = new Set((values.get(key) || "").split(/\s+/));
    if (expectedDeps.some(unit => !deps.has(unit))) {
      throw new Error(`Linux forwarder unit lost its ${key} dependency.`);
    }
  }
  const command = `{ path=${input.record.brokerNode} ; argv[]=${input.record.brokerNode} ` +
    `${forwarderEntry(input)} ; ignore_errors=no ; }`;
  if (values.get("ExecStart") !== command) {
    throw new Error("Linux forwarder unit command changed.");
  }
}

async function assertInactive(host: LinuxManagedInstallHost, unit: string): Promise<void> {
  const properties = parseProperties(await host.unit(unit, ["Id", "LoadState", "ActiveState"]));
  if (properties.get("Id") !== unit || properties.get("ActiveState") !== "inactive") {
    throw new Error(`Linux installer found an active or uncertain unit: ${unit}`);
  }
}

async function readbackSocket(host: LinuxManagedInstallHost, record: LinuxManagedPlanRecord,
  filename: string, expectedState: "inactive" | "active"): Promise<void> {
  const unit = path.basename(filename);
  const output = await host.unit(unit, unitFields);
  const values = parseProperties(output);
  if (values.get("LoadState") !== "loaded" || values.get("DropInPaths") ||
      values.get("SocketUser") !== "root" ||
      values.get("SocketGroup") !== String(record.mcpForwarder?.gid ?? record.plan.gid) ||
      !["0660", "660"].includes(values.get("SocketMode") || "") ||
      !["0711", "711"].includes(values.get("DirectoryMode") || "") ||
      values.get("PassCredentials") !== "yes" || values.get("Accept") !== "no" ||
      values.get("RemoveOnStop") !== "no" ||
      values.get("FileDescriptorName") !==
        (filename === record.mcpSocketUnitFile ? `s-gw-agent-${record.plan.sessionId}` :
          `s-gw-model-${record.plan.sessionId}`)) {
    throw new Error(`Linux installer socket properties differ from its unit: ${unit}`);
  }
  if (filename === record.mcpSocketUnitFile) {
    assertManagedMcpSocketUnit(record, output, expectedState);
  } else {
    assertModelSocketUnit(record, output, expectedState);
  }
}

async function readbackBroker(host: LinuxManagedInstallHost,
  input: LinuxManagedInstallPlan, active: boolean): Promise<void> {
  const output = await host.unit(input.record.brokerUnit,
    [...unitFields, "MainPID", "ControlGroup", "InvocationID"]);
  const values = parseProperties(output);
  if (values.get("LoadState") !== "loaded" || values.get("DropInPaths") ||
      values.get("FragmentPath") !== input.record.brokerUnitFile ||
      values.get("User") !== String(input.record.plan.brokerUid) ||
      values.get("Group") !== String(input.brokerGid)) {
    throw new Error("Linux installer broker unit has different live properties.");
  }
  if (active) {
    const pid = Number(values.get("MainPID"));
    if (!Number.isSafeInteger(pid) || pid < 1) throw new Error("Linux broker has no live main PID.");
    brokerUnitInvocation(input.record, pid, output);
  } else if (values.get("ActiveState") !== "inactive") {
    throw new Error("Linux installer broker was active before approval.");
  }
}

async function readbackControl(host: LinuxManagedInstallHost,
  input: LinuxManagedInstallPlan, expectedState: "active" | "inactive" = "active"):
  Promise<{ pid: number; invocationId: string } | undefined> {
  const output = await host.unit(controlName, [...unitFields, "MainPID", "InvocationID"]);
  const values = parseProperties(output);
  if (values.get("DropInPaths") || values.get("LoadState") !== "loaded" ||
      values.get("User") !== "root" || values.get("Group") !== "root") {
    throw new Error("Linux installer root control unit has different live properties.");
  }
  assertControlUnitPreflight(output, { ...input.control,
    args: ["--serve", String(input.control.brokerUid), String(input.control.brokerGid)] },
  expectedState);
  if (expectedState === "inactive") return;
  const pid = Number(values.get("MainPID"));
  const invocationId = values.get("InvocationID") || "";
  if (!Number.isSafeInteger(pid) || pid < 1 || !/^[a-f0-9]{32}$/.test(invocationId)) {
    throw new Error("Linux installer root control has no stable live invocation.");
  }
  return { pid, invocationId };
}

async function controlSocketReady(host: LinuxManagedInstallHost, filename: string,
  gid: number, mode: number): Promise<boolean> {
  const item = await host.file(filename);
  if (!item) return false;
  if (item.kind !== "socket" || item.uid !== 0 || item.gid !== gid ||
      item.mode !== mode || item.nlink !== 1 || await host.realpath(filename) !== filename) {
    throw new Error("Linux installer found an untrusted root control socket: " + filename);
  }
  return true;
}

async function waitForControlSockets(host: LinuxManagedInstallHost, input: LinuxManagedInstallPlan,
  started: { pid: number; invocationId: string }): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const current = await readbackControl(host, input);
    if (current?.pid !== started.pid || current.invocationId !== started.invocationId) {
      throw new Error("Linux installer root control changed while opening its sockets.");
    }
    const brokerReady = await controlSocketReady(host, controlSocket, input.brokerGid, 0o660);
    const prepareReady = await controlSocketReady(host, prepareSocket, 0, 0o600);
    if (brokerReady && prepareReady) {
      const after = await readbackControl(host, input);
      if (after?.pid !== started.pid || after.invocationId !== started.invocationId) {
        throw new Error("Linux installer root control changed after opening its sockets.");
      }
      if (!await controlSocketReady(host, controlSocket, input.brokerGid, 0o660) ||
          !await controlSocketReady(host, prepareSocket, 0, 0o600)) {
        throw new Error("Linux installer root control sockets vanished during staging.");
      }
      return;
    }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error("Linux installer root control sockets did not become ready.");
}

export class LinuxManagedUnitInstaller {
  constructor(private readonly host: LinuxManagedInstallHost) {}

  async stage(input: LinuxManagedInstallPlan): Promise<void> {
    validateInstallPlan(input);
    await this.host.assertRoot();
    return withInstallLock(this.host, () => this.stageLocked(input));
  }

  private async stageLocked(input: LinuxManagedInstallPlan): Promise<void> {
    const { host } = this;
    const { config, record, control } = input;
    await assertInactive(host, controlName);
    const bundle = renderLinuxManagedUnitBundle(config, record, input.brokerGid, "prepare");
    const plan = record.plan;
    const planFile = `/run/s-gw/agent-plans/${plan.sessionId}.json`;
    const mcpUnit = path.basename(record.mcpSocketUnitFile);
    const modelUnit = record.modelRelaySocketUnitFile && path.basename(record.modelRelaySocketUnitFile);
    const forwarderUnit = record.mcpForwarder && path.basename(record.mcpForwarder.unitFile);
    await assertAccountIsolation(host, input);
    for (const filename of [control.node, control.entry, control.preflight, record.brokerNode,
      record.brokerEntry, record.brokerPreflight]) {
      await checkedFile(host, filename, 0, 0);
    }
    await checkedFile(host, record.brokerEnvironmentFile, 0, 0, 0o600);
    await checkForwarderRoot(host, input);
    if (record.brokerCa) await checkedFile(host, record.brokerCa, 0, 0);
    await assertInactive(host, mcpUnit);
    if (modelUnit) await assertInactive(host, modelUnit);
    await assertInactive(host, record.brokerUnit);
    if (forwarderUnit) await assertInactive(host, forwarderUnit);
    await assertInactive(host, linuxAgentUnitName(plan.sessionId));
    for (const filename of [controlSocket, prepareSocket]) {
      if (await host.file(filename)) {
        throw new Error("Linux installer found a preexisting root control socket: " + filename);
      }
    }
    await ensureDirectory(host, "/run/s-gw", 0, 0, 0o755);
    await ensureDirectory(host, "/run/s-gw/agents", 0, 0, 0o711);
    await ensureDirectory(host, `/run/s-gw/agents/${plan.sessionId}`, 0, 0, 0o711);
    await ensureDirectory(host, "/run/s-gw/agent-plans", 0, 0, 0o700);
    await ensureDirectory(host, config.leaseDir, plan.brokerUid, input.brokerGid, 0o700);
    await ensureDirectory(host, "/var/lib/s-gw", 0, 0, 0o700);
    await ensureDirectory(host, linuxAgentIdentityDir, 0, 0, 0o700);
    if (await host.file(linuxForwarderIdentityDir)) {
      await checkedDirectory(host, linuxForwarderIdentityDir, 0, 0, 0o700);
      if (await host.file(`${linuxForwarderIdentityDir}/uid-${plan.uid}.json`) ||
          await host.file(`${linuxForwarderIdentityDir}/gid-${plan.gid}.json`)) {
        throw new Error("Linux agent and forwarder identity histories overlap.");
      }
    }
    if (record.mcpForwarder) {
      await ensureDirectory(host, linuxForwarderIdentityDir, 0, 0, 0o700);
      await rejectAgentIdentityReuse(host, record.mcpForwarder);
      const receipt = linuxForwarderIdentityRecord(record);
      for (const filename of [`uid-${record.mcpForwarder.uid}.json`,
        `gid-${record.mcpForwarder.gid}.json`, `session-${plan.sessionId}.json`]) {
        await publishExpected(host, `${linuxForwarderIdentityDir}/${filename}`,
          receipt, 0, 0, 0o600, []);
      }
      await ensureDirectory(host, "/run/s-gw/netns", 0, 0, 0o700);
      await ensureDirectory(host, "/run/s-gw/forwarder-proofs", 0, 0, 0o711);
      await checkForwarderNamespace(host, input, "create");
    }

    const identity = `${JSON.stringify({ logicalAgentId: plan.logicalAgentId,
      identityGeneration: plan.identityGeneration, uid: plan.uid, gid: plan.gid })}\n`;
    // Generation receipts stay even if unit publication later fails.
    await publishExpected(host, `${linuxAgentIdentityDir}/generation-${plan.identityGeneration}.json`,
      identity, 0, 0, 0o600, []);
    await publishExpected(host, `${linuxAgentIdentityDir}/uid-${plan.uid}.json`,
      identity, 0, 0, 0o600, []);

    const created: SavedFile[] = [];
    let startedControl = false;
    try {
      await publishExpected(host, control.unitFile, renderLinuxAgentControlUnit(control),
        0, 0, 0o644, created);
      await publishExpected(host, record.brokerConfig, bundle.brokerConfig,
        0, input.brokerGid, 0o640, created);
      await publishExpected(host, planFile, bundle.planRecord, 0, 0, 0o600, created);
      await publishExpected(host, record.brokerUnitFile, bundle.brokerUnit, 0, 0, 0o644, created);
      await publishExpected(host, record.mcpSocketUnitFile, bundle.mcpSocketUnit, 0, 0, 0o644, created);
      if (record.modelRelaySocketUnitFile) {
        await publishExpected(host, record.modelRelaySocketUnitFile, bundle.modelSocketUnit!,
          0, 0, 0o644, created);
      }
      if (record.mcpForwarder) {
        await publishExpected(host, record.mcpForwarder.unitFile, bundle.forwarderUnit!,
          0, 0, 0o644, created);
        await publishExpected(host, `/run/s-gw/forwarder-proofs/${plan.sessionId}.json`,
          "PENDING\n", 0, 0, 0o644, created);
        await publishExpected(host, `${record.mcpForwarder.rootDirectory}/run/s-gw/broker.sock`,
          "", 0, 0, 0o600, created);
        await publishExpected(host, `${record.mcpForwarder.rootDirectory}/run/s-gw/forwarder-attestation.json`,
          "", 0, 0, 0o600, created);
      }
      await verifyInstalledFiles(host, input, bundle.brokerConfig);
      await host.action("daemon-reload");
      await readbackBroker(host, input, false);
      await readbackForwarder(host, input);
      await readbackSocket(host, record, record.mcpSocketUnitFile, "inactive");
      if (record.modelRelaySocketUnitFile) {
        await readbackSocket(host, record, record.modelRelaySocketUnitFile, "inactive");
      }
      await readbackControl(host, input, "inactive");
      startedControl = true;
      await host.action("start", controlName);
      const started = await readbackControl(host, input);
      if (!started) throw new Error("Linux installer root control did not start.");
      await waitForControlSockets(host, input, started);
    } catch (error) {
      const cleanup: unknown[] = [];
      if (startedControl) {
        try { await host.action("stop", controlName); }
        catch (failure) { cleanup.push(failure); }
        try {
          await assertInactive(host, controlName);
          for (const filename of [controlSocket, prepareSocket]) {
            if (await host.file(filename)) {
              throw new Error("Linux root control socket remained after staging failure: " + filename);
            }
          }
        } catch (failure) { cleanup.push(failure); }
      }
      try {
        await assertInactive(host, mcpUnit);
        if (modelUnit) await assertInactive(host, modelUnit);
        await assertInactive(host, record.brokerUnit);
        if (forwarderUnit) await assertInactive(host, forwarderUnit);
        await assertInactive(host, linuxAgentUnitName(plan.sessionId));
        if (!cleanup.length) {
          for (const file of created.reverse()) await host.remove(file);
          await host.action("daemon-reload");
        }
      } catch (failure) { cleanup.push(failure); }
      if (cleanup.length) throw new AggregateError([error, ...cleanup],
        "Linux staging failed and safe rollback could not be proved.");
      throw error;
    }
  }

  async activate(input: LinuxManagedInstallPlan, requestId: string,
    getRequest: (id: string) => Promise<RequestRecord>): Promise<void> {
    validateInstallPlan(input);
    if (input.record.mcpForwarder) {
      throw new Error("MCP forwarder staging cannot activate without a model relay transport and root proof.");
    }
    await this.host.assertRoot();
    return withInstallLock(this.host, () => this.activateLocked(input, requestId, getRequest));
  }

  private async activateLocked(input: LinuxManagedInstallPlan, requestId: string,
    getRequest: (id: string) => Promise<RequestRecord>): Promise<void> {
    const { host } = this;
    const { config, record } = input;
    if (!/^[A-Za-z0-9_-]{1,256}$/.test(requestId)) {
      throw new Error("Linux installer needs a bounded approved request ID.");
    }
    const staged = renderLinuxManagedUnitBundle(config, record, input.brokerGid, "prepare");
    const sealedConfig: LinuxManagedMcpConfig = { ...config,
      relay: { ...config.relay!, requestId } };
    const sealed = renderLinuxManagedUnitBundle(sealedConfig, record, input.brokerGid, "runtime");
    const mcpUnit = path.basename(record.mcpSocketUnitFile);
    const modelUnit = path.basename(record.modelRelaySocketUnitFile!);
    const agentUnit = linuxAgentUnitName(record.plan.sessionId);
    const forwarderUnit = record.mcpForwarder && path.basename(record.mcpForwarder.unitFile);
    await assertAccountIsolation(host, input);
    await readbackControl(host, input);
    await readbackBroker(host, input, false);
    await readbackSocket(host, record, record.mcpSocketUnitFile, "inactive");
    await readbackSocket(host, record, record.modelRelaySocketUnitFile!, "inactive");
    await assertInactive(host, agentUnit);
    if (forwarderUnit) {
      await assertInactive(host, forwarderUnit);
      await checkForwarderRoot(host, input);
      await checkForwarderNamespace(host, input, "check");
      await readbackForwarder(host, input);
    }
    const old = await checkedFile(host, record.brokerConfig, 0, input.brokerGid, 0o640);
    if (await host.read(record.brokerConfig) !== staged.brokerConfig) {
      throw new Error("Linux broker config changed after preparation.");
    }
    await verifyInstalledFiles(host, input, staged.brokerConfig);
    const request = await getRequest(requestId);
    assertApprovedLinuxManagedRelay(sealedConfig, request);
    const next = await host.replace(record.brokerConfig, old, sealed.brokerConfig,
      0, input.brokerGid, 0o640);
    let started = false;
    try {
      await checkedFile(host, record.brokerConfig, 0, input.brokerGid, 0o640);
      if (await host.read(record.brokerConfig) !== sealed.brokerConfig) {
        throw new Error("Linux sealed broker config changed before socket activation.");
      }
      assertApprovedLinuxManagedRelay(sealedConfig, await getRequest(requestId));
      started = true;
      await host.action("start", mcpUnit);
      await readbackSocket(host, record, record.mcpSocketUnitFile, "active");
      await checkedSocketNode(host, record.plan.brokerSocket,
        record.mcpForwarder?.gid ?? record.plan.gid);
      await host.action("start", modelUnit);
      await readbackSocket(host, record, record.modelRelaySocketUnitFile!, "active");
      await checkedSocketNode(host, record.plan.modelRelaySocket!,
        record.mcpForwarder?.gid ?? record.plan.gid);
      await host.action("start", record.brokerUnit);
      await readbackBroker(host, input, true);
    } catch (error) {
      const cleanup: unknown[] = [];
      if (started) {
        for (const unit of [mcpUnit, modelUnit, record.brokerUnit]) {
          try { await host.action("stop", unit); }
          catch (failure) { cleanup.push(failure); }
        }
      }
      try {
        await assertInactive(host, mcpUnit);
        await assertInactive(host, modelUnit);
        await assertInactive(host, record.brokerUnit);
        await assertInactive(host, agentUnit);
        if (!cleanup.length) await host.replace(record.brokerConfig, next,
          staged.brokerConfig, 0, input.brokerGid, 0o640);
      } catch (failure) { cleanup.push(failure); }
      if (cleanup.length) throw new AggregateError([error, ...cleanup],
        "Linux activation failed; the sealed config was retained because teardown is uncertain.");
      throw error;
    }
  }
}

export function linuxManagedApprovalReaderArgs(input: LinuxManagedInstallPlan,
  requestId: string, unitName: string): string[] {
  validateInstallPlan(input);
  if (input.record.mcpForwarder) {
    throw new Error("MCP forwarder staging cannot request model relay approval.");
  }
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(requestId) ||
      !/^s-gw-approval-[a-f0-9]{32}$/.test(unitName)) {
    throw new Error("Linux approval reader needs a bounded request and fresh unit name.");
  }
  const record = input.record;
  const reader = path.join(path.dirname(record.brokerEntry), "linux-managed-approval-reader.js");
  return ["--system", "--quiet", "--wait", "--pipe", "--collect", "--no-ask-password",
    `--unit=${unitName}`,
    `--property=User=${record.plan.brokerUid}`,
    `--property=Group=${input.brokerGid}`,
    `--property=EnvironmentFile=${record.brokerEnvironmentFile}`,
    `--property=UnsetEnvironment=${unsafeStartupEnv.join(" ")}`,
    "--property=Type=exec", "--property=NoNewPrivileges=yes",
    "--property=PrivateNetwork=yes", "--property=CapabilityBoundingSet=",
    "--property=RestrictAddressFamilies=AF_UNIX", "--property=RuntimeMaxSec=15s",
    record.brokerPreflight, "verify-exec", record.brokerRuntimeRoot, record.brokerNode,
    reader, record.brokerConfig, record.brokerCa ?? "-", record.brokerEnvironmentFile,
    "--", record.brokerConfig, requestId];
}

export async function readApprovedLinuxManagedRelayFromBroker(input: LinuxManagedInstallPlan,
  requestId: string, host: LinuxManagedInstallHost = nativeLinuxInstallHost): Promise<RequestRecord> {
  await host.assertRoot();
  const reader = path.join(path.dirname(input.record.brokerEntry), "linux-managed-approval-reader.js");
  await checkedFile(host, reader, 0, 0);
  await checkedFile(host, input.record.brokerEnvironmentFile, 0, 0, 0o600);
  const args = linuxManagedApprovalReaderArgs(input, requestId,
    `s-gw-approval-${randomBytes(16).toString("hex")}`);
  const output = await run("/usr/bin/systemd-run", args, 20_000, linuxManagedInstallPayloadMaxBytes);
  let request: RequestRecord;
  try { request = JSON.parse(output) as RequestRecord; }
  catch { throw new Error("Linux broker approval reader returned invalid JSON."); }
  assertApprovedLinuxManagedRelay({ ...input.config,
    relay: { ...input.config.relay!, requestId } }, request);
  return request;
}

async function checkedSocketNode(host: LinuxManagedInstallHost,
  filename: string, gid: number): Promise<void> {
  await checkedDirectory(host, path.dirname(filename), 0, 0, 0o711);
  const node = await host.file(filename);
  if (!node || node.kind !== "socket" || node.uid !== 0 || node.gid !== gid ||
      node.mode !== 0o660 || await host.realpath(filename) !== filename) {
    throw new Error(`Linux activated socket node is not agent-group isolated: ${filename}`);
  }
}

function nativeState(value: Stats): FileState {
  return { kind: value.isFile() ? "file" : value.isDirectory() ? "directory" :
    value.isSocket() ? "socket" : "other", uid: value.uid, gid: value.gid,
    mode: value.mode & 0o777, nlink: value.nlink, size: value.size, dev: value.dev, ino: value.ino };
}

async function nativeFile(filename: string): Promise<FileState | undefined> {
  try { return nativeState(await lstat(filename)); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
}

async function syncDirectory(filename: string): Promise<void> {
  const dir = await open(filename, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await dir.sync(); }
  finally { await dir.close(); }
}

async function writeTemp(filename: string, content: string,
  uid: number, gid: number, mode: number): Promise<string> {
  const tmp = `${filename}.tmp-${randomBytes(16).toString("hex")}`;
  const file = await open(tmp,
    constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    await file.chown(uid, gid);
    await file.chmod(mode);
    await file.writeFile(content);
    await file.sync();
  } catch (error) {
    await file.close();
    await unlink(tmp);
    throw error;
  }
  await file.close();
  return tmp;
}

async function run(command: string, args: string[], timeout = 10_000,
  maxOutput = 32_768): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env: { PATH: "/usr/bin:/bin", LANG: "C" },
      stdio: ["ignore", "pipe", "pipe"], timeout });
    const stdout: Buffer[] = [];
    let outBytes = 0;
    let err = "";
    child.stdout!.on("data", (chunk: Buffer) => {
      outBytes += chunk.length;
      if (outBytes > maxOutput) { child.kill(); return; }
      stdout.push(chunk);
    });
    child.stderr!.on("data", chunk => { err += String(chunk); if (err.length > 4096) child.kill(); });
    child.once("error", reject);
    child.once("close", code => code === 0 && outBytes <= maxOutput ? resolve(Buffer.concat(stdout).toString("utf8")) :
      reject(new Error(`Linux provisioner command failed: ${path.basename(command)} (${code ?? "signal"}).`)));
  });
}

export const nativeLinuxInstallHost: LinuxManagedInstallHost = {
  async assertRoot() {
    if (process.platform !== "linux" || process.getuid?.() !== 0 || process.geteuid?.() !== 0) {
      throw new Error("Linux unit installation needs a privileged Linux root operator.");
    }
  },
  file: nativeFile,
  realpath,
  read: filename => readFile(filename, "utf8"),
  list: directory => readdir(directory),
  sha256: filename => new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const input = createReadStream(filename);
    input.on("data", chunk => hash.update(chunk));
    input.once("error", reject);
    input.once("end", () => resolve(hash.digest("hex")));
  }),
  async ensureDirectory(filename, uid, gid, mode) {
    if (await nativeFile(filename)) return false;
    await mkdir(filename, { mode });
    await chown(filename, uid, gid);
    await chmod(filename, mode);
    await syncDirectory(path.dirname(filename));
    return true;
  },
  async publish(filename, content, uid, gid, mode) {
    const tmp = await writeTemp(filename, content, uid, gid, mode);
    let linked = false;
    try {
      await link(tmp, filename);
      linked = true;
      await unlink(tmp);
      await syncDirectory(path.dirname(filename));
      const item = await lstat(filename);
      return { filename, dev: item.dev, ino: item.ino };
    } catch (error) {
      if (linked) {
        const target = await nativeFile(filename);
        const staged = await nativeFile(tmp);
        if (target && (!staged || sameFile(target, { filename: tmp, dev: staged.dev, ino: staged.ino }))) {
          await unlink(filename);
          await syncDirectory(path.dirname(filename));
        }
      }
      throw error;
    } finally {
      if (await nativeFile(tmp)) await unlink(tmp);
    }
  },
  async replace(filename, before, content, uid, gid, mode) {
    const current = await nativeFile(filename);
    if (!current || current.kind !== "file" || !sameFile(current, before)) {
      throw new Error(`Linux provisioner file changed before replacement: ${filename}`);
    }
    const tmp = await writeTemp(filename, content, uid, gid, mode);
    try {
      const again = await nativeFile(filename);
      if (!again || !sameFile(again, before)) {
        throw new Error(`Linux provisioner file changed during replacement: ${filename}`);
      }
      await rename(tmp, filename);
      await syncDirectory(path.dirname(filename));
      const next = await lstat(filename);
      return { filename, dev: next.dev, ino: next.ino };
    } finally {
      if (await nativeFile(tmp)) await unlink(tmp);
    }
  },
  async remove(file) {
    const item = await nativeFile(file.filename);
    if (!item || item.kind !== "file" || !sameFile(item, file)) {
      throw new Error(`Linux provisioner file changed before rollback: ${file.filename}`);
    }
    await unlink(file.filename);
    await syncDirectory(path.dirname(file.filename));
  },
  unit: (unit, fields) => run("/usr/bin/systemctl", ["--system", "--no-pager", "--all", "show", unit,
    ...fields.flatMap(field => ["-p", field])]),
  async action(action, unit) {
    await run("/usr/bin/systemctl", ["--system", "--no-ask-password", action,
      ...(unit ? [unit] : [])]);
  },
  async account(uid) {
    const entry = (await run("/usr/bin/getent", ["passwd", String(uid)])).trimEnd().split(":");
    if (entry.length !== 7 || !entry[0] || Number(entry[2]) !== uid) {
      throw new Error("Linux installer could not resolve its dedicated account.");
    }
    const groups = (await run("/usr/bin/id", ["-G", "--", entry[0]])).trim().split(/\s+/).map(Number);
    if (groups.some(group => !Number.isSafeInteger(group) || group < 1)) {
      throw new Error("Linux installer found an invalid account group.");
    }
    return { gid: Number(entry[3]), groups };
  },
  async networkNamespace(filename, helper, operation) {
    await run(helper, [operation, filename]);
  }
};

export const nativeLinuxManagedUnitInstaller = new LinuxManagedUnitInstaller(nativeLinuxInstallHost);
