import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { chmod, chown, link, lstat, mkdir, open, readFile, realpath, rename, unlink } from "node:fs/promises";
import path from "node:path";
import { assertControlUnitPreflight, assertManagedMcpSocketUnit, assertModelSocketUnit,
  brokerUnitInvocation, linuxManagedControlMaxFrame,
  type LinuxManagedPlanRecord } from "./linux-agent-control.js";
import { linuxAgentIdentityDir } from "./linux-agent-identity.js";
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
  ensureDirectory(filename: string, uid: number, gid: number, mode: number): Promise<boolean>;
  publish(filename: string, content: string, uid: number, gid: number, mode: number): Promise<SavedFile>;
  replace(filename: string, before: SavedFile, content: string,
    uid: number, gid: number, mode: number): Promise<SavedFile>;
  remove(file: SavedFile): Promise<void>;
  unit(unit: string, fields: string[]): Promise<string>;
  action(action: "daemon-reload" | "start" | "stop", unit?: string): Promise<void>;
  account(uid: number): Promise<{ gid: number; groups: number[] }>;
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
    [record.mcpSocketUnitFile, bundle.mcpSocketUnit, 0, 0o644],
    [record.modelRelaySocketUnitFile!, bundle.modelSocketUnit!, 0, 0o644]
  ];
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
      record.modelRelaySocketUnitFile !== `/run/systemd/system/s-gw-managed-model-${sessionId}.socket` ||
      record.brokerConfig !== `/run/s-gw/${sessionId}.json` ||
      config.leaseDir !== "/run/s-gw/managed-leases" ||
      record.plan.uid === control.brokerUid || record.plan.gid === brokerGid) {
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
      values.get("SocketGroup") !== String(record.plan.gid) ||
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
    const modelUnit = path.basename(record.modelRelaySocketUnitFile!);
    await assertAccountIsolation(host, input);
    for (const filename of [control.node, control.entry, control.preflight, record.brokerNode,
      record.brokerEntry, record.brokerPreflight]) {
      await checkedFile(host, filename, 0, 0);
    }
    await checkedFile(host, record.brokerEnvironmentFile, 0, 0, 0o600);
    if (record.brokerCa) await checkedFile(host, record.brokerCa, 0, 0);
    await assertInactive(host, mcpUnit);
    await assertInactive(host, modelUnit);
    await assertInactive(host, record.brokerUnit);
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
      await publishExpected(host, record.modelRelaySocketUnitFile!, bundle.modelSocketUnit!,
        0, 0, 0o644, created);
      await verifyInstalledFiles(host, input, bundle.brokerConfig);
      await host.action("daemon-reload");
      await readbackBroker(host, input, false);
      await readbackSocket(host, record, record.mcpSocketUnitFile, "inactive");
      await readbackSocket(host, record, record.modelRelaySocketUnitFile!, "inactive");
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
        await assertInactive(host, modelUnit);
        await assertInactive(host, record.brokerUnit);
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
    await assertAccountIsolation(host, input);
    await readbackControl(host, input);
    await readbackBroker(host, input, false);
    await readbackSocket(host, record, record.mcpSocketUnitFile, "inactive");
    await readbackSocket(host, record, record.modelRelaySocketUnitFile!, "inactive");
    await assertInactive(host, agentUnit);
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
      await checkedSocketNode(host, record.plan.brokerSocket, record.plan.gid);
      await host.action("start", modelUnit);
      await readbackSocket(host, record, record.modelRelaySocketUnitFile!, "active");
      await checkedSocketNode(host, record.plan.modelRelaySocket!, record.plan.gid);
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

async function run(command: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { env: { PATH: "/usr/bin:/bin", LANG: "C" },
      stdio: ["ignore", "pipe", "pipe"], timeout: 10_000 });
    let out = "";
    let err = "";
    child.stdout!.on("data", chunk => { out += String(chunk); if (out.length > 32_768) child.kill(); });
    child.stderr!.on("data", chunk => { err += String(chunk); if (err.length > 4096) child.kill(); });
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve(out) :
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
  }
};

export const nativeLinuxManagedUnitInstaller = new LinuxManagedUnitInstaller(nativeLinuxInstallHost);
