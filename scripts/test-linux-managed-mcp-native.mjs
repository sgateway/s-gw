import { spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { chmod, chown, copyFile, lstat, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux" || process.geteuid() !== 0 || process.env.CI !== "true" ||
    process.argv[2] !== "--root" || process.argv.length !== 5) {
  throw new Error("Run this native fixture as root on a disposable Linux CI host with broker UID and GID.");
}

const project = fileURLToPath(new URL("..", import.meta.url));
const brokerUid = Number(process.argv[3]);
const brokerGid = Number(process.argv[4]);
if (!Number.isSafeInteger(brokerUid) || brokerUid < 1 || !Number.isSafeInteger(brokerGid) || brokerGid < 1) {
  throw new Error("Invalid native fixture broker identity.");
}

function run(command, args, allowFailure = false) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 30_000 });
  if (!allowFailure && (result.error || result.status !== 0)) {
    throw new Error(`${command} failed: ${result.error?.message || result.stderr || result.stdout || result.status}`);
  }
  return result;
}

async function until(probe, label, timeout = 30_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    const value = await probe();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for ${label}.`);
}

async function maybeText(filename) {
  try { return await readFile(filename, "utf8"); }
  catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
}

function availableUid() {
  for (let uid = 232000; uid < 232999; uid++) {
    if (run("getent", ["passwd", String(uid)], true).status === 2 &&
        run("getent", ["group", String(uid)], true).status === 2) return uid;
  }
  throw new Error("No disposable Linux UID is available.");
}

function safeUnitValue(value) {
  if (!/^[\/A-Za-z0-9_.@+-]+$/.test(value)) throw new Error("Unsafe CI systemd unit value.");
  return value;
}

function unitProperties(unit, names) {
  const args = ["--system", "show", unit];
  for (const name of names) args.push("-p", name);
  const result = run("systemctl", args, true);
  if (result.error || result.status !== 0) {
    throw new Error(`Could not inspect native fixture unit ${unit}.`);
  }
  const values = new Map();
  for (const line of result.stdout.trimEnd().split("\n")) {
    const separator = line.indexOf("=");
    const name = line.slice(0, separator);
    if (separator < 1 || !names.includes(name) || values.has(name)) {
      throw new Error(`Invalid systemd properties for ${unit}.`);
    }
    values.set(name, line.slice(separator + 1));
  }
  for (const name of names) {
    if (!values.has(name)) throw new Error(`Missing ${name} for ${unit}.`);
  }
  return values;
}

function invocationId(properties) {
  const value = properties.get("InvocationID");
  return /^[0-9a-f]{32}$/.test(value ?? "") ? value : undefined;
}

const runId = randomBytes(5).toString("hex");
const sessionId = `ci-mcp-${runId}`;
const uid = availableUid();
const groupName = `sgwmcp${runId.slice(0, 7)}`;
const userName = groupName;
const brokerUser = run("id", ["-nu", String(brokerUid)]).stdout.trim();
const brokerGroup = run("getent", ["group", String(brokerGid)]).stdout.split(":")[0];
const arch = process.arch;
const root = `/var/lib/s-gw/agent-roots/${sessionId}`;
const socketPath = `/run/s-gw/agents/${sessionId}/broker.sock`;
const leaseDir = `/run/s-gw/ci-lease-${runId}`;
const storeHome = `/run/s-gw/ci-store-${runId}`;
const configPath = `/run/s-gw/ci-config-${runId}.json`;
const installed = `/run/s-gw/ci-control-${runId}`;
const controlDir = path.join(installed, "control");
const rootNode = path.join(installed, "node");
const controlEntry = path.join(controlDir, "linux-agent-control.js");
const controlUnit = "s-gw-agent-control.service";
const controlDescription = `s-gw-ci-control:${runId}`;
const agentUnit = `s-gw-agent-${sessionId}.service`;
const socketUnit = `s-gw-managed-mcp-${sessionId}.socket`;
const brokerUnit = `s-gw-managed-mcp-${sessionId}.service`;
const socketUnitFile = `/run/systemd/system/${socketUnit}`;
const brokerUnitFile = `/run/systemd/system/${brokerUnit}`;
const plan = {
  sessionId, uid, gid: uid, brokerUid, rootDirectory: root, brokerSocket: socketPath,
  executable: "/usr/bin/managed-mcp-probe", args: [],
  launchGate: true, activatedSocket: true, isolatedSharedMemory: true,
  serializedLifecycle: true, sealedStdio: true, supervisedControlUnit: true
};
const owned = new Map();
async function remember(filename) {
  const info = await lstat(filename);
  owned.set(filename, { dev: info.dev, ino: info.ino });
}

async function removeOwned(filename, recursive = false) {
  const expected = owned.get(filename);
  if (!expected) return;
  let current;
  try { current = await lstat(filename); }
  catch (error) { if (error.code === "ENOENT") return; throw error; }
  if (current.dev !== expected.dev || current.ino !== expected.ino) {
    throw new Error(`Native fixture path changed before cleanup: ${filename}`);
  }
  await rm(filename, { recursive, force: true });
}

async function assertOwned(filename) {
  const expected = owned.get(filename);
  if (!expected) return false;
  const current = await lstat(filename);
  if (current.dev !== expected.dev || current.ino !== expected.ino) {
    throw new Error(`Native fixture path changed: ${filename}`);
  }
  return true;
}

function fixtureControl(properties) {
  const command = `argv[]=${rootNode} ${controlEntry} --serve ${brokerUid} ${brokerGid} ;`;
  return properties.get("Id") === controlUnit &&
    properties.get("Description") === controlDescription &&
    properties.get("ExecStart")?.includes(command) &&
    properties.get("ControlGroup") === `/system.slice/${controlUnit}`;
}

async function fixtureUnitFile(unit, filename) {
  if (!(await assertOwned(filename))) return false;
  const properties = unitProperties(unit, ["Id", "FragmentPath"]);
  return properties.get("Id") === unit && properties.get("FragmentPath") === filename;
}

let accountCreated = false;
let groupCreated = false;
let unitsInstalled = false;
let controlStarted = false;
let controlStartAttempted = false;
let socketStartAttempted = false;
let socketStarted = false;
let fixtureOwned = false;
let controlInvocation;
let agentInvocation;
let brokerInvocation;
try {
  let controlSocketExists = false;
  try { await lstat("/run/s-gw/agent-control.sock"); controlSocketExists = true; }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  const oldControl = run("systemctl", ["--system", "show", controlUnit,
    "-p", "LoadState"], true).stdout.trim();
  if (oldControl !== "LoadState=not-found" ||
      controlSocketExists) {
    throw new Error("A Linux agent control service is already installed on this CI host.");
  }
  for (const filename of [root, path.dirname(socketPath), leaseDir, storeHome, configPath,
    installed, socketUnitFile, brokerUnitFile]) {
    try { await lstat(filename); throw new Error(`Native fixture path already exists: ${filename}`); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  fixtureOwned = true;
  for (const directory of ["/var/lib/s-gw", "/var/lib/s-gw/agent-roots", "/run/s-gw",
    "/run/s-gw/agents", "/run/s-gw/launch-gates"]) {
    await mkdir(directory, { recursive: true, mode: 0o755 });
  }
  await mkdir(installed, { mode: 0o755 });
  await remember(installed);
  await mkdir(controlDir, { mode: 0o755 });
  await mkdir(root, { mode: 0o755 });
  await remember(root);
  for (const relative of ["usr", "usr/bin", "usr/libexec", "usr/libexec/s-gw",
    "run", "run/s-gw", "run/s-gw/launch-gate", "dev", "dev/shm", "workspace"]) {
    await mkdir(path.join(root, relative), { recursive: true, mode: 0o755 });
  }
  await mkdir(leaseDir, { mode: 0o700 });
  await remember(leaseDir);
  await chown(leaseDir, brokerUid, brokerGid);
  await mkdir(storeHome, { mode: 0o700 });
  await remember(storeHome);
  await chown(storeHome, brokerUid, brokerGid);
  run("groupadd", ["--gid", String(uid), groupName]);
  groupCreated = true;
  run("useradd", ["--system", "--uid", String(uid), "--gid", groupName,
    "--no-create-home", "--shell", "/usr/sbin/nologin", userName]);
  accountCreated = true;
  await chown(`${root}/workspace`, uid, uid);
  await chmod(`${root}/workspace`, 0o700);
  for (const name of ["linux-agent-control.js", "linux-agent-unit.js", "linux-peer-identity.js"]) {
    await copyFile(path.join(project, "dist", name), path.join(controlDir, name));
    await chmod(path.join(controlDir, name), 0o755);
  }
  await writeFile(path.join(controlDir, "package.json"), '{"type":"module"}\n', { mode: 0o644 });
  await copyFile(process.execPath, rootNode);
  await chmod(rootNode, 0o755);
  run("cc", ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/peer-credentials/peer-credentials.c"),
    "-o", path.join(installed, "peer-credentials")]);
  const gate = `${root}/usr/libexec/s-gw/agent-launch-gate`;
  const probe = `${root}/usr/bin/managed-mcp-probe`;
  run("cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/linux-agent-gate/launch-gate.c"), "-o", gate]);
  run("cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "scripts/linux-managed-mcp-probe.c"), "-o", probe]);
  await chmod(gate, 0o755);
  await chmod(probe, 0o755);
  await writeFile(configPath, JSON.stringify({ name: "Native managed MCP agent", leaseDir, plan }) + "\n",
    { mode: 0o640 });
  await chown(configPath, 0, brokerGid);
  await chmod(configPath, 0o640);
  await remember(configPath);
  const node = safeUnitValue(process.execPath);
  const entry = safeUnitValue(path.join(project, "dist/linux-managed-mcp.js"));
  const config = safeUnitValue(configPath);
  const fixtureHome = safeUnitValue(storeHome);
  const secret = `synthetic-${randomUUID()}`;
  await writeFile(socketUnitFile, `[Unit]\nDescription=Native s-gw managed MCP fixture socket\n[Socket]\nListenStream=${socketPath}\nSocketUser=root\nSocketGroup=${groupName}\nSocketMode=0660\nDirectoryMode=0711\nFileDescriptorName=s-gw-agent-${sessionId}\nAccept=no\nRemoveOnStop=no\nService=${brokerUnit}\n`, { mode: 0o644 });
  await remember(socketUnitFile);
  await writeFile(brokerUnitFile, `[Unit]\nDescription=Native s-gw managed MCP fixture broker\nBindsTo=s-gw-agent-control.service\nAfter=s-gw-agent-control.service\n[Service]\nType=exec\nUser=${brokerUser}\nGroup=${brokerGroup}\nEnvironment=SGW_HOME=${fixtureHome}\nEnvironment=SGW_MASTER_PASSPHRASE=${secret}\nEnvironment=SGW_DISABLE_KEYCHAIN=1\nExecStart=${node} ${entry} ${config}\nRestart=no\n`, { mode: 0o644 });
  await remember(brokerUnitFile);
  unitsInstalled = true;
  run("systemctl", ["--system", "daemon-reload"]);
  controlStartAttempted = true;
  run("systemd-run", ["--system", "--no-ask-password", "--unit=s-gw-agent-control",
    `--description=${controlDescription}`,
    "--property=Type=exec", "--property=Restart=no", "--",
    rootNode, controlEntry, "--serve", String(brokerUid), String(brokerGid)]);
  const control = unitProperties(controlUnit,
    ["Id", "Description", "ExecStart", "ControlGroup", "InvocationID"]);
  controlInvocation = invocationId(control);
  if (!fixtureControl(control) || !controlInvocation) {
    throw new Error("The started root control unit has no verified fixture invocation.");
  }
  controlStarted = true;
  await until(async () => {
    try {
      const item = await lstat("/run/s-gw/agent-control.sock");
      return item.isSocket() && item.uid === 0 && item.gid === brokerGid;
    } catch { return false; }
  }, "root Linux agent control service");
  await remember("/run/s-gw/agent-control.sock");
  socketStartAttempted = true;
  run("systemctl", ["--system", "start", socketUnit]);
  socketStarted = true;
  await remember(path.dirname(socketPath));
  await new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    socket.once("error", reject);
    socket.once("connect", () => { socket.destroy(); resolve(); });
  });
  const result = await until(() => maybeText(`${root}/workspace/result`), "verified MCP agent request");
  if (result !== "verified-mcp=1\n") throw new Error(`Unexpected verified MCP result: ${result}`);
  const broker = unitProperties(brokerUnit, ["Id", "FragmentPath", "InvocationID"]);
  brokerInvocation = invocationId(broker);
  if (broker.get("Id") !== brokerUnit || broker.get("FragmentPath") !== brokerUnitFile ||
      !brokerInvocation) {
    throw new Error("The managed MCP broker has no verified fixture invocation.");
  }
  if (run("systemctl", ["--system", "is-active", agentUnit], true).status !== 0) {
    throw new Error("The protected agent unit stopped before control-service revocation.");
  }
  const agent = unitProperties(agentUnit, ["Id", "Description", "User", "RootDirectory",
    "ControlGroup", "InvocationID"]);
  agentInvocation = invocationId(agent);
  if (agent.get("Id") !== agentUnit ||
      !/^s-gw-agent-start:[a-f0-9]{32}$/.test(agent.get("Description") ?? "") ||
      agent.get("User") !== String(uid) || agent.get("RootDirectory") !== root ||
      agent.get("ControlGroup") !== `/system.slice/${agentUnit}` || !agentInvocation) {
    throw new Error("The protected agent has no verified fixture invocation or cgroup.");
  }
  await remember(`/run/s-gw/launch-gates/${sessionId}`);
  await remember(`/run/s-gw/agent-unit-lifecycle/${agentUnit}`);
  const fenceRoot = "/run/s-gw/agent-unit-lifecycle";
  for (const name of await readdir(fenceRoot)) {
    if (name.startsWith(`${agentUnit}.launch-`)) await remember(path.join(fenceRoot, name));
  }
  run("systemctl", ["--system", "kill", "--signal=SIGKILL", "--kill-who=main",
    controlUnit]);
  await until(() => run("systemctl", ["--system", "is-active", agentUnit], true).status !== 0,
    "BindsTo teardown after root control death");
  console.log("Native Linux managed MCP passed: root-owned control code, systemd socket activation, dedicated UID/cgroup, verified MCP request, and BindsTo teardown after root-service death.");
} catch (error) {
  const logs = run("journalctl", ["--no-pager", "-n", "80", "-u", "s-gw-agent-control.service",
    "-u", brokerUnit], true).stdout;
  throw new Error(`${String(error)}\n${logs}`);
} finally {
  if (fixtureOwned) {
    if (controlStartAttempted && !controlStarted) {
      const uncertain = unitProperties(controlUnit,
        ["Id", "Description", "ExecStart", "ControlGroup", "ActiveState", "InvocationID"]);
      if (uncertain.get("ActiveState") === "active" && fixtureControl(uncertain) &&
          invocationId(uncertain)) {
        run("systemctl", ["--system", "stop", controlUnit], true);
      }
      throw new Error("Root control start was ambiguous; its root-owned fixture tree was preserved.");
    }
    if (socketStartAttempted && !socketStarted) {
      const currentControl = unitProperties(controlUnit,
        ["Id", "Description", "ExecStart", "ControlGroup", "ActiveState", "InvocationID"]);
      if (currentControl.get("ActiveState") === "active" && fixtureControl(currentControl) &&
          invocationId(currentControl) === controlInvocation) {
        run("systemctl", ["--system", "stop", controlUnit], true);
      }
      if (await fixtureUnitFile(socketUnit, socketUnitFile)) {
        run("systemctl", ["--system", "stop", socketUnit], true);
      }
      if (await fixtureUnitFile(brokerUnit, brokerUnitFile)) {
        run("systemctl", ["--system", "stop", brokerUnit], true);
      }
      throw new Error("Managed MCP socket start was ambiguous; its fixture paths were preserved.");
    }
    const currentControl = unitProperties(controlUnit,
      ["Id", "Description", "ExecStart", "ControlGroup", "ActiveState", "InvocationID"]);
    const controlActive = currentControl.get("ActiveState") === "active";
    const controlOwned = controlStarted && controlInvocation && fixtureControl(currentControl) &&
      invocationId(currentControl) === controlInvocation;
    if (controlActive && !controlOwned) {
      throw new Error("Root control unit changed; native fixture state was preserved.");
    }
    const agentState = unitProperties(agentUnit, ["Id", "Description", "ActiveState", "User",
      "RootDirectory", "InvocationID"]);
    const agentActive = agentState.get("ActiveState") === "active";
    if (agentActive && (agentState.get("Id") !== agentUnit ||
        !/^s-gw-agent-start:[a-f0-9]{32}$/.test(agentState.get("Description") ?? "") ||
        agentState.get("User") !== String(uid) || agentState.get("RootDirectory") !== root ||
        !agentInvocation || invocationId(agentState) !== agentInvocation)) {
      if (controlActive && controlOwned) run("systemctl", ["--system", "stop", controlUnit], true);
      throw new Error("Agent unit changed; native fixture state was preserved.");
    }
    const brokerState = unitProperties(brokerUnit, ["Id", "FragmentPath", "ActiveState", "InvocationID"]);
    const brokerActive = brokerState.get("ActiveState") === "active";
    const brokerOwned = await fixtureUnitFile(brokerUnit, brokerUnitFile);
    if (brokerActive && (!brokerOwned || !brokerInvocation ||
        invocationId(brokerState) !== brokerInvocation)) {
      if (controlActive && controlOwned) run("systemctl", ["--system", "stop", controlUnit], true);
      throw new Error("Broker unit changed; native fixture state was preserved.");
    }
    const socketState = unitProperties(socketUnit, ["Id", "FragmentPath", "ActiveState"]);
    const socketActive = socketState.get("ActiveState") === "active";
    const socketOwned = await fixtureUnitFile(socketUnit, socketUnitFile);
    if (socketActive && !socketOwned) {
      if (controlActive && controlOwned) run("systemctl", ["--system", "stop", controlUnit], true);
      throw new Error("Socket unit changed; native fixture state was preserved.");
    }
    if (socketActive) run("systemctl", ["--system", "stop", socketUnit], true);
    if (brokerActive) run("systemctl", ["--system", "stop", brokerUnit], true);
    if (agentActive) run("systemctl", ["--system", "stop", agentUnit], true);
    if (controlActive) run("systemctl", ["--system", "stop", controlUnit], true);
    for (const unit of [socketUnit, brokerUnit, agentUnit, ...(controlStarted ? [controlUnit] : [])]) {
      if (run("systemctl", ["--system", "is-active", unit], true).status === 0) {
        throw new Error(`Native fixture unit is still active; paths preserved: ${unit}`);
      }
    }
    const alive = run("pgrep", ["-u", String(uid)], true).status === 0;
    if (alive) throw new Error("Native Linux agent UID still has processes; fixture paths were preserved.");
    await removeOwned(socketUnitFile);
    await removeOwned(brokerUnitFile);
    if (unitsInstalled) run("systemctl", ["--system", "daemon-reload"], true);
    for (const filename of owned.keys()) {
      if (filename.startsWith(`/run/s-gw/agent-unit-lifecycle/${agentUnit}.launch-`)) {
        await removeOwned(filename);
      }
    }
    await removeOwned(`/run/s-gw/agent-unit-lifecycle/${agentUnit}`, true);
    await removeOwned(`/run/s-gw/launch-gates/${sessionId}`, true);
    await removeOwned("/run/s-gw/agent-control.sock");
    await removeOwned(path.dirname(socketPath), true);
    await removeOwned(root, true);
    await removeOwned(configPath);
    await removeOwned(leaseDir, true);
    await removeOwned(storeHome, true);
    await removeOwned(installed, true);
    if (accountCreated) run("userdel", [userName], true);
    if (groupCreated) run("groupdel", [groupName], true);
  }
}
