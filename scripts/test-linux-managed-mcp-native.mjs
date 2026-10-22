import { spawn, spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, chown, copyFile, lstat, mkdir, readFile, readdir, readlink, realpath, rename, rm, rmdir, writeFile } from "node:fs/promises";
import { createSocket } from "node:dgram";
import { createServer as createHttpsServer } from "node:https";
import { createConnection, createServer } from "node:net";
import { networkInterfaces } from "node:os";
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
if (process.env.SGW_TEST_MANAGED_RELAY && process.env.SGW_TEST_MANAGED_RELAY !== "1") {
  throw new Error("Invalid native fixture model-relay option.");
}
const testRelay = process.env.SGW_TEST_MANAGED_RELAY === "1";
const runuser = ["/usr/sbin/runuser", "/usr/bin/runuser"].find(candidate => existsSync(candidate));
if (!runuser) throw new Error("The native Linux fixture requires runuser in a system directory.");

function run(command, args, allowFailure = false, env = process.env) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 30_000, env });
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

function hostIpv4Address() {
  for (const interfaces of Object.values(networkInterfaces())) {
    for (const item of interfaces || []) {
      if (item.family === "IPv4" && !item.internal) return item.address;
    }
  }
  throw new Error("No non-loopback IPv4 address is available for the native egress probe.");
}

async function tcpCanary(host) {
  let hits = 0;
  const server = createServer(socket => { hits++; socket.destroy(); });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => { server.off("error", reject); resolve(); });
  });
  return { host, port: server.address().port, hits: () => hits,
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(resolve); }) };
}

async function udpCanary(host, family) {
  let hits = 0;
  const server = createSocket(family);
  server.on("message", () => { hits++; });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.bind(0, host, () => { server.off("error", reject); resolve(); });
  });
  return { host, port: server.address().port, hits: () => hits,
    close: () => new Promise(resolve => server.close(resolve)) };
}

async function positiveTcp(canary) {
  await new Promise((resolve, reject) => {
    const socket = createConnection(canary.port, canary.host);
    socket.once("error", reject);
    socket.once("connect", () => { socket.destroy(); resolve(); });
  });
}

async function positiveUdp(canary, family) {
  const socket = createSocket(family);
  try {
    await new Promise((resolve, reject) => {
      socket.send("positive", canary.port, canary.host, error => error ? reject(error) : resolve());
    });
  } finally {
    socket.close();
  }
}

function availableUid() {
  for (let uid = 232000; uid < 232998; uid++) {
    if (run("getent", ["passwd", String(uid)], true).status === 2 &&
        run("getent", ["group", String(uid)], true).status === 2 &&
        run("getent", ["passwd", String(uid + 1)], true).status === 2 &&
        run("getent", ["group", String(uid + 1)], true).status === 2) return uid;
  }
  throw new Error("No disposable Linux UID pair is available.");
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

async function assertSafeNodeEnv(properties, caFile) {
  const pid = Number(properties.get("MainPID"));
  if (!Number.isSafeInteger(pid) || pid < 1) {
    throw new Error("The native broker or root control has no live main PID.");
  }
  const environment = (await readFile(`/proc/${pid}/environ`)).toString("utf8").split("\0");
  if (environment.some(value => value.startsWith("NODE_OPTIONS=") ||
      value.startsWith("NODE_PATH=") || value.startsWith("NODE_TLS_REJECT_UNAUTHORIZED="))) {
    throw new Error("A native broker or root control inherited an unsafe Node override.");
  }
  const caSettings = environment.filter(value => value.startsWith("NODE_EXTRA_CA_CERTS="));
  if (caSettings.length !== (caFile ? 1 : 0) ||
      (caFile && caSettings[0] !== `NODE_EXTRA_CA_CERTS=${caFile}`)) {
    throw new Error("Native Node CA bundle does not match the root-owned fixture certificate.");
  }
}

const runId = randomBytes(5).toString("hex");
const modelAddress = `198.20.${1 + Number.parseInt(runId.slice(0, 2), 16) % 254}.${1 + Number.parseInt(runId.slice(2, 4), 16) % 254}`;
const modelAliasLabel = `lo:sgw${runId.slice(0, 6)}`;
const uid = availableUid();
const brokerUser = run("id", ["-nu", String(brokerUid)]).stdout.trim();
const brokerGroup = run("getent", ["group", String(brokerGid)]).stdout.split(":")[0];
const arch = process.arch;
const leaseDir = `/run/s-gw/ci-lease-${runId}`;
const storeHome = `/run/s-gw/ci-store-${runId}`;
const recoveryHome = `/run/s-gw/ci-recovery-${runId}`;
const storeCanary = path.join(storeHome, "boundary-canary");
const recoveryCanary = path.join(recoveryHome, "boundary-canary");
const envFile = `/run/s-gw/ci-env-${runId}`;
const planDir = "/run/s-gw/agent-plans";
const identityDir = "/var/lib/s-gw/agent-identities";
const installed = `/run/s-gw/ci-control-${runId}`;
const modelHostsFile = path.join(installed, "model-hosts");
const controlDir = path.join(installed, "control");
const brokerPackage = path.join(installed, "broker");
const rootNode = path.join(installed, "node");
const runtimeVerifier = path.join(installed, "s-gw-linux-broker-runtime");
const controlEntry = path.join(controlDir, "linux-agent-control.js");
const operatorEntry = path.join(project, "scripts/linux-managed-mcp-operator.mjs");
const controlUnit = "s-gw-agent-control.service";
const controlUnitFile = `/run/systemd/system/${controlUnit}`;
const controlDescription = `s-gw-ci-control:${runId}`;
const loaderUnset = "NODE_OPTIONS NODE_PATH NODE_TLS_REJECT_UNAUTHORIZED LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT OPENSSL_CONF SSL_CERT_FILE SSL_CERT_DIR GLIBC_TUNABLES MALLOC_CHECK_ MALLOC_PERTURB_ TZDIR";
const agents = [0, 1].map(index => {
  const letter = index === 0 ? "a" : "b";
  const sessionId = `ci-mcp-${runId}-${letter}`;
  const agentUid = uid + index;
  const userName = `sgwmcp${runId.slice(0, 7)}${letter}`;
  const root = `/var/lib/s-gw/agent-roots/${sessionId}`;
  const privateCanary = `${root}/workspace/private-canary`;
  const socketPath = `/run/s-gw/agents/${sessionId}/broker.sock`;
  const modelSocketPath = `/run/s-gw/agents/${sessionId}/model.sock`;
  const agentUnit = `s-gw-agent-${sessionId}.service`;
  const socketUnit = `s-gw-managed-mcp-${sessionId}.socket`;
  const modelSocketUnit = `s-gw-managed-model-${sessionId}.socket`;
  const brokerUnit = `s-gw-managed-mcp-${sessionId}.service`;
  const socketUnitFile = `/run/systemd/system/${socketUnit}`;
  const modelSocketUnitFile = `/run/systemd/system/${modelSocketUnit}`;
  const brokerUnitFile = `/run/systemd/system/${brokerUnit}`;
  const configPath = `/run/s-gw/ci-config-${runId}-${letter}.json`;
  const planPath = `${planDir}/${sessionId}.json`;
  const claimPaths = [`${planDir}/uid-${agentUid}.used`, `${planDir}/gid-${agentUid}.used`,
    `${planDir}/session-${sessionId}.used`];
  const name = `Native managed MCP agent ${letter.toUpperCase()}`;
  const identityGeneration = randomBytes(16).toString("hex");
  const logicalAgentId = sessionId;
  const plan = { sessionId, uid: agentUid, gid: agentUid, brokerUid,
    rootDirectory: root, brokerSocket: socketPath,
    ...(testRelay ? { modelRelaySocket: modelSocketPath } : {}),
    executable: "/usr/bin/managed-mcp-probe", args: [],
    launchGate: true, activatedSocket: true, isolatedSharedMemory: true,
    serializedLifecycle: true, sealedStdio: true, restrictedSocketFamilies: true,
    requirePtracePolicy: true,
    supervisedControlUnit: true,
    logicalAgentId, identityGeneration };
  const identityRecord = { logicalAgentId, identityGeneration, uid: agentUid, gid: agentUid };
  const identityPaths = [`${identityDir}/uid-${agentUid}.json`,
    `${identityDir}/generation-${identityGeneration}.json`];
  return { sessionId, uid: agentUid, userName, root, privateCanary, socketPath, modelSocketPath,
    agentUnit, socketUnit, modelSocketUnit, brokerUnit, socketUnitFile, modelSocketUnitFile,
    brokerUnitFile, configPath, planPath, claimPaths,
    identityRecord, identityPaths, name, plan };
});
const owned = new Map();
const unitFileTexts = new Map();
async function remember(filename) {
  const info = await lstat(filename);
  owned.set(filename, { dev: info.dev, ino: info.ino });
}

async function rememberUnitFile(filename) {
  await remember(filename);
  unitFileTexts.set(filename, await readFile(filename, "utf8"));
}

async function assertFixtureUnitFile(filename) {
  if (!unitFileTexts.has(filename)) return false;
  if (!(await assertOwned(filename)) || await readFile(filename, "utf8") !== unitFileTexts.get(filename)) {
    throw new Error(`Native fixture unit file changed: ${filename}`);
  }
  await checkedInstalledFile(filename);
  return true;
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

async function checkedBrokerTree() {
  const pending = [brokerPackage];
  while (pending.length) {
    const filename = pending.pop();
    const stat = await lstat(filename);
    if (stat.isSymbolicLink()) {
      const target = await realpath(filename);
      if (!target.startsWith(`${brokerPackage}/`)) {
        throw new Error(`Native broker package symlink escapes its root: ${filename}`);
      }
      continue;
    }
    if (stat.uid !== 0 || (stat.mode & 0o022) !== 0 ||
        (!stat.isFile() && !stat.isDirectory())) {
      throw new Error(`Native broker package is writable or not root-owned: ${filename} ` +
        `(uid=${stat.uid}, mode=${(stat.mode & 0o777).toString(8)})`);
    }
    if (stat.isDirectory()) {
      for (const name of await readdir(filename)) pending.push(path.join(filename, name));
    }
  }
}

async function checkedInstalledFile(filename) {
  const item = await lstat(filename);
  if (!item.isFile() || item.uid !== 0 || item.nlink !== 1 ||
      (item.mode & 0o022) !== 0 || await realpath(filename) !== filename) {
    throw new Error(`Native fixture file is not root controlled: ${filename}`);
  }
  let parent = path.dirname(filename);
  while (true) {
    const dir = await lstat(parent);
    if (!dir.isDirectory() || dir.uid !== 0 || (dir.mode & 0o022) !== 0 ||
        await realpath(parent) !== parent) {
      throw new Error(`Native fixture parent is not root controlled: ${parent}`);
    }
    const next = path.dirname(parent);
    if (next === parent) return;
    parent = next;
  }
}

async function rememberClaimMarkers(agent) {
  const expected = `${agent.sessionId} ${agent.uid} ${agent.plan.gid}\n`;
  for (const filename of agent.claimPaths) {
    const value = await until(() => maybeText(filename), `${agent.sessionId} identity claim`);
    const info = await lstat(filename);
    if (value !== expected || !info.isFile() || info.uid !== 0 ||
        (info.mode & 0o777) !== 0o600 || info.nlink !== 1) {
      throw new Error(`The root identity claim changed: ${filename}`);
    }
    await remember(filename);
  }
}

function fixtureControl(properties) {
  const command = `argv[]=${runtimeVerifier} verify-exec ${installed} ${rootNode} ${controlEntry} ${controlUnitFile} - - -- --serve ${brokerUid} ${brokerGid} ;`;
  const preflight = `argv[]=${runtimeVerifier} verify ${installed} ${rootNode} ${controlEntry} ${controlUnitFile} - - ;`;
  return properties.get("Id") === controlUnit &&
    properties.get("Description") === controlDescription &&
    properties.get("FragmentPath") === controlUnitFile &&
    properties.get("ExecStart")?.includes(command) &&
    properties.get("ExecStartPre")?.includes(preflight) &&
    loaderUnset.split(" ").every(name => properties.get("UnsetEnvironment")?.split(/\s+/).includes(name)) &&
    properties.get("ControlGroup") === `/system.slice/${controlUnit}`;
}
const controlProperties = ["Id", "Description", "FragmentPath", "ExecStart", "ExecStartPre",
  "UnsetEnvironment", "ControlGroup", "ActiveState", "InvocationID", "MainPID"];

function activeFixtureUnit(unit) {
  const state = unitProperties(unit, ["ActiveState"]).get("ActiveState");
  if (state === "active") return true;
  if (state === "inactive" || state === "failed") return false;
  throw new Error(`Native fixture unit has an unsettled state: ${unit} (${state}).`);
}

async function fixtureUnitFile(unit, filename) {
  if (!(await assertFixtureUnitFile(filename))) return false;
  const properties = unitProperties(unit, ["Id", "FragmentPath"]);
  return properties.get("Id") === unit && properties.get("FragmentPath") === filename;
}

async function rejectWritableImport(unit, filename, marker) {
  const original = await readFile(filename, "utf8");
  const writeMarker = `import { writeFileSync } from "node:fs"; writeFileSync(${JSON.stringify(marker)}, "loaded");\n`;
  const split = original.startsWith("#!") ? original.indexOf("\n") + 1 : 0;
  if (original.startsWith("#!") && split === 0) throw new Error("Invalid staged Node entry.");
  await writeFile(filename, original.slice(0, split) + writeMarker + original.slice(split));
  await chmod(filename, 0o777);
  try {
    const attempt = run("systemctl", ["--system", "start", unit], true);
    const active = run("systemctl", ["--system", "is-active", unit], true).status === 0;
    if (active) run("systemctl", ["--system", "stop", unit], true);
    if (attempt.error || attempt.status === 0 || active || await maybeText(marker) !== undefined) {
      throw new Error(`Writable import reached Node before the ${unit} pre-exec gate.`);
    }
  } finally {
    await writeFile(filename, original);
    await chmod(filename, 0o755);
    run("systemctl", ["--system", "reset-failed", unit], true);
  }
}

const accountsCreated = [];
const groupsCreated = [];
let unitsInstalled = false;
let controlStarted = false;
let controlStartAttempted = false;
const socketStartAttempted = new Set();
const socketStarted = new Set();
const modelSocketStartAttempted = new Set();
const modelSocketStarted = new Set();
let fixtureOwned = false;
let planDirCreated = false;
let identityDirCreated = false;
let controlInvocation;
const agentInvocations = new Map();
const agentMainPids = new Map();
const brokerInvocations = new Map();
let upstream;
const networkCanaries = [];
const handoffHelpers = new Map();
const handoffOutcomes = [];
const modelRequests = [];
const modelStreams = new Map();
let modelUpstream;
let modelAliasAdded = false;

function modelAliasEntries() {
  const interfaces = JSON.parse(run("ip", ["-j", "-4", "address", "show", "dev", "lo"]).stdout);
  if (!Array.isArray(interfaces) || interfaces.length !== 1 || !Array.isArray(interfaces[0].addr_info)) {
    throw new Error("Could not inspect the disposable model relay IP alias.");
  }
  return interfaces[0].addr_info.filter(item => item.local === modelAddress);
}

async function closeNetworkFixtures() {
  try {
    if (modelAliasAdded) {
      const liveBroker = agents.some(agent => activeFixtureUnit(agent.brokerUnit) &&
        Number(unitProperties(agent.brokerUnit, ["MainPID"]).get("MainPID")) > 0);
      if (liveBroker) {
        throw new Error("A managed broker is still live; its local model IP alias was preserved.");
      }
      const aliases = modelAliasEntries();
      if (aliases.length !== 1 || aliases[0].prefixlen !== 32 || aliases[0].label !== modelAliasLabel) {
        throw new Error("The native model relay IP alias changed before cleanup.");
      }
      run("ip", ["-4", "address", "del", `${modelAddress}/32`, "dev", "lo"]);
    }
  } finally {
    for (const canary of networkCanaries.reverse()) await canary.close();
  }
}

async function modelFixtureResponse(request, response) {
  try {
    let body = "";
    for await (const chunk of request) {
      body += chunk;
      if (body.length > 4096) throw new Error("Native model fixture request is too large.");
    }
    const agent = agents.find(item => item.model &&
      request.headers.authorization === `Bearer ${item.model.value}`);
    const parsed = JSON.parse(body);
    const phase = parsed?.messages?.[0]?.content;
    const record = { sessionId: agent?.sessionId, phase, body,
      authorization: request.headers.authorization, clientKey: request.headers["x-api-key"],
      host: request.headers.host, version: request.headers["anthropic-version"],
      serverName: request.socket.servername, method: request.method, path: request.url };
    modelRequests.push(record);
    if (!agent || !["fixture-stream-complete", "fixture-cancel"].includes(phase) ||
        modelStreams.has(`${agent.sessionId}:${phase}`)) {
      response.writeHead(403);
      response.end();
      return;
    }
    const stream = { response, closed: false, released: false };
    modelStreams.set(`${agent.sessionId}:${phase}`, stream);
    response.once("close", () => { stream.closed = true; });
    response.writeHead(200, { "content-type": "text/event-stream", "x-request-id": "native-model-fixture" });
    const marker = phase === "fixture-cancel" ? "fixture-cancel-first" : "fixture-first";
    response.write(`event: message_start\ndata: {"type":"message_start","marker":"${marker}","pad":"${"x".repeat(256)}"}\n\n`);
  } catch {
    response.destroy();
  }
}
async function startHandoffHelper(agent, model = false, receiver = agent) {
  const crossSession = receiver !== agent;
  const channel = crossSession ? "cross-model-handoff" : model ? "model-handoff" : "handoff";
  const shared = `${agent.root}/run/s-gw/handoff-cross`;
  const socketPath = crossSession ? `${shared}/model.sock` : `${agent.root}/workspace/${channel}.sock`;
  const resultPath = crossSession ? `${shared}/result` : `${agent.root}/workspace/${channel}-result`;
  const pidPath = crossSession ? `${shared}/pid` : `${agent.root}/workspace/${channel}-pid`;
  const agentPid = agentMainPids.get(agent.sessionId);
  const receiverPid = agentMainPids.get(receiver.sessionId);
  if (!agentPid || !receiverPid) throw new Error(`No live agent PID for ${agent.sessionId} descriptor handoff.`);
  const child = spawn(`${agent.root}/usr/bin/managed-mcp-probe`,
    [crossSession ? "--receive-cross-model-handoff" : model ? "--receive-model-handoff" : "--receive-handoff",
      socketPath, resultPath, pidPath,
      model ? agent.model.handle : agent.seeded.handle,
      String(agentPid), String(receiver.uid), String(receiver.uid),
      ...(crossSession ? [String(receiverPid)] : [])],
  { detached: true, stdio: ["ignore", "ignore", "pipe"],
    env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" } });
  let errors = "";
  child.stderr.on("data", chunk => { errors = (errors + String(chunk)).slice(0, 2048); });
  const finished = new Promise(resolve => {
    child.once("error", error => resolve({ error: error.message }));
    child.once("close", (code, signal) => resolve({ code, signal, errors }));
  });
  handoffHelpers.set(`${agent.sessionId}:${channel}`, { child, finished, socketPath });
  const pid = await until(async () => {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(`The ${agent.sessionId} descriptor receiver exited: ${JSON.stringify(await finished)}`);
    }
    const contents = await maybeText(pidPath);
    if (!contents) return false;
    if (!/^[1-9][0-9]*\n$/.test(contents)) throw new Error("Invalid descriptor receiver PID.");
    const item = await lstat(socketPath);
    if (!item.isSocket() || item.uid !== receiver.uid ||
        (crossSession && (item.mode & 0o777) !== 0o666)) {
      throw new Error("The descriptor receiver did not bind an agent-owned Unix socket.");
    }
    return Number(contents.trim());
  }, `${agent.sessionId} ${channel} out-of-cgroup descriptor receiver`);
  const status = await readFile(`/proc/${pid}/status`, "utf8");
  const cgroup = await readFile(`/proc/${pid}/cgroup`, "utf8");
  const hostCgroup = await readFile("/proc/self/cgroup", "utf8");
  const receiverCgroup = await readFile(`/proc/${receiverPid}/cgroup`, "utf8");
  const hostNet = await readlink("/proc/self/ns/net");
  const receiverNet = await readlink(`/proc/${receiverPid}/ns/net`);
  const hostPidNs = await readlink("/proc/self/ns/pid");
  const receiverPidNs = await readlink(`/proc/${receiverPid}/ns/pid`);
  const uidValues = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
  const gidValues = /^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
  const extraGroups = status.split("\n").find(line => line.startsWith("Groups:"));
  const unprivileged = ["CapInh", "CapPrm", "CapEff", "CapAmb"].every(name => {
    const value = new RegExp(`^${name}:\\s+([0-9a-fA-F]+)$`, "m").exec(status)?.[1];
    return Boolean(value && /^0+$/.test(value));
  });
  if (!uidValues || uidValues.slice(1).some(value => Number(value) !== receiver.uid) ||
      !gidValues || gidValues.slice(1).some(value => Number(value) !== receiver.uid) ||
      extraGroups?.trim() !== "Groups:" || cgroup !== hostCgroup || cgroup === receiverCgroup ||
      !unprivileged || receiverPidNs !== hostPidNs ||
      await readlink(`/proc/${pid}/ns/pid`) !== hostPidNs ||
      receiverNet === hostNet || await readlink(`/proc/${pid}/ns/net`) !== receiverNet) {
    throw new Error(`The ${agent.sessionId} descriptor receiver lacks its dedicated UID/GID, host cgroup/PID namespace, zero effective capabilities, or receiver network namespace.`);
  }
}

async function stopHandoffHelper(helper) {
  if (helper.child.exitCode === null && helper.child.signalCode === null && helper.child.pid) {
    try { process.kill(-helper.child.pid, "SIGKILL"); }
    catch (error) { if (error.code !== "ESRCH") throw error; }
  }
  return helper.finished;
}

let passed = false;
let primaryFailure;
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
  const uniquePaths = [leaseDir, storeHome, recoveryHome, envFile, installed, controlUnitFile,
    ...agents.flatMap(agent => [agent.root, path.dirname(agent.socketPath), agent.configPath,
      agent.planPath, agent.socketUnitFile, agent.brokerUnitFile,
      ...(testRelay ? [agent.modelSocketUnitFile] : []), ...agent.claimPaths,
      ...agent.identityPaths])];
  for (const filename of uniquePaths) {
    try { await lstat(filename); throw new Error(`Native fixture path already exists: ${filename}`); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
  }
  fixtureOwned = true;
  for (const directory of ["/var/lib/s-gw", "/var/lib/s-gw/agent-roots", "/run/s-gw",
    "/run/s-gw/agents", "/run/s-gw/launch-gates"]) {
    await mkdir(directory, { recursive: true, mode: 0o755 });
  }
  try {
    const stat = await lstat(planDir);
    if (!stat.isDirectory() || stat.uid !== 0 || (stat.mode & 0o777) !== 0o700) {
      throw new Error("The Linux agent-plan directory is not root-owned mode 0700.");
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    await mkdir(planDir, { mode: 0o700 });
    await remember(planDir);
    planDirCreated = true;
  }
  try {
    const stat = await lstat(identityDir);
    if (!stat.isDirectory() || stat.uid !== 0 || (stat.mode & 0o777) !== 0o700 ||
        await realpath(identityDir) !== identityDir) {
      throw new Error("The Linux agent-identity directory is not root-owned mode 0700.");
    }
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    await mkdir(identityDir, { mode: 0o700 });
    await remember(identityDir);
    identityDirCreated = true;
  }
  for (const agent of agents) {
    for (const filename of agent.identityPaths) {
      await writeFile(filename, JSON.stringify(agent.identityRecord) + "\n", { mode: 0o600, flag: "wx" });
      await remember(filename);
      await checkedInstalledFile(filename);
      if (((await lstat(filename)).mode & 0o777) !== 0o600) {
        throw new Error("Native Linux agent identity record is not root-private.");
      }
    }
  }
  const { attestDurableLinuxAgentIdentity } = await import(new URL("../dist/linux-agent-identity.js", import.meta.url));
  for (const agent of agents) await attestDurableLinuxAgentIdentity(agent.plan);
  const firstIdentity = agents[0];
  const reassigned = { logicalAgentId: `ci-mcp-${runId}-reassigned`,
    identityGeneration: randomBytes(16).toString("hex"), uid: firstIdentity.uid, gid: firstIdentity.uid };
  const newReceipt = `${identityDir}/generation-${reassigned.identityGeneration}.json`;
  await writeFile(newReceipt, JSON.stringify(reassigned) + "\n", { mode: 0o600, flag: "wx" });
  await remember(newReceipt);
  try {
    await writeFile(firstIdentity.identityPaths[0], JSON.stringify(reassigned) + "\n");
    let rejected = false;
    try { await attestDurableLinuxAgentIdentity(firstIdentity.plan); }
    catch { rejected = true; }
    if (!rejected) throw new Error("An old Linux identity was accepted after UID reassignment.");
  } finally {
    await writeFile(firstIdentity.identityPaths[0], JSON.stringify(firstIdentity.identityRecord) + "\n");
    await assertOwned(newReceipt);
    await removeOwned(newReceipt);
  }
  await attestDurableLinuxAgentIdentity(firstIdentity.plan);
  const heldReceipt = `${firstIdentity.identityPaths[1]}.hold-${runId}`;
  if (await maybeText(heldReceipt) !== undefined) throw new Error("Native identity receipt hold path already exists.");
  await rename(firstIdentity.identityPaths[1], heldReceipt);
  await remember(heldReceipt);
  try {
    let rejected = false;
    try { await attestDurableLinuxAgentIdentity(firstIdentity.plan); }
    catch { rejected = true; }
    if (!rejected) throw new Error("A missing Linux generation receipt was accepted.");
  } finally {
    await assertOwned(heldReceipt);
    await rename(heldReceipt, firstIdentity.identityPaths[1]);
  }
  await attestDurableLinuxAgentIdentity(firstIdentity.plan);
  await mkdir(installed, { mode: 0o755 });
  await remember(installed);
  await mkdir(controlDir, { mode: 0o755 });
  await mkdir(brokerPackage, { mode: 0o755 });
  run("cp", ["-R", path.join(project, "dist"), brokerPackage]);
  run("cp", ["-R", path.join(project, "node_modules"), brokerPackage]);
  await mkdir(path.join(brokerPackage, "tools"), { mode: 0o755 });
  run("cp", ["-R", path.join(project, "tools/desktop-packager"),
    path.join(brokerPackage, "tools")]);
  await copyFile(path.join(project, "package.json"), path.join(brokerPackage, "package.json"));
  run("chown", ["-R", "0:0", brokerPackage]);
  run("chmod", ["-R", "go-w", brokerPackage]);
  for (const agent of agents) {
    await mkdir(agent.root, { mode: 0o755 });
    await remember(agent.root);
    for (const relative of ["usr", "usr/bin", "usr/libexec", "usr/libexec/s-gw",
      "run", "run/s-gw", "run/s-gw/launch-gate", "dev", "dev/shm", "workspace"]) {
      await mkdir(path.join(agent.root, relative), { recursive: true, mode: 0o755 });
    }
  }
  await mkdir(leaseDir, { mode: 0o700 });
  await remember(leaseDir);
  await chown(leaseDir, brokerUid, brokerGid);
  await mkdir(storeHome, { mode: 0o700 });
  await remember(storeHome);
  await chown(storeHome, brokerUid, brokerGid);
  await mkdir(recoveryHome, { mode: 0o700 });
  await remember(recoveryHome);
  await chown(recoveryHome, brokerUid, brokerGid);
  for (const [filename, value] of [[storeCanary, `store-${runId}\n`],
    [recoveryCanary, `recovery-${runId}\n`]]) {
    await writeFile(filename, value, { mode: 0o600, flag: "wx" });
    await chown(filename, brokerUid, brokerGid);
    const info = await lstat(filename);
    if (!info.isFile() || info.uid !== brokerUid || (info.mode & 0o777) !== 0o600) {
      throw new Error(`Synthetic broker canary is not private: ${filename}`);
    }
    const check = 'const fs=require("node:fs");const fd=fs.openSync(process.argv[1],"r+");' +
      'const byte=Buffer.alloc(1);if(fs.readSync(fd,byte,0,1,0)!==1)process.exit(1);' +
      'if(fs.writeSync(fd,byte,0,1,0)!==1)process.exit(1);fs.closeSync(fd)';
    run(runuser, ["-u", brokerUser, "--", process.execPath, "-e", check, filename],
      false, { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" });
    if (await readFile(filename, "utf8") !== value) {
      throw new Error(`Broker canary positive control changed its content: ${filename}`);
    }
  }
  for (const agent of agents) {
    run("groupadd", ["--gid", String(agent.uid), agent.userName]);
    groupsCreated.push(agent.userName);
    run("useradd", ["--system", "--uid", String(agent.uid), "--gid", agent.userName,
      "--no-create-home", "--shell", "/usr/sbin/nologin", agent.userName]);
    accountsCreated.push(agent.userName);
    await chown(`${agent.root}/workspace`, agent.uid, agent.uid);
    await chmod(`${agent.root}/workspace`, 0o700);
    if (testRelay) {
      const crossHandoff = `${agent.root}/run/s-gw/handoff-cross`;
      await mkdir(crossHandoff, { mode: 0o733 });
      await chmod(crossHandoff, 0o733);
    }
    await writeFile(agent.privateCanary, `private-${agent.sessionId}\n`,
      { mode: 0o600, flag: "wx" });
    await chown(agent.privateCanary, agent.uid, agent.uid);
    const info = await lstat(agent.privateCanary);
    if (!info.isFile() || info.uid !== agent.uid || (info.mode & 0o777) !== 0o600) {
      throw new Error(`Agent workspace canary has the wrong identity: ${agent.privateCanary}`);
    }
  }
  for (const name of ["linux-agent-control.js", "linux-agent-unit.js",
    "linux-peer-identity.js", "linux-agent-identity.js"]) {
    await copyFile(path.join(project, "dist", name), path.join(controlDir, name));
    await chmod(path.join(controlDir, name), 0o755);
  }
  await writeFile(path.join(controlDir, "package.json"), '{"type":"module"}\n', { mode: 0o644 });
  await copyFile(process.execPath, rootNode);
  await chmod(rootNode, 0o755);
  run("cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/linux-broker-runtime/verify.c"), "-o", runtimeVerifier]);
  await chmod(runtimeVerifier, 0o755);
  const brokerVerifierDir = path.join(brokerPackage, "dist", "native", `linux-${arch}`);
  await mkdir(brokerVerifierDir, { recursive: true, mode: 0o755 });
  run("cc", ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/peer-credentials/peer-credentials.c"),
    "-o", path.join(brokerVerifierDir, "s-gw-peer-credentials")]);
  await checkedBrokerTree();
  for (const filename of [rootNode, runtimeVerifier, path.join(brokerPackage, "dist/linux-managed-mcp.js"),
    path.join(brokerVerifierDir, "s-gw-peer-credentials")]) {
    await checkedInstalledFile(filename);
  }
  const verifierDir = path.join(installed, "dist", "native", `linux-${arch}`);
  await mkdir(verifierDir, { recursive: true, mode: 0o755 });
  run("cc", ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/linux-peer-identity/verify.c"),
    "-o", path.join(verifierDir, "s-gw-linux-peer-identity")]);
  for (const agent of agents) {
    const gate = `${agent.root}/usr/libexec/s-gw/agent-launch-gate`;
    const probe = `${agent.root}/usr/bin/managed-mcp-probe`;
    run("cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
      path.join(project, "native/linux-agent-gate/launch-gate.c"), "-o", gate]);
    run("cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
      path.join(project, "scripts/linux-managed-mcp-probe.c"), "-o", probe]);
    run(probe, ["--netlink-positive"]);
    await chmod(gate, 0o755);
    await chmod(probe, 0o755);
  }
  const keyFile = path.join(installed, "upstream.key");
  const certFile = path.join(installed, "upstream.crt");
  run("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyFile,
    "-out", certFile, "-days", "1", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:api.anthropic.com"]);
  await chmod(certFile, 0o644);
  await checkedInstalledFile(certFile);
  const tls = { key: await readFile(keyFile), cert: await readFile(certFile) };
  const upstreamAuths = [];
  upstream = createHttpsServer(tls, (request, response) => {
    upstreamAuths.push({ authorization: String(request.headers.authorization || ""),
      method: request.method, path: request.url });
    response.end("approved fixture");
  });
  await new Promise((resolve, reject) => {
    upstream.once("error", reject);
    upstream.listen(0, "127.0.0.1", () => { upstream.off("error", reject); resolve(); });
  });
  const upstreamAddress = upstream.address();
  if (!upstreamAddress || typeof upstreamAddress === "string") {
    throw new Error("Native HTTPS fixture has no loopback port.");
  }
  const upstreamPort = upstreamAddress.port;
  const url = `https://127.0.0.1:${upstreamPort}/operation`;
  const hostIp = hostIpv4Address();
  if (testRelay) {
    await writeFile(modelHostsFile, `127.0.0.1 localhost\n::1 localhost\n${modelAddress} api.anthropic.com\n`,
      { mode: 0o644, flag: "wx" });
    await remember(modelHostsFile);
    await checkedInstalledFile(modelHostsFile);
    if (modelAliasEntries().length !== 0) {
      throw new Error("The disposable model relay IP alias is already in use.");
    }
    run("ip", ["-4", "address", "add", `${modelAddress}/32`, "dev", "lo", "label", modelAliasLabel]);
    modelAliasAdded = true;
    const aliases = modelAliasEntries();
    if (aliases.length !== 1 || aliases[0].prefixlen !== 32 || aliases[0].label !== modelAliasLabel) {
      throw new Error("The native model relay IP alias did not match its fixture label.");
    }
    modelUpstream = createHttpsServer(tls, (request, response) => {
      void modelFixtureResponse(request, response);
    });
    await new Promise((resolve, reject) => {
      modelUpstream.once("error", reject);
      modelUpstream.listen(443, modelAddress, () => {
        modelUpstream.off("error", reject);
        resolve();
      });
    });
  }
  const direct = { tcp4: await tcpCanary("127.0.0.1") };
  networkCanaries.push(direct.tcp4);
  direct.tcp6 = await tcpCanary("::1");
  networkCanaries.push(direct.tcp6);
  direct.tcpHost = await tcpCanary(hostIp);
  networkCanaries.push(direct.tcpHost);
  direct.udp4 = await udpCanary("127.0.0.1", "udp4");
  networkCanaries.push(direct.udp4);
  direct.udp6 = await udpCanary("::1", "udp6");
  networkCanaries.push(direct.udp6);
  direct.udpHost = await udpCanary(hostIp, "udp4");
  networkCanaries.push(direct.udpHost);
  for (const canary of [direct.tcp4, direct.tcp6, direct.tcpHost]) await positiveTcp(canary);
  await positiveUdp(direct.udp4, "udp4");
  await positiveUdp(direct.udp6, "udp6");
  await positiveUdp(direct.udpHost, "udp4");
  await until(() => networkCanaries.every(item => item.hits() === 1),
    "six broker-reachable native network canaries", 3000);
  for (let index = 0; index < agents.length; index++) {
    agents[index].plan.args = [storeCanary, recoveryCanary, agents[1 - index].privateCanary,
      String(direct.tcp4.port), String(direct.tcp6.port), hostIp, String(direct.tcpHost.port),
      String(direct.udp4.port), String(direct.udp6.port), String(direct.udpHost.port),
      ...(testRelay ? [modelAddress] : [])];
  }
  const secret = `synthetic-${randomUUID()}`;
  const operatorEnv = { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", CI: "true", SGW_HOME: storeHome,
    SGW_RECOVERY_HOME: recoveryHome, SGW_MASTER_PASSPHRASE: secret,
    SGW_DISABLE_KEYCHAIN: "1", SGW_DISABLE_ONEPASSWORD_BACKUP: "1" };
  const asBroker = (mode, args) => run(runuser, ["-u", brokerUser, "--", process.execPath,
    operatorEntry, mode, ...args], false, operatorEnv).stdout.trim();
  for (const agent of agents) {
    agent.seeded = JSON.parse(asBroker("seed", [String(upstreamPort)]));
    if (!/^s-gw:api-token:[A-Za-z0-9_-]+$/.test(agent.seeded.handle) ||
        !/^synthetic-managed-mcp-[A-Za-z0-9-]+$/.test(agent.seeded.value)) {
      throw new Error("Invalid native fixture handle or synthetic value.");
    }
    await writeFile(`${agent.root}/workspace/handle`, `${agent.seeded.handle}\n`, { mode: 0o644 });
    await writeFile(`${agent.root}/workspace/url`, `${url}\n`, { mode: 0o644 });
    if (testRelay) {
      agent.model = JSON.parse(asBroker("seed-relay", []));
      if (!/^s-gw:api-token:[A-Za-z0-9_-]+$/.test(agent.model.handle) ||
          !/^synthetic-managed-model-[A-Za-z0-9-]+$/.test(agent.model.value)) {
        throw new Error("Invalid native fixture model handle or synthetic value.");
      }
      agent.relay = { grant: { handle: agent.model.handle, provider: "anthropic",
        routes: ["POST /v1/messages"], ttlMs: 30 * 60_000, payloadProfile: "strict",
        allowedModels: ["fixture-model"], maxRequests: 8 } };
    }
    await writeFile(agent.configPath, JSON.stringify({ name: agent.name, leaseDir, plan: agent.plan,
      ...(testRelay ? { relay: agent.relay } : {}) }) + "\n",
      { mode: 0o640 });
    await chown(agent.configPath, 0, brokerGid);
    await chmod(agent.configPath, 0o640);
    await remember(agent.configPath);
  }
  const node = safeUnitValue(rootNode);
  const entry = safeUnitValue(path.join(brokerPackage, "dist/linux-managed-mcp.js"));
  const verifier = safeUnitValue(runtimeVerifier);
  const runtimeRoot = safeUnitValue(installed);
  const environmentFile = safeUnitValue(envFile);
  await writeFile(envFile, `CI=true\nSGW_HOME=${storeHome}\nSGW_RECOVERY_HOME=${recoveryHome}\nSGW_MASTER_PASSPHRASE=${secret}\nSGW_DISABLE_KEYCHAIN=1\nSGW_DISABLE_ONEPASSWORD_BACKUP=1\nNODE_EXTRA_CA_CERTS=${certFile}\n`, { mode: 0o600 });
  await remember(envFile);
  await writeFile(controlUnitFile, `[Unit]\nDescription=${controlDescription}\n[Service]\nType=exec\nExecStartPre=${verifier} verify ${runtimeRoot} ${node} ${controlEntry} ${controlUnitFile} - -\nUnsetEnvironment=${loaderUnset} NODE_EXTRA_CA_CERTS\nExecStart=${verifier} verify-exec ${runtimeRoot} ${node} ${controlEntry} ${controlUnitFile} - - -- --serve ${brokerUid} ${brokerGid}\nRestart=no\n`, { mode: 0o644 });
  await rememberUnitFile(controlUnitFile);
  for (const agent of agents) {
    const config = safeUnitValue(agent.configPath);
    await writeFile(agent.socketUnitFile, `[Unit]\nDescription=Native s-gw managed MCP fixture socket\nBindsTo=s-gw-agent-control.service\nAfter=s-gw-agent-control.service\n[Socket]\nListenStream=${agent.socketPath}\nSocketUser=root\nSocketGroup=${agent.userName}\nSocketMode=0660\nDirectoryMode=0711\nPassCredentials=yes\nFileDescriptorName=s-gw-agent-${agent.sessionId}\nAccept=no\nRemoveOnStop=no\nService=${agent.brokerUnit}\n`, { mode: 0o644 });
    await rememberUnitFile(agent.socketUnitFile);
    if (testRelay) {
      await writeFile(agent.modelSocketUnitFile, `[Unit]\nDescription=Native s-gw managed model fixture socket\nBindsTo=s-gw-agent-control.service\nAfter=s-gw-agent-control.service\n[Socket]\nListenStream=${agent.modelSocketPath}\nSocketUser=root\nSocketGroup=${agent.userName}\nSocketMode=0660\nDirectoryMode=0711\nPassCredentials=yes\nFileDescriptorName=s-gw-model-${agent.sessionId}\nAccept=no\nRemoveOnStop=no\nService=${agent.brokerUnit}\n`, { mode: 0o644 });
      await rememberUnitFile(agent.modelSocketUnitFile);
    }
    await writeFile(agent.brokerUnitFile, `[Unit]\nDescription=Native s-gw managed MCP fixture broker\nBindsTo=s-gw-agent-control.service\nAfter=s-gw-agent-control.service\n[Service]\nType=exec\nUser=${brokerUser}\nGroup=${brokerGroup}\nEnvironmentFile=${environmentFile}\nUnsetEnvironment=${loaderUnset}\n${testRelay ? `BindReadOnlyPaths=${modelHostsFile}:/etc/hosts\nExecCondition=/usr/bin/grep -qFx "${modelAddress} api.anthropic.com" /etc/hosts\n` : ""}ExecStartPre=${verifier} verify ${runtimeRoot} ${node} ${entry} ${config} ${certFile} ${environmentFile}\nExecStart=${verifier} verify-exec ${runtimeRoot} ${node} ${entry} ${config} ${certFile} ${environmentFile} -- ${config}\nRestart=no\n`, { mode: 0o644 });
    await rememberUnitFile(agent.brokerUnitFile);
    await writeFile(agent.planPath, JSON.stringify({ plan: agent.plan, brokerUnit: agent.brokerUnit,
      brokerUnitFile: agent.brokerUnitFile, mcpSocketUnitFile: agent.socketUnitFile,
      brokerEntry: entry, brokerConfig: config,
      ...(testRelay ? { modelRelaySocketUnitFile: agent.modelSocketUnitFile } : {}),
      brokerNode: node, brokerRuntimeRoot: runtimeRoot, brokerPreflight: verifier,
      brokerEnvironmentFile: environmentFile, brokerCa: certFile }) + "\n",
      { mode: 0o600 });
    await remember(agent.planPath);
    await checkedInstalledFile(agent.configPath);
    await checkedInstalledFile(agent.planPath);
    await checkedInstalledFile(agent.socketUnitFile);
    if (testRelay) await checkedInstalledFile(agent.modelSocketUnitFile);
    const configInfo = await lstat(agent.configPath);
    const planInfo = await lstat(agent.planPath);
    if (configInfo.gid !== brokerGid || (configInfo.mode & 0o777) !== 0o640 ||
        (planInfo.mode & 0o777) !== 0o600) {
      throw new Error("Native broker config or root plan has unsafe ownership or mode.");
    }
  }
  await checkedInstalledFile(envFile);
  await checkedInstalledFile(controlUnitFile);
  if (((await lstat(envFile)).mode & 0o777) !== 0o600) {
    throw new Error("Native broker environment file is readable outside root.");
  }
  unitsInstalled = true;
  run("systemctl", ["--system", "daemon-reload"]);
  await rejectWritableImport(controlUnit, path.join(controlDir, "linux-agent-unit.js"),
    path.join(installed, "control-preexec-marker"));
  controlStartAttempted = true;
  run("systemctl", ["--system", "start", controlUnit]);
  const control = unitProperties(controlUnit, controlProperties);
  controlInvocation = invocationId(control);
  if (!fixtureControl(control) || !controlInvocation) {
    throw new Error("The started root control unit has no verified fixture invocation.");
  }
  await assertSafeNodeEnv(control);
  controlStarted = true;
  await until(async () => {
    try {
      const item = await lstat("/run/s-gw/agent-control.sock");
      return item.isSocket() && item.uid === 0 && item.gid === brokerGid;
    } catch { return false; }
  }, "root Linux agent control service");
  await remember("/run/s-gw/agent-control.sock");
  await rejectWritableImport(agents[0].brokerUnit, entry,
    path.join(installed, "broker-preexec-marker"));
  for (const agent of agents) {
    socketStartAttempted.add(agent.sessionId);
    run("systemctl", ["--system", "start", agent.socketUnit]);
    socketStarted.add(agent.sessionId);
    if (testRelay) {
      modelSocketStartAttempted.add(agent.sessionId);
      run("systemctl", ["--system", "start", agent.modelSocketUnit]);
      modelSocketStarted.add(agent.sessionId);
    }
    await remember(path.dirname(agent.socketPath));
    await new Promise((resolve, reject) => {
      const socket = createConnection(agent.socketPath);
      socket.once("error", reject);
      socket.once("connect", () => { socket.destroy(); resolve(); });
    });
  }
  if (testRelay) {
    for (const agent of agents) {
      const requestId = await until(() => {
        const found = asBroker("relay-pending", [agent.sessionId, agent.name,
          agent.model.handle, agent.plan.identityGeneration]);
        return found === "none" ? false : found;
      }, `${agent.sessionId} pending model relay grant`);
      if (!/^[A-Za-z0-9_-]{1,256}$/.test(requestId)) {
        throw new Error("Invalid native model relay request ID.");
      }
      if (run("systemctl", ["--system", "is-active", agent.agentUnit], true).status === 0) {
        throw new Error("Managed agent launched before model relay approval.");
      }
      await until(() => run("systemctl", ["--system", "is-active", agent.brokerUnit], true).status !== 0,
        `${agent.sessionId} preapproval broker exit`);
      if (asBroker("approve-relay", [requestId]) !== requestId) {
        throw new Error("Native model relay approval changed its request ID.");
      }
      agent.relay.requestId = requestId;
    }
    for (let index = 0; index < agents.length; index++) {
      const agent = agents[index];
      const other = agents[1 - index];
      asBroker("reject-relay-claim", [agent.relay.requestId, other.sessionId,
        other.name, other.plan.identityGeneration]);
      const sealed = `${agent.configPath}.sealed`;
      await writeFile(sealed, JSON.stringify({ name: agent.name, leaseDir,
        plan: agent.plan, relay: agent.relay }) + "\n", { flag: "wx", mode: 0o640 });
      await remember(sealed);
      await chown(sealed, 0, brokerGid);
      await chmod(sealed, 0o640);
      await rename(sealed, agent.configPath);
      await remember(agent.configPath);
      await checkedInstalledFile(agent.configPath);
      run("systemctl", ["--system", "reset-failed", agent.brokerUnit], true);
      run("systemctl", ["--system", "start", agent.brokerUnit]);
      await until(() => {
        try { return asBroker("assert-relay-state", [agent.relay.requestId, "executing"]) === "executing"; }
        catch { return false; }
      }, `${agent.sessionId} model relay claim`);
    }
  }
  for (const agent of agents) {
    const ready = await until(() => maybeText(`${agent.root}/workspace/handoff-ready`),
      `${agent.sessionId} initialized MCP handoff gate`);
    if (ready !== "ready\n") throw new Error(`Unexpected MCP handoff gate: ${ready}`);
    const live = unitProperties(agent.agentUnit, ["Id", "User", "ControlGroup", "MainPID"]);
    const mainPid = Number(live.get("MainPID"));
    if (live.get("Id") !== agent.agentUnit || live.get("User") !== String(agent.uid) ||
        live.get("ControlGroup") !== `/system.slice/${agent.agentUnit}` ||
        !Number.isSafeInteger(mainPid) || mainPid < 1) {
      throw new Error(`The ${agent.sessionId} handoff donor is not a live managed agent.`);
    }
    agentMainPids.set(agent.sessionId, mainPid);
    run(runuser, ["-u", agent.userName, "--", `${agent.root}/usr/bin/managed-mcp-probe`,
      "--ptrace-out-of-cgroup", String(mainPid)], false,
    { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" });
  }
  for (const agent of agents) {
    await startHandoffHelper(agent);
    if (testRelay) {
      await startHandoffHelper(agent, true);
      await startHandoffHelper(agent, true, agents.find(item => item !== agent));
    }
  }
  for (const agent of agents) {
    await writeFile(`${agent.root}/workspace/handoff-go`, "go\n", { mode: 0o644 });
  }
  for (const agent of agents) await rememberClaimMarkers(agent);
  const { claimIdentityMarkers } = await import(new URL("../dist/linux-agent-control.js", import.meta.url));
  for (const plan of [
    { ...agents[0].plan, sessionId: `ci-mcp-${runId}-duplicate-uid`, gid: uid + 2 },
    { ...agents[0].plan, sessionId: `ci-mcp-${runId}-duplicate-gid`, uid: uid + 2 }
  ]) {
    const unused = [`${planDir}/uid-${uid + 2}.used`, `${planDir}/gid-${uid + 2}.used`,
      `${planDir}/session-${plan.sessionId}.used`];
    for (const filename of unused) {
      if (await maybeText(filename) !== undefined) {
        throw new Error(`Native collision probe path already exists: ${filename}`);
      }
    }
    try {
      await claimIdentityMarkers(plan, planDir);
      throw new Error("A duplicate Linux agent identity was accepted.");
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    for (const filename of unused) {
      if (await maybeText(filename) !== undefined) {
        throw new Error(`Rejected Linux identity left a marker: ${filename}`);
      }
    }
  }
  for (const agent of agents) {
    const requested = await until(() => maybeText(`${agent.root}/workspace/requested`),
      `${agent.sessionId} verified MCP HTTPS request`);
    if (requested !== "pending\n") throw new Error(`Unexpected HTTPS request marker: ${requested}`);
    const broker = unitProperties(agent.brokerUnit, ["Id", "FragmentPath", "InvocationID", "MainPID"]);
    const brokerInvocation = invocationId(broker);
    if (broker.get("Id") !== agent.brokerUnit || broker.get("FragmentPath") !== agent.brokerUnitFile ||
        !brokerInvocation) {
      throw new Error("The managed MCP broker has no verified fixture invocation.");
    }
    await assertSafeNodeEnv(broker, certFile);
    brokerInvocations.set(agent.sessionId, brokerInvocation);
    if (run("systemctl", ["--system", "is-active", agent.agentUnit], true).status !== 0) {
      throw new Error("The protected agent unit stopped before control-service revocation.");
    }
    const live = unitProperties(agent.agentUnit, ["Id", "Description", "User", "RootDirectory",
      "ControlGroup", "InvocationID", "MainPID"]);
    const agentInvocation = invocationId(live);
    const mainPid = Number(live.get("MainPID"));
    if (live.get("Id") !== agent.agentUnit ||
        !/^s-gw-agent-start:[a-f0-9]{32}$/.test(live.get("Description") ?? "") ||
        live.get("User") !== String(agent.uid) || live.get("RootDirectory") !== agent.root ||
        live.get("ControlGroup") !== `/system.slice/${agent.agentUnit}` || !agentInvocation ||
        !Number.isSafeInteger(mainPid) || mainPid < 1) {
      throw new Error("The protected agent has no verified fixture invocation or cgroup.");
    }
    agentInvocations.set(agent.sessionId, agentInvocation);
    agentMainPids.set(agent.sessionId, mainPid);
    if (testRelay) {
      const processData = Buffer.concat([
        await readFile(`/proc/${mainPid}/environ`), await readFile(`/proc/${mainPid}/cmdline`)
      ]).toString("utf8");
      if (processData.includes(agent.model.value) ||
          (await readFile(agent.configPath, "utf8")).includes(agent.model.value)) {
        throw new Error(`The ${agent.sessionId} synthetic model bearer reached agent or config text.`);
      }
    }
  }
  if (new Set(agents.map(agent => agent.uid)).size !== 2 ||
      new Set(agents.map(agent => unitProperties(agent.agentUnit, ["ControlGroup"]).get("ControlGroup"))).size !== 2) {
    throw new Error("The two native agents did not have distinct UIDs and cgroups.");
  }
  const netNamespaces = [await readlink("/proc/self/ns/net"),
    ...await Promise.all(agents.map(agent => readlink(`/proc/${agentMainPids.get(agent.sessionId)}/ns/net`)))];
  if (new Set(netNamespaces).size !== 3) {
    throw new Error("An agent retained the host or another agent's network namespace.");
  }
  for (const agent of agents) {
    const result = await until(() => maybeText(`${agent.root}/workspace/boundary`),
      `${agent.sessionId} direct-egress and canary result`);
    if (result !== `files=1 tcp4=1 tcp6=1 tcphost=1 udp4=1 udp6=1 udphost=1 netlink=1${testRelay ? " model=1" : ""}\n`) {
      throw new Error(`${agent.sessionId} reached a direct service or another private file: ${result}`);
    }
  }
  await new Promise(resolve => setTimeout(resolve, 1000));
  if (networkCanaries.some(item => item.hits() !== 1)) {
    throw new Error("An agent reached a broker-only IPv4, IPv6, or UDP listener.");
  }
  if (await readFile(storeCanary, "utf8") !== `store-${runId}\n` ||
      await readFile(recoveryCanary, "utf8") !== `recovery-${runId}\n` ||
      (await Promise.all(agents.map(agent => readFile(agent.privateCanary, "utf8"))))
        .some((value, index) => value !== `private-${agents[index].sessionId}\n`)) {
    throw new Error("A synthetic broker or peer workspace canary changed during agent probes.");
  }
  for (const agent of agents) {
    const result = await until(() => maybeText(`${agent.root}/workspace/handoff-result`),
      `${agent.sessionId} connected descriptor handoff result`);
    if (result === "accepted\n") {
      throw new Error(`A same-UID out-of-cgroup process used ${agent.sessionId}'s admitted broker socket.`);
    }
    if (result !== "denied\n") {
      throw new Error(`The ${agent.sessionId} descriptor handoff was inconclusive: ${result}`);
    }
    const helper = handoffHelpers.get(`${agent.sessionId}:handoff`);
    const finished = await helper.finished;
    if (finished.code !== 0) {
      throw new Error(`The ${agent.sessionId} descriptor receiver failed: ${JSON.stringify(finished)}`);
    }
    handoffOutcomes.push(`${agent.sessionId}:${result.trim()}`);
    if (testRelay) {
      const modelResult = await until(() => maybeText(`${agent.root}/workspace/model-handoff-result`),
        `${agent.sessionId} model relay descriptor handoff result`);
      if (modelResult !== "denied\n") {
        throw new Error(`The ${agent.sessionId} model descriptor handoff was not denied: ${modelResult}`);
      }
      const modelHelper = handoffHelpers.get(`${agent.sessionId}:model-handoff`);
      const modelFinished = await modelHelper.finished;
      if (modelFinished.code !== 0) {
        throw new Error(`The ${agent.sessionId} model descriptor receiver failed: ${JSON.stringify(modelFinished)}`);
      }
      const crossResult = await until(() => maybeText(`${agent.root}/run/s-gw/handoff-cross/result`),
        `${agent.sessionId} cross-session model descriptor handoff result`);
      if (crossResult !== "denied\n") {
        throw new Error(`The ${agent.sessionId} model descriptor reached the other agent UID: ${crossResult}`);
      }
      const crossHelper = handoffHelpers.get(`${agent.sessionId}:cross-model-handoff`);
      const crossFinished = await crossHelper.finished;
      if (crossFinished.code !== 0) {
        throw new Error(`The ${agent.sessionId} cross-session model descriptor receiver failed: ${JSON.stringify(crossFinished)}`);
      }
      const first = await until(() => maybeText(`${agent.root}/workspace/model-stream-first`),
        `${agent.sessionId} first streamed model event`);
      const stream = modelStreams.get(`${agent.sessionId}:fixture-stream-complete`);
      if (first !== "first\n" || !stream || stream.closed || stream.released) {
        throw new Error(`The ${agent.sessionId} model stream did not pause after its first event.`);
      }
      stream.released = true;
      stream.response.write('event: content_block_delta\ndata: {"type":"content_block_delta","text":"fixture-second"}\n\n');
      const middle = Math.floor(agent.model.value.length / 2);
      stream.response.write(`event: echo\ndata: ${agent.model.value.slice(0, middle)}`);
      stream.response.end(`${agent.model.value.slice(middle)}\n\n`);
      await writeFile(`${agent.root}/workspace/model-stream-go`, "go\n", { mode: 0o644 });
      const streamed = await until(() => maybeText(`${agent.root}/workspace/model-stream-result`),
        `${agent.sessionId} complete streamed model response`);
      if (streamed !== "streamed\n") {
        throw new Error(`The ${agent.sessionId} model stream was incomplete: ${streamed}`);
      }
      const ownResult = await until(() => maybeText(`${agent.root}/workspace/model-result`),
        `${agent.sessionId} strict model relay response`);
      if (ownResult !== "strict-rejected-and-streamed\n") {
        throw new Error(`The ${agent.sessionId} strict relay check failed: ${ownResult}`);
      }
      handoffOutcomes.push(`${agent.sessionId}:model-${modelResult.trim()}`);
      handoffOutcomes.push(`${agent.sessionId}:cross-model-${crossResult.trim()}`);
    }
  }
  for (const agent of agents) {
    const probe = `${agent.root}/usr/bin/managed-mcp-probe`;
    const claimant = run(runuser, ["-u", agent.userName, "--", "/usr/bin/env",
      `SGW_BROKER_SOCKET=${agent.socketPath}`, probe, "--out-of-cgroup"], true,
      { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" });
    if (claimant.error || claimant.status !== 0) {
      throw new Error(`The same-UID out-of-cgroup process reached ${agent.sessionId}: ${claimant.stderr || claimant.status}`);
    }
    if (testRelay) {
      const outsider = run(runuser, ["-u", agent.userName, "--", "/usr/bin/env",
        `SGW_MODEL_RELAY_SOCKET=${agent.modelSocketPath}`, probe, "--model-out-of-cgroup"], true,
        { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" });
      if (outsider.error || outsider.status !== 0) {
        throw new Error(`The same-UID out-of-cgroup process reached ${agent.sessionId}'s model relay: ${outsider.stderr || outsider.status}`);
      }
      const other = agents.find(item => item !== agent);
      const foreign = run(runuser, ["-u", other.userName, "--", "/usr/bin/env",
        `SGW_MODEL_RELAY_SOCKET=${agent.modelSocketPath}`, probe, "--model-cross-uid"], true,
        { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" });
      if (foreign.error || foreign.status !== 0) {
        throw new Error(`The other agent UID connected to ${agent.sessionId}'s model relay: ${foreign.stderr || foreign.status}`);
      }
    }
  }
  for (const agent of agents) {
    agent.requestId = asBroker("approve", [agent.sessionId, String(agent.uid), agent.name,
      agent.seeded.handle, url, agent.plan.identityGeneration]);
    if (!/^[A-Za-z0-9_-]{1,256}$/.test(agent.requestId)) {
      throw new Error("Invalid native fixture approved request ID.");
    }
  }
  for (let index = 0; index < agents.length; index++) {
    const agent = agents[index];
    const other = agents[1 - index];
    await writeFile(`${agent.root}/workspace/foreign-id`, `${other.requestId}\n`, { mode: 0o644 });
    await writeFile(`${agent.root}/workspace/approved-id`, `${agent.requestId}\n`, { mode: 0o644 });
  }
  for (const agent of agents) {
    const denied = await until(() => maybeText(`${agent.root}/workspace/foreign-denied`),
      `${agent.sessionId} cross-session claim denial`);
    if (denied !== "denied\n") throw new Error(`Unexpected cross-session result: ${denied}`);
  }
  for (const agent of agents) {
    await writeFile(`${agent.root}/workspace/execute-go`, "go\n", { mode: 0o644 });
  }
  for (const agent of agents) {
    const result = await until(() => maybeText(`${agent.root}/workspace/result`),
      `${agent.sessionId} broker-owned HTTPS result`);
    if (result !== "owned-https=1\n") throw new Error(`Unexpected verified MCP result: ${result}`);
  }
  if (upstreamAuths.length !== 2 ||
      upstreamAuths.some(item => item.method !== "GET" || item.path !== "/operation") ||
      agents.some(agent => upstreamAuths.filter(item => item.authorization === `Bearer ${agent.seeded.value}`).length !== 1)) {
    throw new Error("The broker did not send each approved synthetic credential exactly once.");
  }
  if (testRelay) {
    for (const agent of agents) {
      const ready = await until(() => maybeText(`${agent.root}/workspace/model-cancel-ready`),
        `${agent.sessionId} active model stream before revocation`);
      const held = modelStreams.get(`${agent.sessionId}:fixture-cancel`);
      if (ready !== "first\n" || !held || held.closed || held.released) {
        throw new Error(`The ${agent.sessionId} cancellable model stream did not remain open.`);
      }
      for (const phase of ["fixture-stream-complete", "fixture-cancel"]) {
        const matching = modelRequests.filter(item => item.sessionId === agent.sessionId && item.phase === phase);
        if (matching.length !== 1) throw new Error(`The ${agent.sessionId} model stream was not unique.`);
        const request = matching[0];
        const body = JSON.parse(request.body);
        if (request.authorization !== `Bearer ${agent.model.value}` || request.clientKey !== undefined ||
            request.host !== "api.anthropic.com" || request.serverName !== "api.anthropic.com" ||
            request.version !== "2023-06-01" ||
            request.method !== "POST" || request.path !== "/v1/messages" ||
            body.model !== "fixture-model" || body.max_tokens !== 16 || body.stream !== true ||
            body.messages?.length !== 1 || body.messages[0]?.content !== phase ||
            body.mcp_servers !== undefined) {
          throw new Error(`The ${agent.sessionId} broker did not own its authenticated model TLS request.`);
        }
      }
    }
    if (modelRequests.length !== agents.length * 2) {
      throw new Error("A denied model request reached the synthetic HTTPS provider.");
    }
  }
  const fenceRoot = "/run/s-gw/agent-unit-lifecycle";
  for (const agent of agents) {
    await remember(`/run/s-gw/launch-gates/${agent.sessionId}`);
    await remember(`${fenceRoot}/${agent.agentUnit}`);
    for (const name of await readdir(fenceRoot)) {
      if (name.startsWith(`${agent.agentUnit}.launch-`)) await remember(path.join(fenceRoot, name));
    }
  }
  run("systemctl", ["--system", "stop", agents[0].socketUnit]);
  if (testRelay) run("systemctl", ["--system", "stop", agents[0].modelSocketUnit]);
  run("systemctl", ["--system", "stop", agents[0].brokerUnit]);
  await until(() => run("systemctl", ["--system", "is-active", agents[0].agentUnit], true).status !== 0,
    "first agent teardown after its broker stopped");
  if (testRelay) {
    await until(() => modelStreams.get(`${agents[0].sessionId}:fixture-cancel`)?.closed,
      "first broker-owned model stream cancellation");
    if (modelStreams.get(`${agents[1].sessionId}:fixture-cancel`)?.closed) {
      throw new Error("Stopping one broker also cancelled the other agent's model stream.");
    }
    await until(() => {
      try { return asBroker("assert-relay-state", [agents[0].relay.requestId, "executed"]) === "executed"; }
      catch { return false; }
    }, "first model relay durable session close");
    if (asBroker("reject-relay-reclaim", [agents[0].relay.requestId, agents[0].sessionId,
      agents[0].name, agents[0].plan.identityGeneration]) !== "executed") {
      throw new Error("The stopped model relay approval remained claimable.");
    }
    if (run("systemctl", ["--system", "is-active", agents[1].modelSocketUnit], true).status !== 0) {
      throw new Error("Stopping one broker also stopped the other model socket.");
    }
  }
  if (run("systemctl", ["--system", "is-active", agents[1].agentUnit], true).status !== 0) {
    throw new Error("Stopping one broker also stopped the other agent.");
  }
  run("systemctl", ["--system", "kill", "--signal=SIGKILL", "--kill-who=main",
    controlUnit]);
  await until(() => run("systemctl", ["--system", "is-active", agents[1].agentUnit], true).status !== 0,
    "second agent teardown after root control death");
  await until(() => ["inactive", "failed"].includes(unitProperties(agents[1].socketUnit,
    ["ActiveState"]).get("ActiveState")), "second MCP socket teardown after root control death");
  for (const agent of agents) {
    await until(() => {
      const broker = unitProperties(agent.brokerUnit, ["ActiveState", "MainPID"]);
      return ["inactive", "failed"].includes(broker.get("ActiveState")) && broker.get("MainPID") === "0";
    }, `${agent.sessionId} broker exit after root control death`);
  }
  for (const agent of agents) {
    const refused = await new Promise(resolve => {
      const socket = createConnection(agent.socketPath);
      socket.setTimeout(3000, () => { socket.destroy(); resolve(false); });
      socket.once("connect", () => { socket.destroy(); resolve(false); });
      socket.once("error", error => resolve(["ENOENT", "ECONNREFUSED"].includes(error.code)));
    });
    if (!refused || run("systemctl", ["--system", "is-active", agent.brokerUnit], true).status === 0 ||
        run("systemctl", ["--system", "is-active", agent.agentUnit], true).status === 0) {
      throw new Error(`The ${agent.sessionId} MCP socket reactivated a revoked session.`);
    }
  }
  if (run("systemctl", ["--system", "is-active", controlUnit], true).status === 0) {
    throw new Error("An MCP socket restarted the root control after revocation.");
  }
  if (testRelay) {
    await until(() => run("systemctl", ["--system", "is-active", agents[1].modelSocketUnit], true).status !== 0,
      "second model socket teardown after root control death");
    await until(() => modelStreams.get(`${agents[1].sessionId}:fixture-cancel`)?.closed,
      "second broker-owned model stream cancellation");
    await until(() => {
      try { return asBroker("assert-relay-state", [agents[1].relay.requestId, "executed"]) === "executed"; }
      catch { return false; }
    }, "second model relay durable session close");
    const last = asBroker("reject-relay-reclaim", [agents[1].relay.requestId,
      agents[1].sessionId, agents[1].name, agents[1].plan.identityGeneration]);
    if (last !== "executed") {
      throw new Error(`The root-control death left an unexpected model relay state: ${last}`);
    }
  }
  passed = true;
} catch (error) {
  const logs = run("journalctl", ["--no-pager", "-n", "80", "-u", "s-gw-agent-control.service",
    ...agents.flatMap(agent => ["-u", agent.brokerUnit])], true).stdout;
  primaryFailure = new Error(`${String(error)}\n${logs}`);
  throw primaryFailure;
} finally {
  let cleanupError;
  try {
    for (const helper of handoffHelpers.values()) await stopHandoffHelper(helper);
    if (modelUpstream) {
      modelUpstream.closeAllConnections();
      await new Promise(resolve => modelUpstream.close(resolve));
    }
    if (upstream) {
      upstream.closeAllConnections();
      await new Promise(resolve => upstream.close(resolve));
    }
    if (fixtureOwned) {
      if (controlStartAttempted && !controlStarted) {
        if (activeFixtureUnit(controlUnit)) {
          const uncertain = unitProperties(controlUnit, controlProperties);
          if (fixtureControl(uncertain) && invocationId(uncertain)) {
            run("systemctl", ["--system", "stop", controlUnit], true);
          }
        }
        throw new Error("Root control start was ambiguous; its root-owned fixture tree was preserved.");
      }
      if ([...socketStartAttempted].some(session => !socketStarted.has(session)) ||
          [...modelSocketStartAttempted].some(session => !modelSocketStarted.has(session))) {
        if (activeFixtureUnit(controlUnit)) {
          const currentControl = unitProperties(controlUnit, controlProperties);
          if (fixtureControl(currentControl) && invocationId(currentControl) === controlInvocation) {
            run("systemctl", ["--system", "stop", controlUnit], true);
          }
        }
        for (const agent of agents) {
          if (activeFixtureUnit(agent.socketUnit) &&
              await fixtureUnitFile(agent.socketUnit, agent.socketUnitFile)) {
            run("systemctl", ["--system", "stop", agent.socketUnit], true);
          }
          if (testRelay && activeFixtureUnit(agent.modelSocketUnit) &&
              await fixtureUnitFile(agent.modelSocketUnit, agent.modelSocketUnitFile)) {
            run("systemctl", ["--system", "stop", agent.modelSocketUnit], true);
          }
          if (activeFixtureUnit(agent.brokerUnit) &&
              await fixtureUnitFile(agent.brokerUnit, agent.brokerUnitFile)) {
            run("systemctl", ["--system", "stop", agent.brokerUnit], true);
          }
        }
        throw new Error("Managed MCP socket start was ambiguous; its fixture paths were preserved.");
      }
      const controlActive = activeFixtureUnit(controlUnit);
      const currentControl = controlActive ? unitProperties(controlUnit, controlProperties) : undefined;
      const controlOwned = controlActive && controlStarted && controlInvocation && fixtureControl(currentControl) &&
        invocationId(currentControl) === controlInvocation;
      if (controlActive && !controlOwned) {
        throw new Error("Root control unit changed; native fixture state was preserved.");
      }
      const states = [];
      for (const agent of agents) {
        const agentActive = activeFixtureUnit(agent.agentUnit);
        const agentState = agentActive ? unitProperties(agent.agentUnit, ["Id", "Description", "ActiveState", "User",
          "RootDirectory", "InvocationID"]) : undefined;
        if (agentActive && (agentState.get("Id") !== agent.agentUnit ||
            !/^s-gw-agent-start:[a-f0-9]{32}$/.test(agentState.get("Description") ?? "") ||
            agentState.get("User") !== String(agent.uid) || agentState.get("RootDirectory") !== agent.root ||
            !agentInvocations.get(agent.sessionId) ||
            invocationId(agentState) !== agentInvocations.get(agent.sessionId))) {
          if (controlActive && controlOwned) run("systemctl", ["--system", "stop", controlUnit], true);
          throw new Error("Agent unit changed; native fixture state was preserved.");
        }
        const brokerActive = activeFixtureUnit(agent.brokerUnit);
        const brokerState = brokerActive ? unitProperties(agent.brokerUnit,
          ["Id", "FragmentPath", "ActiveState", "InvocationID"]) : undefined;
        const brokerOwned = brokerActive && await fixtureUnitFile(agent.brokerUnit, agent.brokerUnitFile);
        if (brokerActive && (!brokerOwned || !brokerInvocations.get(agent.sessionId) ||
            invocationId(brokerState) !== brokerInvocations.get(agent.sessionId))) {
          if (controlActive && controlOwned) run("systemctl", ["--system", "stop", controlUnit], true);
          throw new Error("Broker unit changed; native fixture state was preserved.");
        }
        const socketActive = activeFixtureUnit(agent.socketUnit);
        const socketOwned = socketActive && await fixtureUnitFile(agent.socketUnit, agent.socketUnitFile);
        if (socketActive && !socketOwned) {
          if (controlActive && controlOwned) run("systemctl", ["--system", "stop", controlUnit], true);
          throw new Error("Socket unit changed; native fixture state was preserved.");
        }
        let modelSocketActive = false;
        if (testRelay) {
          modelSocketActive = activeFixtureUnit(agent.modelSocketUnit);
          const modelOwned = modelSocketActive &&
            await fixtureUnitFile(agent.modelSocketUnit, agent.modelSocketUnitFile);
          if (modelSocketActive && !modelOwned) {
            if (controlActive && controlOwned) run("systemctl", ["--system", "stop", controlUnit], true);
            throw new Error("Model socket unit changed; native fixture state was preserved.");
          }
        }
        states.push({ agent, agentActive, brokerActive, socketActive, modelSocketActive });
      }
      for (const { agent, socketActive, modelSocketActive } of states) {
        if (socketActive) run("systemctl", ["--system", "stop", agent.socketUnit], true);
        if (modelSocketActive) run("systemctl", ["--system", "stop", agent.modelSocketUnit], true);
      }
      for (const { agent, brokerActive } of states) {
        if (brokerActive) run("systemctl", ["--system", "stop", agent.brokerUnit], true);
      }
      for (const { agent, agentActive } of states) {
        if (agentActive) run("systemctl", ["--system", "stop", agent.agentUnit], true);
      }
      if (controlActive) run("systemctl", ["--system", "stop", controlUnit], true);
      const allUnits = agents.flatMap(agent => [agent.socketUnit, agent.brokerUnit, agent.agentUnit,
        ...(testRelay ? [agent.modelSocketUnit] : [])]);
      if (controlStarted) allUnits.push(controlUnit);
      for (const unit of allUnits) {
        if (run("systemctl", ["--system", "is-active", unit], true).status === 0) {
          throw new Error(`Native fixture unit is still active; paths preserved: ${unit}`);
        }
      }
      for (const agent of agents) {
        if (run("pgrep", ["-u", String(agent.uid)], true).status === 0) {
          throw new Error(`Native Linux agent ${agent.sessionId} still has processes; paths preserved.`);
        }
      }
      for (const agent of agents) {
        await assertFixtureUnitFile(agent.socketUnitFile);
        if (testRelay) await assertFixtureUnitFile(agent.modelSocketUnitFile);
        await assertFixtureUnitFile(agent.brokerUnitFile);
        await removeOwned(agent.socketUnitFile);
        if (testRelay) await removeOwned(agent.modelSocketUnitFile);
        await removeOwned(agent.brokerUnitFile);
      }
      await assertFixtureUnitFile(controlUnitFile);
      await removeOwned(controlUnitFile);
      if (unitsInstalled) run("systemctl", ["--system", "daemon-reload"], true);
      for (const agent of agents) {
        for (const filename of owned.keys()) {
          if (filename.startsWith(`/run/s-gw/agent-unit-lifecycle/${agent.agentUnit}.launch-`)) {
            await removeOwned(filename);
          }
        }
        await removeOwned(`/run/s-gw/agent-unit-lifecycle/${agent.agentUnit}`, true);
        await removeOwned(`/run/s-gw/launch-gates/${agent.sessionId}`, true);
      }
      await removeOwned("/run/s-gw/agent-control.sock");
      for (const agent of agents) {
        await removeOwned(path.dirname(agent.socketPath), true);
        await removeOwned(agent.root, true);
        await removeOwned(agent.configPath);
        if (testRelay) await removeOwned(`${agent.configPath}.sealed`);
        await removeOwned(agent.planPath);
        for (const filename of agent.identityPaths) {
          if (!owned.has(filename)) continue;
          const value = await readFile(filename, "utf8");
          if (value !== JSON.stringify(agent.identityRecord) + "\n") {
            throw new Error(`Native identity record changed before cleanup: ${filename}`);
          }
          await removeOwned(filename);
        }
        for (const filename of agent.claimPaths) {
          if (owned.has(filename)) {
            const value = await readFile(filename, "utf8");
            if (value !== `${agent.sessionId} ${agent.uid} ${agent.plan.gid}\n`) {
              throw new Error(`Native identity claim changed before cleanup: ${filename}`);
            }
            await removeOwned(filename);
          }
        }
      }
      await removeOwned(envFile);
      if (planDirCreated) {
        await assertOwned(planDir);
        await rmdir(planDir);
      }
      if (identityDirCreated) {
        await assertOwned(identityDir);
        await rmdir(identityDir);
      }
      await removeOwned(leaseDir, true);
      await removeOwned(storeHome, true);
      await removeOwned(recoveryHome, true);
      await removeOwned(installed, true);
      for (const name of accountsCreated.reverse()) run("userdel", [name]);
      for (const name of groupsCreated.reverse()) {
        const before = run("getent", ["group", name], true);
        if (before.error || (before.status !== 0 && before.status !== 2)) {
          throw new Error(`Could not check fixture group ${name}: ${before.error?.message || before.status}`);
        }
        if (before.status === 0) run("groupdel", [name]);
        const after = run("getent", ["group", name], true);
        if (after.error || after.status !== 2) {
          throw new Error(`Fixture group remains after cleanup: ${name}`);
        }
      }
    }
  } catch (error) {
    cleanupError = error;
  }
  try {
    await closeNetworkFixtures();
  } catch (error) {
    cleanupError = cleanupError
      ? new AggregateError([cleanupError, error], "Native fixture teardown and network cleanup both failed.")
      : error;
  }
  if (cleanupError) {
    if (primaryFailure) {
      throw new AggregateError([primaryFailure, cleanupError],
        "Native Linux managed MCP test and cleanup both failed.");
    }
    throw cleanupError;
  }
}
if (passed) {
  console.log(`Native Linux managed MCP passed: two UIDs/cgroups/net namespaces, direct IPv4/IPv6/TCP/UDP and private-file denial, restricted AF_NETLINK socket creation, same-UID outsider ptrace denial, connected-descriptor handoff ${handoffOutcomes.join(", ")}, out-of-cgroup direct-connect denial, UID/GID claim-function collisions, cross-session claim denial, two broker-owned HTTPS actions, independent teardown, and root-control death teardown.${testRelay ? " Opt-in model relay: durable approval and claim, strict-body rejection, cross-session/UID/cgroup/FD-transfer denial, broker-owned authenticated TLS streaming and redaction, and active-stream cancellation on both teardown paths." : ""}`);
}
