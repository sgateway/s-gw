import { spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, chown, copyFile, lstat, mkdir, readFile, readdir, realpath, rm, rmdir,
  unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux" || process.getuid?.() !== 0 || process.geteuid?.() !== 0 ||
    process.env.CI !== "true" || process.argv.length !== 3 || process.argv[2] !== "--root") {
  throw new Error("Run the installer fixture as root on a disposable Linux CI host.");
}

const project = fileURLToPath(new URL("..", import.meta.url));
const runuser = ["/usr/sbin/runuser", "/usr/bin/runuser"].find(existsSync);
if (!runuser) throw new Error("The installer fixture needs runuser.");

function run(command, args, allowFailure = false, env = { PATH: "/usr/sbin:/usr/bin:/sbin:/bin",
  LANG: "C.UTF-8", CI: "true" }) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 60_000, env });
  if (!allowFailure && (result.error || result.status !== 0)) {
    throw new Error(path.basename(command) + " failed: " +
      (result.error?.message || result.stderr || result.stdout || result.status));
  }
  return result;
}

async function statMaybe(filename) {
  try { return await lstat(filename); }
  catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
}

async function textMaybe(filename) {
  try { return await readFile(filename, "utf8"); }
  catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
}

async function until(check, label) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const found = await check();
    if (found) return found;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error("Timed out waiting for " + label);
}

function freeUidPair() {
  for (let uid = 234000; uid < 234998; uid += 2) {
    const numbers = [uid, uid + 1];
    if (numbers.every(value => run("getent", ["passwd", String(value)], true).status === 2 &&
        run("getent", ["group", String(value)], true).status === 2)) return uid;
  }
  throw new Error("No disposable account pair is free.");
}

function properties(unit, names) {
  const args = ["--system", "--no-pager", "--all", "show", unit,
    ...names.flatMap(name => ["-p", name])];
  const result = run("systemctl", args);
  const found = new Map();
  for (const line of result.stdout.trimEnd().split("\n")) {
    const pos = line.indexOf("=");
    if (pos < 1 || found.has(line.slice(0, pos))) {
      throw new Error("Invalid systemd readback for " + unit);
    }
    found.set(line.slice(0, pos), line.slice(pos + 1));
  }
  for (const name of names) {
    if (!found.has(name)) throw new Error("Missing " + name + " for " + unit);
  }
  return found;
}

function assertInactive(unit) {
  const state = properties(unit, ["ActiveState"]).get("ActiveState");
  if (state !== "inactive") throw new Error("Installer fixture unit is still " + state + ": " + unit);
}

const runId = randomBytes(5).toString("hex");
const uid = freeUidPair();
const brokerUid = uid;
const agentUid = uid + 1;
const brokerName = "sgwins" + runId.slice(0, 7) + "b";
const agentName = "sgwins" + runId.slice(0, 7) + "a";
const sessionId = "ci-installer-" + runId;
const displayName = "Native managed installer " + runId;
const installed = "/run/s-gw/ci-installer-" + runId;
const brokerPackage = path.join(installed, "broker");
const controlDir = path.join(installed, "control");
const node = path.join(installed, "node");
const verifier = path.join(installed, "s-gw-linux-broker-runtime");
const controlEntry = path.join(controlDir, "linux-agent-control.js");
const brokerEntry = path.join(brokerPackage, "dist/linux-managed-mcp.js");
const installEntry = path.join(brokerPackage, "dist/linux-managed-install.js");
const installPlan = "/run/s-gw/ci-installer-input-" + runId + ".json";
const rootDir = "/var/lib/s-gw/agent-roots/" + sessionId;
const probe = path.join(rootDir, "usr/bin/installer-probe");
const gate = path.join(rootDir, "usr/libexec/s-gw/agent-launch-gate");
const storeHome = "/run/s-gw/ci-installer-store-" + runId;
const recoveryHome = "/run/s-gw/ci-installer-recovery-" + runId;
const envFile = "/run/s-gw/ci-installer-env-" + runId;
const leaseDir = "/run/s-gw/managed-leases";
const launchGates = "/run/s-gw/launch-gates";
const lifecycleDir = "/run/s-gw/agent-unit-lifecycle";
const identityDir = "/var/lib/s-gw/agent-identities";
const plansDir = "/run/s-gw/agent-plans";
const agentsDir = "/run/s-gw/agents";
const socketDir = path.join(agentsDir, sessionId);
const controlUnit = "s-gw-agent-control.service";
const agentUnit = "s-gw-agent-" + sessionId + ".service";
const brokerUnit = "s-gw-managed-mcp-" + sessionId + ".service";
const mcpUnit = "s-gw-managed-mcp-" + sessionId + ".socket";
const modelUnit = "s-gw-managed-model-" + sessionId + ".socket";
const operatorEntry = path.join(brokerPackage, "scripts/linux-managed-mcp-operator.mjs");
const plan = { sessionId, uid: agentUid, gid: agentUid, brokerUid,
  rootDirectory: rootDir, brokerSocket: path.join(socketDir, "broker.sock"),
  modelRelaySocket: path.join(socketDir, "model.sock"),
  executable: "/usr/bin/installer-probe", args: ["--installer-idle"],
  launchGate: true, activatedSocket: true, isolatedSharedMemory: true,
  serializedLifecycle: true, sealedStdio: true, restrictedSocketFamilies: true,
  requirePtracePolicy: true, supervisedControlUnit: true, logicalAgentId: sessionId,
  identityGeneration: randomBytes(16).toString("hex") };
const control = { unitFile: "/run/systemd/system/" + controlUnit, runtimeRoot: installed,
  preflight: verifier, node, entry: controlEntry, brokerUid, brokerGid: brokerUid };
const record = { plan, brokerUnit, brokerUnitFile: "/run/systemd/system/" + brokerUnit,
  mcpSocketUnitFile: "/run/systemd/system/" + mcpUnit,
  modelRelaySocketUnitFile: "/run/systemd/system/" + modelUnit,
  brokerEntry, brokerConfig: "/run/s-gw/" + sessionId + ".json", brokerNode: node,
  brokerRuntimeRoot: installed, brokerPreflight: verifier, brokerEnvironmentFile: envFile,
  brokerCa: null };
const planFile = path.join(plansDir, sessionId + ".json");
const receipts = [path.join(identityDir, "uid-" + agentUid + ".json"),
  path.join(identityDir, "generation-" + plan.identityGeneration + ".json")];
const claims = [path.join(plansDir, "uid-" + agentUid + ".used"),
  path.join(plansDir, "gid-" + agentUid + ".used"),
  path.join(plansDir, "session-" + sessionId + ".used")];
const owned = new Map();
const madeDirs = [];
const accounts = [];
const groups = [];
let stageAttempted = false;
let approvedActivationAttempted = false;
let configReplacedCaptured = false;
let activated = false;
let asBroker;
let bundle;
let controlText;
let sealedConfigText;
let passed = false;
let failure;

async function remember(filename) {
  const item = await lstat(filename);
  owned.set(filename, { dev: item.dev, ino: item.ino });
}

async function assertOwned(filename) {
  const expected = owned.get(filename);
  if (!expected) throw new Error("Installer fixture does not own " + filename);
  const current = await lstat(filename);
  if (current.dev !== expected.dev || current.ino !== expected.ino) {
    throw new Error("Installer fixture path changed: " + filename);
  }
  return current;
}

async function removeFile(filename) {
  if (!owned.has(filename)) return;
  const item = await assertOwned(filename);
  if (!item.isFile() && !item.isSocket()) throw new Error("Expected installer fixture file: " + filename);
  await unlink(filename);
}

async function removeTree(filename) {
  if (!owned.has(filename)) return;
  const item = await assertOwned(filename);
  if (!item.isDirectory()) throw new Error("Expected installer fixture directory: " + filename);
  await rm(filename, { recursive: true });
}

async function makeDirectory(filename, mode) {
  if (await statMaybe(filename)) throw new Error("Installer fixture path already exists: " + filename);
  await mkdir(filename, { mode });
  await remember(filename);
  madeDirs.push(filename);
}

async function rootDirectory(filename, mode) {
  const item = await statMaybe(filename);
  if (!item) return makeDirectory(filename, mode);
  if (!item.isDirectory() || item.uid !== 0 || (item.mode & 0o777) !== mode ||
      await realpath(filename) !== filename) {
    throw new Error("Installer fixture needs a trusted root directory: " + filename);
  }
}

async function checkedBrokerTree() {
  const pending = [brokerPackage];
  while (pending.length) {
    const filename = pending.pop();
    const item = await lstat(filename);
    if (item.isSymbolicLink()) {
      const target = await realpath(filename);
      if (!target.startsWith(brokerPackage + "/")) {
        throw new Error("Installer broker package symlink escapes its root: " + filename);
      }
      continue;
    }
    if (item.uid !== 0 || (item.mode & 0o022) !== 0 ||
        (!item.isFile() && !item.isDirectory())) {
      throw new Error("Installer broker package is not root-controlled: " + filename);
    }
    if (item.isDirectory()) {
      for (const name of await readdir(filename)) pending.push(path.join(filename, name));
    }
  }
}

async function captureStageFiles() {
  if (!stageAttempted) return;
  const expected = new Map([
    [control.unitFile, controlText], [record.brokerUnitFile, bundle.brokerUnit],
    [record.mcpSocketUnitFile, bundle.mcpSocketUnit],
    [record.modelRelaySocketUnitFile, bundle.modelSocketUnit],
    [planFile, bundle.planRecord], [record.brokerConfig, bundle.brokerConfig]
  ]);
  for (const [filename, value] of expected) {
    const text = await textMaybe(filename);
    if (text === undefined) continue;
    if (filename !== record.brokerConfig && text !== value) {
      throw new Error("Installer unit or plan changed before cleanup: " + filename);
    }
    if (filename === record.brokerConfig) {
      if (text !== value && text !== sealedConfigText) {
        throw new Error("Installer config changed before cleanup.");
      }
    }
    if (owned.has(filename) &&
        (filename !== record.brokerConfig || !approvedActivationAttempted || configReplacedCaptured)) {
      await assertOwned(filename);
    } else {
      await remember(filename);
      if (filename === record.brokerConfig && approvedActivationAttempted) {
        configReplacedCaptured = true;
      }
    }
  }
  for (const filename of receipts) {
    if (await statMaybe(filename)) {
      const expectedReceipt = JSON.stringify({ logicalAgentId: sessionId,
        identityGeneration: plan.identityGeneration, uid: agentUid, gid: agentUid }) + "\n";
      if (await readFile(filename, "utf8") !== expectedReceipt) {
        throw new Error("Installer identity receipt changed before cleanup.");
      }
      if (owned.has(filename)) await assertOwned(filename);
      else await remember(filename);
    }
  }
}

async function captureStageDirs() {
  if (!stageAttempted) return;
  for (const [filename, owner, mode] of [[socketDir, 0, 0o711],
    [agentsDir, 0, 0o711], [plansDir, 0, 0o700],
    [identityDir, 0, 0o700], [leaseDir, brokerUid, 0o700]]) {
    const item = await statMaybe(filename);
    if (!item) continue;
    if (!item.isDirectory() || item.uid !== owner || (item.mode & 0o777) !== mode ||
        await realpath(filename) !== filename) {
      throw new Error("Installer fixture directory changed: " + filename);
    }
    if (owned.has(filename)) await assertOwned(filename);
    else await remember(filename);
  }
}

function ownedUnit(unit, filename, content) {
  const current = properties(unit, ["Id", "FragmentPath", "DropInPaths", "ActiveState"]);
  if (current.get("Id") !== unit || current.get("FragmentPath") !== filename ||
      current.get("DropInPaths") || !owned.has(filename)) {
    throw new Error("Installer fixture cannot prove unit ownership: " + unit);
  }
  return readFile(filename, "utf8").then(text => {
    if (text !== content) throw new Error("Installer fixture unit file changed: " + filename);
    return current.get("ActiveState");
  });
}

let requestId;
try {
  for (const unit of [controlUnit, brokerUnit, mcpUnit, modelUnit, agentUnit]) {
    if (properties(unit, ["LoadState"]).get("LoadState") !== "not-found") {
      throw new Error("Installer fixture found an existing unit: " + unit);
    }
  }
  for (const filename of [installed, rootDir, storeHome, recoveryHome, envFile, leaseDir,
    launchGates, lifecycleDir,
    identityDir, plansDir, agentsDir, control.unitFile, record.brokerUnitFile,
    record.mcpSocketUnitFile, record.modelRelaySocketUnitFile, record.brokerConfig,
    "/run/s-gw/agent-control.sock", "/run/s-gw/agent-prepare.sock",
    "/run/s-gw/managed-install.lock", ...receipts, ...claims]) {
    if (await statMaybe(filename)) throw new Error("Installer fixture path already exists: " + filename);
  }
  const ptrace = await readFile("/proc/sys/kernel/yama/ptrace_scope", "utf8");
  if (!/^[123]\n?$/.test(ptrace)) throw new Error("Installer fixture requires restricted host ptrace.");
  await rootDirectory("/run/s-gw", 0o755);
  await rootDirectory(launchGates, 0o755);
  await rootDirectory("/var/lib/s-gw", 0o700);
  await rootDirectory("/var/lib/s-gw/agent-roots", 0o755);
  await makeDirectory(installed, 0o755);
  await makeDirectory(controlDir, 0o755);
  await makeDirectory(brokerPackage, 0o755);
  run("cp", ["-R", path.join(project, "dist"), brokerPackage]);
  run("cp", ["-R", path.join(project, "node_modules"), brokerPackage]);
  await mkdir(path.join(brokerPackage, "tools"), { mode: 0o755 });
  run("cp", ["-R", path.join(project, "tools/desktop-packager"),
    path.join(brokerPackage, "tools")]);
  await copyFile(path.join(project, "package.json"), path.join(brokerPackage, "package.json"));
  await mkdir(path.dirname(operatorEntry), { mode: 0o755 });
  await copyFile(path.join(project, "scripts/linux-managed-mcp-operator.mjs"), operatorEntry);
  for (const filename of ["linux-agent-control.js", "linux-agent-unit.js",
    "linux-peer-identity.js", "linux-agent-identity.js", "linux-managed-forwarder-attestation.js",
    "linux-managed-forwarder-binding.js", "model-relay-action.js"]) {
    await copyFile(path.join(project, "dist", filename), path.join(controlDir, filename));
  }
  await writeFile(path.join(controlDir, "package.json"), '{"type":"module"}\n', { mode: 0o644 });
  await copyFile(process.execPath, node);
  run("cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/linux-broker-runtime/verify.c"), "-o", verifier]);
  const rootHelpers = path.join(installed, "dist/native/linux-" + process.arch);
  const brokerHelpers = path.join(brokerPackage, "dist/native/linux-" + process.arch);
  await mkdir(rootHelpers, { recursive: true, mode: 0o755 });
  await mkdir(brokerHelpers, { recursive: true, mode: 0o755 });
  for (const [source, name] of [
    ["native/linux-peer-identity/verify.c", "s-gw-linux-peer-identity"],
    ["native/peer-credentials/peer-credentials.c", "s-gw-peer-credentials"]
  ]) {
    run("cc", ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
      path.join(project, source), "-o", path.join(rootHelpers, name)]);
    if (name === "s-gw-peer-credentials") {
      run("cc", ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
        path.join(project, source), "-o", path.join(brokerHelpers, name)]);
    }
  }
  await makeDirectory(rootDir, 0o755);
  for (const relative of ["usr", "usr/bin", "usr/libexec", "usr/libexec/s-gw",
    "run", "run/s-gw", "run/s-gw/launch-gate", "dev", "dev/shm", "workspace"]) {
    await mkdir(path.join(rootDir, relative), { recursive: true, mode: 0o755 });
  }
  run("cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/linux-agent-gate/launch-gate.c"), "-o", gate]);
  run("cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "scripts/linux-agent-native-probe.c"), "-o", probe]);
  run("chown", ["-R", "0:0", installed]);
  run("chmod", ["-R", "go-w", installed]);
  await checkedBrokerTree();
  await chmod(node, 0o755);
  await chmod(verifier, 0o755);
  await chmod(controlEntry, 0o755);
  await chmod(gate, 0o755);
  await chmod(probe, 0o755);
  await chmod(path.join(rootDir, "workspace"), 0o700);
  run("groupadd", ["--gid", String(brokerUid), brokerName]);
  groups.push(brokerName);
  run("useradd", ["--system", "--uid", String(brokerUid), "--gid", brokerName,
    "--no-create-home", "--shell", "/usr/sbin/nologin", brokerName]);
  accounts.push(brokerName);
  run("groupadd", ["--gid", String(agentUid), agentName]);
  groups.push(agentName);
  run("useradd", ["--system", "--uid", String(agentUid), "--gid", agentName,
    "--no-create-home", "--shell", "/usr/sbin/nologin", agentName]);
  accounts.push(agentName);
  await chown(path.join(rootDir, "workspace"), agentUid, agentUid);
  await makeDirectory(storeHome, 0o700);
  await chown(storeHome, brokerUid, brokerUid);
  await makeDirectory(recoveryHome, 0o700);
  await chown(recoveryHome, brokerUid, brokerUid);
  const operatorEnv = { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", CI: "true",
    SGW_HOME: storeHome, SGW_RECOVERY_HOME: recoveryHome,
    SGW_MASTER_PASSPHRASE: "synthetic-installer-" + randomUUID(),
    SGW_DISABLE_KEYCHAIN: "1", SGW_DISABLE_ONEPASSWORD_BACKUP: "1" };
  asBroker = (mode, args = []) => run(runuser,
    ["-u", brokerName, "--", process.execPath, operatorEntry, mode, ...args],
    false, operatorEnv).stdout.trim();
  const seeded = JSON.parse(asBroker("seed-relay"));
  if (!/^s-gw:api-token:[A-Za-z0-9_-]+$/.test(seeded.handle) ||
      !/^synthetic-managed-model-[A-Za-z0-9-]+$/.test(seeded.value)) {
    throw new Error("Installer fixture did not create a synthetic model handle.");
  }
  await writeFile(envFile, "CI=true\nSGW_HOME=" + storeHome + "\nSGW_RECOVERY_HOME=" +
    recoveryHome + "\nSGW_MASTER_PASSPHRASE=" + operatorEnv.SGW_MASTER_PASSPHRASE +
    "\nSGW_DISABLE_KEYCHAIN=1\nSGW_DISABLE_ONEPASSWORD_BACKUP=1\n", { mode: 0o600, flag: "wx" });
  await remember(envFile);
  const config = { name: displayName, leaseDir, plan,
    relay: { grant: { handle: seeded.handle, provider: "anthropic",
      routes: ["POST /v1/messages"], ttlMs: 30 * 60_000,
      payloadProfile: "strict", allowedModels: ["fixture-model"], maxRequests: 2 } } };
  const input = { control, config, record, brokerGid: brokerUid };
  await writeFile(installPlan, JSON.stringify(input) + "\n", { mode: 0o600, flag: "wx" });
  await remember(installPlan);
  const install = (mode, id, allowFailure = false) => run(verifier,
    ["verify-exec", installed, node, installEntry, installPlan, "-", "-", "--",
      mode, installPlan, ...(id ? [id] : [])], allowFailure);
  const { renderLinuxAgentControlUnit, renderLinuxManagedUnitBundle } =
    await import(new URL("../dist/linux-agent-provision.js", import.meta.url));
  controlText = renderLinuxAgentControlUnit(control);
  bundle = renderLinuxManagedUnitBundle(config, record, brokerUid, "prepare");
  stageAttempted = true;
  install("stage");
  await captureStageFiles();
  await captureStageDirs();
  const prepared = install("prepare").stdout.trim();
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(prepared)) {
    throw new Error("Root preparation returned an invalid installer request.");
  }
  requestId = prepared;
  const getRequest = async id => JSON.parse(asBroker("relay-request", [id]));
  const pending = await getRequest(requestId);
  if (pending.state !== "pending" || pending.agentSource !== "managed-peer" ||
      pending.agentSessionId !== sessionId ||
      pending.principalId !== "linux:managed:" + plan.identityGeneration ||
      pending.handle !== seeded.handle || pending.action?.kind !== "model_relay" ||
      pending.action.model?.payloadProfile !== "strict" ||
      pending.action.model?.routes?.join(",") !== "POST /v1/messages") {
    throw new Error("Root preparation did not create the expected pending request.");
  }
  const pendingAttempt = install("activate", requestId, true);
  const pendingDenied = pendingAttempt.status !== 0;
  if (!pendingDenied || await readFile(record.brokerConfig, "utf8") !== bundle.brokerConfig) {
    throw new Error("Pending model relay request activated or changed the staged config.");
  }
  for (const unit of [mcpUnit, modelUnit, brokerUnit, agentUnit]) assertInactive(unit);
  if (asBroker("approve-relay", [requestId]) !== requestId) {
    throw new Error("Installer fixture approval changed the request ID.");
  }
  const sealedConfig = JSON.parse(bundle.brokerConfig);
  sealedConfig.relay.requestId = requestId;
  sealedConfigText = JSON.stringify(sealedConfig) + "\n";
  approvedActivationAttempted = true;
  install("activate", requestId);
  activated = true;
  await remember(record.brokerConfig);
  configReplacedCaptured = true;
  const liveConfig = await readFile(record.brokerConfig, "utf8");
  const sealed = JSON.parse(liveConfig);
  if (liveConfig !== sealedConfigText) {
    throw new Error("Installer sealed broker config differs from the approved plan.");
  }
  if (sealed.relay?.requestId !== requestId || sealed.plan?.sessionId !== sessionId ||
      sealed.relay?.grant?.handle !== seeded.handle) {
    throw new Error("Installer did not seal the approved grant into its broker config.");
  }
  for (const [unit, filename, content] of [[mcpUnit, record.mcpSocketUnitFile, bundle.mcpSocketUnit],
    [modelUnit, record.modelRelaySocketUnitFile, bundle.modelSocketUnit]]) {
    if (await ownedUnit(unit, filename, content) !== "active") {
      throw new Error("Installer socket is not active: " + unit);
    }
  }
  for (const filename of [plan.brokerSocket, plan.modelRelaySocket]) {
    const item = await lstat(filename);
    if (!item.isSocket() || item.uid !== 0 || item.gid !== agentUid ||
        (item.mode & 0o777) !== 0o660) {
      throw new Error("Installer socket has wrong ownership: " + filename);
    }
    await remember(filename);
  }
  const rootState = properties(controlUnit, ["Id", "FragmentPath", "ActiveState", "User"]);
  const brokerState = properties(brokerUnit, ["Id", "FragmentPath", "ActiveState", "User", "Group", "MainPID"]);
  const brokerPid = Number(brokerState.get("MainPID"));
  if (rootState.get("Id") !== controlUnit || rootState.get("FragmentPath") !== control.unitFile ||
      rootState.get("ActiveState") !== "active" || rootState.get("User") !== "root" ||
      brokerState.get("Id") !== brokerUnit || brokerState.get("FragmentPath") !== record.brokerUnitFile ||
      brokerState.get("ActiveState") !== "active" || brokerState.get("User") !== String(brokerUid) ||
      brokerState.get("Group") !== String(brokerUid) ||
      !Number.isSafeInteger(brokerPid) || brokerPid < 1) {
    throw new Error("Installer root or broker unit readback changed after activation.");
  }
  const agentState = await until(() => {
    const state = properties(agentUnit, ["Id", "Description", "ActiveState", "User", "Group",
      "RootDirectory", "MainPID"]);
    if (state.get("ActiveState") === "failed") throw new Error("Installer agent unit failed.");
    return state.get("ActiveState") === "active" ? state : false;
  }, "installer agent unit");
  if (agentState.get("Id") !== agentUnit ||
      !/^s-gw-agent-start:[a-f0-9]{32}$/.test(agentState.get("Description") || "") ||
      agentState.get("User") !== String(agentUid) ||
      agentState.get("Group") !== String(agentUid) ||
      agentState.get("RootDirectory") !== rootDir ||
      !Number.isSafeInteger(Number(agentState.get("MainPID"))) ||
      Number(agentState.get("MainPID")) < 1) {
    throw new Error("Installer agent unit has different live identity.");
  }
  if (await until(() => textMaybe(path.join(rootDir, "workspace/installer-ready")),
    "installer probe") !== "ready\n" ||
      asBroker("assert-relay-state", [requestId, "executing"]) !== "executing") {
    throw new Error("Installer agent did not launch with its approved request.");
  }
  passed = true;
} catch (error) {
  failure = error;
} finally {
  let cleanupError;
  try {
    await captureStageFiles();
    await captureStageDirs();
    for (const [unit, filename, content] of [
      [mcpUnit, record.mcpSocketUnitFile, bundle?.mcpSocketUnit],
      [modelUnit, record.modelRelaySocketUnitFile, bundle?.modelSocketUnit],
      [brokerUnit, record.brokerUnitFile, bundle?.brokerUnit],
      [controlUnit, control.unitFile, controlText]
    ]) {
      if (!owned.has(filename)) continue;
      const state = await ownedUnit(unit, filename, content);
      if (state === "active" || state === "activating" || state === "failed") {
        run("systemctl", ["--system", "stop", unit]);
      } else if (state !== "inactive") {
        throw new Error("Uncertain fixture unit state: " + unit + " " + state);
      }
    }
    const agentState = stageAttempted
      ? properties(agentUnit, ["LoadState", "ActiveState", "Description", "User", "RootDirectory"])
      : undefined;
    if (agentState?.get("ActiveState") === "active") {
      if (!/^s-gw-agent-start:[a-f0-9]{32}$/.test(agentState.get("Description") || "") ||
          agentState.get("User") !== String(agentUid) ||
          agentState.get("RootDirectory") !== rootDir) {
        throw new Error("Installer agent ownership changed before teardown.");
      }
      run("systemctl", ["--system", "stop", agentUnit]);
    }
    if (stageAttempted) {
      for (const unit of [mcpUnit, modelUnit, brokerUnit, controlUnit, agentUnit]) {
        const state = await until(() => {
          const current = properties(unit, ["ActiveState"]).get("ActiveState");
          return ["inactive", "failed"].includes(current) ? current : false;
        }, unit + " teardown");
        if (state === "failed") run("systemctl", ["--system", "reset-failed", unit]);
      }
    }
    for (const value of accounts.length ? [brokerUid, agentUid] : []) {
      const processCheck = run("pgrep", ["-u", String(value)], true);
      if (processCheck.error || processCheck.status !== 1) {
        throw new Error("Installer fixture process survived teardown: " + value);
      }
    }
    if (activated) {
      await until(() => {
        try { return asBroker("assert-relay-state", [requestId, "executed"]) === "executed"; }
        catch { return false; }
      }, "installer model relay durable close");
      if (asBroker("reject-relay-reclaim", [requestId, sessionId, displayName,
        plan.identityGeneration]) !== "executed") {
        throw new Error("Installer model relay approval remained claimable.");
      }
    }
    for (const filename of stageAttempted ? [plan.brokerSocket, plan.modelRelaySocket] : []) {
      if (!owned.has(filename)) {
        const item = await statMaybe(filename);
        if (item) {
          if (!item.isSocket() || item.uid !== 0 || item.gid !== agentUid ||
              (item.mode & 0o777) !== 0o660) {
            throw new Error("Installer socket changed before teardown: " + filename);
          }
          await remember(filename);
        }
      }
      await removeFile(filename);
    }
    for (const filename of stageAttempted ? claims : []) {
      if (!await statMaybe(filename)) continue;
      const value = await readFile(filename, "utf8");
      if (value !== sessionId + " " + agentUid + " " + agentUid + "\n") {
        throw new Error("Installer identity claim changed before teardown.");
      }
      const item = await lstat(filename);
      if (!item.isFile() || item.uid !== 0 || (item.mode & 0o777) !== 0o600 ||
          item.nlink !== 1) {
        throw new Error("Installer identity claim ownership changed before teardown.");
      }
      await remember(filename);
      await removeFile(filename);
    }
    if (stageAttempted) {
      for (const name of ["session-" + sessionId, "uid-" + agentUid, "gid-" + agentUid]) {
        const filename = path.join(leaseDir, name);
        const item = await statMaybe(filename);
        if (!item) continue;
        const value = JSON.parse(await readFile(filename, "utf8"));
        if (!item.isFile() || item.uid !== brokerUid || item.gid !== brokerUid ||
            (item.mode & 0o777) !== 0o600 || item.nlink !== 1 ||
            value.sessionId !== sessionId || value.uid !== agentUid || value.gid !== agentUid ||
            !Number.isFinite(Date.parse(value.createdAt || "")) ||
            Object.keys(value).sort().join(",") !== "createdAt,gid,sessionId,uid") {
          throw new Error("Installer broker lease changed before teardown.");
        }
        await remember(filename);
        await removeFile(filename);
      }
    }
    for (const filename of [installPlan, record.mcpSocketUnitFile, record.modelRelaySocketUnitFile,
      record.brokerUnitFile, control.unitFile, record.brokerConfig, planFile, ...receipts]) {
      await removeFile(filename);
    }
    if (stageAttempted) {
      run("systemctl", ["--system", "daemon-reload"]);
      for (const unit of [mcpUnit, modelUnit, brokerUnit, controlUnit]) {
        if (properties(unit, ["LoadState"]).get("LoadState") !== "not-found") {
          throw new Error("Installer fixture unit remained installed: " + unit);
        }
      }
    }
    for (const filename of [socketDir, plansDir, identityDir, agentsDir, leaseDir]) {
      if (!owned.has(filename)) continue;
      const item = await statMaybe(filename);
      if (!item) continue;
      await assertOwned(filename);
      if (!item.isDirectory()) throw new Error("Installer fixture directory changed: " + filename);
      if ((await readdir(filename)).length !== 0) {
        throw new Error("Installer fixture directory is not empty: " + filename);
      }
      await rmdir(filename);
    }
    if (stageAttempted) {
      for (const filename of ["/run/s-gw/agent-control.sock",
        "/run/s-gw/agent-prepare.sock", "/run/s-gw/managed-install.lock"]) {
        if (await statMaybe(filename)) {
          throw new Error("Installer fixture left a control socket or install lock: " + filename);
        }
      }
      const lifecycle = await statMaybe(lifecycleDir);
      if (lifecycle) {
        const lock = path.join(lifecycleDir, agentUnit + ".lock");
        const lockInfo = await statMaybe(lock);
        if (lockInfo) {
          if (!lockInfo.isFile() || lockInfo.uid !== 0 ||
              (lockInfo.mode & 0o777) !== 0o600 || lockInfo.nlink !== 1 ||
              lockInfo.size !== 0) {
            throw new Error("Installer fixture lifecycle lock changed.");
          }
          await remember(lock);
          await removeFile(lock);
        }
        if (!lifecycle.isDirectory() || lifecycle.uid !== 0 ||
            (lifecycle.mode & 0o777) !== 0o700 ||
            (await readdir(lifecycleDir)).length !== 0) {
          throw new Error("Installer fixture left a lifecycle lease or launch fence.");
        }
        await rmdir(lifecycleDir);
      }
    }
    await removeFile(envFile);
    for (const filename of [rootDir, storeHome, recoveryHome, installed]) await removeTree(filename);
    for (const name of accounts.reverse()) run("userdel", [name]);
    for (const name of groups.reverse()) {
      const expectedGid = name === brokerName ? brokerUid : agentUid;
      const before = run("getent", ["group", name], true);
      if (before.error || (before.status !== 0 && before.status !== 2)) {
        throw new Error("Could not inspect installer fixture group: " + name);
      }
      if (before.status === 0) {
        const fields = before.stdout.trimEnd().split(":");
        if (fields.length !== 4 || fields[0] !== name || Number(fields[2]) !== expectedGid) {
          throw new Error("Installer fixture group changed before teardown: " + name);
        }
        run("groupdel", [name]);
      }
      const after = run("getent", ["group", name], true);
      if (after.error || after.status !== 2) {
        throw new Error("Installer fixture group survived teardown: " + name);
      }
    }
    for (const filename of madeDirs.reverse()) {
      if (!await statMaybe(filename)) continue;
      if (!owned.has(filename)) continue;
      const item = await assertOwned(filename);
      if (!item.isDirectory() || (await readdir(filename)).length !== 0) {
        throw new Error("Installer fixture directory remained populated: " + filename);
      }
      await rmdir(filename);
    }
  } catch (error) {
    cleanupError = error;
  }
  if (cleanupError) {
    if (failure) throw new AggregateError([failure, cleanupError],
      "Installer fixture and teardown both failed; uncertain paths were preserved.");
    throw cleanupError;
  }
}

if (failure) throw failure;
if (passed) console.log("Native Linux managed installer passed: pending approval refusal, sealed approval activation, agent UID connections to both sockets, root/broker/agent unit readback, terminal relay state, and teardown.");
