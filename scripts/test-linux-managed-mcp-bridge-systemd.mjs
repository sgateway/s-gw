import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { chmod, chown, copyFile, lstat, mkdir, mkdtemp, readFile, readlink, rename,
  rm, rmdir, unlink, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux" || process.getuid?.() !== 0 || process.geteuid?.() !== 0 ||
    process.env.CI !== "true" || process.argv[2] !== "--root" || process.argv.length !== 5) {
  throw new Error("Run the bridge fixture as root on a disposable Linux CI host with the runner UID and GID.");
}
const brokerUid = Number(process.argv[3]);
const brokerGid = Number(process.argv[4]);
if (!Number.isSafeInteger(brokerUid) || brokerUid < 1 ||
    !Number.isSafeInteger(brokerGid) || brokerGid < 1) {
  throw new Error("Invalid runner identity for the bridge fixture.");
}

const project = fileURLToPath(new URL("..", import.meta.url));
const runId = randomBytes(5).toString("hex");
const sessionId = `ci-bridge-${runId}`;
const agentUnit = `s-gw-agent-${sessionId}.service`;
const forwarderUnit = `s-gw-forwarder-${sessionId}.service`;
const runRoot = "/run/s-gw";
const proofPath = path.join(runRoot, "forwarder-attestation.json");
const brokerPath = path.join(runRoot, "broker.sock");
const port = 43871;
const owned = new Map();
const started = new Set();
const accounts = [];
const groups = [];
let madeRunRoot = false;
let work;
let broker;
let reboundBroker;
let fixtureError;
let passed = false;

function run(command, args, allowFailure = false) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 30_000,
    env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C.UTF-8" } });
  if (!allowFailure && (result.error || result.status !== 0)) {
    throw new Error(`${command} failed: ${result.error?.message || result.stderr || result.stdout || result.status}`);
  }
  return result;
}

async function until(check, label) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for ${label}.`);
}

async function statMaybe(filename) {
  try { return await lstat(filename); }
  catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
}

async function remember(filename) {
  const item = await lstat(filename);
  owned.set(filename, { dev: item.dev, ino: item.ino });
  return item;
}

async function assertOwned(filename) {
  const item = await statMaybe(filename);
  if (!item) return undefined;
  const expected = owned.get(filename);
  if (!expected || item.dev !== expected.dev || item.ino !== expected.ino) {
    throw new Error(`Fixture path changed before cleanup: ${filename}`);
  }
  return item;
}

function unitProperties(unit, names) {
  const result = run("systemctl", ["--system", "--all", "show", unit,
    ...names.flatMap(name => ["-p", name])]);
  const values = new Map();
  for (const line of result.stdout.trimEnd().split("\n")) {
    const pos = line.indexOf("=");
    if (pos < 1 || values.has(line.slice(0, pos))) throw new Error(`Invalid systemd readback for ${unit}.`);
    values.set(line.slice(0, pos), line.slice(pos + 1));
  }
  for (const name of names) {
    if (!values.has(name)) throw new Error(`Missing ${name} for ${unit}.`);
  }
  return values;
}

function expectedDescription(unit) {
  return `s-gw bridge fixture ${runId} ${unit === agentUnit ? "agent" : "forwarder"}`;
}

function liveUnit(unit, name) {
  const fields = unitProperties(unit, ["LoadState", "Description", "ActiveState", "MainPID",
    "User", "Group", "ControlGroup", "InvocationID", "PrivateNetwork", "PrivatePIDs"]);
  const pid = Number(fields.get("MainPID"));
  if (fields.get("LoadState") !== "loaded" || fields.get("Description") !== expectedDescription(unit) ||
      fields.get("ActiveState") !== "active" || !Number.isSafeInteger(pid) || pid < 1 ||
      fields.get("User") !== name || fields.get("Group") !== name ||
      fields.get("ControlGroup") !== `/system.slice/${unit}` ||
      !/^[0-9a-f]{32}$/.test(fields.get("InvocationID") || "") ||
      fields.get("PrivatePIDs") !== (unit === agentUnit ? "yes" : "no") ||
      (unit === agentUnit && fields.get("PrivateNetwork") !== "yes")) {
    throw new Error(`The ${unit} systemd identity or isolation differs from the fixture.`);
  }
  return pid;
}

async function processState(pid, uid, gid) {
  const status = await readFile(`/proc/${pid}/status`, "utf8");
  const uids = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
  const gids = /^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
  if (!uids || !gids || uids.slice(1).some(value => Number(value) !== uid) ||
      gids.slice(1).some(value => Number(value) !== gid)) {
    throw new Error(`Process ${pid} has different real, effective, saved, or filesystem credentials.`);
  }
  return {
    net: await readlink(`/proc/${pid}/ns/net`), pid: await readlink(`/proc/${pid}/ns/pid`),
    ipc: await readlink(`/proc/${pid}/ns/ipc`), mount: await readlink(`/proc/${pid}/ns/mnt`)
  };
}

function freeUids() {
  for (let uid = 236000; uid < 236998; uid += 2) {
    if (uid === brokerUid || uid + 1 === brokerUid || uid === brokerGid || uid + 1 === brokerGid) continue;
    if ([uid, uid + 1].every(value =>
      run("getent", ["passwd", String(value)], true).status === 2 &&
      run("getent", ["group", String(value)], true).status === 2 &&
      run("pgrep", ["-u", String(value)], true).status === 1 &&
      run("pgrep", ["-U", String(value)], true).status === 1)) return [uid, uid + 1];
  }
  throw new Error("No unused numeric UID/GID pair is available for the bridge fixture.");
}

function createIdentity(uid, name) {
  if (run("getent", ["passwd", name], true).status !== 2 ||
      run("getent", ["group", name], true).status !== 2) {
    throw new Error(`Fixture account name is already in use: ${name}`);
  }
  run("groupadd", ["-g", String(uid), name]);
  groups.push({ uid, name });
  run("useradd", ["-u", String(uid), "-g", String(uid), "-M", "-s", "/usr/sbin/nologin", name]);
  accounts.push({ uid, name });
}

async function hostPortClosed() {
  return new Promise(resolve => {
    const socket = createConnection({ host: "127.0.0.1", port });
    socket.setTimeout(2000, () => { socket.destroy(); resolve(false); });
    socket.once("connect", () => { socket.destroy(); resolve(false); });
    socket.once("error", error => resolve(error.code === "ECONNREFUSED"));
  });
}

async function makeBroker(entry, uid, gid, forwarderGid) {
  const child = spawn(process.execPath, [entry, brokerPath, String(forwarderGid),
    String(uid), String(gid)], { stdio: ["ignore", "ignore", "pipe", "ipc"],
    env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" } });
  let ready = false, exited = false, stderr = "";
  let nextId = 0;
  const pending = new Map();
  child.stderr.on("data", bytes => { stderr = (stderr + bytes.toString()).slice(-4096); });
  child.on("message", message => {
    if (message?.kind === "ready") ready = true;
    if (message?.kind !== "snapshot") return;
    const resolve = pending.get(message.id);
    if (resolve) { pending.delete(message.id); resolve(message); }
  });
  child.once("exit", () => { exited = true; });
  child.once("error", error => { stderr += error.message; exited = true; });
  let brokerState, cgroup;
  try {
    await until(() => {
      if (exited) throw new Error(`Synthetic broker exited before ready: ${stderr}`);
      return ready;
    }, "synthetic broker identity drop");
    await remember(brokerPath);
    brokerState = await processState(child.pid, uid, gid);
    cgroup = await readFile(`/proc/${child.pid}/cgroup`, "utf8");
    if (!/^0::\//m.test(cgroup) || cgroup.includes(agentUnit) || cgroup.includes(forwarderUnit)) {
      throw new Error("Synthetic broker shares an agent or forwarder cgroup.");
    }
  } catch (error) {
    if (!exited) {
      child.kill("SIGTERM");
      try {
        await until(() => exited, "failed synthetic broker exit");
      } catch (stopError) {
        child.kill("SIGKILL");
        try { await until(() => exited, "failed synthetic broker kill"); }
        catch (killError) {
          throw new AggregateError([error, stopError, killError],
            "Synthetic broker startup and cleanup failed.");
        }
      }
    }
    throw error;
  }
  return {
    pid: child.pid, cgroup, namespace: brokerState.net,
    async counts() {
      if (exited) throw new Error(`Synthetic broker exited before its MCP readback: ${stderr}`);
      const id = ++nextId;
      const reply = new Promise(resolve => pending.set(id, resolve));
      let timer;
      child.send({ kind: "snapshot", id });
      try {
        return await Promise.race([reply, new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error("Synthetic broker readback timed out.")), 3000);
        })]);
      } finally {
        clearTimeout(timer);
        pending.delete(id);
      }
    },
    async close() {
      if (exited) return;
      child.kill("SIGTERM");
      await until(() => exited, "synthetic broker exit");
    }
  };
}

function systemdOptions(unit, name) {
  return ["--unit=" + unit, "--property=Description=" + expectedDescription(unit),
    "--property=Type=exec", "--property=User=" + name, "--property=Group=" + name,
    "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
    "--property=PrivateIPC=yes", "--property=PrivateTmp=yes",
    "--property=ProtectSystem=strict", "--property=ProtectHome=read-only",
    "--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    "--property=SystemCallFilter=~@privileged", "--property=KillMode=control-group",
    "--property=TimeoutStopSec=5s"];
}

function startUnit(unit, args) {
  if (unitProperties(unit, ["LoadState"]).get("LoadState") !== "not-found") {
    throw new Error(`Fixture unit already exists: ${unit}`);
  }
  started.add(unit);
  run("systemd-run", args);
}

async function marker(name) {
  await writeFile(path.join(work, name), "go\n", { mode: 0o644, flag: "wx" });
}

async function outputMarker(name) {
  return until(async () => {
    const value = await statMaybe(path.join(work, "agent-output", name));
    if (value?.isFile()) return true;
    const active = unitProperties(agentUnit, ["ActiveState"]).get("ActiveState");
    if (active !== "active") throw new Error(`Agent exited before ${name}: ${active}`);
    return false;
  }, name);
}

async function cleanup() {
  const errors = [];
  for (const unit of [forwarderUnit, agentUnit]) {
    if (!started.has(unit)) continue;
    try {
      const fields = unitProperties(unit, ["LoadState", "Description"]);
      if (fields.get("LoadState") !== "not-found") {
        if (fields.get("Description") !== expectedDescription(unit)) {
          throw new Error(`Fixture unit changed before cleanup: ${unit}`);
        }
        const stop = run("systemctl", ["--system", "stop", unit], true);
        if (stop.status !== 0 &&
            unitProperties(unit, ["LoadState"]).get("LoadState") !== "not-found") {
          throw new Error(`Could not stop the fixture unit: ${unit}: ${stop.stderr}`);
        }
        const reset = run("systemctl", ["--system", "reset-failed", unit], true);
        if (reset.status !== 0 &&
            unitProperties(unit, ["LoadState"]).get("LoadState") !== "not-found") {
          throw new Error(`Could not reset the fixture unit after stop: ${unit}: ${reset.stderr}`);
        }
      }
    } catch (error) { errors.push(error); }
  }
  for (const server of [reboundBroker, broker]) {
    if (!server) continue;
    try { await server.close(); }
    catch (error) { errors.push(error); }
  }
  for (const { uid, name } of accounts.toReversed()) {
    try {
      if (run("pgrep", ["-u", String(uid)], true).status !== 1 ||
          run("pgrep", ["-U", String(uid)], true).status !== 1) {
        throw new Error(`Fixture UID still has live processes: ${uid}`);
      }
      run("userdel", [name]);
    } catch (error) { errors.push(error); }
  }
  for (const { uid, name } of groups.toReversed()) {
    try {
      const found = run("getent", ["group", name], true);
      if (found.status === 2) continue;
      if (found.status !== 0 || found.stdout.split(":")[2] !== String(uid)) {
        throw new Error(`Fixture group identity changed before cleanup: ${name}`);
      }
      run("groupdel", [name]);
    }
    catch (error) { errors.push(error); }
  }
  for (const filename of [proofPath, brokerPath, work && path.join(work, "old-broker.sock")]) {
    if (!filename) continue;
    try {
      const item = await assertOwned(filename);
      if (item) await unlink(filename);
    } catch (error) { errors.push(error); }
  }
  if (work) {
    try {
      if (await assertOwned(work)) await rm(work, { recursive: true });
    } catch (error) { errors.push(error); }
  }
  if (madeRunRoot) {
    try {
      if (await assertOwned(runRoot)) await rmdir(runRoot);
    } catch (error) { errors.push(error); }
  }
  if (errors.length) throw new AggregateError(errors, "Managed bridge fixture cleanup failed.");
}

try {
  for (const executable of ["cc", "systemd-run", "systemctl", "nsenter", "ss", "getent", "pgrep",
    "groupadd", "groupdel", "useradd", "userdel"]) {
    if (run("sh", ["-c", `command -v ${executable}`], true).status !== 0) {
      throw new Error(`The hosted bridge fixture needs ${executable}.`);
    }
  }
  if (!existsSync(path.join(project, "dist/linux-managed-mcp-forwarder.js"))) {
    throw new Error("Build the Linux managed forwarder before the hosted bridge fixture.");
  }
  const sdkModules = path.join(project, "node_modules");
  if (!existsSync(path.join(sdkModules, "@modelcontextprotocol/sdk/dist/esm/client/index.js"))) {
    throw new Error("Install the MCP SDK before the hosted bridge fixture.");
  }
  if (await statMaybe(proofPath) || await statMaybe(brokerPath)) {
    throw new Error("The hosted bridge fixture found an existing global forwarder proof or broker socket.");
  }
  if (!(await hostPortClosed())) throw new Error("Host loopback already has the managed MCP port.");
  let rootInfo = await statMaybe(runRoot);
  if (!rootInfo) {
    await mkdir(runRoot, { mode: 0o755 });
    await remember(runRoot);
    madeRunRoot = true;
    rootInfo = await lstat(runRoot);
  }
  if (!rootInfo.isDirectory() || rootInfo.uid !== 0 || (rootInfo.mode & 0o777) !== 0o755) {
    throw new Error("The hosted /run/s-gw directory is not root-owned mode 0755.");
  }
  work = await mkdtemp(path.join(runRoot, "ci-forwarder-"));
  await remember(work);
  await chmod(work, 0o755);
  const [agentUid, forwarderUid] = freeUids();
  const agentName = `sgwbr${runId.slice(0, 7)}a`;
  const forwarderName = `sgwbr${runId.slice(0, 7)}f`;
  createIdentity(agentUid, agentName);
  createIdentity(forwarderUid, forwarderName);
  const output = path.join(work, "agent-output");
  await mkdir(output, { mode: 0o700 });
  await chown(output, agentUid, agentUid);
  await mkdir(path.join(work, "node_modules"), { mode: 0o755 });
  const bridge = path.join(work, "bridge");
  run("cc", ["-static", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
    path.join(project, "native/linux-managed-mcp-stdio/bridge.c"), "-o", bridge]);
  await chmod(bridge, 0o755);
  const forwarder = path.join(work, "forwarder.mjs");
  const agentScript = path.join(work, "agent.mjs");
  const brokerScript = path.join(work, "broker.mjs");
  await copyFile(path.join(project, "dist/linux-managed-mcp-forwarder.js"), forwarder);
  await copyFile(path.join(project, "scripts/fixtures/linux-managed-bridge-agent.mjs"), agentScript);
  await copyFile(path.join(project, "scripts/fixtures/linux-managed-bridge-broker.mjs"), brokerScript);
  await chmod(forwarder, 0o644);
  await chmod(agentScript, 0o644);
  await chmod(brokerScript, 0o644);
  const gate = path.join(work, "forwarder-gate.sh");
  await writeFile(gate, "#!/bin/sh\nset -eu\nwhile [ ! -f \"$1\" ]; do sleep 0.05; done\nexec \"$2\" \"$3\"\n",
    { mode: 0o755, flag: "wx" });
  broker = await makeBroker(brokerScript, brokerUid, brokerGid, forwarderUid);
  const originalSocket = await lstat(brokerPath);
  assert.equal(originalSocket.uid, 0);
  assert.equal(originalSocket.gid, forwarderUid);
  assert.equal(originalSocket.mode & 0o777, 0o660);

  startUnit(agentUnit, [...systemdOptions(agentUnit, agentName),
    "--property=PrivateNetwork=yes", "--property=PrivatePIDs=yes",
    "--property=ReadWritePaths=" + output,
    "--property=BindReadOnlyPaths=" + sdkModules + ":" + path.join(work, "node_modules"),
    process.execPath, agentScript, project, work, bridge, String(agentUid)]);
  await outputMarker("ready");
  const agentPid = liveUnit(agentUnit, agentName);
  const agentNs = await processState(agentPid, agentUid, agentUid);
  const hostNet = await readlink("/proc/self/ns/net");
  const hostPid = await readlink("/proc/self/ns/pid");
  if (agentNs.net === hostNet) throw new Error("The agent retained the host network namespace.");
  if (agentNs.pid === hostPid) throw new Error("The agent retained the host PID namespace.");
  if (broker.namespace !== hostNet) throw new Error("The synthetic broker left the host network namespace.");

  const release = path.join(work, "release-forwarder");
  startUnit(forwarderUnit, [...systemdOptions(forwarderUnit, forwarderName),
    "--property=PrivateNetwork=yes", "--property=NetworkNamespacePath=/proc/" + agentPid + "/ns/net",
    "--property=BindsTo=" + agentUnit, "--property=After=" + agentUnit,
    "/bin/sh", gate, release, process.execPath, forwarder]);
  const forwarderPid = await until(() => {
    const state = unitProperties(forwarderUnit, ["ActiveState", "MainPID"]);
    return state.get("ActiveState") === "active" && Number(state.get("MainPID")) > 0 ?
      Number(state.get("MainPID")) : undefined;
  }, "forwarder gate");
  assert.equal(liveUnit(forwarderUnit, forwarderName), forwarderPid);
  const forwarderNs = await processState(forwarderPid, forwarderUid, forwarderUid);
  if (forwarderNs.net !== agentNs.net || forwarderNs.net === hostNet ||
      forwarderNs.pid !== hostPid || forwarderNs.ipc === agentNs.ipc ||
      forwarderNs.mount === agentNs.mount) {
    throw new Error("Forwarder and agent lack a shared private network and separate process namespaces.");
  }
  const socket = await lstat(brokerPath);
  if (!socket.isSocket() || socket.uid !== 0 || socket.gid !== forwarderUid ||
      (socket.mode & 0o777) !== 0o660) {
    throw new Error("Broker Unix socket owner or group changed before forwarder proof.");
  }
  await writeFile(proofPath, JSON.stringify({ version: 1, sessionId, uid: forwarderUid,
    gid: forwarderUid, agentUid, brokerUid,
    cgroup: `/system.slice/${forwarderUnit}`, networkNamespace: forwarderNs.net,
    hostNetworkNamespace: hostNet, pidNamespace: forwarderNs.pid,
    agentPidNamespace: agentNs.pid, ipcNamespace: forwarderNs.ipc,
    agentIpcNamespace: agentNs.ipc, mountNamespace: forwarderNs.mount,
    agentMountNamespace: agentNs.mount, brokerSocketDevice: String(socket.dev),
    brokerSocketInode: String(socket.ino) }) + "\n", { mode: 0o444, flag: "wx" });
  await remember(proofPath);
  await marker("release-forwarder");
  await until(() => {
    const state = unitProperties(forwarderUnit, ["ActiveState"]).get("ActiveState");
    if (state !== "active") throw new Error(`Forwarder exited before listening: ${state}`);
    const result = run("nsenter", [`--net=/proc/${agentPid}/ns/net`, "--", "ss", "-ltn"], true);
    if (result.error || result.status !== 0) throw new Error("Could not inspect the private TCP listener.");
    return /\b127\.0\.0\.1:43871\b/.test(result.stdout);
  }, "fixed MCP port in the private namespace");
  assert.equal(liveUnit(forwarderUnit, forwarderName), forwarderPid);
  assert.deepEqual(await processState(forwarderPid, forwarderUid, forwarderUid), forwarderNs);
  const commandLine = (await readFile(`/proc/${forwarderPid}/cmdline`)).toString("utf8");
  if (!commandLine.split("\0").includes(forwarder)) {
    throw new Error("The forwarder gate did not exec the staged product entrypoint.");
  }
  if (!(await hostPortClosed())) throw new Error("The managed MCP port escaped into host loopback.");
  await marker("go");
  await outputMarker("handshake");
  if (!(await statMaybe(path.join(output, "bridge-scope")))) {
    throw new Error("The SDK bridge process did not pass its live seccomp and namespace scope check.");
  }
  await processState(broker.pid, brokerUid, brokerGid);
  if (await readFile(`/proc/${broker.pid}/cgroup`, "utf8") !== broker.cgroup) {
    throw new Error("Synthetic broker cgroup changed during the MCP handshake.");
  }
  const firstCounts = await broker.counts();
  if (firstCounts.invalid || firstCounts.initializes !== 1 || firstCounts.lists !== 1) {
    throw new Error(`The Unix broker did not receive one SDK handshake and tools/list: ${JSON.stringify(firstCounts)}`);
  }

  const oldSocket = path.join(work, "old-broker.sock");
  await rename(brokerPath, oldSocket);
  owned.delete(brokerPath);
  await remember(oldSocket);
  reboundBroker = await makeBroker(brokerScript, brokerUid, brokerGid, forwarderUid);
  const newSocket = await lstat(brokerPath);
  if (newSocket.ino === originalSocket.ino && newSocket.dev === originalSocket.dev) {
    throw new Error("The broker socket rebind did not change its inode.");
  }
  await marker("rebound");
  await outputMarker("rebind-denied");
  assert.equal(liveUnit(forwarderUnit, forwarderName), forwarderPid);
  const reboundCounts = await reboundBroker.counts();
  const originalCounts = await broker.counts();
  if (reboundCounts.initializes || reboundCounts.lists || reboundCounts.invalid ||
      originalCounts.initializes !== 1 || originalCounts.lists !== 1 || originalCounts.invalid) {
    throw new Error("A stale forwarder proof reached the rebound Unix broker.");
  }
  run("systemctl", ["--system", "stop", forwarderUnit]);
  await until(() => unitProperties(forwarderUnit, ["ActiveState", "MainPID"])
    .get("ActiveState") === "inactive", "forwarder teardown");
  const afterStop = run("nsenter", [`--net=/proc/${agentPid}/ns/net`, "--", "ss", "-ltn"], true);
  if (afterStop.status !== 0 || /\b127\.0\.0\.1:43871\b/.test(afterStop.stdout)) {
    throw new Error("The fixed MCP listener remained after forwarder stop.");
  }
  await marker("forwarder-stopped");
  await outputMarker("teardown-denied");
  passed = true;
} catch (error) {
  fixtureError = error;
  for (const unit of [forwarderUnit, agentUnit]) {
    if (!started.has(unit)) continue;
    const logs = run("journalctl", ["--no-pager", "-n", "20", "-u", unit], true).stdout;
    if (logs) process.stderr.write(`${unit}:\n${logs}\n`);
  }
} finally {
  try { await cleanup(); }
  catch (error) {
    fixtureError = fixtureError ? new AggregateError([fixtureError, error],
      "Managed bridge fixture and cleanup failed.") : error;
  }
}
if (fixtureError) throw fixtureError;
if (!passed) throw new Error("Managed bridge fixture ended without its acceptance checks.");
console.log("Native managed MCP bridge passed: two UIDs, shared private network namespace, fixed TCP port, root-owned broker socket, SDK handshake, wrong-UID denial, socket-rebind denial, and forwarder teardown.");
