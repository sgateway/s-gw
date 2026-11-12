import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { createReadStream, createWriteStream, existsSync } from "node:fs";
import { chmod, chown, copyFile, lstat, mkdir, mkdtemp, open, readFile, readdir, readlink,
  realpath, rename, rm, rmdir, stat, statfs, writeFile } from "node:fs/promises";
import { createServer as createHttpsServer } from "node:https";
import { createConnection, createServer as createTcpServer } from "node:net";
import { networkInterfaces } from "node:os";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";

const version = "0.167.1";
const archiveUrl = `https://github.com/openai/codex/releases/download/rust-v${version}/` +
  "codex-x86_64-unknown-linux-musl.tar.gz";
const archiveSha256 = "64bcc99c32e434b4bcb0508a97df9b7aeecdb97e956d976fb13661096ec4e3e2";
const project = fileURLToPath(new URL("..", import.meta.url));

if (process.platform !== "linux" || process.arch !== "x64" || process.geteuid() !== 0 ||
    process.env.CI !== "true" || process.env.SGW_TEST_NATIVE_CODEX !== "1" ||
    process.argv[2] !== "--root" || process.argv.length !== 5) {
  throw new Error("Use SGW_TEST_NATIVE_CODEX=1 on a disposable x86_64 Linux CI host as root, with --root <broker UID> <broker GID>.");
}
const brokerUid = Number(process.argv[3]);
const brokerGid = Number(process.argv[4]);
if (!Number.isSafeInteger(brokerUid) || brokerUid < 1 ||
    !Number.isSafeInteger(brokerGid) || brokerGid < 1) {
  throw new Error("Invalid native Codex broker identity.");
}
if (!existsSync(path.join(project, "dist/linux-managed-mcp.js")) ||
    !existsSync(path.join(project, "node_modules"))) {
  throw new Error("Build the package and install its dependencies before the native Codex fixture.");
}

function run(command, args, allowFailure = false, env = process.env, timeoutMs = 120_000) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: timeoutMs, env,
    maxBuffer: 2_000_000 });
  if (!allowFailure && (result.error || result.status !== 0)) {
    throw new Error(`${command} failed: ${result.error?.message || result.stderr || result.stdout || result.status}`);
  }
  return result;
}

async function until(check, label, timeoutMs = 45_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Timed out waiting for ${label}.`);
}

async function maybeText(filename) {
  try { return await readFile(filename, "utf8"); }
  catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
}

function properties(unit, names) {
  const result = run("systemctl", ["--system", "--all", "show", unit,
    ...names.flatMap(name => ["-p", name])]);
  const fields = new Map();
  for (const line of result.stdout.trimEnd().split("\n")) {
    const split = line.indexOf("=");
    if (split < 1 || fields.has(line.slice(0, split))) throw new Error(`Invalid ${unit} property output.`);
    fields.set(line.slice(0, split), line.slice(split + 1));
  }
  for (const name of names) if (!fields.has(name)) throw new Error(`${unit} has no ${name} property.`);
  return fields;
}

function unusedUid() {
  for (let uid = 234000; uid < 234998; uid++) {
    if ([uid, uid + 1].every(value =>
      run("getent", ["passwd", String(value)], true).status === 2 &&
      run("getent", ["group", String(value)], true).status === 2)) return uid;
  }
  throw new Error("No unused native Codex UID pair is available.");
}

function hostAddress() {
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries || []) {
      if (entry.family === "IPv4" && !entry.internal) return entry.address;
    }
  }
  throw new Error("Native Codex egress canary needs a non-loopback host IPv4 address.");
}

async function sha256(filename) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(filename)) hash.update(chunk);
  return hash.digest("hex");
}

async function enoughSpace(requirements) {
  const byDevice = new Map();
  for (const [location, bytes] of requirements) {
    const device = (await stat(location)).dev;
    const current = byDevice.get(device);
    if (current) current.bytes += bytes;
    else byDevice.set(device, { location, bytes });
  }
  for (const item of byDevice.values()) {
    const space = await statfs(item.location);
    if (space.bavail * space.bsize < item.bytes) {
      throw new Error(`Native Codex fixture has insufficient disposable space at ${item.location}.`);
    }
  }
}

async function loadCodex(tempDir) {
  const archive = path.join(tempDir, "codex.tar.gz");
  if (process.env.SGW_CODEX_ARCHIVE) {
    await copyFile(process.env.SGW_CODEX_ARCHIVE, archive);
  } else {
    run("curl", ["--fail", "--location", "--silent", "--show-error", "--retry", "3",
      "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "--output",
      archive, archiveUrl], false, process.env, 300_000);
  }
  if (await sha256(archive) !== archiveSha256) {
    throw new Error(`Pinned Codex ${version} archive SHA-256 mismatch.`);
  }
  const entries = run("tar", ["-tzf", archive]).stdout.trimEnd().split("\n");
  const selected = entries.filter(entry => /(?:^|\/)(?:codex|codex-x86_64-unknown-linux-musl)$/.test(entry));
  if (selected.length !== 1 || selected[0].startsWith("/") ||
      selected[0].split("/").includes("..")) {
    throw new Error("Pinned Codex archive has no unique safe CLI member.");
  }
  const output = path.join(tempDir, "codex");
  const child = spawn("tar", ["-xOf", archive, selected[0]], { stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", data => { stderr += data; });
  const exited = new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", resolve);
  });
  await pipeline(child.stdout, createWriteStream(output, { mode: 0o755, flags: "wx" }));
  const code = await exited;
  if (code !== 0) throw new Error(`Pinned Codex extraction failed: ${stderr.slice(0, 500)}`);
  await chmod(output, 0o755);
  const file = await open(output, "r");
  try {
    const header = Buffer.alloc(20);
    if ((await file.read(header, 0, header.length, 0)).bytesRead !== header.length ||
        !header.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ||
        header[4] !== 2 || header[5] !== 1 || header.readUInt16LE(18) !== 62) {
      throw new Error("Pinned Codex archive does not contain an x86_64 ELF executable.");
    }
  } finally { await file.close(); }
  return output;
}

async function stageNode(root, agentUid) {
  const binary = path.join(root, "usr/bin/node");
  await copyFile(process.execPath, binary);
  await chmod(binary, 0o755);
  const deps = run("ldd", [process.execPath], true);
  if (deps.error || (deps.status !== 0 && !/not a dynamic executable/.test(deps.stdout + deps.stderr)) ||
      /not found/.test(deps.stdout + deps.stderr)) {
    throw new Error("Could not inspect the hosted Node runtime dependencies.");
  }
  const paths = new Set([...deps.stdout.matchAll(/(?:^|\s)(\/[\w./+_-]+)(?=\s|$)/gm)]
    .map(match => match[1]));
  for (const dep of paths) {
    const target = path.join(root, dep);
    await mkdir(path.dirname(target), { recursive: true, mode: 0o755 });
    await copyFile(dep, target);
    await chmod(target, 0o755);
    const info = await lstat(target);
    if (!info.isFile() || info.uid !== 0 || (info.mode & 0o022)) {
      throw new Error(`Staged Node dependency is not root controlled: ${target}`);
    }
  }
  run("chroot", [`--userspec=${agentUid}:${agentUid}`, root, "/usr/bin/node", "--version"],
    false, { PATH: "/usr/bin", HOME: "/workspace", LANG: "C.UTF-8" });
}

function responseEvents(response) {
  const item = { id: "msg_synthetic", type: "message", role: "assistant", status: "completed",
    content: [{ type: "output_text", text: "HELLO", annotations: [] }] };
  const complete = { id: "resp_synthetic", object: "response", created_at: Math.floor(Date.now() / 1000),
    status: "completed", model: "gpt-5.3-codex", output: [item],
    usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } };
  let sequence = 1;
  const emit = (type, fields) => response.write(`event: ${type}\ndata: ` +
    `${JSON.stringify({ type, ...fields, sequence_number: ++sequence })}\n\n`);
  emit("response.output_item.added", { output_index: 0, item: { ...item, status: "in_progress", content: [] } });
  emit("response.content_part.added", { item_id: item.id, output_index: 0, content_index: 0,
    part: { ...item.content[0], text: "", logprobs: [] } });
  emit("response.output_text.delta", { item_id: item.id, output_index: 0, content_index: 0,
    delta: "HELLO", logprobs: [] });
  emit("response.output_text.done", { item_id: item.id, output_index: 0, content_index: 0,
    text: "HELLO", logprobs: [] });
  emit("response.content_part.done", { item_id: item.id, output_index: 0, content_index: 0,
    part: item.content[0] });
  emit("response.output_item.done", { output_index: 0, item });
  emit("response.completed", { response: complete });
  response.end();
}

const runId = randomBytes(5).toString("hex");
const uid = unusedUid();
const brokerUser = run("id", ["-nu", String(brokerUid)]).stdout.trim();
const modelAddress = `198.20.${1 + Number.parseInt(runId.slice(0, 2), 16) % 254}.${1 + Number.parseInt(runId.slice(2, 4), 16) % 254}`;
const hostIp = hostAddress();
const installed = `/run/s-gw/ci-codex-control-${runId}`;
const controlDir = path.join(installed, "control");
const brokerPackage = path.join(installed, "broker");
const rootNode = path.join(installed, "node");
const verifier = path.join(installed, "s-gw-linux-broker-runtime");
const controlEntry = path.join(controlDir, "linux-agent-control.js");
const controlUnit = "s-gw-agent-control.service";
const controlUnitFile = `/run/systemd/system/${controlUnit}`;
const modelHosts = path.join(installed, "model-hosts");
const certFile = path.join(installed, "upstream.crt");
const envFile = `/run/s-gw/ci-codex-env-${runId}`;
const storeHome = `/run/s-gw/ci-codex-store-${runId}`;
const recoveryHome = `/run/s-gw/ci-codex-recovery-${runId}`;
const leaseDir = `/run/s-gw/ci-codex-lease-${runId}`;
const planDir = "/run/s-gw/agent-plans";
const identityDir = "/var/lib/s-gw/agent-identities";
const operator = path.join(project, "scripts/linux-native-codex-operator.mjs");
const agents = [0, 1].map(index => {
  const letter = index ? "b" : "a";
  const sessionId = `ci-codex-${runId}-${letter}`;
  const agentUid = uid + index;
  const root = `/var/lib/s-gw/agent-roots/${sessionId}`;
  const socketDir = `/run/s-gw/agents/${sessionId}`;
  const brokerUnit = `s-gw-managed-mcp-${sessionId}.service`;
  const mcpSocketUnit = `s-gw-managed-mcp-${sessionId}.socket`;
  const modelSocketUnit = `s-gw-managed-model-${sessionId}.socket`;
  const agentUnit = `s-gw-agent-${sessionId}.service`;
  const identityGeneration = randomBytes(16).toString("hex");
  const plan = { sessionId, uid: agentUid, gid: agentUid, brokerUid,
    rootDirectory: root, brokerSocket: `${socketDir}/broker.sock`,
    modelRelaySocket: `${socketDir}/model.sock`,
    executable: "/usr/bin/node",
    args: ["/usr/libexec/s-gw/native-codex-agent.mjs", modelAddress, hostIp, "0"],
    launchGate: true, activatedSocket: true, isolatedSharedMemory: true,
    serializedLifecycle: true, sealedStdio: true, restrictedSocketFamilies: true,
    requirePtracePolicy: true, supervisedControlUnit: true,
    logicalAgentId: sessionId, identityGeneration };
  const name = `Native Codex agent ${letter.toUpperCase()}`;
  const record = { plan, brokerUnit,
    brokerUnitFile: `/run/systemd/system/${brokerUnit}`,
    mcpSocketUnitFile: `/run/systemd/system/${mcpSocketUnit}`,
    modelRelaySocketUnitFile: `/run/systemd/system/${modelSocketUnit}`,
    brokerEntry: path.join(brokerPackage, "dist/linux-managed-mcp.js"),
    brokerConfig: `/run/s-gw/ci-codex-config-${runId}-${letter}.json`,
    brokerNode: rootNode, brokerRuntimeRoot: installed,
    brokerPreflight: verifier, brokerEnvironmentFile: envFile, brokerCa: certFile };
  return { letter, sessionId, uid: agentUid, user: `sgwcodex${runId.slice(0, 6)}${letter}`,
    root, socketDir, brokerUnit, mcpSocketUnit, modelSocketUnit, agentUnit, name,
    plan, record, claimPaths: [`${planDir}/uid-${agentUid}.used`,
      `${planDir}/gid-${agentUid}.used`, `${planDir}/session-${sessionId}.used`],
    planPath: `${planDir}/${sessionId}.json`,
    identityPaths: [`${identityDir}/uid-${agentUid}.json`,
      `${identityDir}/generation-${identityGeneration}.json`],
    identityRecord: { logicalAgentId: sessionId, identityGeneration, uid: agentUid, gid: agentUid } };
});

const owned = new Map();
const unitTexts = new Map();
const accounts = [];
const groups = [];
let controlInvocation;
let aliasAdded = false;
let unitsInstalled = false;
let modelServer;
let canary;
let tempDir;
let failed;

async function remember(filename) {
  const info = await lstat(filename);
  owned.set(filename, { dev: info.dev, ino: info.ino });
}

async function removeOwned(filename, recursive = false) {
  const proof = owned.get(filename);
  if (!proof) return;
  let info;
  try { info = await lstat(filename); }
  catch (error) { if (error.code === "ENOENT") return; throw error; }
  if (info.dev !== proof.dev || info.ino !== proof.ino) {
    throw new Error(`Fixture path changed before cleanup: ${filename}`);
  }
  await rm(filename, { recursive });
}

async function adoptGenerated(filename, kind, expectedText) {
  if (owned.has(filename)) return;
  let info;
  try { info = await lstat(filename); }
  catch (error) { if (error.code === "ENOENT") return; throw error; }
  if (info.uid !== 0 || (info.mode & 0o022) !== 0 ||
      (kind === "directory" && !info.isDirectory()) ||
      (kind === "file" && (!info.isFile() || info.nlink !== 1 ||
        (info.mode & 0o777) !== 0o600)) ||
      (kind === "socket" && !info.isSocket()) ||
      await realpath(filename) !== filename ||
      (expectedText !== undefined && await readFile(filename, "utf8") !== expectedText)) {
    throw new Error(`Unrecognized native Codex fixture node preserved: ${filename}`);
  }
  await remember(filename);
}

async function adoptAgentNodes(agent) {
  if (!owned.has(controlUnitFile)) return;
  const gate = `/run/s-gw/launch-gates/${agent.sessionId}`;
  await adoptGenerated(gate, "directory");
  if (owned.has(gate)) {
    const allowed = new Set(["release", "ready.tmp", "forwarder.tmp",
      "forwarder-attestation.json"]);
    for (const name of await readdir(gate)) {
      const child = await lstat(path.join(gate, name));
      if (!allowed.has(name) || !child.isFile() || child.uid !== 0 ||
          child.nlink !== 1 || (child.mode & 0o022) !== 0 ||
          child.size > (name.startsWith("forwarder") ? 1024 : 96)) {
        throw new Error(`Unrecognized native Codex launch-gate node preserved: ${name}`);
      }
    }
  }
  const lifecycle = `/run/s-gw/agent-unit-lifecycle/${agent.agentUnit}`;
  await adoptGenerated(lifecycle, "directory");
  if (owned.has(lifecycle)) {
    const names = await readdir(lifecycle);
    if (names.length !== 1 || names[0] !== "owner" ||
        !/^[a-f0-9]{32}:[a-f0-9]{32}:\d+\n$/.test(
          await readFile(path.join(lifecycle, "owner"), "utf8"))) {
      throw new Error(`Unrecognized native Codex lifecycle node preserved: ${lifecycle}`);
    }
    const owner = await lstat(path.join(lifecycle, "owner"));
    if (!owner.isFile() || owner.uid !== 0 || owner.nlink !== 1 ||
        (owner.mode & 0o777) !== 0o600) {
      throw new Error(`Unrecognized native Codex lifecycle owner preserved: ${lifecycle}`);
    }
  }
  const socketDir = agent.socketDir;
  await adoptGenerated(socketDir, "directory");
  if (owned.has(socketDir)) {
    for (const name of await readdir(socketDir)) {
      const socket = await lstat(path.join(socketDir, name));
      if (!["broker.sock", "model.sock"].includes(name) || !socket.isSocket() ||
          socket.uid !== 0) {
        throw new Error(`Unrecognized native Codex socket node preserved: ${name}`);
      }
    }
  }
  const fenceRoot = "/run/s-gw/agent-unit-lifecycle";
  if (existsSync(fenceRoot)) {
    for (const name of await readdir(fenceRoot)) {
      const prefix = `${agent.agentUnit}.launch-`;
      if (!name.startsWith(prefix)) continue;
      const attempt = name.slice(prefix.length);
      if (!/^[a-f0-9]{32}$/.test(attempt)) {
        throw new Error(`Unrecognized native Codex launch fence preserved: ${name}`);
      }
      await adoptGenerated(path.join(fenceRoot, name), "file",
        `${agent.agentUnit} ${attempt}\n`);
    }
  }
  for (const marker of agent.claimPaths) {
    await adoptGenerated(marker, "file", `${agent.sessionId} ${agent.uid} ${agent.uid}\n`);
  }
}

async function trustedFile(filename) {
  const info = await lstat(filename);
  if (!info.isFile() || info.uid !== 0 || info.nlink !== 1 || (info.mode & 0o022)) {
    throw new Error(`Native Codex fixture file is not root controlled: ${filename}`);
  }
  let parent = path.dirname(filename);
  while (true) {
    const dir = await lstat(parent);
    if (!dir.isDirectory() || dir.uid !== 0 || (dir.mode & 0o022)) {
      throw new Error(`Native Codex fixture parent is not root controlled: ${parent}`);
    }
    const next = path.dirname(parent);
    if (next === parent) break;
    parent = next;
  }
}

async function procIdentity(pid, agent, netns, executable) {
  const [status, cgroup, network, liveExe, stagedExe] = await Promise.all([
    readFile(`/proc/${pid}/status`, "utf8"), readFile(`/proc/${pid}/cgroup`, "utf8"),
    readlink(`/proc/${pid}/ns/net`), stat(`/proc/${pid}/exe`),
    stat(path.join(agent.root, executable))
  ]);
  const uids = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
  const gids = /^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
  if (!uids || uids.slice(1).some(value => Number(value) !== agent.uid) ||
      !gids || gids.slice(1).some(value => Number(value) !== agent.uid) ||
      cgroup.split("\n").find(line => line.startsWith("0::"))?.slice(3) !==
        `/system.slice/${agent.agentUnit}` || network !== netns ||
      network === await readlink("/proc/self/ns/net") ||
      liveExe.dev !== stagedExe.dev || liveExe.ino !== stagedExe.ino) {
    throw new Error(`Codex process ${pid} escaped ${agent.sessionId}'s verified identity boundary.`);
  }
}

try {
  await enoughSpace([["/tmp", 768 * 1024 ** 2]]);
  const load = run("systemctl", ["--system", "show", controlUnit, "-p", "LoadState"]);
  if (load.stdout.trim() !== "LoadState=not-found" ||
      existsSync("/run/s-gw/agent-control.sock")) {
    throw new Error("The native Codex fixture needs an unused root control service.");
  }
  await mkdir("/run/s-gw", { recursive: true, mode: 0o755 });
  tempDir = await mkdtemp("/tmp/sgw-native-codex-");
  await remember(tempDir);
  const codexBinary = await loadCodex(tempDir);
  const stagedBytes = Number(run("du", ["-sk", path.join(project, "dist"),
    path.join(project, "node_modules"), path.join(project, "tools/desktop-packager")])
    .stdout.trim().split("\n").reduce((sum, line) => sum + Number(line.split(/\s+/)[0]), 0)) * 1024;
  const codexSize = (await stat(codexBinary)).size;
  const nodeSize = (await stat(process.execPath)).size;
  await enoughSpace([["/run", stagedBytes + nodeSize + 192 * 1024 ** 2],
    ["/var/lib", 2 * (codexSize + nodeSize + 128 * 1024 ** 2)]]);
  canary = createTcpServer(socket => { canary.hits++; socket.destroy(); });
  canary.hits = 0;
  await new Promise((resolve, reject) => {
    canary.once("error", reject);
    canary.listen(0, hostIp, () => { canary.off("error", reject); resolve(); });
  });
  const canaryPort = canary.address().port;
  await new Promise((resolve, reject) => {
    const socket = createConnection(canaryPort, hostIp);
    socket.once("error", reject);
    socket.once("connect", () => { socket.destroy(); resolve(); });
  });
  await until(() => canary.hits === 1, "host direct-egress positive control", 3000);
  for (const agent of agents) agent.plan.args[3] = String(canaryPort);

  for (const dir of ["/var/lib/s-gw", "/var/lib/s-gw/agent-roots", "/run/s-gw/agents",
    "/run/s-gw/launch-gates"]) await mkdir(dir, { recursive: true, mode: 0o755 });
  for (const dir of [planDir, identityDir]) {
    if (!existsSync(dir)) { await mkdir(dir, { mode: 0o700 }); await remember(dir); }
    const info = await lstat(dir);
    if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o777) !== 0o700) {
      throw new Error(`Unsafe native Codex registry directory: ${dir}`);
    }
  }
  const paths = [installed, leaseDir, storeHome, recoveryHome, envFile, controlUnitFile,
    ...agents.flatMap(agent => [agent.root, agent.socketDir, agent.record.brokerConfig,
      agent.record.brokerUnitFile, agent.record.mcpSocketUnitFile,
      agent.record.modelRelaySocketUnitFile, agent.planPath,
      ...agent.identityPaths, ...agent.claimPaths])];
  for (const filename of paths) {
    if (existsSync(filename)) throw new Error(`Native Codex fixture path exists: ${filename}`);
  }
  for (const dir of [installed, leaseDir, storeHome, recoveryHome]) {
    await mkdir(dir, { mode: dir === installed ? 0o755 : 0o700 });
    await remember(dir);
  }
  await chown(leaseDir, brokerUid, brokerGid);
  for (const dir of [storeHome, recoveryHome]) await chown(dir, brokerUid, brokerGid);
  await mkdir(controlDir, { mode: 0o755 });
  await mkdir(brokerPackage, { mode: 0o755 });
  run("cp", ["-R", path.join(project, "dist"), brokerPackage]);
  run("cp", ["-R", path.join(project, "node_modules"), brokerPackage]);
  await mkdir(path.join(brokerPackage, "tools"), { mode: 0o755 });
  run("cp", ["-R", path.join(project, "tools/desktop-packager"),
    path.join(brokerPackage, "tools")]);
  await copyFile(path.join(project, "package.json"), path.join(brokerPackage, "package.json"));
  run("chmod", ["-R", "go-w", brokerPackage]);
  const controlFiles = ["linux-agent-control.js", "linux-agent-unit.js",
    "linux-peer-identity.js", "linux-agent-identity.js", "model-relay-action.js"];
  for (const filename of controlFiles) {
    await copyFile(path.join(project, "dist", filename), path.join(controlDir, filename));
    await trustedFile(path.join(controlDir, filename));
  }
  await writeFile(path.join(controlDir, "package.json"), '{"type":"module"}\n', { mode: 0o644 });
  await copyFile(process.execPath, rootNode);
  await chmod(rootNode, 0o755);
  run("cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/linux-broker-runtime/verify.c"), "-o", verifier]);
  await chmod(verifier, 0o755);
  const brokerHelper = path.join(brokerPackage, "dist/native/linux-x64/s-gw-peer-credentials");
  await mkdir(path.dirname(brokerHelper), { recursive: true, mode: 0o755 });
  run("cc", ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/peer-credentials/peer-credentials.c"), "-o", brokerHelper]);
  const rootHelperDir = path.join(installed, "dist/native/linux-x64");
  await mkdir(rootHelperDir, { recursive: true, mode: 0o755 });
  for (const [source, target] of [
    ["native/linux-peer-identity/verify.c", "s-gw-linux-peer-identity"],
    ["native/peer-credentials/peer-credentials.c", "s-gw-peer-credentials"]]) {
    run("cc", ["-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
      path.join(project, source), "-o", path.join(rootHelperDir, target)]);
  }

  for (const agent of agents) {
    run("groupadd", ["--gid", String(agent.uid), agent.user]);
    groups.push(agent.user);
    run("useradd", ["--system", "--uid", String(agent.uid), "--gid", agent.user,
      "--no-create-home", "--shell", "/usr/sbin/nologin", agent.user]);
    accounts.push(agent.user);
    await mkdir(agent.root, { mode: 0o755 });
    await remember(agent.root);
    for (const dir of ["usr/bin", "usr/libexec/s-gw", "run/s-gw/launch-gate", "dev/shm",
      "workspace", "proc", "etc"]) {
      await mkdir(path.join(agent.root, dir), { recursive: true, mode: 0o755 });
    }
    await chown(path.join(agent.root, "workspace"), agent.uid, agent.uid);
    await chmod(path.join(agent.root, "workspace"), 0o700);
    await mkdir(path.join(agent.root, "workspace/codex"), { mode: 0o700 });
    await chown(path.join(agent.root, "workspace/codex"), agent.uid, agent.uid);
    await copyFile(codexBinary, path.join(agent.root, "usr/bin/codex"));
    await chmod(path.join(agent.root, "usr/bin/codex"), 0o755);
    await stageNode(agent.root, agent.uid);
    await copyFile(path.join(project, "dist/agent-local-model-forwarder.js"),
      path.join(agent.root, "usr/libexec/s-gw/agent-local-model-forwarder.js"));
    await copyFile(path.join(project, "scripts/linux-native-codex-agent.mjs"),
      path.join(agent.root, "usr/libexec/s-gw/native-codex-agent.mjs"));
    await writeFile(path.join(agent.root, "usr/libexec/s-gw/package.json"),
      '{"type":"module"}\n', { mode: 0o644 });
    await writeFile(path.join(agent.root, "etc/passwd"),
      `root:x:0:0:root:/root:/bin/false\n${agent.user}:x:${agent.uid}:${agent.uid}:fixture:/workspace:/bin/false\n`,
      { mode: 0o644 });
    await writeFile(path.join(agent.root, "etc/group"),
      `root:x:0:\n${agent.user}:x:${agent.uid}:\n`, { mode: 0o644 });
    if (run("chroot", [`--userspec=${agent.uid}:${agent.uid}`, agent.root,
      "/usr/bin/codex", "--version"], false, {
      PATH: "/usr/bin", HOME: "/workspace", CODEX_HOME: "/workspace/codex", LANG: "C.UTF-8"
    }).stdout.trim() !== `codex-cli ${version}`) {
      throw new Error("Pinned Codex archive reported an unexpected CLI version.");
    }
    for (const file of ["usr/bin/codex", "usr/bin/node",
      "usr/libexec/s-gw/agent-local-model-forwarder.js",
      "usr/libexec/s-gw/native-codex-agent.mjs"]) {
      await trustedFile(path.join(agent.root, file));
    }
    for (const filename of agent.identityPaths) {
      await writeFile(filename, JSON.stringify(agent.identityRecord) + "\n",
        { mode: 0o600, flag: "wx" });
      await remember(filename);
    }
  }
  const { attestDurableLinuxAgentIdentity } = await import(new URL("../dist/linux-agent-identity.js", import.meta.url));
  for (const agent of agents) await attestDurableLinuxAgentIdentity(agent.plan);
  run("chown", ["-R", "0:0", installed]);
  await trustedFile(rootNode);
  await trustedFile(verifier);
  await trustedFile(brokerHelper);
  const keyFile = path.join(installed, "upstream.key");
  run("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyFile,
    "-out", certFile, "-days", "1", "-subj", "/CN=api.openai.com",
    "-addext", "subjectAltName=DNS:api.openai.com"]);
  await chmod(certFile, 0o644);
  await trustedFile(certFile);
  await writeFile(modelHosts, `127.0.0.1 localhost\n::1 localhost\n${modelAddress} api.openai.com\n`,
    { mode: 0o644 });
  await trustedFile(modelHosts);
  run("ip", ["-4", "address", "add", `${modelAddress}/32`, "dev", "lo",
    "label", `lo:sgw${runId.slice(0, 6)}`]);
  aliasAdded = true;
  const requests = [];
  modelServer = createHttpsServer({ key: await readFile(keyFile), cert: await readFile(certFile) },
    async (request, response) => {
      try {
        let body = "";
        for await (const chunk of request) {
          body += chunk;
          if (body.length > 1_000_000) throw new Error("Oversized Codex fixture body.");
        }
        const entry = { method: request.method, path: request.url,
          host: request.headers.host, serverName: request.socket.servername,
          authorization: String(request.headers.authorization || ""), body, response };
        requests.push(entry);
        response.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
        const created = { id: "resp_synthetic", object: "response",
          created_at: Math.floor(Date.now() / 1000), status: "in_progress",
          model: "gpt-5.3-codex", output: [] };
        response.write(`event: response.created\ndata: ${JSON.stringify({ type: "response.created",
          response: created, sequence_number: 1 })}\n\n`);
      } catch { response.destroy(); }
    });
  await new Promise((resolve, reject) => {
    modelServer.once("error", reject);
    modelServer.listen(443, modelAddress, () => { modelServer.off("error", reject); resolve(); });
  });

  const secret = `synthetic-codex-store-${randomUUID()}`;
  const brokerEnv = { PATH: "/usr/bin:/bin", LANG: "C.UTF-8", CI: "true",
    SGW_HOME: storeHome, SGW_RECOVERY_HOME: recoveryHome,
    SGW_MASTER_PASSPHRASE: secret, SGW_DISABLE_KEYCHAIN: "1",
    SGW_DISABLE_ONEPASSWORD_BACKUP: "1" };
  const asBroker = (mode, args) => run("runuser", ["-u", brokerUser, "--",
    process.execPath, operator, mode, ...args], false, brokerEnv).stdout.trim();
  for (const agent of agents) {
    agent.secret = JSON.parse(asBroker("seed", []));
    agent.grant = { handle: agent.secret.handle, provider: "openai",
      routes: ["POST /v1/responses"], ttlMs: 30 * 60_000,
      payloadProfile: "strict", toolBoundary: "client-only",
      allowedModels: ["gpt-5.3-codex"], maxRequests: 8 };
  }
  await writeFile(envFile, `CI=true\nSGW_HOME=${storeHome}\nSGW_RECOVERY_HOME=${recoveryHome}\n` +
    `SGW_MASTER_PASSPHRASE=${secret}\nSGW_DISABLE_KEYCHAIN=1\n` +
    `SGW_DISABLE_ONEPASSWORD_BACKUP=1\nNODE_EXTRA_CA_CERTS=${certFile}\n`,
    { mode: 0o600, flag: "wx" });
  await remember(envFile);
  await trustedFile(envFile);
  const { renderLinuxAgentControlUnit, renderLinuxManagedUnitBundle } =
    await import(new URL("../dist/linux-agent-provision.js", import.meta.url));
  const controlText = renderLinuxAgentControlUnit({ unitFile: controlUnitFile,
    runtimeRoot: installed, preflight: verifier, node: rootNode, entry: controlEntry,
    brokerUid, brokerGid }).replace("Description=s-gw root agent control",
    `Description=s-gw-ci-codex:${runId}`);
  await writeFile(controlUnitFile, controlText, { mode: 0o644 });
  await remember(controlUnitFile);
  unitTexts.set(controlUnitFile, controlText);
  for (const agent of agents) {
    const config = { name: agent.name, leaseDir, plan: agent.plan,
      relay: { grant: agent.grant } };
    const bundle = renderLinuxManagedUnitBundle(config, agent.record, brokerGid, "prepare");
    await writeFile(agent.record.brokerConfig, bundle.brokerConfig, { mode: 0o640 });
    await chown(agent.record.brokerConfig, 0, brokerGid);
    await remember(agent.record.brokerConfig);
    await writeFile(agent.record.mcpSocketUnitFile, bundle.mcpSocketUnit, { mode: 0o644 });
    await writeFile(agent.record.modelRelaySocketUnitFile, bundle.modelSocketUnit, { mode: 0o644 });
    const brokerText = bundle.brokerUnit.replace("ExecStartPre=",
      `BindReadOnlyPaths=${modelHosts}:/etc/hosts\n` +
      `ExecCondition=/usr/bin/grep -qFx "${modelAddress} api.openai.com" /etc/hosts\nExecStartPre=`);
    await writeFile(agent.record.brokerUnitFile, brokerText, { mode: 0o644 });
    await writeFile(agent.planPath, bundle.planRecord, { mode: 0o600 });
    for (const [filename, content] of [
      [agent.record.mcpSocketUnitFile, bundle.mcpSocketUnit],
      [agent.record.modelRelaySocketUnitFile, bundle.modelSocketUnit],
      [agent.record.brokerUnitFile, brokerText]]) {
      await remember(filename);
      unitTexts.set(filename, content);
      await trustedFile(filename);
    }
    await remember(agent.planPath);
  }
  unitsInstalled = true;
  run("systemctl", ["--system", "daemon-reload"]);
  run("systemctl", ["--system", "start", controlUnit]);
  const startedControl = await until(() => {
    const state = properties(controlUnit, ["Id", "Description", "ActiveState", "InvocationID"]);
    return state.get("ActiveState") === "active" ? state : false;
  }, "native Codex root control service");
  controlInvocation = startedControl.get("InvocationID");
  if (startedControl.get("Id") !== controlUnit ||
      startedControl.get("Description") !== `s-gw-ci-codex:${runId}` ||
      startedControl.get("ActiveState") !== "active" ||
      !/^[a-f0-9]{32}$/.test(controlInvocation)) {
    throw new Error("Native Codex root control service was not attested.");
  }
  for (const socket of ["/run/s-gw/agent-control.sock", "/run/s-gw/agent-prepare.sock"]) {
    await until(async () => {
      try { return (await lstat(socket)).isSocket(); }
      catch (error) { if (error.code === "ENOENT") return false; throw error; }
    }, `native Codex root control socket ${socket}`);
    await remember(socket);
  }
  for (const agent of agents) {
    run("systemctl", ["--system", "start", agent.mcpSocketUnit]);
    run("systemctl", ["--system", "start", agent.modelSocketUnit]);
    await remember(agent.socketDir);
    const prepared = JSON.parse(run(rootNode, [controlEntry, "--prepare", agent.sessionId],
      false, { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" }).stdout);
    const requestId = asBroker("pending", [agent.sessionId, agent.name,
      agent.secret.handle, agent.plan.identityGeneration]);
    if (prepared.sessionId !== agent.sessionId || prepared.requestId !== requestId ||
        run("systemctl", ["--system", "is-active", agent.agentUnit], true).status === 0) {
      throw new Error("Native Codex grant was not prepared before agent launch.");
    }
    asBroker("approve", [requestId]);
    agent.requestId = requestId;
  }
  for (let index = 0; index < agents.length; index++) {
    const agent = agents[index];
    const other = agents[1 - index];
    asBroker("reject-foreign", [agent.requestId, other.sessionId,
      other.name, other.plan.identityGeneration]);
    const sealed = `${agent.record.brokerConfig}.sealed`;
    const bundle = renderLinuxManagedUnitBundle({ name: agent.name, leaseDir,
      plan: agent.plan, relay: { grant: agent.grant, requestId: agent.requestId } },
    agent.record, brokerGid, "runtime");
    await writeFile(sealed, bundle.brokerConfig, { flag: "wx", mode: 0o640 });
    await chown(sealed, 0, brokerGid);
    await rename(sealed, agent.record.brokerConfig);
    await remember(agent.record.brokerConfig);
    run("systemctl", ["--system", "start", agent.mcpSocketUnit]);
    run("systemctl", ["--system", "start", agent.modelSocketUnit]);
    await new Promise((resolve, reject) => {
      const socket = createConnection(agent.plan.brokerSocket);
      socket.once("error", reject);
      socket.once("connect", () => { socket.destroy(); resolve(); });
    });
    await until(() => {
      try { return asBroker("state", [agent.requestId, "executing"]) === "executing"; }
      catch { return false; }
    }, `${agent.sessionId} relay claim`);
    const state = await until(() => {
      const item = properties(agent.agentUnit, ["Id", "ActiveState", "User", "RootDirectory",
        "ControlGroup", "MainPID", "InvocationID"]);
      if (item.get("ActiveState") !== "active") return false;
      if (item.get("Id") !== agent.agentUnit || item.get("User") !== String(agent.uid) ||
          item.get("RootDirectory") !== agent.root ||
          item.get("ControlGroup") !== `/system.slice/${agent.agentUnit}` ||
          !/^[a-f0-9]{32}$/.test(item.get("InvocationID"))) {
        throw new Error(`Native Codex agent ${agent.sessionId} is not root attested.`);
      }
      return item;
    }, `${agent.sessionId} managed unit`);
    agent.mainPid = Number(state.get("MainPID"));
    agent.netns = await readlink(`/proc/${agent.mainPid}/ns/net`);
    const gateDir = `/run/s-gw/launch-gates/${agent.sessionId}`;
    const lifecycleDir = `/run/s-gw/agent-unit-lifecycle/${agent.agentUnit}`;
    await remember(gateDir);
    await remember(lifecycleDir);
    const lifecycleRoot = "/run/s-gw/agent-unit-lifecycle";
    for (const name of await readdir(lifecycleRoot)) {
      if (name.startsWith(`${agent.agentUnit}.launch-`)) {
        await remember(path.join(lifecycleRoot, name));
      }
    }
    for (const marker of agent.claimPaths) {
      if (await readFile(marker, "utf8") !== `${agent.sessionId} ${agent.uid} ${agent.uid}\n`) {
        throw new Error(`Native Codex identity claim changed: ${marker}`);
      }
      await remember(marker);
    }
    await procIdentity(agent.mainPid, agent, agent.netns, "/usr/bin/node");
    const ready = await until(() => maybeText(`${agent.root}/workspace/forwarder-ready`),
      `${agent.sessionId} attested forwarder`);
    if (!/^\d{1,5}\n$/.test(ready)) throw new Error("Native Codex forwarder did not bind loopback.");
  }
  if (agents[0].uid === agents[1].uid || agents[0].netns === agents[1].netns) {
    throw new Error("Native Codex agents share a UID or private network namespace.");
  }

  await until(() => requests.length >= 2, "both native Codex provider requests", 45_000);
  if (requests.length !== 2 || canary.hits !== 1) {
    throw new Error("A Codex agent reached the direct network or sent unexpected upstream requests.");
  }
  for (const agent of agents) {
    const pid = Number(await until(() => maybeText(`${agent.root}/workspace/codex-pid`),
      `${agent.sessionId} real Codex PID`));
    if (!Number.isSafeInteger(pid) || pid < 1) {
      throw new Error(`Real Codex did not run in ${agent.sessionId}'s UID/cgroup/net namespace.`);
    }
    await procIdentity(pid, agent, agent.netns, "/usr/bin/codex");
    const matching = requests.filter(request =>
      request.authorization === `Bearer ${agent.secret.value}`);
    if (matching.length !== 1) throw new Error(`${agent.sessionId} did not use its broker credential exactly once.`);
    const request = matching[0];
    const body = JSON.parse(request.body);
    if (request.method !== "POST" || request.path !== "/v1/responses" ||
        request.host !== "api.openai.com" || request.serverName !== "api.openai.com" ||
        request.body.includes("synthetic-client-placeholder") || body.model !== "gpt-5.3-codex" ||
        body.store !== false || body.background === true ||
        (body.tools !== undefined &&
          (!Array.isArray(body.tools) ||
            body.tools.some(tool => tool.type !== "function" && tool.type !== "custom")))) {
      throw new Error(`${agent.sessionId} bypassed its strict broker-owned Responses grant.`);
    }
    responseEvents(request.response);
  }
  for (const agent of agents) {
    const output = JSON.parse(await until(() => maybeText(`${agent.root}/workspace/codex-result.json`),
      `${agent.sessionId} Codex JSON result`, 50_000));
    const events = output.stdout?.split("\n").filter(Boolean).map(line => JSON.parse(line));
    if (output.code !== 0 || output.directDenied !== true || !events?.some(event =>
      event.type === "item.completed" && event.item?.type === "agent_message" &&
      event.item.text === "HELLO")) {
      throw new Error(`${agent.sessionId} Codex CLI failed: ${String(output.error || output.stderr).slice(0, 1000)}`);
    }
  }
  if (requests.length !== 2 || agents.some(agent => requests.filter(request =>
    request.authorization === `Bearer ${agent.secret.value}`).length !== 1)) {
    throw new Error("Codex sent an additional request after synthetic SSE completion.");
  }
  run("systemctl", ["--system", "stop", controlUnit]);
  for (const agent of agents) {
    await until(() => {
      try { return asBroker("state", [agent.requestId, "executed"]) === "executed"; }
      catch { return false; }
    },
      `${agent.sessionId} durable grant close`);
  }
} catch (error) {
  failed = error;
} finally {
  const cleanupErrors = [];
  async function cleanupStep(action) {
    try { await action(); return true; }
    catch (error) { cleanupErrors.push(error); return false; }
  }
  let canRemovePaths = true;
  for (const agent of agents) {
    for (const unit of [agent.modelSocketUnit, agent.mcpSocketUnit,
      agent.brokerUnit, agent.agentUnit]) {
      const stopped = await cleanupStep(async () => {
        if (run("systemctl", ["--system", "is-active", unit], true).status !== 0) return;
        const file = unit === agent.agentUnit ? null :
          unit === agent.modelSocketUnit ? agent.record.modelRelaySocketUnitFile :
          unit === agent.mcpSocketUnit ? agent.record.mcpSocketUnitFile : agent.record.brokerUnitFile;
        if (file) {
          if (!owned.has(file) || await readFile(file, "utf8") !== unitTexts.get(file) ||
              properties(unit, ["FragmentPath"]).get("FragmentPath") !== file) {
            throw new Error(`Managed unit changed; fixture paths preserved: ${unit}`);
          }
        } else {
          const state = properties(unit, ["Description", "User", "RootDirectory",
            "ControlGroup", "MainPID"]);
          if (!/^s-gw-agent-start:[a-f0-9]{32}$/.test(state.get("Description") || "") ||
              state.get("User") !== String(agent.uid) ||
              state.get("RootDirectory") !== agent.root ||
              state.get("ControlGroup") !== `/system.slice/${unit}` ||
              (agent.mainPid && Number(state.get("MainPID")) !== agent.mainPid)) {
            throw new Error(`Managed agent changed; fixture paths preserved: ${unit}`);
          }
        }
        run("systemctl", ["--system", "stop", unit]);
      });
      if (!stopped) canRemovePaths = false;
    }
  }
  const rootStopped = await cleanupStep(async () => {
    if (run("systemctl", ["--system", "is-active", controlUnit], true).status !== 0) return;
    if (!owned.has(controlUnitFile) ||
        await readFile(controlUnitFile, "utf8") !== unitTexts.get(controlUnitFile)) {
      throw new Error("Root control unit file changed; fixture paths preserved.");
    }
    const control = properties(controlUnit, ["Description", "InvocationID", "FragmentPath"]);
    if (control.get("Description") !== `s-gw-ci-codex:${runId}` ||
        control.get("FragmentPath") !== controlUnitFile ||
        (controlInvocation && control.get("InvocationID") !== controlInvocation)) {
      throw new Error("Root control changed; fixture paths preserved for inspection.");
    }
    run("systemctl", ["--system", "stop", controlUnit]);
  });
  if (!rootStopped) canRemovePaths = false;
  for (const agent of agents) {
    const quiet = await cleanupStep(async () => {
      if (run("pgrep", ["-u", String(agent.uid)], true).status === 0) {
        throw new Error(`Native Codex UID ${agent.uid} has live processes; paths preserved.`);
      }
    });
    if (!quiet) canRemovePaths = false;
  }
  await cleanupStep(async () => {
    modelServer?.closeAllConnections();
    if (modelServer) await new Promise(resolve => modelServer.close(resolve));
  });
  await cleanupStep(async () => {
    if (canary) await new Promise(resolve => canary.close(resolve));
  });
  await cleanupStep(async () => {
    if (aliasAdded) run("ip", ["-4", "address", "del", `${modelAddress}/32`, "dev", "lo"]);
  });
  if (canRemovePaths) await cleanupStep(async () => {
    for (const agent of agents) await adoptAgentNodes(agent);
    if (owned.has(controlUnitFile)) {
      for (const socket of ["/run/s-gw/agent-control.sock", "/run/s-gw/agent-prepare.sock"]) {
        await adoptGenerated(socket, "socket");
        if (!owned.has(socket)) continue;
        const info = await lstat(socket);
        const prepare = socket.endsWith("agent-prepare.sock");
        if (info.gid !== (prepare ? 0 : brokerGid) ||
            (info.mode & 0o777) !== (prepare ? 0o600 : 0o660)) {
          throw new Error(`Unrecognized root-control socket preserved: ${socket}`);
        }
      }
    }
    for (const agent of agents) {
      for (const file of [agent.record.mcpSocketUnitFile,
        agent.record.modelRelaySocketUnitFile, agent.record.brokerUnitFile]) {
        if (owned.has(file) && await readFile(file, "utf8") !== unitTexts.get(file)) {
          throw new Error(`Fixture unit file changed; paths preserved: ${file}`);
        }
        await removeOwned(file);
      }
    }
    if (owned.has(controlUnitFile) &&
        await readFile(controlUnitFile, "utf8") !== unitTexts.get(controlUnitFile)) {
      throw new Error("Root control unit file changed; paths preserved.");
    }
    await removeOwned(controlUnitFile);
    if (unitsInstalled) run("systemctl", ["--system", "daemon-reload"]);
    for (const socket of ["/run/s-gw/agent-control.sock", "/run/s-gw/agent-prepare.sock"]) {
      await removeOwned(socket);
    }
    for (const agent of agents) {
      for (const file of owned.keys()) {
        if (file.startsWith(`/run/s-gw/agent-unit-lifecycle/${agent.agentUnit}.launch-`)) {
          await removeOwned(file);
        }
      }
      await removeOwned(`/run/s-gw/launch-gates/${agent.sessionId}`, true);
      await removeOwned(`/run/s-gw/agent-unit-lifecycle/${agent.agentUnit}`, true);
      await removeOwned(agent.socketDir, true);
      await removeOwned(agent.root, true);
      await removeOwned(agent.record.brokerConfig);
      await removeOwned(agent.planPath);
      for (const file of agent.identityPaths) {
        if (!owned.has(file)) continue;
        if (await readFile(file, "utf8") !== JSON.stringify(agent.identityRecord) + "\n") {
          throw new Error(`Fixture identity changed; paths preserved: ${file}`);
        }
        await removeOwned(file);
      }
      for (const file of agent.claimPaths) {
        if (!owned.has(file)) continue;
        if (await readFile(file, "utf8") !== `${agent.sessionId} ${agent.uid} ${agent.uid}\n`) {
          throw new Error(`Fixture identity claim changed; paths preserved: ${file}`);
        }
        await removeOwned(file);
      }
    }
    await removeOwned(envFile);
    for (const dir of [planDir, identityDir]) {
      if (owned.has(dir)) { await lstat(dir); await rmdir(dir); }
    }
    for (const dir of [leaseDir, storeHome, recoveryHome, installed]) {
      await removeOwned(dir, true);
    }
    for (const name of accounts.reverse()) run("userdel", [name]);
    for (const name of groups.reverse()) run("groupdel", [name]);
  });
  await cleanupStep(() => removeOwned(tempDir, true));
  const cleanupError = cleanupErrors.length ?
    new AggregateError(cleanupErrors, "Native Codex fixture cleanup failed.") : undefined;
  if (cleanupError && failed) throw new AggregateError([failed, cleanupError],
    "Native Codex fixture and cleanup both failed.");
  if (cleanupError) throw cleanupError;
}
if (failed) throw failed;
console.log("Native Codex model relay passed: two verified Linux UIDs/cgroups/net namespaces, production agent-local forwarder, broker-owned synthetic Responses, direct-egress denial, and durable grant close.");
