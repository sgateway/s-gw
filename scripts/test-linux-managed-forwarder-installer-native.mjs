import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, copyFile, lstat, mkdir, readFile, readdir, realpath, rm, rmdir, stat,
  unlink, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux" || process.getuid?.() !== 0 || process.geteuid?.() !== 0 ||
    process.env.CI !== "true" || process.argv.length !== 3 || process.argv[2] !== "--root") {
  throw new Error("Run the managed forwarder installer fixture as root on disposable Linux CI.");
}

const project = fileURLToPath(new URL("..", import.meta.url));
const runId = randomBytes(5).toString("hex");
const sessionId = `ci-forwarder-${runId}`;
const runtimeRoot = `/run/s-gw/ci-forwarder-runtime-${runId}`;
const controlDir = `${runtimeRoot}/control`;
const node = `${runtimeRoot}/node`;
const verifier = `${runtimeRoot}/s-gw-linux-broker-runtime`;
const netnsHelper = `${runtimeRoot}/s-gw-linux-netns`;
const brokerEntry = `${runtimeRoot}/dist/linux-managed-mcp.js`;
const forwarderEntry = `${runtimeRoot}/dist/linux-managed-mcp-forwarder.js`;
const agentRoot = `/var/lib/s-gw/agent-roots/${sessionId}`;
const forwarderRoot = `/var/lib/s-gw/forwarder-roots/${sessionId}`;
const namespacePath = `/run/s-gw/netns/${sessionId}`;
const proofPath = `/run/s-gw/forwarder-proofs/${sessionId}.json`;
const agentIdentityDir = "/var/lib/s-gw/agent-identities";
const forwarderIdentityDir = "/var/lib/s-gw/forwarder-identities";
const planFile = `/run/s-gw/agent-plans/${sessionId}.json`;
const inputFile = `/run/s-gw/ci-forwarder-input-${runId}.json`;
const envFile = `/run/s-gw/ci-forwarder-env-${runId}`;
const controlUnit = "s-gw-agent-control.service";
const agentUnit = `s-gw-agent-${sessionId}.service`;
const brokerUnit = `s-gw-managed-mcp-${sessionId}.service`;
const forwarderUnit = `s-gw-forwarder-${sessionId}.service`;
const mcpUnit = `s-gw-managed-mcp-${sessionId}.socket`;
const modelUnit = `s-gw-managed-model-${sessionId}.socket`;
const probeUnit = `s-gw-forwarder-root-probe-${runId}.service`;
const madeDirs = new Map();
const madeFiles = new Map();
const autoDirs = [
  `/run/s-gw/agents/${sessionId}`, "/run/s-gw/agents", "/run/s-gw/agent-plans",
  "/run/s-gw/managed-leases", "/run/s-gw/netns", "/run/s-gw/forwarder-proofs",
  agentIdentityDir, forwarderIdentityDir
];
const absentAutoDirs = new Set();
const accounts = [];
const groups = [];

function run(command, args, allowFailure = false) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 30_000,
    env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C.UTF-8", CI: "true" } });
  if (!allowFailure && (result.error || result.status !== 0)) {
    throw new Error(`${path.basename(command)} failed: ` +
      (result.error?.message || result.stderr || result.stdout || result.status));
  }
  return result;
}

async function maybe(filename) {
  try { return await lstat(filename); }
  catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
}

async function remember(filename, directory = false) {
  const item = await lstat(filename);
  (directory ? madeDirs : madeFiles).set(filename, { dev: item.dev, ino: item.ino });
}

async function checkedOwned(filename, directory = false) {
  const expected = (directory ? madeDirs : madeFiles).get(filename);
  if (!expected) throw new Error("Forwarder fixture does not own " + filename);
  const item = await lstat(filename);
  if (item.dev !== expected.dev || item.ino !== expected.ino || item.uid !== 0 ||
      (item.mode & 0o022) !== 0 ||
      (directory ? !item.isDirectory() : !item.isFile())) {
    throw new Error("Forwarder fixture path changed: " + filename);
  }
  return item;
}

async function ensureDir(filename, mode) {
  const old = await maybe(filename);
  if (old) {
    if (!old.isDirectory() || old.uid !== 0 || (old.mode & 0o777) !== mode ||
        await realpath(filename) !== filename) {
      throw new Error(`Untrusted forwarder fixture directory: ${filename} ` +
        `(uid=${old.uid}, mode=${(old.mode & 0o777).toString(8)})`);
    }
    return;
  }
  await mkdir(filename, { mode });
  await remember(filename, true);
}

async function ownedFile(filename, content, mode = 0o600) {
  if (await maybe(filename)) throw new Error("Forwarder fixture path already exists: " + filename);
  await writeFile(filename, content, { mode, flag: "wx" });
  await remember(filename);
}

function properties(unit, fields) {
  const text = run("/usr/bin/systemctl", ["--system", "--no-pager", "--all", "show", unit,
    ...fields.flatMap(field => ["-p", field])]).stdout;
  const values = new Map();
  for (const line of text.trimEnd().split("\n")) {
    const pos = line.indexOf("=");
    if (pos < 1 || values.has(line.slice(0, pos))) throw new Error("Invalid systemd readback.");
    values.set(line.slice(0, pos), line.slice(pos + 1));
  }
  return values;
}

function assertForwarderPortClosed() {
  const probe = `import { connect } from "node:net"; ` +
    `const socket = connect(43871, "127.0.0.1"); ` +
    `socket.once("connect", () => process.exit(2)); ` +
    `socket.once("error", error => { if (error.code !== "ECONNREFUSED") process.exit(3); ` +
    `console.log("FORWARDER_PORT_CLOSED"); }); ` +
    `socket.setTimeout(2000, () => process.exit(4));`;
  const result = run("/usr/bin/nsenter", [`--net=${namespacePath}`, "--", process.execPath,
    "--input-type=module", "--eval", probe]);
  if (result.stdout.trim() !== "FORWARDER_PORT_CLOSED") {
    throw new Error("Forwarder port 43871 did not refuse a local connection.");
  }
}

function freeTriple() {
  for (let uid = 236000; uid < 236990; uid += 3) {
    const values = [uid, uid + 1, uid + 2];
    if (values.every(value => run("/usr/bin/getent", ["passwd", String(value)], true).status === 2 &&
      run("/usr/bin/getent", ["group", String(value)], true).status === 2)) return values;
  }
  throw new Error("No isolated UID triple is free for the forwarder fixture.");
}

const [brokerUid, agentUid, forwarderUid] = freeTriple();
const brokerName = `sgwf${runId.slice(0, 7)}b`;
const agentName = `sgwf${runId.slice(0, 7)}a`;
const forwarderName = `sgwf${runId.slice(0, 7)}f`;
const generation = randomBytes(16).toString("hex");
const plan = { sessionId, uid: agentUid, gid: agentUid, brokerUid,
  rootDirectory: agentRoot, brokerSocket: `/run/s-gw/agents/${sessionId}/broker.sock`,
  executable: "/usr/bin/agent", args: [], launchGate: true, activatedSocket: true,
  isolatedSharedMemory: true, serializedLifecycle: true, sealedStdio: true,
  supervisedControlUnit: true, restrictedSocketFamilies: true, requirePtracePolicy: true,
  logicalAgentId: sessionId, identityGeneration: generation,
  managedForwarderNetworkNamespace: namespacePath };
const control = { unitFile: `/run/systemd/system/${controlUnit}`, runtimeRoot,
  preflight: verifier, node, entry: `${controlDir}/linux-agent-control.js`,
  brokerUid, brokerGid: brokerUid };
const forwarder = { uid: forwarderUid, gid: forwarderUid,
  unitFile: `/run/systemd/system/${forwarderUnit}`,
  rootDirectory: forwarderRoot, networkNamespacePath: namespacePath };
const record = { plan, brokerUnit, brokerUnitFile: `/run/systemd/system/${brokerUnit}`,
  mcpSocketUnitFile: `/run/systemd/system/${mcpUnit}`,
  brokerEntry, brokerConfig: `/run/s-gw/${sessionId}.json`, brokerNode: node,
  brokerRuntimeRoot: runtimeRoot, brokerPreflight: verifier,
  brokerEnvironmentFile: envFile, brokerCa: null, mcpForwarder: forwarder };
const config = { name: `Native forwarder ${runId}`, leaseDir: "/run/s-gw/managed-leases",
  plan, mcpForwarder: { uid: forwarderUid, gid: forwarderUid } };
const input = { control, record, config, brokerGid: brokerUid };
const { renderLinuxAgentControlUnit, renderLinuxManagedUnitBundle } =
  await import(new URL("../dist/linux-agent-provision.js", import.meta.url));
const { runLinuxManagedInstall } = await import(new URL("../dist/linux-managed-install.js", import.meta.url));
const { discoverLinuxForwarderElfClosure } =
  await import(new URL("../dist/linux-forwarder-elf.js", import.meta.url));
const { linuxForwarderEntry, linuxForwarderNode, linuxForwarderPackage,
  linuxForwarderRuntimeDir } =
  await import(new URL("../dist/linux-forwarder-runtime.js", import.meta.url));
const bundle = renderLinuxManagedUnitBundle(config, record, brokerUid, "prepare");
let staged = false;
let failure;

try {
  const version = /^systemd (\d+)/.exec(run("/usr/bin/systemctl", ["--version"]).stdout)?.[1];
  if (!version || Number(version) < 259) {
    throw new Error("Forwarder fixture needs Ubuntu 26 systemd 259 or newer.");
  }
  for (const unit of [controlUnit, agentUnit, brokerUnit, forwarderUnit, mcpUnit, modelUnit,
    probeUnit]) {
    if (properties(unit, ["LoadState"]).get("LoadState") !== "not-found") {
      throw new Error("Forwarder fixture found an existing unit: " + unit);
    }
  }
  for (const filename of [runtimeRoot, agentRoot, forwarderRoot, namespacePath, proofPath,
    inputFile, envFile, control.unitFile, record.brokerUnitFile, forwarder.unitFile,
    record.mcpSocketUnitFile, record.brokerConfig, planFile,
    `${agentIdentityDir}/uid-${agentUid}.json`,
    `${agentIdentityDir}/generation-${generation}.json`,
    `${forwarderIdentityDir}/uid-${forwarderUid}.json`,
    `${forwarderIdentityDir}/gid-${forwarderUid}.json`,
    `${forwarderIdentityDir}/session-${sessionId}.json`]) {
    if (await maybe(filename)) throw new Error("Forwarder fixture path already exists: " + filename);
  }
  for (const directory of autoDirs) {
    if (!await maybe(directory)) absentAutoDirs.add(directory);
  }
  await ensureDir("/run/s-gw", 0o755);
  await ensureDir("/var/lib/s-gw", 0o700);
  await ensureDir("/var/lib/s-gw/agent-roots", 0o755);
  await ensureDir("/var/lib/s-gw/forwarder-roots", 0o700);
  await ensureDir(runtimeRoot, 0o755);
  await ensureDir(controlDir, 0o755);
  run("/bin/cp", ["-R", path.join(project, "dist"), runtimeRoot]);
  for (const name of ["linux-agent-control.js", "linux-agent-unit.js", "linux-peer-identity.js",
    "linux-agent-identity.js", "linux-forwarder-identity.js",
    "linux-managed-forwarder-attestation.js", "linux-managed-forwarder-binding.js",
    "model-relay-action.js"]) {
    await copyFile(path.join(project, "dist", name), path.join(controlDir, name));
  }
  await writeFile(path.join(controlDir, "package.json"), '{"type":"module"}\n', { mode: 0o644 });
  await copyFile(process.execPath, node);
  await copyFile(path.join(project, "dist/native", `linux-${process.arch}`, "s-gw-linux-netns"),
    netnsHelper);
  run("/usr/bin/cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/linux-broker-runtime/verify.c"), "-o", verifier]);
  run("/bin/chown", ["-R", "0:0", runtimeRoot]);
  run("/bin/chmod", ["-R", "go-w", runtimeRoot]);
  await chmod(node, 0o755);
  await chmod(verifier, 0o755);
  await chmod(netnsHelper, 0o755);

  await ensureDir(agentRoot, 0o755);
  await ensureDir(forwarderRoot, 0o755);
  const rootDir = await lstat(forwarderRoot);
  const rootParent = await lstat(path.dirname(forwarderRoot));
  if (rootDir.uid !== 0 || (rootDir.mode & 0o777) !== 0o755 ||
      rootParent.uid !== 0 || (rootParent.mode & 0o777) !== 0o700) {
    throw new Error("Forwarder fixture root is not traversable after chroot.");
  }
  for (const relative of ["proc", "sys", "dev", "run", "run/s-gw",
    "opt", "opt/s-gw", linuxForwarderRuntimeDir.slice(1)]) {
    await mkdir(path.join(forwarderRoot, relative), { recursive: true, mode: 0o755 });
  }
  await copyFile(node, `${forwarderRoot}${linuxForwarderNode}`);
  await copyFile(forwarderEntry, `${forwarderRoot}${linuxForwarderEntry}`);
  await writeFile(`${forwarderRoot}${linuxForwarderPackage}`, '{"type":"module"}\n',
    { mode: 0o644, flag: "wx" });
  const elf = await discoverLinuxForwarderElfClosure(node);
  for (const file of elf.files) {
    const inside = `${forwarderRoot}${file.targetPath}`;
    if (await maybe(inside)) throw new Error("Forwarder fixture ELF target already exists: " + inside);
    await mkdir(path.dirname(inside), { recursive: true, mode: 0o755 });
    await copyFile(file.sourcePath, inside);
    await chmod(inside, file.mode);
  }
  await ownedFile(envFile, "", 0o600);
  for (const [name, uid] of [[brokerName, brokerUid], [agentName, agentUid],
    [forwarderName, forwarderUid]]) {
    run("/usr/sbin/groupadd", ["--gid", String(uid), name]);
    groups.push(name);
    run("/usr/sbin/useradd", ["--system", "--uid", String(uid), "--gid", name,
      "--no-create-home", "--shell", "/usr/sbin/nologin", name]);
    accounts.push(name);
  }
  await ownedFile(inputFile, JSON.stringify(input) + "\n", 0o600);
  const loader = `${forwarderRoot}${elf.interpreter}`;
  await unlink(loader);
  let missingLoaderDenied = false;
  try { await runLinuxManagedInstall(["stage", inputFile]); }
  catch (error) { missingLoaderDenied = String(error).includes(loader); }
  if (!missingLoaderDenied || await maybe(namespacePath) ||
      properties(controlUnit, ["LoadState"]).get("LoadState") !== "not-found") {
    throw new Error("Forwarder fixture did not reject its missing ELF loader before staging.");
  }
  const loaderFile = elf.files.find(file => file.targetPath === elf.interpreter);
  if (!loaderFile) throw new Error("Forwarder fixture closure lost its ELF interpreter.");
  await copyFile(loaderFile.sourcePath, loader);
  await chmod(loader, loaderFile.mode);
  const library = elf.files.find(file => file.targetPath !== elf.interpreter);
  if (!library) throw new Error("Forwarder fixture has no dynamic library to check.");
  const libraryInside = `${forwarderRoot}${library.targetPath}`;
  await writeFile(libraryInside, "tampered library\n");
  let tamperedLibraryDenied = false;
  try { await runLinuxManagedInstall(["stage", inputFile]); }
  catch (error) { tamperedLibraryDenied = /forwarder ELF closure differs/i.test(String(error)); }
  if (!tamperedLibraryDenied || await maybe(namespacePath) ||
      properties(controlUnit, ["LoadState"]).get("LoadState") !== "not-found") {
    throw new Error("Forwarder fixture did not reject a changed ELF library before staging.");
  }
  await copyFile(library.sourcePath, libraryInside);
  await chmod(libraryInside, library.mode);
  const loaderConfigDir = `${forwarderRoot}/etc`;
  await mkdir(loaderConfigDir, { mode: 0o755 });
  await writeFile(`${loaderConfigDir}/ld.so.preload`, "/run/s-gw/unsafe.so\n", { mode: 0o644 });
  let loaderConfigDenied = false;
  try { await runLinuxManagedInstall(["stage", inputFile]); }
  catch (error) { loaderConfigDenied = /loader configuration/i.test(String(error)); }
  if (!loaderConfigDenied || await maybe(namespacePath) ||
      properties(controlUnit, ["LoadState"]).get("LoadState") !== "not-found") {
    throw new Error("Forwarder fixture did not reject loader configuration before staging.");
  }
  await unlink(`${loaderConfigDir}/ld.so.preload`);
  await rmdir(loaderConfigDir);

  staged = true;
  await runLinuxManagedInstall(["stage", inputFile]);

  const pinned = await stat(namespacePath, { bigint: true });
  const probe = `import { readFileSync, statSync } from "node:fs";\n` +
    `import { createServer } from "node:net";\n` +
    `import { checkManagedMcpForwarderBoundary } from "file://${linuxForwarderEntry}";\n` +
    `if (process.getuid() !== ${forwarderUid} || process.getgid() !== ${forwarderUid} || ` +
    `process.getgroups().length !== 1 || process.getgroups()[0] !== ${forwarderUid} || ` +
    `typeof checkManagedMcpForwarderBoundary !== "function" || ` +
    `readFileSync("${linuxForwarderPackage}", "utf8") !== '{"type":"module"}\\n') ` +
    `throw new Error("wrong forwarder root or identity");\n` +
    `const ns = statSync("/proc/self/ns/net", { bigint: true });\n` +
    `if (ns.dev !== ${pinned.dev}n || ns.ino !== ${pinned.ino}n) ` +
    `throw new Error("wrong forwarder namespace");\n` +
    `const server = createServer(); server.listen(0, "127.0.0.1", () => { ` +
    `server.close(() => console.log("FORWARDER_ROOT_PROBE_OK")); });\n`;
  const probeRun = run("/usr/bin/systemd-run", ["--system", "--wait", "--pipe",
    "--quiet", "--no-ask-password", `--unit=${probeUnit}`, "--property=Type=exec",
    `--property=User=${forwarderUid}`, `--property=Group=${forwarderUid}`,
    `--property=RootDirectory=${forwarderRoot}`, "--property=WorkingDirectory=/",
    `--property=NetworkNamespacePath=${namespacePath}`, "--property=PrivateNetwork=yes",
    "--property=PrivateIPC=yes", "--property=PrivateTmp=yes", "--property=MountFlags=private",
    "--property=BindLogSockets=no", "--property=MountAPIVFS=yes",
    "--property=ProtectHome=yes", "--property=ProtectSystem=strict",
    "--property=PrivateDevices=yes", "--property=NoNewPrivileges=yes",
    "--property=CapabilityBoundingSet=", "--property=AmbientCapabilities=",
    "--property=RestrictNamespaces=yes", "--property=SystemCallArchitectures=native",
    "--", linuxForwarderNode, "--input-type=module", "--eval", probe], true);
  if (probeRun.error || probeRun.status !== 0) {
    const state = run("/usr/bin/systemctl", ["--system", "--no-pager", "show", probeUnit,
      "-p", "LoadState", "-p", "ActiveState", "-p", "Result", "-p", "ExecMainCode",
      "-p", "ExecMainStatus", "-p", "StatusErrno"], true);
    const journal = run("/usr/bin/journalctl", ["--no-pager", "--unit", probeUnit,
      "--lines=12", "--output=cat"], true);
    throw new Error("Forwarder root probe failed: " + [
      `systemd-run status=${probeRun.status} error=${probeRun.error?.message || "none"}`,
      probeRun.stderr, probeRun.stdout, state.stdout, state.stderr, journal.stdout, journal.stderr
    ].filter(Boolean).map(value => String(value).slice(0, 4096)).join("\n"));
  }
  const probeOutput = probeRun.stdout;
  if (!probeOutput.includes("FORWARDER_ROOT_PROBE_OK")) {
    throw new Error("Forwarder Node/ESM root probe did not execute under its dedicated UID.");
  }
  assertForwarderPortClosed();

  const state = properties(forwarderUnit, ["Id", "LoadState", "ActiveState", "FragmentPath",
    "User", "Group", "RootDirectory", "NetworkNamespacePath", "PrivatePIDs", "MountAPIVFS",
    "MountFlags",
    "BindLogSockets", "BindReadOnlyPaths"]);
  if (state.get("Id") !== forwarderUnit || state.get("LoadState") !== "loaded" ||
      state.get("ActiveState") !== "inactive" || state.get("FragmentPath") !== forwarder.unitFile ||
      state.get("User") !== String(forwarderUid) || state.get("Group") !== String(forwarderUid) ||
      state.get("RootDirectory") !== forwarderRoot ||
      state.get("NetworkNamespacePath") !== namespacePath ||
      state.get("PrivatePIDs") !== "no" || state.get("MountAPIVFS") !== "yes" ||
      state.get("MountFlags") !== "private" ||
      state.get("BindLogSockets") !== "no") {
    throw new Error("Installed forwarder unit lost its staged identity or isolation.");
  }
  const binds = state.get("BindReadOnlyPaths") || "";
  if (!binds.includes(`${plan.brokerSocket}:/run/s-gw/broker.sock`) ||
      !binds.includes(`${proofPath}:/run/s-gw/forwarder-attestation.json`)) {
    throw new Error("Installed forwarder unit lost its fixed broker mounts.");
  }
  if (await readFile(proofPath, "utf8") !== "PENDING\n" ||
      await readFile(forwarder.unitFile, "utf8") !== bundle.forwarderUnit ||
      await readFile(record.brokerConfig, "utf8") !== bundle.brokerConfig) {
    throw new Error("Forwarder proof, unit, or broker config changed after staging.");
  }
  run(netnsHelper, ["check", namespacePath]);
  for (const unit of [agentUnit, brokerUnit, forwarderUnit, mcpUnit]) {
    if (properties(unit, ["ActiveState"]).get("ActiveState") !== "inactive") {
      throw new Error("Forwarder staging started a non-control unit: " + unit);
    }
  }
  if (properties(modelUnit, ["LoadState"]).get("LoadState") !== "not-found") {
    throw new Error("MCP-only forwarder staging installed a model socket.");
  }
  let denied = false;
  try { await runLinuxManagedInstall(["activate", inputFile, "req_pending"]); }
  catch (error) { denied = /forwarder staging cannot activate/i.test(String(error)); }
  if (!denied || await readFile(proofPath, "utf8") !== "PENDING\n" ||
      await readFile(record.brokerConfig, "utf8") !== bundle.brokerConfig) {
    throw new Error("Pending forwarder activation did not fail before mutation.");
  }
  assertForwarderPortClosed();
  for (const unit of [agentUnit, brokerUnit, forwarderUnit, mcpUnit]) {
    if (properties(unit, ["ActiveState"]).get("ActiveState") !== "inactive") {
      throw new Error("Pending forwarder activation started a unit: " + unit);
    }
  }
  console.log("Native MCP-only forwarder root executed under its UID; staged unit read back and PENDING refused activation.");
} catch (error) {
  failure = error;
} finally {
  let cleanupError;
  try {
    const probeState = properties(probeUnit, ["LoadState", "ActiveState"]);
    if (probeState.get("LoadState") !== "not-found") {
      if (probeState.get("ActiveState") !== "inactive") {
        run("/usr/bin/systemctl", ["--system", "stop", probeUnit]);
      }
      run("/usr/bin/systemctl", ["--system", "reset-failed", probeUnit]);
    }
    if (staged) {
      const controlState = properties(controlUnit, ["Id", "FragmentPath", "ActiveState"]);
      if (controlState.get("Id") === controlUnit &&
          controlState.get("FragmentPath") === control.unitFile &&
          controlState.get("ActiveState") === "active") {
        run("/usr/bin/systemctl", ["--system", "stop", controlUnit]);
      }
      for (const unit of [controlUnit, agentUnit, brokerUnit, forwarderUnit, mcpUnit, probeUnit]) {
        if (properties(unit, ["ActiveState"]).get("ActiveState") !== "inactive") {
          throw new Error("Forwarder fixture unit survived teardown: " + unit);
        }
      }
    }
    if (await maybe(namespacePath)) {
      run(netnsHelper, ["check", namespacePath]);
      run("/usr/bin/umount", [namespacePath]);
      const item = await lstat(namespacePath);
      if (!item.isFile() || item.uid !== 0) throw new Error("Namespace mountpoint changed.");
      await unlink(namespacePath);
    }
    const expected = new Map([
      [control.unitFile, renderLinuxAgentControlUnit(control)],
      [record.brokerUnitFile, bundle.brokerUnit],
      [forwarder.unitFile, bundle.forwarderUnit], [record.mcpSocketUnitFile, bundle.mcpSocketUnit],
      [record.brokerConfig, bundle.brokerConfig], [planFile, bundle.planRecord],
      [proofPath, "PENDING\n"],
      [`${forwarderRoot}/run/s-gw/broker.sock`, ""],
      [`${forwarderRoot}/run/s-gw/forwarder-attestation.json`, ""],
      [`${agentIdentityDir}/uid-${agentUid}.json`, JSON.stringify({ logicalAgentId: sessionId,
        identityGeneration: generation, uid: agentUid, gid: agentUid }) + "\n"],
      [`${agentIdentityDir}/generation-${generation}.json`, JSON.stringify({ logicalAgentId: sessionId,
        identityGeneration: generation, uid: agentUid, gid: agentUid }) + "\n"],
      [`${forwarderIdentityDir}/uid-${forwarderUid}.json`, JSON.stringify({ sessionId,
        identityGeneration: generation, uid: forwarderUid, gid: forwarderUid }) + "\n"],
      [`${forwarderIdentityDir}/gid-${forwarderUid}.json`, JSON.stringify({ sessionId,
        identityGeneration: generation, uid: forwarderUid, gid: forwarderUid }) + "\n"],
      [`${forwarderIdentityDir}/session-${sessionId}.json`, JSON.stringify({ sessionId,
        identityGeneration: generation, uid: forwarderUid, gid: forwarderUid }) + "\n"]
    ]);
    for (const [filename, content] of expected) {
      const item = await maybe(filename);
      if (!item) continue;
      if (!item.isFile() || item.uid !== 0 || item.nlink !== 1 ||
          (item.mode & 0o022) !== 0 ||
          (content !== undefined && await readFile(filename, "utf8") !== content)) {
        throw new Error("Forwarder fixture file changed before cleanup: " + filename);
      }
      await unlink(filename);
    }
    for (const filename of [inputFile, envFile]) {
      if (madeFiles.has(filename)) {
        await checkedOwned(filename);
        await unlink(filename);
      }
    }
    if (staged) run("/usr/bin/systemctl", ["--system", "daemon-reload"]);
    for (const unit of [controlUnit, brokerUnit, forwarderUnit, mcpUnit, probeUnit]) {
      if (properties(unit, ["LoadState"]).get("LoadState") !== "not-found") {
        throw new Error("Forwarder fixture unit remained installed: " + unit);
      }
    }
    for (const name of accounts.reverse()) run("/usr/sbin/userdel", [name]);
    for (const name of groups.reverse()) {
      const found = run("/usr/bin/getent", ["group", name], true);
      if (found.status === 0) run("/usr/sbin/groupdel", [name]);
    }
    for (const filename of [forwarderRoot, agentRoot, runtimeRoot]) {
      if (!madeDirs.has(filename)) continue;
      await checkedOwned(filename, true);
      await rm(filename, { recursive: true });
      madeDirs.delete(filename);
    }
    for (const filename of autoDirs) {
      if (!absentAutoDirs.has(filename)) continue;
      const item = await maybe(filename);
      if (item?.isDirectory() && (await readdir(filename)).length === 0) await rmdir(filename);
    }
    for (const filename of [...madeDirs.keys()].reverse()) {
      const item = await maybe(filename);
      if (!item) continue;
      await checkedOwned(filename, true);
      if ((await readdir(filename)).length !== 0) throw new Error("Fixture directory is not empty.");
      await rmdir(filename);
    }
    for (const filename of ["/run/s-gw/agent-control.sock", "/run/s-gw/agent-prepare.sock",
      "/run/s-gw/managed-install.lock"]) {
      if (await maybe(filename)) throw new Error("Forwarder fixture left a control socket or lock.");
    }
  } catch (error) {
    cleanupError = error;
  }
  if (cleanupError) {
    if (failure) throw new AggregateError([failure, cleanupError],
      "Forwarder fixture and teardown both failed; uncertain paths were preserved.");
    throw cleanupError;
  }
}
if (failure) throw failure;
