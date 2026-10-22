import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, chown, copyFile, mkdir, readFile, rename, rm, stat } from "node:fs/promises";
import { createSocket } from "node:dgram";
import { createServer } from "node:net";
import { networkInterfaces } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { checkLinuxActivatedSocket } from "../dist/linux-activated-socket.js";
import { LinuxAgentSessionLeases } from "../dist/linux-agent-session.js";
import { linuxAgentUnitName, rejectUnresolvedUnitLaunchFences,
  SystemdRunAgentUnitManager } from "../dist/linux-agent-unit.js";
import { PeerSessionRegistry } from "../dist/peer-identity.js";

const project = fileURLToPath(new URL("..", import.meta.url));
const helper = path.join(project, `dist/native/linux-${process.arch}/s-gw-peer-credentials`);
const mode = process.argv[2];

if (process.platform !== "linux") throw new Error("Linux native acceptance must run on Linux.");

function command(name, args, options = {}) {
  const result = spawnSync(name, args, { encoding: "utf8", timeout: 30_000, ...options });
  if (result.error || result.status !== 0) {
    throw new Error(`${name} failed: ${result.error?.message || result.stderr || result.stdout || result.status}`);
  }
  return result.stdout.trim();
}

function wait(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function until(read, label, timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await read();
    if (value !== undefined) return value;
    await wait(100);
  }
  throw new Error(`Timed out waiting for ${label}.`);
}

async function textFile(filename) {
  try { return await readFile(filename, "utf8"); }
  catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
}

function hostAddress() {
  for (const items of Object.values(networkInterfaces())) {
    for (const item of items || []) {
      if (item.family === "IPv4" && !item.internal) return item.address;
    }
  }
  throw new Error("No host IPv4 address is available for the direct-egress probe.");
}

async function listener(host) {
  let hits = 0;
  const server = createServer(socket => { hits++; socket.destroy(); });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => { server.off("error", reject); resolve(); });
  });
  const port = server.address().port;
  return { port, hits: () => hits, close: () => new Promise(resolve => server.close(resolve)) };
}

async function udpListener(host) {
  let hits = 0;
  const server = createSocket("udp4");
  server.on("message", () => { hits++; });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.bind(0, host, () => { server.off("error", reject); resolve(); });
  });
  return { port: server.address().port, hits: () => hits,
    close: () => new Promise(resolve => server.close(resolve)) };
}

function listenPath(server, location) {
  return new Promise((resolve, reject) => {
    const failed = error => reject(error);
    server.once("error", failed);
    server.listen(location, () => { server.off("error", failed); resolve(); });
  });
}

function availableIdentity() {
  for (let uid = 230000; uid < 230999; uid++) {
    if (spawnSync("getent", ["passwd", String(uid)]).status === 2 &&
        spawnSync("getent", ["group", String(uid)]).status === 2 &&
        spawnSync("getent", ["passwd", String(uid + 1)]).status === 2 &&
        spawnSync("getent", ["group", String(uid + 1)]).status === 2) return uid;
  }
  throw new Error("No unused CI UID/GID pair is available.");
}

function removeGroupIfPresent(name) {
  const lookup = spawnSync("getent", ["group", name], { encoding: "utf8", timeout: 30_000 });
  if (lookup.error || (lookup.status !== 0 && lookup.status !== 2)) {
    throw new Error(`Could not check CI group ${name}: ${lookup.error?.message || lookup.stderr || lookup.status}`);
  }
  if (lookup.status === 0) command("groupdel", [name]);
}

async function stageRoot(plan, gateBinary, probeBinary) {
  const root = plan.rootDirectory;
  for (const relative of ["", "usr", "usr/bin", "usr/libexec", "usr/libexec/s-gw",
    "run", "run/s-gw", "run/s-gw/launch-gate", "dev", "dev/shm", "workspace"]) {
    await mkdir(path.join(root, relative), { recursive: true, mode: 0o755 });
  }
  await chmod(root, 0o755);
  await chown(path.join(root, "workspace"), plan.uid, plan.gid);
  await chmod(path.join(root, "workspace"), 0o700);
  const gate = path.join(root, "usr/libexec/s-gw/agent-launch-gate");
  const probe = path.join(root, "usr/bin/s-gw-native-probe");
  await copyFile(gateBinary, gate);
  await copyFile(probeBinary, probe);
  await chmod(gate, 0o755);
  await chmod(probe, 0o755);
}

function compile(source, output) {
  command("cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", output]);
}

function plan(sessionId, uid, brokerUid, otherId, ports, address) {
  return {
    sessionId, uid, gid: uid, brokerUid,
    rootDirectory: `/var/lib/s-gw/agent-roots/${sessionId}`,
    brokerSocket: `/run/s-gw/agents/${sessionId}/broker.sock`,
    executable: "/usr/bin/s-gw-native-probe",
    args: [sessionId, otherId, String(ports.ipv4), String(ports.ipv6), address, String(ports.host),
      String(ports.udp4), String(ports.udpHost)],
    launchGate: true, activatedSocket: true, isolatedSharedMemory: true,
    serializedLifecycle: true, sealedStdio: true
  };
}

function createMailbox(child, errorText) {
  const events = [];
  child.on("message", message => {
    if (message.kind === "rpc") return;
    events.push(message);
  });
  child.once("exit", (code, signal) => events.push({ kind: "exit", code, signal }));
  child.once("error", error => events.push({ kind: "exit", error: String(error) }));
  return {
    events,
    async next(kind, timeoutMs = 30_000) {
      return until(async () => {
        const exit = events.find(event => event.kind === "exit");
        if (exit) throw new Error(`Broker fixture exited early: ${JSON.stringify(exit)}. ${errorText()}`);
        const index = events.findIndex(event => event.kind === kind);
        return index < 0 ? undefined : events.splice(index, 1)[0];
      }, kind, timeoutMs);
    }
  };
}

async function asUid(uid, gid, script, location) {
  return new Promise((resolve, reject) => {
    const child = spawn("/usr/bin/python3", ["-c", script, location],
      { uid, gid, stdio: ["ignore", "pipe", "pipe"] });
    let output = "";
    let error = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 9000);
    child.stdout.on("data", chunk => { output += String(chunk); });
    child.stderr.on("data", chunk => { error += String(chunk); });
    child.once("error", reject);
    child.once("close", code => {
      clearTimeout(timer);
      if (code !== 0) reject(new Error(error || `Peer probe exited ${code}.`));
      else resolve(output.trim());
    });
  });
}

const socketProbe = `import socket,sys
s=socket.socket(socket.AF_UNIX)
try:
 s.connect(sys.argv[1])
except OSError:
 print('CONNECT_DENIED'); sys.exit(0)
try:
 s.sendall(b'CLAIM other\\n'); s.settimeout(6)
 print(s.recv(96).decode().strip() or 'CONNECTED_DENIED')
except socket.timeout:
 print('TIMEOUT')
except OSError:
 print('CONNECTED_DENIED')
finally:
 s.close()`;

async function rootRun() {
  const brokerUid = Number(process.argv[3]);
  const brokerGid = Number(process.argv[4]);
  if (process.geteuid() !== 0 || !Number.isSafeInteger(brokerUid) || brokerUid < 1 ||
      !Number.isSafeInteger(brokerGid) || brokerGid < 1) {
    throw new Error("Run through sudo with the CI runner UID and GID.");
  }
  const runId = randomBytes(5).toString("hex");
  const ids = [`ci-${runId}a`, `ci-${runId}b`];
  const names = [`sgwci${runId.slice(0, 6)}a`, `sgwci${runId.slice(0, 6)}b`];
  const first = availableIdentity();
  const uids = [first, first + 1];
  if (spawnSync("getent", ["passwd", String(uids[1])]).status !== 2 ||
      spawnSync("getent", ["group", String(uids[1])]).status !== 2) {
    throw new Error("The second CI UID/GID pair is unavailable.");
  }
  const hostIp = hostAddress();
  const hosts = {
    ipv4: await listener("127.0.0.1"),
    ipv6: await listener("::1"),
    host: await listener(hostIp),
    udp4: await udpListener("127.0.0.1"),
    udpHost: await udpListener(hostIp)
  };
  const ports = { ipv4: hosts.ipv4.port, ipv6: hosts.ipv6.port, host: hosts.host.port,
    udp4: hosts.udp4.port, udpHost: hosts.udpHost.port };
  const plans = [plan(ids[0], uids[0], brokerUid, ids[1], ports, hostIp),
    plan(ids[1], uids[1], brokerUid, ids[0], ports, hostIp)];
  const leaseDir = `/run/s-gw/ci-leases-${runId}`;
  const temp = `/run/s-gw/ci-build-${runId}`;
  const units = new SystemdRunAgentUnitManager();
  const states = new Map();
  const started = new Set();
  const unresolvedStarts = new Set();
  const rpcInFlight = new Set();
  const createdUsers = [];
  const createdGroups = [];
  let broker;
  let rebound;
  try {
    for (const base of ["/var/lib/s-gw", "/var/lib/s-gw/agent-roots", "/run/s-gw",
      "/run/s-gw/agents", "/run/s-gw/launch-gates", temp]) {
      await mkdir(base, { recursive: true, mode: 0o755 });
    }
    await mkdir(leaseDir, { mode: 0o700 });
    await chown(leaseDir, brokerUid, brokerGid);
    const gate = path.join(temp, "gate");
    const probe = path.join(temp, "probe");
    compile(path.join(project, "native/linux-agent-gate/launch-gate.c"), gate);
    compile(path.join(project, "scripts/linux-agent-native-probe.c"), probe);
    command(probe, ["--rights-positive"]);
    command(probe, ["--tcp-positive", "ipv4", "127.0.0.1", String(ports.ipv4)]);
    command(probe, ["--tcp-positive", "ipv6", "::1", String(ports.ipv6)]);
    command(probe, ["--tcp-positive", "ipv4", hostIp, String(ports.host)]);
    command(probe, ["--udp-positive", "127.0.0.1", String(ports.udp4)]);
    command(probe, ["--udp-positive", hostIp, String(ports.udpHost)]);
    await until(() => hosts.udp4.hits() === 1 && hosts.udpHost.hits() === 1 ? true : undefined,
      "host UDP positive controls", 3000);
    for (let index = 0; index < 2; index++) {
      command("groupadd", ["--gid", String(uids[index]), names[index]]);
      createdGroups.push(names[index]);
      command("useradd", ["--system", "--uid", String(uids[index]), "--gid", names[index],
        "--no-create-home", "--shell", "/usr/sbin/nologin", names[index]]);
      createdUsers.push(names[index]);
      await stageRoot(plans[index], gate, probe);
      await mkdir(path.dirname(plans[index].brokerSocket), { mode: 0o700 });
      await chown(path.dirname(plans[index].brokerSocket), brokerUid, brokerGid);
    }

    broker = spawn(process.execPath, [fileURLToPath(import.meta.url), "--broker",
      JSON.stringify(plans), leaseDir], { uid: brokerUid, gid: brokerGid, cwd: project,
      env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" },
      stdio: ["ignore", "pipe", "pipe", "ipc"] });
    let brokerError = "";
    broker.stderr.on("data", chunk => { brokerError += String(chunk); });
    broker.stdout.on("data", chunk => process.stdout.write(chunk));
    const mailbox = createMailbox(broker, () => brokerError);
    broker.on("message", message => {
      if (message.kind !== "rpc") return;
      const operation = (async () => {
        try {
          const value = await units[message.method](...message.args);
          if (message.method === "start") started.add(message.args[0].sessionId);
          if (message.method === "stop") started.delete(message.args[0].sessionId);
          if (message.method === "inspect") states.set(message.args[0].sessionId, value);
          if (broker.connected) broker.send({ kind: "rpc-result", id: message.id, value });
        } catch (error) {
          if (message.method === "start") unresolvedStarts.add(message.args[0].sessionId);
          if (broker.connected) broker.send({ kind: "rpc-result", id: message.id, error: String(error) });
        }
      })();
      rpcInFlight.add(operation);
      void operation.finally(() => rpcInFlight.delete(operation));
    });
    const bound = await mailbox.next("bound");
    if (bound.error) throw new Error(bound.error);
    // This fixture gives the broker a kernel listener FD before root takes custody of its node.
    for (const item of plans) {
      await chown(item.brokerSocket, 0, item.gid);
      await chmod(item.brokerSocket, 0o660);
      await chown(path.dirname(item.brokerSocket), 0, 0);
      await chmod(path.dirname(item.brokerSocket), 0o711);
    }
    broker.send({ kind: "launch" });
    const live = await mailbox.next("live");
    if (live.error) throw new Error(live.error);
    if (states.size !== 2 || states.get(ids[0]).uid === states.get(ids[1]).uid ||
        states.get(ids[0]).cgroup === states.get(ids[1]).cgroup) {
      throw new Error("The two agents did not attest distinct UIDs and cgroups.");
    }
    for (const item of plans) {
      const result = await until(() => textFile(path.join(item.rootDirectory, "workspace/result")),
        `${item.sessionId} native result`);
      if (!/^own=1 cross=1 ipv4=1 ipv6=1 host=1 udp4=[01] udphost=[01]\n$/.test(result)) {
        throw new Error(`${item.sessionId} escaped its own socket, cross-session, or network boundary: ${result}`);
      }
    }
    for (const item of plans) {
      let fenced = false;
      try {
        await rejectUnresolvedUnitLaunchFences("/run/s-gw/agent-unit-lifecycle",
          linuxAgentUnitName(item.sessionId));
      } catch (error) {
        fenced = /unresolved prior launch attempt/.test(String(error));
      }
      if (!fenced) throw new Error("A running Linux agent lacked its durable launch fence.");
    }
    const legacyUnits = new SystemdRunAgentUnitManager();
    for (const item of plans) {
      let blocked = false;
      try { await legacyUnits.stop({ ...item, serializedLifecycle: false }); }
      catch (error) { blocked = /active or unreconciled serialized lifecycle lease/.test(String(error)); }
      if (!blocked) throw new Error("A separate legacy manager stopped or bypassed a serialized agent unit.");
      const current = await units.inspect(item);
      if (current.invocationId !== states.get(item.sessionId).invocationId) {
        throw new Error("A denied legacy stop changed the serialized agent unit.");
      }
    }
    const shmRoots = await Promise.all(plans.map(item =>
      stat(`/proc/${states.get(item.sessionId).mainPid}/root/dev/shm`)));
    const hostShm = await stat("/dev/shm");
    if (shmRoots.some(item => !item.isDirectory() || item.dev === hostShm.dev) ||
        shmRoots[0].dev === shmRoots[1].dev) {
      throw new Error("The two Linux agents did not receive distinct private shared-memory mounts.");
    }
    for (const item of plans) {
      const ready = await until(() => textFile(path.join(item.rootDirectory, "workspace/transfer-ready")),
        `${item.sessionId} Unix rendezvous listener`);
      if (ready !== "ready\n") throw new Error(`${item.sessionId} did not prepare its Unix listeners.`);
      const rightsNode = await stat(path.join(item.rootDirectory, "workspace", `rights-${item.sessionId}.sock`));
      if (!rightsNode.isSocket()) throw new Error(`${item.sessionId} did not bind its descriptor receiver.`);
    }
    for (const item of plans) process.kill(states.get(item.sessionId).mainPid, "SIGUSR2");
    for (const item of plans) {
      const result = await until(() => textFile(path.join(item.rootDirectory, "workspace/transfer")),
        `${item.sessionId} peer Unix socket result`);
      if (result !== "rights=1 ownfs=1 ownabstract=1 fs=1 hostfs=1 abstract=1 ownshm=1 crossshm=1 ownrights=1 ownrightsa=1 rightsfs=1 rightshostfs=1 rightsa=1\n") {
        throw new Error(`${item.sessionId} failed a peer Unix socket, descriptor transfer, or POSIX shared-memory probe: ${result}`);
      }
    }
    await until(() => mailbox.events.filter(event => event.kind === "accepted").length >= 2 ? true : undefined,
      "two authenticated agent events");
    const accepted = mailbox.events.filter(event => event.kind === "accepted");
    if (accepted.length !== 2 || new Set(accepted.map(event => event.sessionId)).size !== 2 ||
        accepted.some(event =>
      event.claim !== plans.find(item => item.sessionId === event.sessionId)?.args[1])) {
      throw new Error("The broker did not authenticate both separate agents.");
    }
    for (const item of plans) {
      const own = await asUid(item.uid, item.gid, socketProbe, item.brokerSocket);
      if (own !== "CONNECTED_DENIED") {
        throw new Error("The broker did not reject a connected same-UID process outside the registered cgroup.");
      }
      const other = plans.find(planItem => planItem !== item);
      const cross = await asUid(item.uid, item.gid, socketProbe, other.brokerSocket);
      if (cross !== "CONNECT_DENIED") throw new Error("One agent UID reached another agent's socket.");
    }
    await until(() => mailbox.events.filter(event => event.kind === "rejected" &&
      /Could not verify live Linux peer in its cgroup/.test(event.reason)).length >= 2 ? true : undefined,
    "two outside-cgroup rejections");
    const oldSocket = `${plans[0].brokerSocket}.old`;
    await rename(plans[0].brokerSocket, oldSocket);
    rebound = createServer(socket => {
      socket.on("error", () => socket.destroy());
      socket.end("replacement\n");
    });
    await listenPath(rebound, plans[0].brokerSocket);
    await chown(plans[0].brokerSocket, 0, plans[0].gid);
    await chmod(plans[0].brokerSocket, 0o660);
    broker.send({ kind: "assert-rebind" });
    const rebind = await mailbox.next("rebind");
    if (rebind.failed !== true) throw new Error("The broker accepted a replaced activated socket node.");
    const before = mailbox.events.filter(event => event.kind === "accepted").length;
    process.kill(states.get(ids[0]).mainPid, "SIGUSR1");
    const retry = await until(() => textFile(path.join(plans[0].rootDirectory, "workspace/rebind")),
      "rebound agent probe");
    if (retry !== "rebind=denied\n" ||
        mailbox.events.filter(event => event.kind === "accepted").length !== before) {
      throw new Error("The broker accepted an agent after its activated path was rebound.");
    }
    await wait(200);
    if (hosts.ipv4.hits() !== 1 || hosts.ipv6.hits() !== 1 || hosts.host.hits() !== 1 ||
        hosts.udp4.hits() !== 1 || hosts.udpHost.hits() !== 1) {
      throw new Error("An agent reached a host TCP or UDP listener outside its private network namespace.");
    }
    broker.send({ kind: "stop" });
    const stopped = await mailbox.next("stopped");
    if (stopped.error) throw new Error(stopped.error);
    for (const item of plans) {
      await rejectUnresolvedUnitLaunchFences("/run/s-gw/agent-unit-lifecycle",
        linuxAgentUnitName(item.sessionId));
    }
    broker.send({ kind: "reuse" });
    const reuse = await mailbox.next("reuse");
    if (!reuse.leaseRejected || !reuse.registryRejected) {
      throw new Error("A stopped Linux agent UID or session could be reused by the same broker.");
    }
    if (await asUid(plans[1].uid, plans[1].gid, socketProbe, plans[1].brokerSocket) !== "CONNECTED_DENIED") {
      throw new Error("A revoked agent UID was still authorized.");
    }
    broker.send({ kind: "close" });
    await mailbox.next("closed");
  } finally {
    if (broker && broker.exitCode === null) broker.kill("SIGKILL");
    await Promise.allSettled([...rpcInFlight]);
    const teardownErrors = [];
    for (const item of plans) {
      if (!started.has(item.sessionId)) continue;
      try {
        await units.stop(item);
        started.delete(item.sessionId);
      } catch (error) { teardownErrors.push(error); }
    }
    if (unresolvedStarts.size > 0) teardownErrors.push(new Error(
      `Could not prove whether these units started: ${[...unresolvedStarts].join(", ")}.`));
    if (rebound) await new Promise(resolve => rebound.close(resolve));
    if (teardownErrors.length === 0) {
      for (const item of plans) {
        await rm(item.rootDirectory, { recursive: true, force: true });
        await rm(path.dirname(item.brokerSocket), { recursive: true, force: true });
      }
      await rm(leaseDir, { recursive: true, force: true });
      await rm(temp, { recursive: true, force: true });
      for (const name of createdUsers.reverse()) command("userdel", [name]);
      for (const name of createdGroups.reverse()) removeGroupIfPresent(name);
    }
    await Promise.all(Object.values(hosts).map(item => item.close()));
    if (teardownErrors.length > 0) {
      throw new AggregateError(teardownErrors,
        "Native Linux agent teardown failed; its dedicated account and root were preserved for investigation.");
    }
  }
  console.log("Native Linux component-chain fixture passed: two UIDs/cgroups, broker identity, host egress, tested peer pathname/abstract Unix socket denial, local SCM_RIGHTS and blocked descriptor sends to three peer address candidates, private POSIX shared memory, revocation, and socket rebind. The listener was manually staged; other descriptor-transfer routes, an installed systemd socket unit, and production MCP/model relay remain untested.");
}

async function peer(socket) {
  return new Promise((resolve, reject) => {
    const child = spawn(helper, [], { stdio: ["ignore", "pipe", "pipe", socket], env: {} });
    let output = "";
    child.stdout.on("data", chunk => { output += String(chunk); });
    child.once("error", reject);
    child.once("close", code => {
      const match = /^(\d+) (\d+) (\d+)\n$/.exec(output);
      if (code !== 0 || !match) reject(new Error("Native peer credentials failed."));
      else resolve({ uid: Number(match[1]), gid: Number(match[2]), pid: Number(match[3]) });
    });
  });
}

async function brokerRun() {
  const plans = JSON.parse(process.argv[3]);
  const leaseDir = process.argv[4];
  const registry = new PeerSessionRegistry(true);
  const pending = new Map();
  const endpoints = new Map();
  const stops = [];
  let nextId = 0;
  const send = value => process.send(value);
  const units = Object.fromEntries(["start", "inspect", "release", "stop"].map(method => [method,
    (...args) => new Promise((resolve, reject) => {
      const id = ++nextId;
      const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Root ${method} timed out.`)); }, 20_000);
      pending.set(id, { resolve, reject, timer });
      send({ kind: "rpc", id, method, args });
    })]));
  const leases = new LinuxAgentSessionLeases(leaseDir, units);
  for (const item of plans) {
    const server = createServer(socket => {
      socket.pause();
      socket.setTimeout(8000, () => socket.destroy());
      socket.on("error", () => socket.destroy());
      const fd = endpoints.get(item.sessionId).fd;
      const snapshot = registry.snapshot();
      void checkLinuxActivatedSocket(item.brokerSocket, fd, item.gid)
        .then(() => peer(socket)).then(identity => registry.authenticate(identity, socket, snapshot))
        .then(principal => {
          let request = Buffer.alloc(0);
          const readRequest = chunk => {
            if (request.length + chunk.length > 96) { socket.destroy(); return; }
            request = Buffer.concat([request, chunk]);
            const newline = request.indexOf(10);
            if (newline < 0) return;
            socket.off("data", readRequest);
            if (newline !== request.length - 1) { socket.destroy(); return; }
            const line = request.toString("utf8");
            if (line === "TRANSFER\n") {
              socket.on("data", () => socket.destroy());
              socket.write("READY\n");
              return;
            }
            const claim = /^CLAIM ([a-z0-9-]+)\n$/.exec(line)?.[1] || "invalid";
            send({ kind: "accepted", sessionId: principal.sessionId, claim });
            socket.end(`ALLOW ${principal.sessionId}\n`);
          };
          socket.on("data", readRequest);
          socket.resume();
        }).catch(error => {
          send({ kind: "rejected", reason: String(error) });
          socket.destroy();
        });
    });
    await listenPath(server, item.brokerSocket);
    const fd = server._handle?.fd;
    if (!Number.isInteger(fd)) throw new Error("No Linux listener descriptor was created.");
    endpoints.set(item.sessionId, { server, fd });
  }
  send({ kind: "bound" });
  process.on("message", async message => {
    if (message.kind === "rpc-result") {
      const item = pending.get(message.id);
      if (!item) return;
      pending.delete(message.id);
      clearTimeout(item.timer);
      if (message.error) item.reject(new Error(message.error));
      else item.resolve(message.value);
      return;
    }
    try {
      if (message.kind === "launch") {
        for (const item of plans) {
          const fd = endpoints.get(item.sessionId).fd;
          stops.push(await leases.launch(item, "CI agent", session => registry.register(session),
            () => checkLinuxActivatedSocket(item.brokerSocket, fd, item.gid)));
        }
        send({ kind: "live" });
      } else if (message.kind === "assert-rebind") {
        let failed = false;
        try { await checkLinuxActivatedSocket(plans[0].brokerSocket,
          endpoints.get(plans[0].sessionId).fd, plans[0].gid); }
        catch { failed = true; }
        send({ kind: "rebind", failed });
      } else if (message.kind === "stop") {
        for (const stop of stops.reverse()) await stop();
        send({ kind: "stopped" });
      } else if (message.kind === "reuse") {
        const item = plans[1];
        let leaseRejected = false;
        let registryRejected = false;
        try {
          await leases.launch(item, "CI agent", session => registry.register(session),
            () => checkLinuxActivatedSocket(item.brokerSocket, endpoints.get(item.sessionId).fd, item.gid));
        } catch (error) { leaseRejected = /already used/.test(String(error)); }
        try {
          registry.register({ uid: item.uid, gid: item.gid, sessionId: item.sessionId,
            name: "CI agent", linuxCgroup: `/system.slice/s-gw-agent-${item.sessionId}.service` });
        } catch (error) { registryRejected = /cannot be reused|already registered/.test(String(error)); }
        send({ kind: "reuse", leaseRejected, registryRejected });
      } else if (message.kind === "close") {
        for (const { server } of endpoints.values()) {
          await new Promise(resolve => server.close(resolve));
        }
        send({ kind: "closed" });
      }
    } catch (error) {
      send({ kind: message.kind === "launch" ? "live" : message.kind === "stop" ? "stopped" : "closed",
        error: String(error) });
    }
  });
}

if (mode === "--root") await rootRun();
else if (mode === "--broker") await brokerRun();
else throw new Error("Expected --root or --broker.");
