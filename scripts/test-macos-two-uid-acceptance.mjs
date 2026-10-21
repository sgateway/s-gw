#!/usr/bin/env node

import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createSocket } from "node:dgram";
import { access, lstat, readFile, realpath, readdir } from "node:fs/promises";
import { constants } from "node:fs";
import { createConnection, createServer, isIP } from "node:net";
import { networkInterfaces } from "node:os";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";

const fixtureRoot = "/private/var/db/s-gw-acceptance";
const runnerControl = "/private/var/db/s-gw/agent-launch-control.sock";
const policyControl = "/private/var/db/s-gw/agent-network-policy.sock";
const runnerLeases = "/private/var/db/s-gw/agent-uid-leases";
const scriptPath = fileURLToPath(import.meta.url);
const sessionPattern = /^[A-Za-z0-9_-]{1,64}$/;

function requireValue(ok, message) {
  if (!ok) throw new Error(message);
}

function isFixturePath(value) {
  return typeof value === "string" && path.isAbsolute(value) &&
    path.resolve(value) === value && value.startsWith(`${fixtureRoot}/`);
}

function parsePlan(raw) {
  const plan = JSON.parse(raw);
  requireValue(plan?.purpose === "s-gw-macos-two-uid-acceptance" && plan.dedicatedTestHost === true,
    "An explicit dedicated-test-host acceptance plan is required.");
  requireValue(isFixturePath(plan.leaseDir) && isFixturePath(plan.stagedAgentScript) &&
    isFixturePath(plan.brokerCanary),
    "Lease, staged-script, and broker-canary paths must be inside the acceptance fixture root.");
  requireValue(typeof plan.nodeExecutable === "string" && path.isAbsolute(plan.nodeExecutable) &&
    path.resolve(plan.nodeExecutable) === plan.nodeExecutable, "A canonical Node executable is required.");
  if (plan.hostIpv4Probe !== undefined) {
    requireValue(typeof plan.hostIpv4Probe === "string" && isIP(plan.hostIpv4Probe) === 4 &&
      !plan.hostIpv4Probe.startsWith("127."), "The host IPv4 probe must use a non-loopback address.");
  }
  requireValue(Array.isArray(plan.agents) && plan.agents.length === 2, "Exactly two agent accounts are required.");
  const uids = new Set();
  const gids = new Set();
  const sessions = new Set();
  const sockets = new Set();
  for (const agent of plan.agents) {
    requireValue(typeof agent.account === "string" && /^_sgwagent_[A-Za-z0-9_-]+$/.test(agent.account),
      "Each account must be a preprovisioned _sgwagent_ account.");
    requireValue(Number.isSafeInteger(agent.uid) && agent.uid > 0 &&
      Number.isSafeInteger(agent.gid) && agent.gid > 0, "Each agent needs a numeric UID and GID.");
    requireValue(typeof agent.sessionId === "string" && sessionPattern.test(agent.sessionId),
      "Each agent needs a safe session ID.");
    requireValue(isFixturePath(agent.workspace) && isFixturePath(agent.socketPath) &&
      isFixturePath(agent.reportSocketPath), "Agent paths must be inside the acceptance fixture root.");
    requireValue(!uids.has(agent.uid) && !gids.has(agent.gid) && !sessions.has(agent.sessionId) &&
      !sockets.has(agent.socketPath) && !sockets.has(agent.reportSocketPath) &&
      agent.socketPath !== agent.reportSocketPath, "Agent identities and socket paths must be distinct.");
    uids.add(agent.uid);
    gids.add(agent.gid);
    sessions.add(agent.sessionId);
    sockets.add(agent.socketPath);
    sockets.add(agent.reportSocketPath);
  }
  requireValue(!sockets.has(plan.leaseDir) && !sockets.has(plan.stagedAgentScript) &&
    !sockets.has(plan.brokerCanary),
    "Fixture paths must not overlap.");
  if (plan.fdTransferProbe !== undefined) {
    const probe = plan.fdTransferProbe;
    requireValue(isFixturePath(probe?.helperExecutable) && isFixturePath(probe?.rendezvousPath) &&
      Buffer.byteLength(probe.rendezvousPath) < 100 &&
      probe.helperExecutable !== probe.rendezvousPath &&
      !sockets.has(probe.rendezvousPath) && !sockets.has(probe.helperExecutable) &&
      ![plan.leaseDir, plan.stagedAgentScript, plan.brokerCanary].includes(probe.rendezvousPath) &&
      ![plan.leaseDir, plan.stagedAgentScript, plan.brokerCanary].includes(probe.helperExecutable),
    "The optional descriptor-transfer helper and rendezvous must be distinct fixture paths.");
  }
  return plan;
}

async function checkedPath(value, type, owner, mode) {
  const info = await lstat(value);
  requireValue(await realpath(value) === value && info.uid === owner &&
    (info.mode & 0o777) === mode &&
    (type === "directory" ? info.isDirectory() : type === "socket" ? info.isSocket() : info.isFile()),
    `Unsafe preprovisioned ${type}: ${value}`);
  await assertNoAclAllow(value);
  return info;
}

async function assertNoAclAllow(value) {
  const { assertNoMacAclAllow } = await import("../dist/macos-path-acl.js");
  await assertNoMacAclAllow(value);
}

async function checkedRootParents(value, agentNeedsTraverse = false) {
  let current = path.dirname(value);
  while (true) {
    const info = await lstat(current);
    requireValue(info.isDirectory() && info.uid === 0 && (info.mode & 0o022) === 0 &&
      (!agentNeedsTraverse || (info.mode & 0o001) !== 0) &&
      await realpath(current) === current, `Untrusted fixture parent: ${current}`);
    await assertNoAclAllow(current);
    const next = path.dirname(current);
    if (next === current) return;
    current = next;
  }
}

async function checkedExecutableParents(value, brokerUid) {
  let current = path.dirname(value);
  while (true) {
    const info = await lstat(current);
    requireValue(info.isDirectory() && (info.uid === 0 || info.uid === brokerUid) &&
      (info.mode & 0o022) === 0 && (info.mode & 0o001) !== 0 &&
      await realpath(current) === current,
    `Untrusted executable parent: ${current}`);
    await assertNoAclAllow(current);
    const next = path.dirname(current);
    if (next === current) return;
    current = next;
  }
}

function accountId(flag, name) {
  const output = execFileSync("/usr/bin/id", [flag, name], { encoding: "utf8", timeout: 1500 }).trim();
  requireValue(/^\d+$/.test(output), `Cannot resolve ${name}.`);
  return Number(output);
}

function accountGroups(name) {
  const output = execFileSync("/usr/bin/id", ["-G", name], { encoding: "utf8", timeout: 1500 }).trim();
  requireValue(/^\d+(?:\s+\d+)*$/.test(output), `Cannot resolve groups for ${name}.`);
  return new Set(output.split(/\s+/).map(Number));
}

async function preflight(plan) {
  requireValue(process.platform === "darwin" && typeof process.getuid === "function" &&
    process.getuid() !== 0, "Run the broker fixture as a non-root macOS account.");
  const brokerGroups = new Set(process.getgroups?.() ?? []);
  if (plan.hostIpv4Probe) {
    const addresses = Object.values(networkInterfaces()).flat();
    requireValue(addresses.some(address => address?.family === "IPv4" &&
      address.address === plan.hostIpv4Probe && !address.internal),
    "The host IPv4 probe must name an active non-loopback interface on this Mac.");
  }
  await checkedPath(fixtureRoot, "directory", 0, 0o755);
  await checkedRootParents(fixtureRoot, true);
  await checkedPath(runnerControl, "socket", process.getuid(), 0o600);
  await checkedPath(policyControl, "socket", 0, 0o600);
  await checkedPath(runnerLeases, "directory", 0, 0o700);
  await checkedRootParents(runnerControl);
  await access(path.dirname(runnerControl), constants.X_OK);
  await checkedRootParents(policyControl);
  await checkedRootParents(runnerLeases);
  await checkedPath(plan.leaseDir, "directory", process.getuid(), 0o700);
  await checkedRootParents(plan.leaseDir);
  await checkedPath(plan.brokerCanary, "file", process.getuid(), 0o600);
  const canaryParent = path.dirname(plan.brokerCanary);
  await checkedPath(canaryParent, "directory", process.getuid(), 0o700);
  await checkedRootParents(canaryParent);
  const node = await lstat(plan.nodeExecutable);
  requireValue(await realpath(plan.nodeExecutable) === plan.nodeExecutable && node.isFile() &&
    (node.uid === 0 || node.uid === process.getuid()) && (node.mode & 0o6022) === 0 &&
    (node.mode & 0o001) !== 0, "The Node executable is not trusted or accessible to both agents.");
  await assertNoAclAllow(plan.nodeExecutable);
  await checkedExecutableParents(plan.nodeExecutable, process.getuid());
  const script = await lstat(plan.stagedAgentScript);
  requireValue(await realpath(plan.stagedAgentScript) === plan.stagedAgentScript && script.isFile() &&
    script.uid === 0 && (script.mode & 0o022) === 0 && (script.mode & 0o004) !== 0,
    "The staged agent fixture must be root-owned and read-only to agents.");
  await assertNoAclAllow(plan.stagedAgentScript);
  await checkedRootParents(plan.stagedAgentScript, true);
  const stagedHash = createHash("sha256").update(await readFile(plan.stagedAgentScript)).digest("hex");
  const sourceHash = createHash("sha256").update(await readFile(scriptPath)).digest("hex");
  requireValue(stagedHash === sourceHash, "The staged agent fixture differs from this test source.");
  if (plan.fdTransferProbe) {
    const { helperExecutable, rendezvousPath } = plan.fdTransferProbe;
    const helper = await lstat(helperExecutable);
    requireValue(helper.isFile() && helper.uid === 0 &&
      await realpath(helperExecutable) === helperExecutable &&
      (helper.mode & 0o222) === 0 && (helper.mode & 0o111) !== 0 &&
      (helper.mode & 0o004) !== 0,
    "The staged descriptor-transfer helper must be root-owned, executable, and read-only to agents.");
    await assertNoAclAllow(helperExecutable);
    await checkedRootParents(helperExecutable, true);
    const sharedDir = path.dirname(rendezvousPath);
    const shared = await lstat(sharedDir);
    requireValue(shared.isDirectory() && shared.uid === 0 &&
      (shared.mode & 0o7777) === 0o1777 && await realpath(sharedDir) === sharedDir,
    "The descriptor-transfer rendezvous needs a root-owned sticky shared directory.");
    await assertNoAclAllow(sharedDir);
    await checkedRootParents(sharedDir, true);
    try { await lstat(rendezvousPath); throw new Error(`Rendezvous path already exists: ${rendezvousPath}`); }
    catch (error) { if (error?.code !== "ENOENT") throw error; }
  }

  for (const agent of plan.agents) {
    requireValue(agent.uid !== process.getuid() && agent.uid !== process.geteuid() &&
      agent.gid !== process.getgid() && agent.gid !== process.getegid(),
    "An agent must not share the broker UID or GID.");
    requireValue(brokerGroups.has(agent.gid),
      `The broker must be a trusted supplementary member of agent socket group ${agent.gid}.`);
    requireValue(accountId("-u", agent.account) === agent.uid &&
      accountId("-g", agent.account) === agent.gid, `Preprovisioned account ${agent.account} does not match the plan.`);
    const groups = accountGroups(agent.account);
    requireValue(groups.has(agent.gid) && plan.agents.every(other =>
      other === agent || !groups.has(other.gid)),
    `Preprovisioned account ${agent.account} can use another agent's socket group.`);
    await checkedPath(agent.workspace, "directory", agent.uid, 0o700);
    await checkedPath(path.join(agent.workspace, "tmp"), "directory", agent.uid, 0o700);
    await checkedRootParents(agent.workspace, true);
    for (const socketPath of [agent.socketPath, agent.reportSocketPath]) {
      const parent = path.dirname(socketPath);
      const info = await lstat(parent);
      requireValue(info.isDirectory() && info.uid === process.getuid() && (info.mode & 0o022) === 0 &&
        (info.mode & 0o001) !== 0 && await realpath(parent) === parent,
      `Unsafe broker socket directory: ${parent}`);
      await assertNoAclAllow(parent);
      await checkedRootParents(parent, true);
      try { await lstat(socketPath); throw new Error(`Socket path already exists: ${socketPath}`); }
      catch (error) { if (error?.code !== "ENOENT") throw error; }
    }
  }
}

function startLoopback(host) {
  let hits = 0;
  const server = createServer(socket => { hits++; socket.destroy(); });
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, host, async () => {
      server.off("error", reject);
      try {
        const port = server.address().port;
        requireValue(await canConnect(host, port), `Broker cannot reach its ${host} test listener.`);
        await delay(50);
        requireValue(hits > 0, `Broker did not observe its ${host} control connection.`);
        hits = 0;
        resolve({ port, hits: () => hits, close: () => new Promise(done => server.close(done)) });
      } catch (error) { server.close(); reject(error); }
    });
  });
}

function canConnect(host, port) {
  return new Promise(resolve => {
    const socket = createConnection({ host, port });
    let done = false;
    function finish(value) {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(value);
    }
    socket.setTimeout(1500, () => finish(false));
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
  });
}

function sendUdpProbe(host, port) {
  return new Promise(resolve => {
    const socket = createSocket(host.includes(":") ? "udp6" : "udp4");
    let done = false;
    const timer = setTimeout(finish, 1500);
    function finish() {
      if (done) return;
      done = true;
      clearTimeout(timer);
      socket.close();
      resolve();
    }
    socket.on("error", finish);
    socket.send("SGW-UDP-PROBE", port, host, finish);
  });
}

function startUdpLoopback(host) {
  let hits = 0;
  const socket = createSocket(host.includes(":") ? "udp6" : "udp4");
  socket.on("message", () => { hits++; });
  return new Promise((resolve, reject) => {
    socket.once("error", reject);
    socket.bind(0, host, async () => {
      socket.off("error", reject);
      try {
        const port = socket.address().port;
        await sendUdpProbe(host, port);
        await delay(50);
        requireValue(hits > 0, `Broker cannot reach its ${host} UDP test listener.`);
        hits = 0;
        resolve({ port, hits: () => hits, close: () => new Promise(done => socket.close(done)) });
      } catch (error) { socket.close(); reject(error); }
    });
  });
}

function sendProbe(location, uid, session) {
  return new Promise(resolve => {
    const socket = createConnection(location);
    let reply = "";
    let done = false;
    function finish() {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(reply);
    }
    socket.setTimeout(2500, finish);
    socket.once("connect", () => socket.end(`HELLO-V1 ${uid} ${session}\n`));
    socket.on("data", chunk => { reply += String(chunk); if (reply.length > 128) finish(); });
    socket.once("error", finish);
    socket.once("close", finish);
  });
}

function readReport(socket) {
  return new Promise((resolve, reject) => {
    let frame = "";
    socket.setTimeout(3000, () => reject(new Error("Agent result timed out.")));
    function onData(chunk) {
      frame += String(chunk);
      if (frame.length > 2048) { reject(new Error("Agent result is too large.")); return; }
      const end = frame.indexOf("\n");
      if (end === -1) return;
      if (end !== frame.length - 1) { reject(new Error("Agent result has extra bytes.")); return; }
      socket.off("data", onData);
      resolve(frame.slice(0, -1));
    }
    socket.on("data", onData);
    socket.once("end", () => reject(new Error("Agent result ended before its newline.")));
    socket.once("error", reject);
    socket.resume();
  });
}

function watchTransferredSocket(socket, failed, donorUid) {
  let frame = "";
  socket.setTimeout(15_000, () => socket.destroy());
  socket.on("data", chunk => {
    frame += String(chunk);
    if (frame.length > 128 || (frame.includes("\n") && frame !== "XFER-USE-V1\n")) {
      failed.resolve(new Error(`Agent ${donorUid} sent an invalid descriptor-transfer frame.`));
      socket.destroy();
      return;
    }
    if (frame === "XFER-USE-V1\n") {
      failed.resolve(new Error(`Agent ${donorUid}'s authenticated broker socket was used by the other UID.`));
      socket.end("XFER-ACK-V1\n");
    }
  });
  socket.resume();
}

function requireTransferDenial(donor, recipient, transferStarted) {
  requireValue(recipient !== "used", "The other UID used a donor-authenticated descriptor.");
  requireValue(donor !== "sent" || transferStarted,
    "The donor reported a sent descriptor without a verified broker connection.");
  requireValue(donor === "denied" || recipient === "denied",
    `Descriptor-transfer result is inconclusive: donor=${donor}, recipient=${recipient}.`);
}

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

async function runBroker(plan) {
  const { startVerifiedPeerServer } = await import("../dist/peer-identity.js");
  const { MacAgentSessionLeases } = await import("../dist/macos-agent-session.js");
  const { acknowledgeMacAgentLaunch } = await import("../dist/macos-agent-probe.js");
  const servers = [];
  const stops = [];
  const received = new Map();
  const revokedReports = new Map();
  const launchSeen = new Map();
  const reports = new Map();
  const heldSeen = new Map();
  const closedSeen = new Map();
  const finalReports = new Map();
  const transferReports = new Map();
  const transferResults = new Map();
  let transferStarted = false;
  const probeStops = new Map();
  const heldMode = new Set();
  const revoking = new Set();
  const heldSockets = new Map();
  const failed = deferred();
  let ipv4;
  let ipv6;
  let udp4;
  let udp6;
  let hostIpv4Tcp;
  let hostIpv4Udp;
  let deadlineTimer;
  function interrupted() { failed.resolve(new Error("Native acceptance was interrupted.")); }
  process.once("SIGINT", interrupted);
  process.once("SIGTERM", interrupted);
  try {
    ipv4 = await startLoopback("127.0.0.1");
    ipv6 = await startLoopback("::1");
    udp4 = await startUdpLoopback("127.0.0.1");
    udp6 = await startUdpLoopback("::1");
    if (plan.hostIpv4Probe) {
      hostIpv4Tcp = await startLoopback(plan.hostIpv4Probe);
      hostIpv4Udp = await startUdpLoopback(plan.hostIpv4Probe);
    }
    for (const agent of plan.agents) {
      launchSeen.set(agent.uid, deferred());
      reports.set(agent.uid, deferred());
      heldSeen.set(agent.uid, deferred());
      closedSeen.set(agent.uid, deferred());
      finalReports.set(agent.uid, deferred());
      if (plan.fdTransferProbe) transferReports.set(agent.uid, deferred());
      const probeServer = await startVerifiedPeerServer({
        socketPath: agent.socketPath, socketMode: 0o660, socketGid: agent.gid,
        onConnection: async (socket, principal, peer) => {
          if (revoking.has(agent.uid)) {
            failed.resolve(new Error(`Agent ${agent.uid} was admitted after revocation.`));
            socket.destroy();
            return;
          }
          if (heldMode.has(agent.uid)) {
            try {
              requireValue(!heldSockets.has(agent.uid) && peer.uid === agent.uid &&
                principal.principalId === `darwin:uid:${agent.uid}`,
              `Agent ${agent.uid} opened an invalid held probe.`);
              heldSockets.set(agent.uid, socket);
              socket.once("close", () => {
                if (!revoking.has(agent.uid)) {
                  failed.resolve(new Error(`Agent ${agent.uid} lost its held probe before revocation.`));
                  return;
                }
                closedSeen.get(agent.uid).resolve();
              });
              socket.write("HELD-V1\n");
              requireValue(await readReport(socket) === "HOLD-ACK-V1",
                `Agent ${agent.uid} did not acknowledge its held probe.`);
              heldSeen.get(agent.uid).resolve();
            } catch (error) {
              failed.resolve(error);
              throw error;
            }
            return;
          }
          await acknowledgeMacAgentLaunch(socket, principal, peer);
          launchSeen.get(agent.uid).resolve();
        }
      });
      servers.push(probeServer);
      const resultServer = await startVerifiedPeerServer({
        socketPath: agent.reportSocketPath, socketMode: 0o660, socketGid: agent.gid,
        onConnection: async (socket, principal, peer) => {
          try {
            const raw = await readReport(socket);
            if (raw === "XFER-START-V1") {
              requireValue(peer.uid === agent.uid && principal.principalId === `darwin:uid:${agent.uid}` &&
                plan.fdTransferProbe && agent.uid === plan.agents[0].uid &&
                received.has(agent.uid) && !transferStarted,
              "Unexpected authenticated descriptor-transfer probe.");
              transferStarted = true;
              socket.write("XFER-READY-V1\n");
              watchTransferredSocket(socket, failed, agent.uid);
              return;
            }
            const result = JSON.parse(raw);
            requireValue(peer.uid === agent.uid && principal.principalId === `darwin:uid:${agent.uid}` &&
              result.uid === agent.uid && result.sessionId === agent.sessionId,
            `Agent ${agent.uid} sent a result under the wrong identity.`);
            if (result.phase === "initial") {
              requireValue(result.wrongClaimDenied === true && result.crossIdentityDenied === true &&
                result.ownAccepted === true && result.ipv4Denied === true && result.ipv6Denied === true &&
                result.brokerCanaryDenied === true && result.otherWorkspaceDenied === true,
              `Agent ${agent.uid} failed a native isolation probe.`);
              if (plan.hostIpv4Probe) {
                requireValue(result.hostIpv4Denied === true,
                  `Agent ${agent.uid} reached the host's non-loopback IPv4 address.`);
              }
              requireValue(!received.has(agent.uid), `Agent ${agent.uid} sent duplicate initial results.`);
              received.set(agent.uid, result);
              heldMode.add(agent.uid);
              socket.end("ACK-V1\n", () => reports.get(agent.uid).resolve());
              return;
            }
            if (result.phase === "fd-transfer") {
              requireValue(plan.fdTransferProbe && received.has(agent.uid) &&
                !transferResults.has(agent.uid) &&
                (agent.uid === plan.agents[0].uid
                  ? ["sent", "denied", "unreachable"].includes(result.status)
                  : ["used", "denied", "unreachable"].includes(result.status)),
              `Agent ${agent.uid} sent an invalid descriptor-transfer result.`);
              transferResults.set(agent.uid, result.status);
              socket.end("ACK-V1\n", () => transferReports.get(agent.uid).resolve());
              return;
            }
            requireValue(result.phase === "revoked" && revoking.has(agent.uid) &&
              heldSockets.has(agent.uid) && result.heldClosed === true &&
              result.reconnectDenied === true && !revokedReports.has(agent.uid),
            `Agent ${agent.uid} failed live peer revocation.`);
            revokedReports.set(agent.uid, result);
            socket.end("ACK-V1\n", () => finalReports.get(agent.uid).resolve());
          } catch (error) {
            failed.resolve(error);
            throw error;
          }
        }
      });
      servers.push(resultServer);
      const session = { uid: agent.uid, gid: agent.gid, sessionId: agent.sessionId, name: agent.account };
      const stopProbe = await new MacAgentSessionLeases(plan.leaseDir).register(session, probeServer.registerSession);
      probeStops.set(agent.uid, stopProbe);
      stops.push(stopProbe);
      stops.push(resultServer.registerSession(session));
    }
    for (const agent of plan.agents) {
      requireValue(await sendProbe(agent.socketPath, agent.uid, agent.sessionId) === "",
        "The broker account was accepted as an agent.");
    }
    const launchPlans = plan.agents.map((agent, i) => {
      const other = plan.agents[1 - i];
      return {
        account: agent.account,
        runnerArgv: [String(agent.uid), String(agent.gid), agent.sessionId, agent.workspace,
          agent.socketPath, plan.nodeExecutable, "--", plan.stagedAgentScript, "--agent",
          String(agent.uid), String(agent.gid), agent.sessionId, agent.socketPath, other.socketPath,
          String(other.uid), other.sessionId, agent.reportSocketPath,
          String(ipv4.port), String(ipv6.port), String(udp4.port), String(udp6.port),
          plan.brokerCanary, other.workspace,
          ...(plan.hostIpv4Probe ? [`--host-ipv4=${plan.hostIpv4Probe},${hostIpv4Tcp.port},${hostIpv4Udp.port}`] : []),
          ...(plan.fdTransferProbe ? [i === 0 ? "send" : "recv",
            plan.fdTransferProbe.helperExecutable, plan.fdTransferProbe.rendezvousPath] : [])]
      };
    });
    process.stdout.write(`${JSON.stringify({ event: "ready", launchPlans })}\n`);
    const timeout = new Promise((_, reject) => {
      deadlineTimer = setTimeout(() => reject(new Error("Two-UID native acceptance timed out.")), 300_000);
    });
    await Promise.race([
      Promise.all([...launchSeen.values(), ...reports.values()].map(item => item.promise)),
      failed.promise.then(error => { throw error; }), timeout
    ]);
    await Promise.race([
      Promise.all([...heldSeen.values(), ...transferReports.values()].map(item => item.promise)),
      failed.promise.then(error => { throw error; }), timeout
    ]);
    if (plan.fdTransferProbe) {
      const donor = transferResults.get(plan.agents[0].uid);
      const recipient = transferResults.get(plan.agents[1].uid);
      requireTransferDenial(donor, recipient, transferStarted);
    }
    for (const agent of plan.agents) {
      revoking.add(agent.uid);
      probeStops.get(agent.uid)();
    }
    await Promise.race([
      Promise.all([...closedSeen.values(), ...finalReports.values()].map(item => item.promise)),
      failed.promise.then(error => { throw error; }), timeout
    ]);
    await delay(200);
    requireValue(ipv4.hits() === 0 && ipv6.hits() === 0 &&
      udp4.hits() === 0 && udp6.hits() === 0,
      "An agent reached a host-loopback listener directly.");
    if (plan.hostIpv4Probe) {
      requireValue(hostIpv4Tcp.hits() === 0 && hostIpv4Udp.hits() === 0,
        "An agent reached the host's non-loopback IPv4 listener directly.");
    }
    for (const stop of stops) stop();
    await Promise.all(plan.agents.map(async agent => {
      try {
        await new MacAgentSessionLeases(plan.leaseDir).register(
          { uid: agent.uid, gid: agent.gid, sessionId: agent.sessionId, name: agent.account }, () => () => {});
        throw new Error(`Agent UID ${agent.uid} was reusable after the broker stopped it.`);
      } catch (error) {
        requireValue(String(error).includes("already used"), `Unexpected UID reuse result: ${error}`);
      }
    }));
    process.stdout.write(`${JSON.stringify({ event: "passed", uids: plan.agents.map(agent => agent.uid),
      brokerLeasesRetained: true, livePeerRevocation: true,
      hostLoopbackDenied: true, udpHostLoopbackDenied: true,
      ...(plan.hostIpv4Probe ? { hostIpv4Denied: true } : {}),
      ...(plan.fdTransferProbe ? { crossAgentDescriptorTransferDenied: true } : {}) })}\n`);
  } finally {
    clearTimeout(deadlineTimer);
    process.off("SIGINT", interrupted);
    process.off("SIGTERM", interrupted);
    for (const stop of stops) stop();
    for (const server of servers.reverse()) await server.close();
    await ipv4?.close();
    await ipv6?.close();
    await udp4?.close();
    await udp6?.close();
    await hostIpv4Tcp?.close();
    await hostIpv4Udp?.close();
  }
}

async function sendReport(location, result) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(location);
    let response = "";
    socket.setTimeout(3000, () => { socket.destroy(); reject(new Error("Broker result acknowledgement timed out.")); });
    socket.once("connect", () => socket.write(`${JSON.stringify(result)}\n`));
    socket.on("data", chunk => { response += String(chunk); });
    socket.once("error", reject);
    socket.once("close", () => response === "ACK-V1\n" ? resolve() : reject(new Error("Broker rejected the agent result.")));
  });
}

function waitForHeldProbeClose(location) {
  return new Promise((resolve, reject) => {
    const socket = createConnection(location);
    let connected = false;
    let acknowledged = false;
    let reply = "";
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error("Held agent probe did not close after revocation."));
    }, 15_000);
    socket.once("connect", () => { connected = true; });
    socket.on("data", chunk => {
      reply += String(chunk);
      if (reply === "HELD-V1\n" && !acknowledged) {
        acknowledged = true;
        socket.write("HOLD-ACK-V1\n");
      } else if (reply.length > "HELD-V1\n".length) {
        socket.destroy();
      }
    });
    socket.once("error", error => { if (!connected) reject(error); });
    socket.once("close", () => {
      clearTimeout(timer);
      if (!connected || !acknowledged) reject(new Error("The held agent probe was never accepted."));
      else resolve();
    });
  });
}

async function selfTestReport() {
  const udp4 = await startUdpLoopback("127.0.0.1");
  const udp6 = await startUdpLoopback("::1");
  try {
    await sendUdpProbe("127.0.0.1", udp4.port);
    await sendUdpProbe("::1", udp6.port);
    await delay(50);
    requireValue(udp4.hits() > 0 && udp6.hits() > 0,
      "The UDP test listeners did not record probe traffic.");
  } finally { await udp4.close(); await udp6.close(); }
  const localIpv4 = Object.values(networkInterfaces()).flat().find(address =>
    address?.family === "IPv4" && !address.internal);
  if (localIpv4) {
    const tcp = await startLoopback(localIpv4.address);
    const udp = await startUdpLoopback(localIpv4.address);
    try {
      requireValue(await canConnect(localIpv4.address, tcp.port),
        "The host IPv4 TCP control is unreachable.");
      await sendUdpProbe(localIpv4.address, udp.port);
      await delay(50);
      requireValue(tcp.hits() > 0 && udp.hits() > 0,
        "The host IPv4 test listeners did not record control traffic.");
    } finally { await tcp.close(); await udp.close(); }
  }
  let received;
  const server = createServer(socket => {
    void readReport(socket).then(frame => {
      received = JSON.parse(frame);
      socket.end("ACK-V1\n");
    }).catch(() => socket.destroy());
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  try {
    await sendReport({ host: "127.0.0.1", port: server.address().port }, { uid: 231001, passed: true });
    requireValue(received?.uid === 231001 && received.passed === true,
      "The newline-framed result exchange failed.");
  } finally { await new Promise(resolve => server.close(resolve)); }
  const heldServer = createServer(socket => {
    socket.write("HELD-V1\n");
    void readReport(socket).then(frame => {
      if (frame !== "HOLD-ACK-V1") throw new Error("The held probe acknowledgement was wrong.");
      socket.destroy();
    }).catch(() => socket.destroy());
  });
  await new Promise((resolve, reject) => {
    heldServer.once("error", reject);
    heldServer.listen(0, "127.0.0.1", resolve);
  });
  try {
    await waitForHeldProbeClose({ host: "127.0.0.1", port: heldServer.address().port });
  } finally { await new Promise(resolve => heldServer.close(resolve)); }
  const transferFailed = deferred();
  const transferServer = createServer(socket => {
    socket.on("error", () => socket.destroy());
    watchTransferredSocket(socket, transferFailed, 231001);
  });
  await new Promise((resolve, reject) => {
    transferServer.once("error", reject);
    transferServer.listen(0, "127.0.0.1", resolve);
  });
  const transferClient = createConnection({ host: "127.0.0.1", port: transferServer.address().port });
  transferClient.on("error", () => transferClient.destroy());
  let transferTimer;
  try {
    await new Promise((resolve, reject) => {
      transferClient.once("connect", resolve);
      transferClient.once("error", reject);
    });
    transferClient.write("XFER-USE-V1\n");
    const breach = await Promise.race([
      transferFailed.promise,
      new Promise((_, reject) => {
        transferTimer = setTimeout(() => reject(new Error("The transferred-socket observer did not reject use.")), 1500);
      })
    ]);
    requireValue(breach instanceof Error && breach.message.includes("used by the other UID"),
      "The transferred-socket observer missed an authenticated descriptor use.");
  } finally {
    clearTimeout(transferTimer);
    transferClient.destroy();
    await new Promise(resolve => transferServer.close(resolve));
  }
  let rejectedUsed = false;
  try { requireTransferDenial("denied", "used", false); }
  catch (error) { rejectedUsed = String(error).includes("used a donor-authenticated descriptor"); }
  requireValue(rejectedUsed, "A recipient that used the descriptor was accepted after a donor denial.");
  requireTransferDenial("denied", "unreachable", false);
  process.stdout.write("Native acceptance result, held-probe framing, and network controls passed local round trips.\n");
}

function runTransferHelper(role, helperExecutable, rendezvousPath, reportSocket) {
  const args = role === "send"
    ? [role, rendezvousPath, reportSocket]
    : [role, rendezvousPath];
  const result = spawnSync(helperExecutable, args, {
    encoding: "utf8", env: {}, timeout: 18_000, maxBuffer: 1024
  });
  requireValue(!result.error && result.status === 0 && !result.stderr,
    `Native descriptor-transfer helper failed: ${result.error?.message || result.stderr || result.status}`);
  const status = result.stdout.trim();
  requireValue(role === "send"
    ? ["sent", "denied", "unreachable"].includes(status)
    : ["used", "denied", "unreachable"].includes(status),
  "Native descriptor-transfer helper returned an invalid result.");
  return status;
}

async function runAgent(args) {
  requireValue(process.platform === "darwin" && args.length >= 14,
    "Invalid native agent fixture arguments.");
  const [uidText, gidText, sessionId, ownSocket, otherSocket, otherUidText, otherSession,
    reportSocket, ipv4Text, ipv6Text, udp4Text, udp6Text, brokerCanary, otherWorkspace] = args;
  const extras = args.slice(14);
  let hostIpv4Probe;
  if (extras[0]?.startsWith("--host-ipv4=")) {
    const match = /^--host-ipv4=([^,]+),(\d+),(\d+)$/.exec(extras.shift());
    requireValue(match && isIP(match[1]) === 4 && !match[1].startsWith("127."),
      "Malformed host IPv4 probe target.");
    hostIpv4Probe = { address: match[1], tcpPort: Number(match[2]), udpPort: Number(match[3]) };
    requireValue(Number.isSafeInteger(hostIpv4Probe.tcpPort) && hostIpv4Probe.tcpPort > 0 &&
      Number.isSafeInteger(hostIpv4Probe.udpPort) && hostIpv4Probe.udpPort > 0,
    "Malformed host IPv4 probe ports.");
  }
  requireValue(extras.length === 0 || extras.length === 3, "Malformed optional agent fixture arguments.");
  const [transferRole, transferHelper, transferRendezvous] = extras;
  const uid = Number(uidText);
  const gid = Number(gidText);
  const otherUid = Number(otherUidText);
  const ipv4Port = Number(ipv4Text);
  const ipv6Port = Number(ipv6Text);
  const udp4Port = Number(udp4Text);
  const udp6Port = Number(udp6Text);
  requireValue(Number.isSafeInteger(uid) && uid > 0 && Number.isSafeInteger(gid) && gid > 0 &&
    Number.isSafeInteger(otherUid) && otherUid > 0 &&
    Number.isSafeInteger(ipv4Port) && ipv4Port > 0 && Number.isSafeInteger(ipv6Port) && ipv6Port > 0 &&
    Number.isSafeInteger(udp4Port) && udp4Port > 0 && Number.isSafeInteger(udp6Port) && udp6Port > 0 &&
    sessionPattern.test(sessionId) && sessionPattern.test(otherSession) &&
    [ownSocket, otherSocket, reportSocket, brokerCanary, otherWorkspace].every(isFixturePath),
    "Malformed agent fixture identity or paths.");
  if (transferRole !== undefined) {
    requireValue(["send", "recv"].includes(transferRole) &&
      isFixturePath(transferHelper) && isFixturePath(transferRendezvous),
    "Malformed descriptor-transfer fixture paths.");
  }
  requireValue(process.getuid?.() === uid && process.geteuid?.() === uid &&
    process.getgid?.() === gid && process.getegid?.() === gid &&
    (process.getgroups?.() ?? []).every(group => group === gid) &&
    process.env.SGW_AGENT_SOCKET === ownSocket, "The agent was not launched under its planned UID and socket.");
  const wrongSession = sessionId === "wrong" ? "other" : "wrong";
  const wrongSessionReply = await sendProbe(ownSocket, uid, wrongSession);
  const wrongUidReply = await sendProbe(ownSocket, otherUid, sessionId);
  const otherReply = await sendProbe(otherSocket, otherUid, otherSession);
  const ownReply = await sendProbe(ownSocket, uid, sessionId);
  await sendUdpProbe("127.0.0.1", udp4Port);
  await sendUdpProbe("::1", udp6Port);
  if (hostIpv4Probe) await sendUdpProbe(hostIpv4Probe.address, hostIpv4Probe.udpPort);
  let brokerCanaryDenied = false;
  let otherWorkspaceDenied = false;
  try { await readFile(brokerCanary); }
  catch (error) { brokerCanaryDenied = error?.code === "EACCES" || error?.code === "EPERM"; }
  try { await readdir(otherWorkspace); }
  catch (error) { otherWorkspaceDenied = error?.code === "EACCES" || error?.code === "EPERM"; }
  const result = {
    phase: "initial", uid, sessionId,
    wrongClaimDenied: wrongSessionReply === "" && wrongUidReply === "",
    crossIdentityDenied: otherReply === "",
    ownAccepted: ownReply === `READY-V1 ${uid} ${sessionId}\n`,
    ipv4Denied: !await canConnect("127.0.0.1", ipv4Port),
    ipv6Denied: !await canConnect("::1", ipv6Port),
    ...(hostIpv4Probe ? { hostIpv4Denied: !await canConnect(hostIpv4Probe.address, hostIpv4Probe.tcpPort) } : {}),
    brokerCanaryDenied, otherWorkspaceDenied
  };
  await sendReport(reportSocket, result);
  requireValue(Object.values(result).slice(3).every(value => value === true),
    "An agent identity or direct-network probe failed.");
  if (transferRole) {
    const status = runTransferHelper(transferRole, transferHelper, transferRendezvous, reportSocket);
    await sendReport(reportSocket, { phase: "fd-transfer", uid, sessionId, status });
  }
  await waitForHeldProbeClose(ownSocket);
  const revoked = { phase: "revoked", uid, sessionId,
    heldClosed: true, reconnectDenied: await sendProbe(ownSocket, uid, sessionId) === "" };
  await sendReport(reportSocket, revoked);
  requireValue(revoked.reconnectDenied, "A revoked agent reconnected to the broker probe.");
}

async function main() {
  const [mode, config, ...extra] = process.argv.slice(2);
  if (mode === "--self-test" && config === undefined) { await selfTestReport(); return; }
  if (mode === "--agent") { await runAgent([config, ...extra]); return; }
  requireValue((mode === "--check" || mode === "--run") && config && extra.length === 0 &&
    path.isAbsolute(config), "Usage: script --check|--run /absolute/plan.json");
  const plan = parsePlan(await readFile(config, "utf8"));
  await preflight(plan);
  if (mode === "--check") { process.stdout.write("Preprovisioned macOS acceptance paths and accounts passed read-only checks.\n"); return; }
  await runBroker(plan);
}

main().catch(error => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
