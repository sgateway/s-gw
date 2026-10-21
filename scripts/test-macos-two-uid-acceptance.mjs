#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { access, lstat, readFile, realpath, readdir } from "node:fs/promises";
import { constants } from "node:fs";
import { createConnection, createServer } from "node:net";
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
  const launchSeen = new Map();
  const reports = new Map();
  const failed = deferred();
  let ipv4;
  let ipv6;
  let deadlineTimer;
  function interrupted() { failed.resolve(new Error("Native acceptance was interrupted.")); }
  process.once("SIGINT", interrupted);
  process.once("SIGTERM", interrupted);
  try {
    ipv4 = await startLoopback("127.0.0.1");
    ipv6 = await startLoopback("::1");
    for (const agent of plan.agents) {
      launchSeen.set(agent.uid, deferred());
      reports.set(agent.uid, deferred());
      const probeServer = await startVerifiedPeerServer({
        socketPath: agent.socketPath, socketMode: 0o660, socketGid: agent.gid,
        onConnection: async (socket, principal, peer) => {
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
            const result = JSON.parse(raw);
            requireValue(peer.uid === agent.uid && principal.principalId === `darwin:uid:${agent.uid}` &&
              result.uid === agent.uid && result.sessionId === agent.sessionId &&
              result.wrongClaimDenied === true && result.crossIdentityDenied === true &&
              result.ownAccepted === true && result.ipv4Denied === true && result.ipv6Denied === true &&
              result.brokerCanaryDenied === true && result.otherWorkspaceDenied === true,
              `Agent ${agent.uid} failed a native isolation probe.`);
            requireValue(!received.has(agent.uid), `Agent ${agent.uid} sent duplicate results.`);
            received.set(agent.uid, result);
            socket.end("ACK-V1\n", () => reports.get(agent.uid).resolve());
          } catch (error) {
            failed.resolve(error);
            throw error;
          }
        }
      });
      servers.push(resultServer);
      const session = { uid: agent.uid, gid: agent.gid, sessionId: agent.sessionId, name: agent.account };
      stops.push(await new MacAgentSessionLeases(plan.leaseDir).register(session, probeServer.registerSession));
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
          String(ipv4.port), String(ipv6.port), plan.brokerCanary, other.workspace]
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
    await delay(200);
    requireValue(ipv4.hits() === 0 && ipv6.hits() === 0,
      "An agent reached a host-loopback listener directly.");
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
      brokerLeasesRetained: true, hostLoopbackDenied: true })}\n`);
  } finally {
    clearTimeout(deadlineTimer);
    process.off("SIGINT", interrupted);
    process.off("SIGTERM", interrupted);
    for (const stop of stops) stop();
    for (const server of servers.reverse()) await server.close();
    await ipv4?.close();
    await ipv6?.close();
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

async function selfTestReport() {
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
  process.stdout.write("Native acceptance result framing passed a local round trip.\n");
}

async function runAgent(args) {
  requireValue(process.platform === "darwin" && args.length === 12, "Invalid native agent fixture arguments.");
  const [uidText, gidText, sessionId, ownSocket, otherSocket, otherUidText, otherSession,
    reportSocket, ipv4Text, ipv6Text, brokerCanary, otherWorkspace] = args;
  const uid = Number(uidText);
  const gid = Number(gidText);
  const otherUid = Number(otherUidText);
  const ipv4Port = Number(ipv4Text);
  const ipv6Port = Number(ipv6Text);
  requireValue(Number.isSafeInteger(uid) && uid > 0 && Number.isSafeInteger(gid) && gid > 0 &&
    Number.isSafeInteger(otherUid) && otherUid > 0 &&
    Number.isSafeInteger(ipv4Port) && ipv4Port > 0 && Number.isSafeInteger(ipv6Port) && ipv6Port > 0 &&
    sessionPattern.test(sessionId) && sessionPattern.test(otherSession) &&
    [ownSocket, otherSocket, reportSocket, brokerCanary, otherWorkspace].every(isFixturePath),
    "Malformed agent fixture identity or paths.");
  requireValue(process.getuid?.() === uid && process.geteuid?.() === uid &&
    process.getgid?.() === gid && process.getegid?.() === gid &&
    (process.getgroups?.() ?? []).every(group => group === gid) &&
    process.env.SGW_AGENT_SOCKET === ownSocket, "The agent was not launched under its planned UID and socket.");
  const wrongSession = sessionId === "wrong" ? "other" : "wrong";
  const wrongSessionReply = await sendProbe(ownSocket, uid, wrongSession);
  const wrongUidReply = await sendProbe(ownSocket, otherUid, sessionId);
  const otherReply = await sendProbe(otherSocket, otherUid, otherSession);
  const ownReply = await sendProbe(ownSocket, uid, sessionId);
  let brokerCanaryDenied = false;
  let otherWorkspaceDenied = false;
  try { await readFile(brokerCanary); }
  catch (error) { brokerCanaryDenied = error?.code === "EACCES" || error?.code === "EPERM"; }
  try { await readdir(otherWorkspace); }
  catch (error) { otherWorkspaceDenied = error?.code === "EACCES" || error?.code === "EPERM"; }
  const result = {
    uid, sessionId,
    wrongClaimDenied: wrongSessionReply === "" && wrongUidReply === "",
    crossIdentityDenied: otherReply === "",
    ownAccepted: ownReply === `READY-V1 ${uid} ${sessionId}\n`,
    ipv4Denied: !await canConnect("127.0.0.1", ipv4Port),
    ipv6Denied: !await canConnect("::1", ipv6Port),
    brokerCanaryDenied, otherWorkspaceDenied
  };
  await sendReport(reportSocket, result);
  requireValue(Object.values(result).slice(2).every(value => value === true),
    "An agent identity or direct-network probe failed.");
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
