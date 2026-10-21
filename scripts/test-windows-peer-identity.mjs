import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import net from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "win32") {
  console.log("Skipping native Windows peer-pipe acceptance test on this platform.");
  process.exit(0);
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const helper = resolve(root, "dist/native", `win32-${process.arch}`, "s-gw-windows-peer-identity.exe");
const tokenSource = resolve(root, "native/windows-peer-identity/test-token.c");
const appContainerSource = resolve(root, "native/windows-peer-identity/test-appcontainer.c");
assert.ok(existsSync(helper), "The native peer helper must be built before its acceptance test.");

function deadline(promise, ms, label) {
  let timer;
  const timed = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out.`)), ms);
  });
  return Promise.race([promise, timed]).finally(() => clearTimeout(timer));
}

function launch(args, executable = helper) {
  const child = spawn(executable, args, { stdio: ["pipe", "pipe", "pipe"], windowsHide: true });
  let output = Buffer.alloc(0);
  let stderr = "";
  let readyDone;
  const ready = new Promise(resolve => { readyDone = resolve; });
  let finish;
  const done = new Promise(resolve => { finish = resolve; });
  let spawnError;

  child.stdout.on("data", chunk => {
    output = Buffer.concat([output, chunk]);
    if (output.length) readyDone(output[0] === 0x52);
  });
  child.stderr.on("data", chunk => { stderr += chunk.toString(); });
  child.once("error", error => { spawnError = error; });
  child.once("close", (code, signal) => {
    readyDone(false);
    finish({ code, signal, output, stderr, spawnError });
  });
  return { child, ready, done };
}

function pipeName() {
  return String.raw`\\.\pipe\LOCAL\s-gw-` + randomBytes(16).toString("hex");
}

async function rejectsBeforePipe(args, label) {
  const run = launch(args);
  try {
    const result = await deadline(run.done, 10_000, label);
    assert.equal(result.spawnError, undefined, `${label}: helper failed to start`);
    assert.notEqual(result.code, 0, `${label}: helper unexpectedly succeeded`);
    assert.equal(result.output.length, 0, `${label}: helper opened a pipe`);
  } finally {
    run.child.kill();
  }
}

async function rejectsClient(args, label) {
  const run = launch(args);
  let socket;
  let reply = Buffer.alloc(0);
  try {
    assert.equal(await deadline(run.ready, 10_000, label), true, `${label}: pipe was not ready`);
    socket = net.createConnection({ path: args[0] });
    socket.on("data", chunk => { reply = Buffer.concat([reply, chunk]); });
    socket.on("error", () => {});
    await deadline(new Promise((resolveConnect, rejectConnect) => {
      socket.once("connect", resolveConnect);
      socket.once("error", rejectConnect);
    }), 10_000, `${label} client connection`);
    socket.write(Buffer.from("untrusted peer"));
    const result = await deadline(run.done, 10_000, label);
    assert.equal(result.spawnError, undefined, `${label}: helper failed to start`);
    assert.notEqual(result.code, 0, `${label}: untrusted peer was accepted`);
    assert.equal(result.output.toString(), "R", `${label}: helper forwarded an untrusted request`);
    assert.equal(reply.length, 0, `${label}: helper replied to an untrusted peer`);
  } finally {
    socket?.destroy();
    run.child.kill();
  }
}

function requestFrame(child) {
  return new Promise((resolveFrame, rejectFrame) => {
    let buffered = Buffer.alloc(0);
    const cleanup = () => {
      child.stdout.off("data", onData);
      child.off("close", onClose);
    };
    const onClose = () => {
      cleanup();
      rejectFrame(new Error("The peer helper closed before forwarding the request."));
    };
    const onData = chunk => {
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.length < 5) return;
      const size = buffered.readUInt32LE(1);
      if (buffered[0] !== 0x51 || size < 1 || size > 32 * 1024 || buffered.length > size + 5) {
        cleanup();
        rejectFrame(new Error("The peer helper sent an invalid request frame."));
        return;
      }
      if (buffered.length < size + 5) return;
      cleanup();
      resolveFrame(buffered.subarray(5));
    };
    child.stdout.on("data", onData);
    child.once("close", onClose);
  });
}

async function acceptsAppContainer(executable, profile, packageSid, brokerSid, logonLuid, sessionId) {
  const name = pipeName();
  const run = launch([name, brokerSid, brokerSid, packageSid, logonLuid, sessionId]);
  const loopback = net.createServer(socket => { loopbackHits++; socket.destroy(); });
  let loopbackHits = 0;
  let client;
  try {
    await deadline(new Promise((resolveListen, rejectListen) => {
      loopback.once("error", rejectListen);
      loopback.listen(0, "127.0.0.1", () => { loopback.off("error", rejectListen); resolveListen(); });
    }), 10_000, "loopback probe listener");
    const hostReached = new Promise(resolveHost => loopback.once("connection", resolveHost));
    const hostProbe = net.createConnection({ host: "127.0.0.1", port: loopback.address().port });
    hostProbe.on("error", () => {});
    await deadline(hostReached, 5_000, "host loopback control");
    hostProbe.destroy();
    assert.equal(loopbackHits, 1, "The host loopback control did not reach its listener.");
    loopbackHits = 0;
    assert.equal(await deadline(run.ready, 30_000, "AppContainer pipe"), true,
      "The AppContainer pipe was not ready.");
    const request = requestFrame(run.child);
    client = launch(["launch", profile, name, String(loopback.address().port)], executable);
    const forwarded = await deadline(Promise.race([
      request,
      client.done.then(result => {
        throw new Error(result.stderr || `AppContainer client exited before the request (${result.code}).`);
      })
    ]), 35_000, "AppContainer request");
    assert.equal(forwarded.toString(), "appcontainer probe");

    const reply = Buffer.from("broker reply");
    const header = Buffer.alloc(5);
    header[0] = 0x53;
    header.writeUInt32LE(reply.length, 1);
    run.child.stdin.end(Buffer.concat([header, reply]));

    const [broker, agent] = await Promise.all([
      deadline(run.done, 30_000, "AppContainer broker exchange"),
      deadline(client.done, 30_000, "AppContainer client")
    ]);
    assert.equal(broker.code, 0, broker.stderr || "The broker did not complete the verified exchange.");
    assert.equal(agent.code, 0, agent.stderr || "The AppContainer client did not receive the broker reply.");
    assert.equal(loopbackHits, 0, "The AppContainer reached host loopback without a network capability.");
  } finally {
    client?.child.kill();
    run.child.kill();
    await new Promise(resolveClose => loopback.close(() => resolveClose()));
  }
}

function compileFixture(source, output, libraries) {
  const compiled = spawnSync("cl", [
    "/nologo", "/std:c11", "/W4", "/WX", "/O2", "/GS", "/sdl", "/DUNICODE", "/D_UNICODE",
    `/Fo${join(tmp, `${output}.obj`)}`, `/Fe${join(tmp, `${output}.exe`)}`, source,
    "/link", "/INCREMENTAL:NO", "/DYNAMICBASE", "/NXCOMPAT", ...libraries
  ], { encoding: "utf8", windowsHide: true });
  assert.equal(compiled.error, undefined, compiled.error?.message);
  assert.equal(compiled.status, 0, compiled.stderr || compiled.stdout);
  return join(tmp, `${output}.exe`);
}

const tmp = mkdtempSync(join(tmpdir(), "s-gw-windows-peer-test-"));
try {
  const tokenProbe = compileFixture(tokenSource, "test-token", ["advapi32.lib"]);
  const appContainerFixture = compileFixture(appContainerSource, "test-appcontainer",
    ["advapi32.lib", "userenv.lib", "ws2_32.lib"]);

  const probed = spawnSync(tokenProbe, [], { encoding: "utf8", windowsHide: true });
  assert.equal(probed.status, 0, probed.stderr || "Could not inspect the CI process token.");
  const [brokerSid, logonLuid, sessionId, isAppContainer] = probed.stdout.trim().split(/\r?\n/);
  assert.match(brokerSid, /^S-1-(?:\d+-)+\d+$/);
  assert.match(logonLuid, /^[a-f\d]{16}$/i);
  assert.match(sessionId, /^\d+$/);
  assert.equal(isAppContainer, "0", "The CI broker must run outside an AppContainer.");

  await rejectsBeforePipe([pipeName(), "S-1-1-0", brokerSid, "-", logonLuid, sessionId],
    "broker SID mismatch");
  await rejectsBeforePipe([pipeName(), brokerSid, brokerSid, "-", logonLuid, sessionId],
    "same broker and agent SID without AppContainer");
  await rejectsBeforePipe([String.raw`\\.\pipe\s-gw-` + randomBytes(16).toString("hex"),
    brokerSid, "S-1-1-0", "-", logonLuid, sessionId], "non-local pipe name");
  await rejectsBeforePipe([pipeName(), brokerSid, "S-1-1-0", "-", "0", sessionId],
    "malformed logon LUID");

  await rejectsClient([pipeName(), brokerSid, "S-1-1-0", "-", logonLuid, sessionId],
    "wrong agent user SID");
  await rejectsClient([pipeName(), brokerSid, brokerSid, "S-1-15-2-1", logonLuid, sessionId],
    "ordinary client without the required AppContainer");

  const profileName = `sgw-pipe-test-${randomBytes(8).toString("hex")}`;
  const created = spawnSync(appContainerFixture, ["create", profileName],
    { encoding: "utf8", windowsHide: true });
  assert.equal(created.status, 0, created.stderr || "Could not create the temporary AppContainer profile.");
  try {
    const packageSid = created.stdout.trim();
    assert.match(packageSid, /^S-1-15-2-(?:\d+-)*\d+$/);
    for (const [path, permission] of [[tmp, `(OI)(CI)RX`], [appContainerFixture, "RX"]]) {
      const acl = spawnSync("icacls", [path, "/grant", `*${packageSid}:${permission}`],
        { encoding: "utf8", windowsHide: true });
      assert.equal(acl.status, 0, acl.stderr || acl.stdout);
    }
    await acceptsAppContainer(appContainerFixture, profileName, packageSid, brokerSid, logonLuid, sessionId);
  } finally {
    const deleted = spawnSync(appContainerFixture, ["delete", profileName],
      { encoding: "utf8", windowsHide: true });
    assert.equal(deleted.status, 0, deleted.stderr || "Could not delete the temporary AppContainer profile.");
  }
  console.log("Native Windows peer-pipe identity rejection and AppContainer exchange passed.");
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
