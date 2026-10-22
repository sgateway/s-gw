import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
const wfpSource = resolve(root, "native/windows-peer-identity/wfp-boundary.c");
const parentEnvCanary = randomBytes(16).toString("hex");
assert.ok(existsSync(helper), "The native peer helper must be built before its acceptance test.");

function deadline(promise, ms, label) {
  let timer;
  const timed = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out.`)), ms);
  });
  return Promise.race([promise, timed]).finally(() => clearTimeout(timer));
}

function launch(args, executable = helper) {
  const child = spawn(executable, args, {
    stdio: ["pipe", "pipe", "pipe"], windowsHide: true,
    env: { ...process.env, SGW_WIN_FIXTURE_PARENT_CANARY: parentEnvCanary }
  });
  let output = Buffer.alloc(0);
  let stderr = "";
  let readyDone;
  const ready = new Promise(resolve => { readyDone = resolve; });
  let jobReadyDone;
  const jobReady = new Promise(resolve => { jobReadyDone = resolve; });
  let wfpReadyDone;
  const wfpReady = new Promise(resolve => { wfpReadyDone = resolve; });
  let finish;
  const done = new Promise(resolve => { finish = resolve; });
  let reportPid;
  const processPid = new Promise(resolve => { reportPid = resolve; });
  let spawnError;

  child.stdout.on("data", chunk => {
    output = Buffer.concat([output, chunk]);
    const report = output.toString("ascii");
    const match = /(?:^|\n)CHILD-PID=(\d+)\r?\n/.exec(report);
    if (match) reportPid(Number(match[1]));
    if (/JOB-READY\r?\n/.test(report)) jobReadyDone(true);
    if (/WFP-READY\r?\n/.test(report)) wfpReadyDone(true);
    if (output.length) readyDone(output[0] === 0x52);
  });
  child.stderr.on("data", chunk => { stderr += chunk.toString(); });
  child.once("error", error => { spawnError = error; });
  child.once("close", (code, signal) => {
    readyDone(false);
    jobReadyDone(false);
    wfpReadyDone(false);
    reportPid(null);
    finish({ code, signal, output, stderr, spawnError });
  });
  return { child, ready, jobReady, wfpReady, done, processPid };
}

function pipeName() {
  return String.raw`\\.\pipe\LOCAL\s-gw-` + randomBytes(16).toString("hex");
}

function jobName() {
  return String.raw`Local\s-gw-agent-` + randomBytes(16).toString("hex");
}

async function rejectsBeforePipe(args, label, expectedStderr) {
  const run = launch(args);
  try {
    const result = await deadline(run.done, 10_000, label);
    assert.equal(result.spawnError, undefined, `${label}: helper failed to start`);
    assert.notEqual(result.code, 0, `${label}: helper unexpectedly succeeded`);
    assert.equal(result.output.length, 0, `${label}: helper opened a pipe`);
    if (expectedStderr) assert.equal(result.stderr.trim(), expectedStderr,
      `${label}: helper rejected the Job for the wrong reason`);
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

async function acceptsAppContainer(profile, brokerSid, logonLuid, sessionId,
  { intruderProfile, stopJob = false, sameProfileOutOfJob = false, transferTo = null } = {}) {
  const name = pipeName();
  const job = jobName();
  let run;
  const loopbackHits = { ipv4: 0, ipv6: 0 };
  const ipv4 = net.createServer(socket => { loopbackHits.ipv4++; socket.destroy(); });
  const ipv6 = net.createServer(socket => { loopbackHits.ipv6++; socket.destroy(); });
  let client, intruder, processProbe, sameProfileProbe, outsider, transferTarget;
  try {
    for (const [server, address, family] of [[ipv4, "127.0.0.1", "ipv4"], [ipv6, "::1", "ipv6"]]) {
      await deadline(new Promise((resolveListen, rejectListen) => {
        server.once("error", rejectListen);
        server.listen(0, address, () => { server.off("error", rejectListen); resolveListen(); });
      }), 10_000, `${family} loopback listener`);
      const hostReached = new Promise(resolveHost => server.once("connection", resolveHost));
      const hostProbe = net.createConnection({ host: address, port: server.address().port });
      hostProbe.on("error", () => {});
      await deadline(hostReached, 5_000, `${family} host loopback control`);
      hostProbe.destroy();
      assert.equal(loopbackHits[family], 1, `The host ${family} control did not reach its listener.`);
      loopbackHits[family] = 0;
    }
    let transferTargetPid = transferTo === "host" ? process.pid : undefined;
    if (transferTo === "same-profile") {
      transferTarget = launch(["launch-paused", profile.name, pipeName(),
        String(ipv4.address().port), String(ipv6.address().port), profile.sharedPath,
        profile.canaryPath, jobName()], profile.executable);
      assert.equal(await deadline(transferTarget.jobReady, 30_000, "transfer target Job"), true,
        "The same-profile target was not held in its own Job.");
      assert.equal(await deadline(transferTarget.wfpReady, 30_000, "transfer target WFP policy"), true,
        "The transfer target did not install its package-SID network deny.");
      transferTargetPid = await deadline(transferTarget.processPid, 10_000, "transfer target PID");
      assert.ok(Number.isInteger(transferTargetPid) && transferTargetPid > 0,
        "The same-profile target process ID was not reported.");
    }
    const launchMode = transferTo ? "launch-transfer-paused"
      : stopJob ? "launch-stop-paused" : "launch-paused";
    const clientArgs = [launchMode, profile.name, name,
      String(ipv4.address().port), String(ipv6.address().port), profile.sharedPath,
      profile.canaryPath, job];
    if (transferTargetPid) clientArgs.push(String(transferTargetPid));
    client = launch(clientArgs, profile.executable);
    assert.equal(await deadline(client.jobReady, 30_000, "AppContainer Job"), true,
      "The launcher did not create and retain the Job before the pipe opened.");
    assert.equal(await deadline(client.wfpReady, 30_000, "AppContainer WFP policy"), true,
      "The package-SID WFP deny was not installed before the agent resumed.");
    run = launch([name, brokerSid, brokerSid, profile.sid, logonLuid, sessionId, job]);
    assert.equal(await deadline(run.ready, 30_000, "AppContainer pipe"), true,
      "The AppContainer pipe was not ready.");
    if (intruderProfile) {
      intruder = launch(["launch", intruderProfile.name, name, String(ipv4.address().port),
        String(ipv6.address().port), intruderProfile.sharedPath, intruderProfile.canaryPath,
        jobName()],
      intruderProfile.executable);
      const denied = await deadline(intruder.done, 35_000, "cross-agent pipe attempt");
      assert.equal(denied.spawnError, undefined, denied.spawnError?.message);
      assert.notEqual(denied.code, 0, "The other AppContainer opened this agent's pipe.");
      assert.match(denied.stderr, /AppContainer pipe open failed: 5\r?\n/,
        "The other AppContainer was not denied by the pipe ACL.");
      assert.equal(run.child.exitCode, null, "The other AppContainer consumed the broker's pipe instance.");
    }
    if (sameProfileOutOfJob) {
      outsider = launch(["launch-unassigned", profile.name, name,
        String(ipv4.address().port), String(ipv6.address().port), profile.sharedPath,
        profile.canaryPath, job], profile.executable);
      const [outsiderResult, denied] = await Promise.all([
        deadline(outsider.done, 35_000, "same-profile process outside Job"),
        deadline(run.done, 35_000, "out-of-Job pipe attempt")
      ]);
      assert.equal(outsiderResult.spawnError, undefined, outsiderResult.spawnError?.message);
      assert.match(outsiderResult.output.toString(), /^OUT-OF-JOB-ATTESTED\r?\n$/,
        "The same-profile process was not checked outside the target Job.");
      assert.notEqual(outsiderResult.code, 0, "The process outside the Job got a broker reply.");
      assert.equal(denied.output.toString(), "R", "The helper forwarded an out-of-Job request.");
      assert.equal(denied.stderr.trim(), "Client outside registered Job.",
        "The helper denied this process for a reason other than Job membership.");
      run = launch([name, brokerSid, brokerSid, profile.sid, logonLuid, sessionId, job]);
      assert.equal(await deadline(run.ready, 30_000, "replacement AppContainer pipe"), true,
        "The helper could not reopen for the in-Job agent.");
    }
    const request = requestFrame(run.child);
    client.child.stdin.write("G");
    const forwarded = await deadline(Promise.race([
      request,
      client.done.then(result => {
        throw new Error(result.stderr || `AppContainer client exited before the request (${result.code}).`);
      })
    ]), 35_000, "AppContainer request");
    assert.equal(forwarded.toString(), "appcontainer probe");

    if (intruderProfile) {
      const targetPid = await deadline(client.processPid, 10_000, "AppContainer child PID");
      assert.ok(Number.isInteger(targetPid) && targetPid > 0,
        "The live AppContainer child process ID was not reported.");
      assert.equal(client.child.exitCode, null, "The target AppContainer exited before the handle probe.");
      assert.equal(run.child.exitCode, null, "The pipe broker exited before the handle probe.");
      processProbe = launch(["launch-process-probe", intruderProfile.name, name,
        String(ipv4.address().port), String(ipv6.address().port),
        intruderProfile.sharedPath, intruderProfile.canaryPath,
        jobName(), String(targetPid), String(run.child.pid)], intruderProfile.executable);
      const probeResult = await deadline(processProbe.done, 35_000, "cross-agent process-handle attempt");
      assert.equal(probeResult.spawnError, undefined, probeResult.spawnError?.message);
      assert.equal(probeResult.code, 0,
        probeResult.stderr || "The other AppContainer could open a protected process handle.");
      assert.match(probeResult.output.toString(), /^PROCESS-DUP-DENIED\r?\n$/,
        "The AppContainer process-handle probe did not run.");
    }
    if (transferTo === "same-profile") {
      const connectedPid = await deadline(client.processPid, 10_000, "connected client PID");
      assert.ok(Number.isInteger(connectedPid) && connectedPid > 0,
        "The connected AppContainer process ID was not reported.");
      sameProfileProbe = launch(["launch-process-probe", profile.name, name,
        String(ipv4.address().port), String(ipv6.address().port), profile.sharedPath,
        profile.canaryPath, jobName(), String(connectedPid), String(run.child.pid)], profile.executable);
      const probeResult = await deadline(sameProfileProbe.done, 35_000,
        "same-profile connected-handle pull attempt");
      assert.equal(probeResult.spawnError, undefined, probeResult.spawnError?.message);
      assert.equal(probeResult.code, 0,
        probeResult.stderr || "The same-profile outsider could open the connected client's process.");
      assert.match(probeResult.output.toString(), /^PROCESS-DUP-DENIED\r?\n$/,
        "The same-profile process-handle probe did not run.");
    }

    if (stopJob) {
      client.child.stdin.end("K");
      const stopped = await deadline(client.done, 15_000, "AppContainer job teardown");
      assert.equal(stopped.code, 0, stopped.stderr || "Closing the Job Object did not stop its child.");
      run.child.stdin.end();
      const broker = await deadline(run.done, 10_000, "broker after agent teardown");
      assert.notEqual(broker.code, 0, "The broker completed a request after the agent was killed.");
      assert.deepEqual(loopbackHits, { ipv4: 0, ipv6: 0 },
        "The AppContainer reached host loopback without a network capability.");
      return;
    }

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
    if (transferTo) {
      assert.match(agent.output.toString(), /(?:^|\n)CONNECTED-PIPE-TRANSFER-DENIED\r?\n/,
        `The connected client did not prove a denied handle transfer to the ${transferTo} target.`);
    }
    assert.deepEqual(loopbackHits, { ipv4: 0, ipv6: 0 },
      "The AppContainer reached host loopback without a network capability.");
  } finally {
    const processes = [processProbe, sameProfileProbe, intruder, outsider, client, run, transferTarget]
      .filter(Boolean);
    for (const item of processes) item.child.kill();
    await Promise.allSettled(processes.map(item => deadline(item.done, 5_000, "fixture cleanup")));
    for (const server of [ipv4, ipv6]) {
      if (server.listening) await new Promise(resolveClose => server.close(() => resolveClose()));
    }
  }
}

function compileFixture(source, output, libraries, extraSources = []) {
  const objects = [];
  for (const [index, file] of [source, ...extraSources].entries()) {
    const object = join(tmp, `${output}-${index}.obj`);
    const compiled = spawnSync("cl", [
      "/nologo", "/std:c11", "/W4", "/WX", "/O2", "/GS", "/sdl", "/DUNICODE", "/D_UNICODE",
      "/c", `/Fo${object}`, file
    ], { encoding: "utf8", windowsHide: true });
    assert.equal(compiled.error, undefined, compiled.error?.message);
    assert.equal(compiled.status, 0, compiled.stderr || compiled.stdout);
    objects.push(object);
  }
  const linked = spawnSync("cl", [
    "/nologo", ...objects, `/Fe${join(tmp, `${output}.exe`)}`,
    "/link", "/INCREMENTAL:NO", "/DYNAMICBASE", "/NXCOMPAT", ...libraries
  ], { encoding: "utf8", windowsHide: true });
  assert.equal(linked.error, undefined, linked.error?.message);
  assert.equal(linked.status, 0, linked.stderr || linked.stdout);
  return join(tmp, `${output}.exe`);
}

const tmp = mkdtempSync(join(tmpdir(), "s-gw-windows-peer-test-"));
try {
  const tokenProbe = compileFixture(tokenSource, "test-token", ["advapi32.lib"]);
  const appContainerFixture = compileFixture(appContainerSource, "test-appcontainer",
    ["advapi32.lib", "userenv.lib", "ws2_32.lib", "ole32.lib", "fwpuclnt.lib"], [wfpSource]);

  const probed = spawnSync(tokenProbe, [], { encoding: "utf8", windowsHide: true });
  assert.equal(probed.status, 0, probed.stderr || "Could not inspect the CI process token.");
  const [brokerSid, logonLuid, sessionId, isAppContainer] = probed.stdout.trim().split(/\r?\n/);
  assert.match(brokerSid, /^S-1-(?:\d+-)+\d+$/);
  assert.match(logonLuid, /^[a-f\d]{16}$/i);
  assert.match(sessionId, /^\d+$/);
  assert.equal(isAppContainer, "0", "The CI broker must run outside an AppContainer.");

  await rejectsBeforePipe([pipeName(), "S-1-1-0", brokerSid, "-", logonLuid, sessionId, jobName()],
    "broker SID mismatch");
  await rejectsBeforePipe([pipeName(), brokerSid, brokerSid, "-", logonLuid, sessionId, jobName()],
    "same broker and agent SID without AppContainer");
  await rejectsBeforePipe([String.raw`\\.\pipe\s-gw-` + randomBytes(16).toString("hex"),
    brokerSid, "S-1-1-0", "-", logonLuid, sessionId, jobName()], "non-local pipe name");
  await rejectsBeforePipe([pipeName(), brokerSid, "S-1-1-0", "-", "0", sessionId, jobName()],
    "malformed logon LUID");
  await rejectsBeforePipe([pipeName(), brokerSid, "S-1-1-0", "-", logonLuid, sessionId,
    "agent-chosen-job"], "malformed Job name");
  await rejectsBeforePipe([pipeName(), brokerSid, "S-1-1-0", "-", logonLuid, sessionId,
    jobName()], "missing launcher Job", "Registered Job unavailable.");

  for (const mode of ["job-host-no-kill", "job-host-breakaway"]) {
    const weakJob = jobName();
    const owner = launch([mode, weakJob], appContainerFixture);
    try {
      assert.equal(await deadline(owner.jobReady, 10_000, mode), true,
        `${mode}: fixture did not create a Job`);
      await rejectsBeforePipe([pipeName(), brokerSid, "S-1-1-0", "-", logonLuid, sessionId,
        weakJob], mode, "Registered Job lacks required limits.");
    } finally {
      owner.child.stdin.end();
      await deadline(owner.done, 10_000, `${mode} cleanup`);
    }
  }

  const emptyJob = jobName();
  const jobHost = launch(["job-host", emptyJob], appContainerFixture);
  try {
    assert.equal(await deadline(jobHost.jobReady, 10_000, "empty Job host"), true);
    await rejectsClient([pipeName(), brokerSid, "S-1-1-0", "-", logonLuid, sessionId,
      emptyJob], "wrong agent user SID");
    await rejectsClient([pipeName(), brokerSid, brokerSid, "S-1-15-2-1", logonLuid, sessionId,
      emptyJob], "ordinary client without the required AppContainer");
  } finally {
    jobHost.child.stdin.end();
    await deadline(jobHost.done, 10_000, "empty Job cleanup");
  }

  const profiles = [];
  try {
    for (let i = 0; i < 2; i++) {
      const name = `sgw-pipe-test-${randomBytes(8).toString("hex")}`;
      const created = spawnSync(appContainerFixture, ["create", name],
        { encoding: "utf8", windowsHide: true });
      assert.equal(created.status, 0, created.stderr || "Could not create a temporary AppContainer profile.");
      const profile = { name };
      profiles.push(profile);
      const [sid, folder] = created.stdout.trim().split(/\r?\n/);
      assert.match(sid, /^S-1-15-2-(?:\d+-)*\d+$/);
      assert.ok(folder && existsSync(folder), "The AppContainer profile folder is unavailable.");
      profile.sid = sid;
      profile.fixtureDir = join(folder, `s-gw-ci-${randomBytes(8).toString("hex")}`);
      mkdirSync(profile.fixtureDir);
      const acl = spawnSync("icacls", [profile.fixtureDir, "/grant", `*${sid}:(OI)(CI)RX`],
        { encoding: "utf8", windowsHide: true });
      assert.equal(acl.status, 0, acl.stderr || acl.stdout);
      profile.executable = join(profile.fixtureDir, "test-appcontainer.exe");
      profile.sharedPath = join(profile.fixtureDir, "agent-readable.txt");
      profile.canaryPath = join(tmp, `broker-only-canary-${name}.txt`);
      copyFileSync(appContainerFixture, profile.executable);
      writeFileSync(profile.sharedPath, "agent-readable fixture\n");
      writeFileSync(profile.canaryPath, "broker-only fixture data\n");
      const denied = spawnSync("icacls", [profile.canaryPath, "/deny", `*${sid}:(GR,GW,DE,WDAC,WO)`],
        { encoding: "utf8", windowsHide: true });
      assert.equal(denied.status, 0, denied.stderr || denied.stdout);
      assert.equal(readFileSync(profile.canaryPath, "utf8"), "broker-only fixture data\n",
        "The broker canary must remain readable to the host account.");
    }
    assert.notEqual(profiles[0].sid, profiles[1].sid, "The two agents need distinct package identities.");
    const wfpCheck = spawnSync(appContainerFixture, ["wfp-selftest", profiles[0].name, profiles[1].name],
      { encoding: "utf8", windowsHide: true, timeout: 30_000 });
    assert.equal(wfpCheck.status, 0, wfpCheck.stderr || "The WFP policy self-test failed.");
    assert.match(wfpCheck.stdout, /WFP-REVOCATION-DETECTED/);
    await acceptsAppContainer(profiles[0], brokerSid, logonLuid, sessionId,
      { intruderProfile: profiles[1], sameProfileOutOfJob: true });
    await acceptsAppContainer(profiles[1], brokerSid, logonLuid, sessionId,
      { intruderProfile: profiles[0] });
    await acceptsAppContainer(profiles[0], brokerSid, logonLuid, sessionId,
      { transferTo: "same-profile" });
    await acceptsAppContainer(profiles[0], brokerSid, logonLuid, sessionId,
      { transferTo: "host" });
    await acceptsAppContainer(profiles[0], brokerSid, logonLuid, sessionId, { stopJob: true });
    for (const profile of profiles) {
      assert.equal(readFileSync(profile.canaryPath, "utf8"), "broker-only fixture data\n",
        "The broker canary changed during AppContainer execution.");
    }
  } finally {
    for (const { name, fixtureDir } of profiles.reverse()) {
      if (fixtureDir) rmSync(fixtureDir, { recursive: true, force: true });
      const deleted = spawnSync(appContainerFixture, ["delete", name],
        { encoding: "utf8", windowsHide: true });
      assert.equal(deleted.status, 0, deleted.stderr || "Could not delete a temporary AppContainer profile.");
    }
  }
  console.log("Native Windows two-agent pipe, same-profile out-of-Job and connected-handle transfer denials to same-profile and host targets, process-handle, IPv4/IPv6 loopback, canary, Job teardown, and exchange passed.");
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
