import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { registerWindowsAgentLaunch } from "../src/windows-agent-launch-control.js";
import { WindowsAgentPipeRegistry, type WindowsAgentPipeIdentity } from "../src/windows-agent-pipe.js";

const oldTestMode = process.env.SGW_TEST_MODE;
beforeAll(() => { process.env.SGW_TEST_MODE = "1"; });
afterAll(() => {
  if (oldTestMode === undefined) delete process.env.SGW_TEST_MODE;
  else process.env.SGW_TEST_MODE = oldTestMode;
});

function identity(changes: Partial<WindowsAgentPipeIdentity> = {}): WindowsAgentPipeIdentity {
  return {
    brokerSid: "S-1-5-21-100-200-300-1001",
    userSid: "S-1-5-21-100-200-300-1001",
    appContainerSid: "S-1-15-2-111-222-333-444",
    logonLuid: "00000000000003e7",
    windowsSessionId: 3,
    jobName: String.raw`Local\s-gw-agent-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
    sessionId: "windows-session-1",
    name: "Synthetic Windows agent",
    ...changes
  };
}

function nativeChecks() {
  return {
    stopped: new AbortController().signal,
    childHandleLive: () => true,
    jobHandleConfined: () => true,
    wfpSessionHealthy: () => true,
    dnsBoundaryReady: () => true
  };
}

function waitingHelper(): ChildProcessWithoutNullStreams {
  const script = `
    const body = Buffer.from('native request');
    const header = Buffer.alloc(5);
    header[0] = 0x51;
    header.writeUInt32LE(body.length, 1);
    process.stdout.write(Buffer.concat([Buffer.from('R'), header, body]));
    setInterval(() => {}, 1000);
  `;
  return spawn(process.execPath, ["-e", script], { stdio: ["pipe", "pipe", "pipe"] });
}

describe("Windows broker launch control", () => {
  it("refuses registration unless every retained boundary check is ready", () => {
    const names = ["childHandleLive", "jobHandleConfined", "wfpSessionHealthy", "dnsBoundaryReady"] as const;
    const reserved = new Set<string>();
    for (const name of names) {
      const native = nativeChecks();
      native[name] = () => false;
      const registry = new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper);
      expect(() => registerWindowsAgentLaunch(registry, identity(), native,
        record => { reserved.add(record.sessionId); })).toThrow(name);
    }
    expect(reserved.size).toBe(0);
  });

  it("rejects an absent or asynchronous DNS check", () => {
    const registry = new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper);
    const absent = nativeChecks();
    delete (absent as Partial<typeof absent>).dnsBoundaryReady;
    expect(() => registerWindowsAgentLaunch(registry, identity(), absent, () => {}))
      .toThrow("dnsBoundaryReady");

    const asyncDns = nativeChecks();
    asyncDns.dnsBoundaryReady = (async () => true) as unknown as () => boolean;
    expect(() => registerWindowsAgentLaunch(new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper),
      identity(), asyncDns, () => {})).toThrow("dnsBoundaryReady");
  });

  it("rechecks DNS readiness before opening a broker pipe", async () => {
    let dnsReady = true;
    const native = { ...nativeChecks(), dnsBoundaryReady: () => dnsReady };
    const session = registerWindowsAgentLaunch(
      new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper), identity(), native, () => {});
    dnsReady = false;
    try {
      await expect(session.pipes.openOnce(async () => Buffer.from("ok"))).rejects.toThrow("dnsBoundaryReady");
    } finally {
      await session.confirmDrained();
    }
  });

  it("keeps native pipe opening disabled after adapter registration", async () => {
    const registry = new WindowsAgentPipeRegistry(
      String.raw`C:\Program Files\s-gw\s-gw-windows-peer-identity.exe`, undefined, "a".repeat(64), async () => {});
    const session = registerWindowsAgentLaunch(registry, identity(), nativeChecks(), () => {});
    try {
      await expect(session.pipes.openOnce(async () => Buffer.from("ok")))
        .rejects.toThrow("verified launcher and egress controls");
    } finally {
      await session.confirmDrained();
    }
  });

  it("uses durable reservation to reject identity reuse after a registry restart", async () => {
    const usedSids = new Set<string>();
    const usedSessions = new Set<string>();
    const usedJobs = new Set<string>();
    const reserve = (record: Readonly<WindowsAgentPipeIdentity>) => {
      if (usedSids.has(record.appContainerSid!) || usedSessions.has(record.sessionId) ||
          usedJobs.has(record.jobName)) throw new Error("durable launch identity already used");
      usedSids.add(record.appContainerSid!);
      usedSessions.add(record.sessionId);
      usedJobs.add(record.jobName);
    };
    const first = registerWindowsAgentLaunch(new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper),
      identity(), nativeChecks(), reserve);
    first.beginRevoke();
    await first.confirmDrained();
    const newSid = "S-1-15-2-555-666-777-888";
    const newJob = String.raw`Local\s-gw-agent-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`;
    const cases = [
      identity({ sessionId: "session-2", jobName: newJob }),
      identity({ appContainerSid: newSid, jobName: newJob }),
      identity({ appContainerSid: newSid, sessionId: "session-2" })
    ];
    for (const reused of cases) {
      expect(() => registerWindowsAgentLaunch(new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper),
        reused, nativeChecks(), reserve)).toThrow("durable launch identity already used");
    }
    expect(usedSids.size).toBe(1);
  });

  it("starts revocation before confirming that broker work and the helper drained", async () => {
    const registry = new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper);
    const session = registerWindowsAgentLaunch(registry, identity(), nativeChecks(), () => {});
    let callbackStarted!: () => void;
    let releaseCallback!: () => void;
    const started = new Promise<void>(resolve => { callbackStarted = resolve; });
    const held = new Promise<void>(resolve => { releaseCallback = resolve; });
    let callbackSignal: AbortSignal | undefined;
    const exchange = await session.pipes.openOnce(async (_request, _principal, signal) => {
      callbackSignal = signal;
      callbackStarted();
      await held;
      signal.throwIfAborted();
      return Buffer.from("ok");
    });
    const completed = exchange.completed.then(
      () => { throw new Error("The revoked exchange completed."); },
      error => { expect(error.message).toContain("session ended"); }
    );
    await started;
    session.beginRevoke();
    expect(callbackSignal?.aborted).toBe(true);
    let drained = false;
    const confirming = session.confirmDrained().then(() => { drained = true; });
    await new Promise(resolve => setTimeout(resolve, 20));
    expect(drained).toBe(false);
    releaseCallback();
    await completed;
    await confirming;
    expect(drained).toBe(true);
  });
});
