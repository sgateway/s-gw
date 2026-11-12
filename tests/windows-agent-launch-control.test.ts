import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { registerWindowsAgentLaunch, registerWindowsNativeAgentLaunch,
  type WindowsNativeLauncherIdentity } from "../src/windows-agent-launch-control.js";
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

function nativeIdentity(changes: Partial<WindowsNativeLauncherIdentity> = {}): WindowsNativeLauncherIdentity {
  return {
    session_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    profile_name: "sgwagent_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    broker_sid: "S-1-5-21-100-200-300-1001",
    user_sid: "S-1-5-21-100-200-300-1001",
    package_sid: "S-1-15-2-111-222-333-444",
    job_name: String.raw`Local\s-gw-agent-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`,
    logon_luid: "00000000000003e7",
    windows_session_id: 3,
    process_id: 1234,
    ...changes
  };
}

function nativeBridge(changes: Partial<WindowsNativeLauncherIdentity> = {}) {
  const record = nativeIdentity(changes);
  return {
    ...nativeChecks(),
    launchIdentity: () => record,
    childProcessId: () => 1234
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
  it("passes the C launcher's package identity to peer verification", async () => {
    let helperArgs: string[] = [];
    const registry = new WindowsAgentPipeRegistry("synthetic-helper", (_path, args) => {
      helperArgs = args;
      return waitingHelper();
    });
    let reserved: WindowsAgentPipeIdentity | undefined;
    const bridge = nativeBridge();
    const session = registerWindowsNativeAgentLaunch(registry, bridge, "Native Windows agent",
      record => { reserved = record; });
    let sawRequest!: () => void;
    const requested = new Promise<void>(resolve => { sawRequest = resolve; });
    let principalId: string | undefined;
    try {
      const exchange = await session.pipes.openOnce(async (_request, principal) => {
        principalId = principal.id;
        sawRequest();
        return Buffer.from("ok");
      });
      await requested;
      expect(principalId).toBe("win32:sid:s-1-15-2-111-222-333-444");
      expect(helperArgs).toEqual([
        exchange.pipeName, "S-1-5-21-100-200-300-1001", "S-1-5-21-100-200-300-1001",
        "S-1-15-2-111-222-333-444", "00000000000003e7", "3",
        String.raw`Local\s-gw-agent-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`
      ]);
      expect(reserved).toMatchObject({ sessionId: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        appContainerSid: "S-1-15-2-111-222-333-444", name: "Native Windows agent" });
    } finally {
      await session.confirmDrained();
    }
  });

  it("rejects a C identity that disagrees with its profile, Job, user or retained child", () => {
    const invalid = [
      [nativeBridge({ profile_name: "sgwagent_other" }), "profile"],
      [nativeBridge({ job_name: String.raw`Local\s-gw-agent-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb` }), "Job"],
      [nativeBridge({ user_sid: "S-1-5-21-100-200-300-1002" }), "user SID"],
      [nativeBridge({ process_id: 4321 }), "child process ID"],
      [nativeBridge({ session_id: "windows-session-1" }), "session ID"]
    ] as const;
    for (const [bridge, reason] of invalid) {
      let reservations = 0;
      const registry = new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper);
      expect(() => registerWindowsNativeAgentLaunch(registry, bridge, "Native Windows agent",
        () => { reservations++; })).toThrow(reason);
      expect(reservations).toBe(0);
    }
  });

  it("rechecks the retained child process ID before broker work", async () => {
    const bridge = nativeBridge();
    const session = registerWindowsNativeAgentLaunch(
      new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper), bridge,
      "Native Windows agent", () => {});
    bridge.childProcessId = () => 4321;
    try {
      await expect(session.pipes.openOnce(async () => Buffer.from("ok")))
        .rejects.toThrow("childHandleLive");
    } finally {
      await session.confirmDrained();
    }
  });

  it("refuses asynchronous identity or retained-handle readings", () => {
    const asyncIdentity = nativeBridge();
    asyncIdentity.launchIdentity = (async () => nativeIdentity()) as unknown as typeof asyncIdentity.launchIdentity;
    expect(() => registerWindowsNativeAgentLaunch(
      new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper), asyncIdentity,
      "Native Windows agent", () => {})).toThrow("identity must finish synchronously");

    const asyncProcessId = nativeBridge();
    asyncProcessId.childProcessId = (async () => 1234) as unknown as typeof asyncProcessId.childProcessId;
    expect(() => registerWindowsNativeAgentLaunch(
      new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper), asyncProcessId,
      "Native Windows agent", () => {})).toThrow("child process ID must finish synchronously");
  });

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

  it("uses current native probes and rejects a replaced stop signal", async () => {
    const native = nativeChecks();
    const session = registerWindowsAgentLaunch(
      new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper), identity(), native, () => {});
    native.dnsBoundaryReady = () => false;
    await expect(session.pipes.openOnce(async () => Buffer.from("ok"))).rejects.toThrow("dnsBoundaryReady");
    await session.confirmDrained();

    const otherNative = nativeChecks();
    const other = registerWindowsAgentLaunch(
      new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper), identity(), otherNative, () => {});
    otherNative.stopped = new AbortController().signal;
    await expect(other.pipes.openOnce(async () => Buffer.from("ok"))).rejects.toThrow("stop signal changed");
    await other.confirmDrained();

    const duringNative = nativeChecks();
    const during = registerWindowsAgentLaunch(
      new WindowsAgentPipeRegistry("synthetic-helper", waitingHelper), identity(), duringNative, () => {});
    duringNative.dnsBoundaryReady = () => {
      duringNative.stopped = new AbortController().signal;
      return true;
    };
    await expect(during.pipes.openOnce(async () => Buffer.from("ok")))
      .rejects.toThrow("during a native check");
    await during.confirmDrained();
  });

  it("keeps native pipe opening disabled after adapter registration", async () => {
    const registry = new WindowsAgentPipeRegistry(
      String.raw`C:\Program Files\s-gw\s-gw-windows-peer-identity.exe`, undefined, "a".repeat(64), async () => {});
    const session = registerWindowsNativeAgentLaunch(registry, nativeBridge(),
      "Native Windows agent", () => {});
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
