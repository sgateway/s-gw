import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { principalForVerifiedPeer, type VerifiedAgentPrincipal } from "./agent-context.js";
import { inspectWindowsPeerHelperAcl } from "./windows-peer-helper-acl.js";
import { windowsSystemEnvironment } from "./windows-system.js";

const maxMessageBytes = 32 * 1024;
const maxExchangesPerSession = 8;
const defaultExchangeTimeoutMs = 30_000;
const sidPattern = /^S-1-(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*)){1,15}$/;
const jobNamePattern = /^Local\\s-gw-agent-[a-f\d]{32}$/;

export interface WindowsAgentPipeIdentity {
  brokerSid: string;
  userSid: string;
  appContainerSid?: string;
  logonLuid: string;
  windowsSessionId: number;
  jobName: string;
  sessionId: string;
  name: string;
}

export interface WindowsPipeExchange {
  pipeName: string;
  completed: Promise<void>;
  close(): void;
}

export type WindowsPipeRequestHandler = (request: Buffer, principal: VerifiedAgentPrincipal,
  signal: AbortSignal, session: WindowsPipeAgentSession) => Promise<Buffer>;

export interface WindowsPipeAgentSession {
  readonly signal: AbortSignal;
  assertActive(): void;
}

// This is a trusted in-process launcher hook, never agent IPC.
export interface WindowsAgentLaunchLease {
  readonly stopped: AbortSignal;
  reserveDurably(identity: Readonly<WindowsAgentPipeIdentity>): void;
  assertLive(): void;
}

export interface WindowsPipeRegistration {
  openOnce(onRequest: WindowsPipeRequestHandler, timeoutMs?: number): Promise<WindowsPipeExchange>;
  revoke(): void;
  revokeAndDrain(): Promise<void>;
}

type HelperStart = (helperPath: string, args: string[]) => ChildProcessWithoutNullStreams;
type HelperInspection = (helperPath: string, expectedSha256: string) => Promise<void>;

interface RunningExchange {
  cancel(error: Error): void;
  drained: Promise<void>;
}

interface LiveWindowsSession {
  identity: WindowsAgentPipeIdentity;
  principal: VerifiedAgentPrincipal;
  exchanges: Set<RunningExchange>;
  opening: number;
  ended: boolean;
  launch?: WindowsAgentLaunchLease;
  stoppedListener?: () => void;
}

export class WindowsAgentPipeRegistry {
  private readonly usedIdentities = new Set<string>();
  private readonly usedSessionIds = new Set<string>();
  private readonly usedJobNames = new Set<string>();

  constructor(private readonly helperPath: string, private readonly startHelper: HelperStart = spawnNativeHelper,
    private readonly expectedHelperSha256?: string,
    private readonly inspectHelper: HelperInspection = inspectWindowsPeerHelperAcl) {
    if (process.platform !== "win32" && process.env.SGW_TEST_MODE !== "1") {
      throw new Error("Windows agent pipes require Windows.");
    }
    if (startHelper !== spawnNativeHelper && process.env.SGW_TEST_MODE !== "1") {
      throw new Error("A synthetic Windows pipe helper is allowed only in isolated tests.");
    }
    if (inspectHelper !== inspectWindowsPeerHelperAcl && process.env.SGW_TEST_MODE !== "1") {
      throw new Error("A synthetic Windows helper inspection is allowed only in isolated tests.");
    }
    if (startHelper === spawnNativeHelper && !/^[a-f\d]{64}$/i.test(expectedHelperSha256 || "")) {
      throw new Error("Native Windows agent pipes require an installer-pinned helper hash.");
    }
  }

  register(identity: WindowsAgentPipeIdentity): WindowsPipeRegistration {
    return this.registerSession(identity);
  }

  registerLaunched(identity: WindowsAgentPipeIdentity, launch: WindowsAgentLaunchLease): WindowsPipeRegistration {
    if (!identity.appContainerSid || !launch || typeof launch.assertLive !== "function" ||
        typeof launch.reserveDurably !== "function" || !launch.stopped ||
        typeof launch.stopped.addEventListener !== "function" ||
        typeof launch.stopped.removeEventListener !== "function" ||
        typeof launch.stopped.aborted !== "boolean" || launch.stopped.aborted) {
      throw new Error("A Windows native pipe session needs a live AppContainer launcher lease.");
    }
    const attested = Object.freeze({ ...identity });
    validateIdentity(attested);
    this.consumeIdentity(attested);
    this.assertLaunchLive(launch);
    assertSyncResult(launch.reserveDurably(attested), "Windows durable identity reservation");
    this.assertLaunchLive(launch);
    if (launch.stopped.aborted) {
      throw new Error("Windows agent launcher stopped during registration.");
    }
    return this.registerSession(attested, launch, true);
  }

  private consumeIdentity(identity: WindowsAgentPipeIdentity): void {
    const key = (identity.appContainerSid || identity.userSid).toLowerCase();
    if (this.usedIdentities.has(key) || this.usedSessionIds.has(identity.sessionId) ||
        this.usedJobNames.has(identity.jobName.toLowerCase())) {
      throw new Error("This Windows agent identity, session, or Job was already used by this broker.");
    }
    this.usedIdentities.add(key);
    this.usedSessionIds.add(identity.sessionId);
    this.usedJobNames.add(identity.jobName.toLowerCase());
  }

  private registerSession(identity: WindowsAgentPipeIdentity, launch?: WindowsAgentLaunchLease,
    consumed = false): WindowsPipeRegistration {
    validateIdentity(identity);
    if (!consumed) this.consumeIdentity(identity);
    const key = (identity.appContainerSid || identity.userSid).toLowerCase();
    const principal = principalForVerifiedPeer(`win32:sid:${key}`, identity.name, identity.sessionId);
    const live: LiveWindowsSession = { identity: { ...identity }, principal, exchanges: new Set(), opening: 0,
      ended: false, launch };
    const session: WindowsPipeRegistration = {
      openOnce: (onRequest, timeoutMs = defaultExchangeTimeoutMs) => this.openOnce(live, onRequest, timeoutMs),
      revoke: () => {
        if (live.ended) return;
        live.ended = true;
        if (launch && live.stoppedListener) launch.stopped.removeEventListener("abort", live.stoppedListener);
        for (const exchange of live.exchanges) exchange.cancel(new Error("Windows agent session ended."));
      },
      revokeAndDrain: async () => {
        session.revoke();
        await Promise.all([...live.exchanges].map(exchange => exchange.drained));
      }
    };
    if (launch) {
      live.stoppedListener = session.revoke;
      launch.stopped.addEventListener("abort", session.revoke, { once: true });
      if (launch.stopped.aborted) session.revoke();
    }
    return session;
  }

  private assertActive(live: LiveWindowsSession): void {
    if (live.ended || live.launch?.stopped.aborted) {
      throw new Error("Windows agent session ended.");
    }
    if (!live.launch) return;
    try {
      this.assertLaunchLive(live.launch);
    } catch (error) {
      live.ended = true;
      if (live.launch && live.stoppedListener) {
        live.launch.stopped.removeEventListener("abort", live.stoppedListener);
      }
      for (const exchange of live.exchanges) exchange.cancel(new Error("Windows agent launcher lost liveness."));
      throw error;
    }
  }

  private assertLaunchLive(launch: WindowsAgentLaunchLease): void {
    assertSyncResult(launch.assertLive(), "Windows native liveness check");
  }

  private async openOnce(live: LiveWindowsSession,
    onRequest: WindowsPipeRequestHandler,
    timeoutMs: number): Promise<WindowsPipeExchange> {
    this.assertActive(live);
    if (live.exchanges.size + live.opening >= maxExchangesPerSession) {
      throw new Error("Windows agent session is ended or has too many pending exchanges.");
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 35 * 60_000) {
      throw new Error("Invalid Windows pipe exchange deadline.");
    }
    live.opening++;
    const pipeName = String.raw`\\.\pipe\LOCAL\s-gw-` + randomBytes(16).toString("hex");
    const identity = live.identity;
    const args = [pipeName, identity.brokerSid, identity.userSid, identity.appContainerSid || "-",
      identity.logonLuid, String(identity.windowsSessionId), identity.jobName];
    let child: ChildProcessWithoutNullStreams;
    try {
      this.assertActive(live);
      if (this.startHelper === spawnNativeHelper) {
        await this.inspectHelper(this.helperPath, this.expectedHelperSha256!);
        this.assertActive(live);
        throw new Error("Native Windows agent pipes require verified launcher and egress controls.");
      }
      child = this.startHelper(this.helperPath, args);
    } finally {
      live.opening--;
    }
    let resolveReady!: () => void;
    let rejectReady!: (error: Error) => void;
    let resolveDone!: () => void;
    let rejectDone!: (error: Error) => void;
    const ready = new Promise<void>((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
    const completed = new Promise<void>((resolve, reject) => { resolveDone = resolve; rejectDone = reject; });
    let buffered = Buffer.alloc(0);
    let sawReady = false;
    let gotRequest = false;
    let sentResponse = false;
    let settled = false;
    let childClosed = false;
    let callbackDone = true;
    let resolveDrained!: () => void;
    const drained = new Promise<void>(resolve => { resolveDrained = resolve; });
    const controller = new AbortController();
    const cancel = (error: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      controller.abort(error);
      child.kill();
      rejectReady(error);
      rejectDone(error);
    };
    const exchange: RunningExchange = { cancel, drained };
    const finishDrain = () => {
      if (!childClosed || !callbackDone) return;
      live.exchanges.delete(exchange);
      resolveDrained();
    };
    live.exchanges.add(exchange);
    void completed.catch(() => {});
    const deadline = setTimeout(() => cancel(new Error("Windows pipe exchange timed out.")), timeoutMs);

    child.stdout.on("data", (chunk: Buffer) => {
      if (settled) return;
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.length > maxMessageBytes + 6 || gotRequest) {
        cancel(new Error("Invalid Windows pipe helper response."));
        return;
      }
      if (!sawReady && buffered.length > 0) {
        if (buffered[0] !== 0x52) { cancel(new Error("Windows pipe helper did not become ready.")); return; }
        sawReady = true;
        buffered = buffered.subarray(1);
        resolveReady();
      }
      if (buffered.length < 5) return;
      const size = buffered.readUInt32LE(1);
      if (buffered[0] !== 0x51 || size < 1 || size > maxMessageBytes || buffered.length > size + 5) {
        cancel(new Error("Invalid Windows pipe helper request frame."));
        return;
      }
      if (buffered.length < size + 5) return;
      gotRequest = true;
      callbackDone = false;
      const request = Buffer.from(buffered.subarray(5));
      buffered = Buffer.alloc(0);
      void (async () => {
        this.assertActive(live);
        const agentSession: WindowsPipeAgentSession = {
          signal: controller.signal,
          assertActive: () => {
            controller.signal.throwIfAborted();
            this.assertActive(live);
          }
        };
        const response = await onRequest(request, live.principal, controller.signal, agentSession);
        controller.signal.throwIfAborted();
        agentSession.assertActive();
        if (!Buffer.isBuffer(response) || response.length < 1 || response.length > maxMessageBytes) {
          throw new Error("Invalid Windows pipe response size.");
        }
        const frame = Buffer.allocUnsafe(response.length + 5);
        frame[0] = 0x53;
        frame.writeUInt32LE(response.length, 1);
        response.copy(frame, 5);
        sentResponse = true;
        child.stdin.end(frame);
      })().catch(error => cancel(error instanceof Error ? error : new Error(String(error))))
        .finally(() => { callbackDone = true; finishDrain(); });
    });
    child.stdout.once("error", error => cancel(error));
    child.stdin.once("error", error => cancel(error));
    child.once("error", error => cancel(error));
    child.once("close", code => {
      childClosed = true;
      finishDrain();
      if (settled) return;
      if (code !== 0 || !sawReady || !gotRequest || !sentResponse || live.ended ||
          live.launch?.stopped.aborted) {
        cancel(new Error("Windows pipe helper ended before a verified exchange completed."));
        return;
      }
      if (live.launch) {
        try { this.assertActive(live); } catch { return; }
      }
      settled = true;
      clearTimeout(deadline);
      resolveDone();
    });

    try {
      await ready;
      this.assertActive(live);
      return { pipeName, completed, close: () => cancel(new Error("Windows pipe exchange closed.")) };
    } catch (error) {
      cancel(error instanceof Error ? error : new Error(String(error)));
      void completed.catch(() => {});
      throw error;
    }
  }
}

function assertSyncResult(result: unknown, operation: string): void {
  if (result === undefined) return;
  if (result && typeof (result as PromiseLike<unknown>).then === "function") {
    void Promise.resolve(result).catch(() => {});
  }
  throw new Error(`${operation} must finish synchronously.`);
}

function validateIdentity(identity: WindowsAgentPipeIdentity): void {
  if (!validSid(identity.brokerSid) || !validSid(identity.userSid) ||
      (identity.appContainerSid !== undefined && !validSid(identity.appContainerSid))) {
    throw new Error("A Windows agent session needs numeric broker, user, and package SIDs.");
  }
  if (identity.appContainerSid && !identity.appContainerSid.startsWith("S-1-15-2-")) {
    throw new Error("A Windows AppContainer session needs a package SID.");
  }
  if (!identity.appContainerSid && identity.brokerSid.toLowerCase() === identity.userSid.toLowerCase()) {
    throw new Error("A dedicated Windows agent account must differ from the broker account.");
  }
  if (!/^[a-f\d]{16}$/i.test(identity.logonLuid) || /^0{16}$/.test(identity.logonLuid) ||
      !Number.isSafeInteger(identity.windowsSessionId) || identity.windowsSessionId < 0 ||
      identity.windowsSessionId > 0xffffffff || !/^[A-Za-z0-9._:-]{1,128}$/.test(identity.sessionId)) {
    throw new Error("A Windows agent session needs a launch-attested logon LUID, session ID, and name.");
  }
  if (typeof identity.name !== "string" || !identity.name.trim()) {
    throw new Error("A Windows agent session needs a display name.");
  }
  if (!jobNamePattern.test(identity.jobName)) {
    throw new Error("A Windows agent session needs a launcher-owned Job name.");
  }
}

function validSid(value: string): boolean {
  if (typeof value !== "string" || value.length > 183 || !sidPattern.test(value)) return false;
  const parts = value.slice(4).split("-");
  if (BigInt(parts[0]) > 0xffffffffffffn) return false;
  return parts.slice(1).every(part => BigInt(part) <= 0xffffffffn);
}

function spawnNativeHelper(helperPath: string, args: string[]): ChildProcessWithoutNullStreams {
  return spawn(helperPath, args, {
    stdio: ["pipe", "pipe", "pipe"], windowsHide: true,
    cwd: path.dirname(helperPath),
    env: windowsSystemEnvironment()
  });
}
