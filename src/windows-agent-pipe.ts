import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { principalForVerifiedPeer, type VerifiedAgentPrincipal } from "./agent-context.js";
import { windowsSystemEnvironment } from "./windows-system.js";

const maxMessageBytes = 32 * 1024;
const maxExchangesPerSession = 8;
const defaultExchangeTimeoutMs = 30_000;
const sidPattern = /^S-1-(?:0|[1-9]\d*)(?:-(?:0|[1-9]\d*)){1,15}$/;

export interface WindowsAgentPipeIdentity {
  brokerSid: string;
  userSid: string;
  appContainerSid?: string;
  logonLuid: string;
  windowsSessionId: number;
  sessionId: string;
  name: string;
}

export interface WindowsPipeExchange {
  pipeName: string;
  completed: Promise<void>;
  close(): void;
}

export type WindowsPipeRequestHandler = (request: Buffer, principal: VerifiedAgentPrincipal,
  signal: AbortSignal) => Promise<Buffer>;

type HelperStart = (helperPath: string, args: string[]) => ChildProcessWithoutNullStreams;

interface RunningExchange {
  cancel(error: Error): void;
}

interface LiveWindowsSession {
  identity: WindowsAgentPipeIdentity;
  principal: VerifiedAgentPrincipal;
  exchanges: Set<RunningExchange>;
  opening: number;
  ended: boolean;
}

export class WindowsAgentPipeRegistry {
  private readonly usedIdentities = new Set<string>();
  private readonly usedSessionIds = new Set<string>();

  constructor(private readonly helperPath: string, private readonly startHelper: HelperStart = spawnNativeHelper) {
    if (process.platform !== "win32" && process.env.SGW_TEST_MODE !== "1") {
      throw new Error("Windows agent pipes require Windows.");
    }
    if (startHelper !== spawnNativeHelper && process.env.SGW_TEST_MODE !== "1") {
      throw new Error("A synthetic Windows pipe helper is allowed only in isolated tests.");
    }
    if (startHelper === spawnNativeHelper) {
      throw new Error("Native Windows agent pipes require installer-verified helper ACLs.");
    }
  }

  register(identity: WindowsAgentPipeIdentity): {
    openOnce(onRequest: WindowsPipeRequestHandler, timeoutMs?: number): Promise<WindowsPipeExchange>;
    revoke(): void;
  } {
    validateIdentity(identity);
    const key = (identity.appContainerSid || identity.userSid).toLowerCase();
    if (this.usedIdentities.has(key) || this.usedSessionIds.has(identity.sessionId)) {
      throw new Error("This Windows agent identity or session was already used by this broker.");
    }
    const principal = principalForVerifiedPeer(`win32:sid:${key}`, identity.name, identity.sessionId);
    const live: LiveWindowsSession = { identity: { ...identity }, principal, exchanges: new Set(), opening: 0,
      ended: false };
    this.usedIdentities.add(key);
    this.usedSessionIds.add(identity.sessionId);
    return {
      openOnce: (onRequest, timeoutMs = defaultExchangeTimeoutMs) => this.openOnce(live, onRequest, timeoutMs),
      revoke: () => {
        if (live.ended) return;
        live.ended = true;
        for (const exchange of live.exchanges) exchange.cancel(new Error("Windows agent session ended."));
      }
    };
  }

  private async openOnce(live: LiveWindowsSession,
    onRequest: WindowsPipeRequestHandler,
    timeoutMs: number): Promise<WindowsPipeExchange> {
    if (live.ended || live.exchanges.size + live.opening >= maxExchangesPerSession) {
      throw new Error("Windows agent session is ended or has too many pending exchanges.");
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 35 * 60_000) {
      throw new Error("Invalid Windows pipe exchange deadline.");
    }
    live.opening++;
    const pipeName = String.raw`\\.\pipe\LOCAL\s-gw-` + randomBytes(16).toString("hex");
    const identity = live.identity;
    const args = [pipeName, identity.brokerSid, identity.userSid, identity.appContainerSid || "-",
      identity.logonLuid, String(identity.windowsSessionId)];
    let child: ChildProcessWithoutNullStreams;
    try {
      if (live.ended) throw new Error("Windows agent session ended.");
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
    const exchange: RunningExchange = { cancel };
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
      const request = Buffer.from(buffered.subarray(5));
      buffered = Buffer.alloc(0);
      void (async () => {
        if (live.ended) throw new Error("Windows agent session ended.");
        const response = await onRequest(request, live.principal, controller.signal);
        controller.signal.throwIfAborted();
        if (live.ended) throw new Error("Windows agent session ended.");
        if (!Buffer.isBuffer(response) || response.length < 1 || response.length > maxMessageBytes) {
          throw new Error("Invalid Windows pipe response size.");
        }
        const frame = Buffer.allocUnsafe(response.length + 5);
        frame[0] = 0x53;
        frame.writeUInt32LE(response.length, 1);
        response.copy(frame, 5);
        sentResponse = true;
        child.stdin.end(frame);
      })().catch(error => cancel(error instanceof Error ? error : new Error(String(error))));
    });
    child.stdout.once("error", error => cancel(error));
    child.stdin.once("error", error => cancel(error));
    child.once("error", error => cancel(error));
    child.once("close", code => {
      live.exchanges.delete(exchange);
      if (settled) return;
      if (code !== 0 || !sawReady || !gotRequest || !sentResponse || live.ended) {
        cancel(new Error("Windows pipe helper ended before a verified exchange completed."));
        return;
      }
      settled = true;
      clearTimeout(deadline);
      resolveDone();
    });

    try {
      await ready;
      if (live.ended) throw new Error("Windows agent session ended.");
      return { pipeName, completed, close: () => cancel(new Error("Windows pipe exchange closed.")) };
    } catch (error) {
      cancel(error instanceof Error ? error : new Error(String(error)));
      void completed.catch(() => {});
      throw error;
    }
  }
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
