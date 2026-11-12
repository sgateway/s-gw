import type { WindowsAgentLaunchLease, WindowsAgentPipeIdentity, WindowsPipeRegistration,
  WindowsAgentPipeRegistry } from "./windows-agent-pipe.js";

export interface WindowsRetainedAgentBoundary {
  readonly stopped: AbortSignal;
  // These checks must read the broker-owned native handles, not reopen a PID or Job by name.
  childHandleLive(): boolean;
  jobHandleConfined(): boolean;
  wfpSessionHealthy(): boolean;
  dnsBoundaryReady(): boolean;
}

export interface WindowsBrokerLaunchSession {
  readonly pipes: WindowsPipeRegistration;
  beginRevoke(): void;
  confirmDrained(): Promise<void>;
}

// Keep agent IPC out of this launch record; only the native callback may supply it.
export interface WindowsNativeLauncherIdentity {
  readonly session_id: string;
  readonly profile_name: string;
  readonly broker_sid: string;
  readonly user_sid: string;
  readonly package_sid: string;
  readonly job_name: string;
  readonly logon_luid: string;
  readonly windows_session_id: number;
  readonly process_id: number;
}

export interface WindowsNativeLaunchBridge extends WindowsRetainedAgentBoundary {
  // The child ID must be read from the retained handle, never reopened by PID.
  launchIdentity(): WindowsNativeLauncherIdentity;
  childProcessId(): number;
}

type BoundaryProbe = Exclude<keyof WindowsRetainedAgentBoundary, "stopped">;

function requireReady(name: BoundaryProbe, owner: WindowsRetainedAgentBoundary): void {
  const probe = owner[name];
  if (typeof probe !== "function") throw new Error(`${name} is unavailable.`);
  const result: unknown = probe.call(owner);
  if (result === true) return;
  if (result && typeof (result as PromiseLike<unknown>).then === "function") {
    void Promise.resolve(result).catch(() => {});
  }
  throw new Error(`${name} failed or did not finish synchronously.`);
}

function retainedChildProcessId(native: WindowsNativeLaunchBridge): number {
  const result: unknown = native.childProcessId();
  if (result && typeof (result as PromiseLike<unknown>).then === "function") {
    void Promise.resolve(result).catch(() => {});
    throw new Error("Windows native launch child process ID must finish synchronously.");
  }
  return typeof result === "number" ? result : NaN;
}

export function registerWindowsAgentLaunch(registry: WindowsAgentPipeRegistry,
  identity: WindowsAgentPipeIdentity, native: WindowsRetainedAgentBoundary,
  reserveDurably: WindowsAgentLaunchLease["reserveDurably"]): WindowsBrokerLaunchSession {
  if (!native || typeof reserveDurably !== "function") {
    throw new Error("Windows broker launch needs native checks and durable reservation.");
  }
  const stopped = native.stopped;
  const lease: WindowsAgentLaunchLease = {
    stopped,
    reserveDurably,
    assertLive: () => {
      if (native.stopped !== stopped) throw new Error("Windows launcher stop signal changed.");
      requireReady("childHandleLive", native);
      requireReady("jobHandleConfined", native);
      requireReady("wfpSessionHealthy", native);
      requireReady("dnsBoundaryReady", native);
      if (native.stopped !== stopped || stopped.aborted) {
        throw new Error("Windows launcher stopped or changed its stop signal during a native check.");
      }
    }
  };
  const pipes = registry.registerLaunched(identity, lease);
  return {
    pipes,
    beginRevoke: () => pipes.revoke(),
    confirmDrained: () => pipes.revokeAndDrain()
  };
}

export function registerWindowsNativeAgentLaunch(registry: WindowsAgentPipeRegistry,
  native: WindowsNativeLaunchBridge, displayName: string,
  reserveDurably: WindowsAgentLaunchLease["reserveDurably"]): WindowsBrokerLaunchSession {
  if (!native || typeof native.launchIdentity !== "function" ||
      typeof native.childProcessId !== "function") {
    throw new Error("Windows native launch needs an in-process identity and retained child handle.");
  }
  const raw: unknown = native.launchIdentity();
  if (raw && typeof (raw as PromiseLike<unknown>).then === "function") {
    void Promise.resolve(raw).catch(() => {});
    throw new Error("Windows native launch identity must finish synchronously.");
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("Windows native launch identity is unavailable.");
  }
  const source = raw as WindowsNativeLauncherIdentity;
  const record: WindowsNativeLauncherIdentity = {
    session_id: source.session_id,
    profile_name: source.profile_name,
    broker_sid: source.broker_sid,
    user_sid: source.user_sid,
    package_sid: source.package_sid,
    job_name: source.job_name,
    logon_luid: source.logon_luid,
    windows_session_id: source.windows_session_id,
    process_id: source.process_id
  };
  if (typeof record.session_id !== "string" || !/^[a-f\d]{32}$/.test(record.session_id)) {
    throw new Error("Windows native launch has an invalid session ID.");
  }
  if (record.profile_name !== `sgwagent_${record.session_id}`) {
    throw new Error("Windows native launch profile does not match its session ID.");
  }
  if (record.job_name !== `Local\\s-gw-agent-${record.session_id}`) {
    throw new Error("Windows native launch Job does not match its session ID.");
  }
  if (typeof record.broker_sid !== "string" || typeof record.user_sid !== "string" ||
      record.broker_sid !== record.user_sid) {
    throw new Error("Windows native launch user SID does not match its broker SID.");
  }
  const processId = record.process_id;
  if (!Number.isInteger(processId) || processId < 1 || processId > 0xffffffff ||
      retainedChildProcessId(native) !== processId) {
    throw new Error("Windows native launch child process ID does not match its retained handle.");
  }
  const identity: WindowsAgentPipeIdentity = {
    brokerSid: record.broker_sid,
    userSid: record.user_sid,
    appContainerSid: record.package_sid,
    logonLuid: record.logon_luid,
    windowsSessionId: record.windows_session_id,
    jobName: record.job_name,
    sessionId: record.session_id,
    name: displayName
  };
  const boundary: WindowsRetainedAgentBoundary = {
    get stopped() { return native.stopped; },
    childHandleLive: () => retainedChildProcessId(native) === processId && native.childHandleLive(),
    jobHandleConfined: () => native.jobHandleConfined(),
    wfpSessionHealthy: () => native.wfpSessionHealthy(),
    dnsBoundaryReady: () => native.dnsBoundaryReady()
  };
  return registerWindowsAgentLaunch(registry, identity, boundary, reserveDurably);
}
