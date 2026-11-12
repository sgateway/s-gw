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

function requireReady(name: string, probe: unknown, owner: WindowsRetainedAgentBoundary): void {
  if (typeof probe !== "function") throw new Error(`${name} is unavailable.`);
  const result: unknown = probe.call(owner);
  if (result === true) return;
  if (result && typeof (result as PromiseLike<unknown>).then === "function") {
    void Promise.resolve(result).catch(() => {});
  }
  throw new Error(`${name} failed or did not finish synchronously.`);
}

export function registerWindowsAgentLaunch(registry: WindowsAgentPipeRegistry,
  identity: WindowsAgentPipeIdentity, native: WindowsRetainedAgentBoundary,
  reserveDurably: WindowsAgentLaunchLease["reserveDurably"]): WindowsBrokerLaunchSession {
  if (!native || typeof reserveDurably !== "function") {
    throw new Error("Windows broker launch needs native checks and durable reservation.");
  }
  const child = native.childHandleLive;
  const job = native.jobHandleConfined;
  const wfp = native.wfpSessionHealthy;
  const dns = native.dnsBoundaryReady;
  const lease: WindowsAgentLaunchLease = {
    stopped: native.stopped,
    reserveDurably,
    assertLive: () => {
      requireReady("childHandleLive", child, native);
      requireReady("jobHandleConfined", job, native);
      requireReady("wfpSessionHealthy", wfp, native);
      requireReady("dnsBoundaryReady", dns, native);
    }
  };
  const pipes = registry.registerLaunched(identity, lease);
  return {
    pipes,
    beginRevoke: () => pipes.revoke(),
    confirmDrained: () => pipes.revokeAndDrain()
  };
}
