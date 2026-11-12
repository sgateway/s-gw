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
