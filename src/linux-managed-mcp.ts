#!/usr/bin/env node
import { createHash } from "node:crypto";
import { lstat, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { principalForVerifiedPeer } from "./agent-context.js";
import { systemdAgentSocketFd, systemdManagedSocketFds } from "./linux-activated-socket.js";
import { assertLinuxPreparationSocketEnvironment, connectLinuxAgentControl, validateLinuxManagedPlan,
  type LinuxAgentControlClient } from "./linux-agent-control.js";
import { LinuxAgentSessionLeases } from "./linux-agent-session.js";
import { traceLinuxManagedStop, type LinuxAgentUnitPlan } from "./linux-agent-unit.js";
import { grantFromModelRelayAction, normalizeModelRelayGrant, type ModelRelayGrant } from "./model-relay-action.js";
import { registerDurableModelRelaySession, StoreBackedModelRelayApprovals } from "./model-relay-approval.js";
import { startVerifiedModelRelayServer, type VerifiedModelRelayServer } from "./model-relay-server.js";
import { SecretStore } from "./store.js";
import { startVerifiedMcpServer, type VerifiedMcpServer } from "./verified-mcp-server.js";

export interface LinuxManagedRelayConfig {
  grant: ModelRelayGrant;
  requestId?: string;
}

export interface LinuxManagedMcpConfig {
  name: string;
  leaseDir: string;
  plan: LinuxAgentUnitPlan;
  relay?: LinuxManagedRelayConfig;
}

export function validateLinuxManagedMcpConfig(value: LinuxManagedMcpConfig): void {
  if (!value || typeof value !== "object" || typeof value.name !== "string" ||
      !value.name.trim() || value.name.length > 120 ||
      typeof value.leaseDir !== "string" || !path.isAbsolute(value.leaseDir) ||
      path.resolve(value.leaseDir) !== value.leaseDir) {
    throw new Error("Invalid Linux managed MCP configuration.");
  }
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("Linux managed MCP needs a broker UID and GID.");
  validateLinuxManagedPlan(value.plan, uid, gid);
  if (Boolean(value.relay) !== Boolean(value.plan.modelRelaySocket)) {
    throw new Error("Managed model relay needs its own root-provisioned activated socket.");
  }
  if (value.relay) {
    if (!value.plan.identityGeneration ||
        Object.keys(value.relay).some(key => key !== "grant" && key !== "requestId") ||
        (value.relay.requestId !== undefined &&
          !/^[A-Za-z0-9_-]{1,256}$/.test(value.relay.requestId))) {
      throw new Error("Managed model relay needs a durable agent identity and request ID.");
    }
    const grant = normalizeModelRelayGrant(value.relay.grant);
    if (grant.payloadProfile !== "strict") {
      throw new Error("Managed model relay needs a strict payload grant.");
    }
  }
}

export function linuxManagedMcpStartMode(config: LinuxManagedMcpConfig,
  env: NodeJS.ProcessEnv = process.env): "prepare" | "runtime" {
  validateLinuxManagedMcpConfig(config);
  if (!config.relay || config.relay.requestId) return "runtime";
  assertLinuxPreparationSocketEnvironment(env);
  return "prepare";
}

async function createManagedRelayRequest(config: LinuxManagedMcpConfig,
  store: SecretStore): Promise<string> {
  const relay = config.relay!;
  const principal = principalForVerifiedPeer(`linux:managed:${config.plan.identityGeneration}`,
    config.name, config.plan.sessionId);
  const existing = (await store.listRequests({ active: true })).filter(request =>
    request.agentSource === "managed-peer" && request.principalId === principal.id &&
    request.agentSessionId === principal.sessionId);
  if (existing.length) {
    const request = existing[0];
    if (existing.length !== 1 || !["pending", "approved"].includes(request.state) ||
        request.agentName !== config.name || request.action.kind !== "model_relay" ||
        JSON.stringify(normalizeModelRelayGrant(relay.grant)) !==
          JSON.stringify(grantFromModelRelayAction(request.handle, request.action))) {
      throw new Error("This Linux model relay session already has a different active request.");
    }
    return request.id;
  }
  const request = await store.createModelRelayRequest(relay.grant, principal,
    "Root-managed Linux agent requested model API access.");
  return request.id;
}

export async function prepareLinuxManagedRelayRequest(config: LinuxManagedMcpConfig,
  store: SecretStore, configHash: string): Promise<string> {
  validateLinuxManagedMcpConfig(config);
  if (!config.relay || config.relay.requestId || !config.plan.identityGeneration) {
    throw new Error("Only an unprepared root-managed relay can create its approval request.");
  }
  if (!/^[a-f0-9]{64}$/.test(configHash)) {
    throw new Error("Linux relay preparation needs the exact root-provisioned config hash.");
  }
  assertLinuxPreparationSocketEnvironment();
  const control = await connectLinuxAgentControl(config.plan);
  try {
    await control.prepare(configHash);
    const requestId = await createManagedRelayRequest(config, store);
    await control.prepared(requestId);
    return requestId;
  } finally {
    await control.close();
  }
}

async function readLinuxManagedMcpConfigWithHash(filename: string): Promise<{
  config: LinuxManagedMcpConfig; hash: string;
}> {
  const gid = process.getgid?.();
  if (process.platform !== "linux" || !Number.isSafeInteger(gid) || gid! < 1 ||
      !path.isAbsolute(filename) || path.resolve(filename) !== filename) {
    throw new Error("Managed Linux MCP needs an absolute root-provisioned config path.");
  }
  const info = await lstat(filename);
  if (!info.isFile() || info.uid !== 0 || info.gid !== gid ||
      (info.mode & 0o777) !== 0o640 || info.nlink !== 1 ||
      await realpath(filename) !== filename) {
    throw new Error("Managed Linux MCP config must be root-owned and broker-group readable.");
  }
  let parent = path.dirname(filename);
  while (true) {
    const item = await lstat(parent);
    if (!item.isDirectory() || item.uid !== 0 || (item.mode & 0o022) !== 0 ||
        await realpath(parent) !== parent) {
      throw new Error("Managed Linux MCP config has an untrusted parent.");
    }
    const next = path.dirname(parent);
    if (next === parent) break;
    parent = next;
  }
  const content = await readFile(filename, "utf8");
  const config = JSON.parse(content) as LinuxManagedMcpConfig;
  validateLinuxManagedMcpConfig(config);
  return { config, hash: createHash("sha256").update(content).digest("hex") };
}

export async function readLinuxManagedMcpConfig(filename: string): Promise<LinuxManagedMcpConfig> {
  return (await readLinuxManagedMcpConfigWithHash(filename)).config;
}

export interface LinuxManagedMcpSession {
  controlLost: AbortSignal;
  close(): Promise<void>;
}

export async function closeLinuxManagedMcpResources(stopAgent: (() => Promise<void>) | undefined,
  mcp: Pick<VerifiedMcpServer, "close"> | undefined,
  control: Pick<LinuxAgentControlClient, "close"> | undefined,
  relay?: Pick<VerifiedModelRelayServer, "close">): Promise<void> {
  const agentStop = stopAgent ? Promise.resolve().then(stopAgent) : Promise.resolve();
  if (stopAgent) {
    traceLinuxManagedStop("agent stop call entering");
    void agentStop.then(() => traceLinuxManagedStop("agent stop resolved"),
      () => traceLinuxManagedStop("agent stop rejected"));
  }
  const cleanup: Promise<void>[] = [];
  if (stopAgent) cleanup.push(agentStop);
  if (mcp) cleanup.push(Promise.resolve().then(() => mcp.close()));
  if (relay) cleanup.push(Promise.resolve().then(() => relay.close()));
  if (control) cleanup.push(agentStop.then(() => control.close(), () => control.close()));
  const failures: unknown[] = [];
  for (const result of await Promise.allSettled(cleanup)) {
    if (result.status === "rejected") failures.push(result.reason);
  }
  if (failures.length) throw new AggregateError(failures, "Linux managed MCP teardown failed.");
}

export async function startLinuxManagedMcpSession(config: LinuxManagedMcpConfig,
  store: SecretStore): Promise<LinuxManagedMcpSession> {
  if (process.platform !== "linux" || process.geteuid?.() === 0) {
    throw new Error("Managed Linux MCP must run under the unprivileged broker account.");
  }
  validateLinuxManagedMcpConfig(config);
  if (config.relay && !config.relay.requestId) {
    throw new Error("Managed model relay needs an approved request ID before agent launch.");
  }
  const fds = config.relay ? systemdManagedSocketFds(config.plan.sessionId) :
    { mcp: systemdAgentSocketFd(config.plan.sessionId) };
  let control: LinuxAgentControlClient | undefined;
  let mcp: VerifiedMcpServer | undefined;
  let relay: VerifiedModelRelayServer | undefined;
  let stopAgent: (() => Promise<void>) | undefined;
  const approvals = config.relay ? new StoreBackedModelRelayApprovals(store) : undefined;
  try {
    control = await connectLinuxAgentControl(config.plan);
    mcp = await startVerifiedMcpServer({ store, socketPath: config.plan.brokerSocket,
      socketGid: config.plan.gid, activatedFd: fds.mcp, requireLinuxMessageGate: true });
    if (config.relay) {
      relay = await startVerifiedModelRelayServer({ store, approval: approvals!,
        socketPath: config.plan.modelRelaySocket!, socketGid: config.plan.gid,
        activatedFd: (fds as { mcp: number; model: number }).model,
        requireLinuxMessageGate: true });
    }
    const leases = new LinuxAgentSessionLeases(config.leaseDir, control);
    stopAgent = await leases.launch(config.plan, config.name,
      async session => {
        const stopRelay = config.relay ? await registerDurableModelRelaySession(
          relay!, approvals!, session, config.relay.requestId!, config.relay.grant) : undefined;
        try {
          const stopMcp = mcp!.registerSession(session);
          return () => { stopMcp(); stopRelay?.(); };
        } catch (error) {
          stopRelay?.();
          throw error;
        }
      }, async () => {
        await mcp!.assertSocketBinding();
        if (relay) await relay.assertSocketBinding();
      });
    if (control.signal.aborted) throw new Error("Linux root control service ended during launch.");
  } catch (error) {
    try { await closeLinuxManagedMcpResources(stopAgent, mcp, control, relay); }
    catch (cleanupError) {
      const failures = cleanupError instanceof AggregateError ? cleanupError.errors : [cleanupError];
      throw new AggregateError([error, ...failures], "Linux managed MCP launch cleanup failed.");
    }
    throw error;
  }
  let closing: Promise<void> | undefined;
  const liveControl = control;
  const liveMcp = mcp;
  const liveRelay = relay;
  const liveStop = stopAgent;
  const close = () => {
    if (closing) return closing;
    traceLinuxManagedStop("session close entered");
    closing = closeLinuxManagedMcpResources(liveStop, liveMcp, liveControl, liveRelay);
    return closing;
  };
  liveControl.signal.addEventListener("abort", () => { void close().catch(() => {}); }, { once: true });
  return { controlLost: liveControl.signal, close };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || !path.isAbsolute(process.argv[2])) {
    throw new Error("Usage: linux-managed-mcp <absolute root-provisioned config.json>");
  }
  const { config, hash } = await readLinuxManagedMcpConfigWithHash(process.argv[2]);
  const startMode = linuxManagedMcpStartMode(config);
  const store = new SecretStore();
  await store.init();
  if (startMode === "prepare") {
    const requestId = await prepareLinuxManagedRelayRequest(config, store, hash);
    process.stdout.write(`${JSON.stringify({ sessionId: config.plan.sessionId, requestId })}\n`);
  } else {
    const session = await startLinuxManagedMcpSession(config, store);
    session.controlLost.addEventListener("abort", () => { process.exitCode = 1; }, { once: true });
    for (const signal of ["SIGINT", "SIGTERM"] as const) {
      process.once(signal, () => {
        traceLinuxManagedStop("process signal received");
        void session.close().then(() => { process.exitCode = 0; }, error => {
          process.stderr.write(`${String(error)}\n`);
          process.exitCode = 1;
        });
      });
    }
  }
}
