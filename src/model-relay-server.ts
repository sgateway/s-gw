import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { Socket } from "node:net";
import type { VerifiedAgentPrincipal } from "./agent-context.js";
import { normalizeModelRelayGrant, SGW_MODEL_RELAY_COMMAND, type ModelRelayGrant } from "./model-relay-action.js";
import { modelRoute, relayModelRequest, type ModelProvider, type ModelUpstreamRequest } from "./model-relay-transport.js";
import { startVerifiedPeerServer, type PeerSession, type VerifiedPeerServerOptions } from "./peer-identity.js";
import type { SecretStore } from "./store.js";

export { SGW_MODEL_RELAY_COMMAND } from "./model-relay-action.js";
export type { ModelRelayGrant } from "./model-relay-action.js";

export interface ModelRelayApproval {
  assertAuthorized(principal: VerifiedAgentPrincipal, grant: Readonly<ModelRelayGrant>): Promise<void>;
  onSessionEnded?(session: PeerSession): Promise<void> | void;
  retryPendingSessionEnds?(): Promise<void>;
}

export interface ModelRelayServerOptions extends Pick<VerifiedPeerServerOptions, "socketPath" | "socketMode" | "socketGid" | "activatedFd"> {
  store: SecretStore;
  approval: ModelRelayApproval;
  maxActiveRequestsPerSession?: number;
  maxPendingBrokerOperations?: number;
  maxVerifiedConnections?: number;
  headerDeadlineMs?: number;
  bodyIdleMs?: number;
  maxBodyDurationMs?: number;
  requestUpstream?: ModelUpstreamRequest;
  onSessionEndError?: (message: string) => void;
}

export interface VerifiedModelRelayServer {
  registerSession(session: PeerSession, grant: ModelRelayGrant): () => void;
  assertSocketBinding(): Promise<void>;
  close(): Promise<void>;
}

interface ActiveGrant {
  session: PeerSession;
  grant: Readonly<ModelRelayGrant>;
  expiresAt: number;
  active: number;
  requestsStarted: number;
  stopPeer: () => void;
  expiry?: ReturnType<typeof setTimeout>;
}

const destinations: Record<ModelProvider, string> = {
  anthropic: "api.anthropic.com:443",
  openai: "api.openai.com:443"
};
const defaultHeaderDeadlineMs = 10_000;
const defaultBodyIdleMs = 20_000;
const defaultMaxBodyDurationMs = 60_000;
const maxActiveRequests = 32;
const maxPendingOperations = 32;

async function within<T>(run: () => Promise<T>, timeoutMs: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(run),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("Model relay broker operation timed out.")), timeoutMs);
        timer.unref();
      })
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function checkGrant(grant: ModelRelayGrant): Readonly<ModelRelayGrant> {
  const checked = normalizeModelRelayGrant(grant);
  return Object.freeze({
    ...checked,
    routes: Object.freeze([...checked.routes]),
    ...(checked.allowedModels ? { allowedModels: Object.freeze([...checked.allowedModels]) } : {}),
    allowedBetaValues: Object.freeze([...checked.allowedBetaValues!])
  });
}

function deny(res: ServerResponse, status: number, message: string): void {
  if (res.headersSent) { res.destroy(); return; }
  res.writeHead(status, {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
    connection: "close"
  });
  res.end(message);
}

export async function startVerifiedModelRelayServer(options: ModelRelayServerOptions): Promise<VerifiedModelRelayServer> {
  if (!options.store || typeof options.approval?.assertAuthorized !== "function") {
    throw new Error("The model relay needs a broker store and an approval verifier.");
  }
  const perSession = options.maxActiveRequestsPerSession ?? 4;
  if (!Number.isSafeInteger(perSession) || perSession < 1 || perSession > 8) {
    throw new Error("Invalid model relay request limit.");
  }
  const pendingLimit = options.maxPendingBrokerOperations ?? maxPendingOperations;
  if (!Number.isSafeInteger(pendingLimit) || pendingLimit < 1 || pendingLimit > maxPendingOperations) {
    throw new Error("Invalid model relay broker operation limit.");
  }
  const connectionLimit = options.maxVerifiedConnections;
  if (connectionLimit !== undefined &&
      (!Number.isSafeInteger(connectionLimit) || connectionLimit < 1 || connectionLimit > 4096)) {
    throw new Error("Invalid model relay connection limit.");
  }
  const headerDeadlineMs = options.headerDeadlineMs ?? defaultHeaderDeadlineMs;
  const bodyIdleMs = options.bodyIdleMs ?? defaultBodyIdleMs;
  const maxBodyDurationMs = options.maxBodyDurationMs ?? defaultMaxBodyDurationMs;
  if (![headerDeadlineMs, bodyIdleMs, maxBodyDurationMs].every(Number.isSafeInteger) ||
      headerDeadlineMs < 1 || headerDeadlineMs > defaultHeaderDeadlineMs ||
      bodyIdleMs < 1 || bodyIdleMs > defaultBodyIdleMs ||
      maxBodyDurationMs < 1 || maxBodyDurationMs > defaultMaxBodyDurationMs) {
    throw new Error("Invalid model relay request deadline.");
  }

  const grants = new Map<string, ActiveGrant>();
  let activeRequests = 0;
  let pendingBrokerOperations = 0;
  let verifiedConnections = 0;
  let closed = false;
  const pendingSessionEnds = new Set<Promise<void>>();
  const sessionEndErrors: Error[] = [];
  const principals = new WeakMap<Socket, VerifiedAgentPrincipal>();
  const headers = new WeakMap<Socket, ReturnType<typeof setTimeout>>();
  const http = createServer((req, res) => { void handleRequest(req, res); });
  http.headersTimeout = headerDeadlineMs;
  http.requestTimeout = maxBodyDurationMs;
  http.maxHeadersCount = 40;
  http.maxRequestsPerSocket = 1;
  http.keepAliveTimeout = 1000;
  http.on("clientError", (_error, socket) => socket.destroy());

  function endSession(session: PeerSession): void {
    const task = Promise.resolve()
      .then(() => options.approval.onSessionEnded?.(session))
      .then(() => {}, error => {
        sessionEndErrors.push(error instanceof Error ? error : new Error(String(error)));
        const message = "Model relay session-end audit failed.";
        try {
          if (options.onSessionEndError) options.onSessionEndError(message);
          else process.emitWarning(message, { code: "SGW_MODEL_RELAY_AUDIT" });
        } catch {
          try { process.emitWarning(message, { code: "SGW_MODEL_RELAY_AUDIT" }); }
          catch { /* The failure remains available to close(). */ }
        }
      });
    pendingSessionEnds.add(task);
    void task.then(() => pendingSessionEnds.delete(task));
  }

  async function brokerOperation<T>(run: () => Promise<T>, timeoutMs: number): Promise<T> {
    if (pendingBrokerOperations >= pendingLimit) throw new Error("Model relay broker is busy.");
    pendingBrokerOperations++;
    const task = Promise.resolve().then(run);
    void task.then(() => { pendingBrokerOperations--; }, () => { pendingBrokerOperations--; });
    return within(() => task, timeoutMs);
  }

  async function assertAuthorized(principal: VerifiedAgentPrincipal, active: ActiveGrant): Promise<void> {
    if (!principal.sessionId || grants.get(principal.sessionId) !== active || Date.now() >= active.expiresAt) {
      throw new Error("Model relay session ended.");
    }
    await brokerOperation(() => options.approval.assertAuthorized(principal, active.grant), 5000);
    const secret = await brokerOperation(() => options.store.getSecretRecord(active.grant.handle), 10_000);
    if (secret.type !== "api-token" || !secret.policy.allowedCommands.includes(SGW_MODEL_RELAY_COMMAND) ||
        !(secret.policy.allowedDestinations || []).some(item => item.toLowerCase() === destinations[active.grant.provider])) {
      throw new Error("Model relay handle policy no longer allows this provider.");
    }
    if (grants.get(principal.sessionId) !== active || Date.now() >= active.expiresAt) {
      throw new Error("Model relay session ended.");
    }
  }

  async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const headerTimer = headers.get(req.socket);
    if (headerTimer) clearTimeout(headerTimer);
    headers.delete(req.socket);
    const principal = principals.get(req.socket);
    const active = principal?.sessionId ? grants.get(principal.sessionId) : undefined;
    if (!principal || !active || active.active >= perSession || activeRequests >= maxActiveRequests) {
      deny(res, active ? 429 : 403, active ? "Model relay is busy." : "Model relay authorization unavailable.");
      return;
    }
    if (active.grant.maxRequests !== undefined && active.requestsStarted >= active.grant.maxRequests) {
      deny(res, 429, "Model relay request limit reached.");
      return;
    }
    try {
      const route = modelRoute(active.grant.provider, req.method, req.url);
      if (!active.grant.routes?.includes(`${req.method} ${route.pathname}`)) {
        throw new Error("Model relay route is outside this grant.");
      }
    } catch {
      deny(res, 404, "Unsupported model relay route.");
      return;
    }
    active.requestsStarted++;
    active.active++;
    activeRequests++;
    res.setHeader("connection", "close");
    let bodyTimer: ReturnType<typeof setTimeout> | undefined;
    if (req.method !== "GET") {
      bodyTimer = setTimeout(() => req.destroy(new Error("Model request body exceeded its deadline.")), maxBodyDurationMs);
      bodyTimer.unref();
      req.socket.setTimeout(bodyIdleMs, () => req.destroy(new Error("Model request body stalled.")));
      req.once("end", () => {
        clearTimeout(bodyTimer);
        req.socket.setTimeout(35 * 60_000);
      });
    }
    try {
      if (options.activatedFd !== undefined) await peer.assertSocketBinding();
      await assertAuthorized(principal, active);
      const credential = await brokerOperation(() => options.store.revealSecretForLocalUse(active.grant.handle, undefined, {
        cache: false
      }), 30_000);
      if (options.activatedFd !== undefined) await peer.assertSocketBinding();
      await assertAuthorized(principal, active);
      if (req.destroyed || res.destroyed) throw new Error("Model relay client disconnected.");
      await relayModelRequest(req, res, {
        provider: active.grant.provider,
        credential,
        assertAuthorized: () => assertAuthorized(principal, active),
        workspaceId: active.grant.workspaceId,
        organizationId: active.grant.organizationId,
        projectId: active.grant.projectId,
        anthropicVersion: active.grant.anthropicVersion,
        allowedBetaValues: active.grant.allowedBetaValues,
        payloadProfile: active.grant.payloadProfile,
        allowedModels: active.grant.allowedModels,
        bufferOwner: principal.sessionId
      }, options.requestUpstream);
    } catch {
      deny(res, 403, "Model relay authorization unavailable.");
    } finally {
      clearTimeout(bodyTimer);
      active.active--;
      activeRequests--;
    }
  }

  const peer = await startVerifiedPeerServer({
    socketPath: options.socketPath,
    socketMode: options.socketMode,
    socketGid: options.socketGid,
    activatedFd: options.activatedFd,
    requireLinuxPeerPidfd: true,
    onConnection(socket, principal) {
      if (connectionLimit !== undefined && verifiedConnections >= connectionLimit) {
        socket.destroy();
        return;
      }
      verifiedConnections++;
      socket.once("close", () => { verifiedConnections--; });
      principals.set(socket, principal);
      const timer = setTimeout(() => socket.destroy(new Error("Model request headers timed out.")), headerDeadlineMs);
      timer.unref();
      headers.set(socket, timer);
      socket.once("close", () => clearTimeout(timer));
      http.emit("connection", socket);
      socket.resume();
    }
  });

  return {
    assertSocketBinding: () => peer.assertSocketBinding(),
    registerSession(session, input) {
      if (closed) throw new Error("Model relay listener is closed.");
      const grant = checkGrant(input);
      if (grants.has(session.sessionId)) throw new Error("This model relay session is already registered.");
      const stopPeer = peer.registerSession(session);
      const active: ActiveGrant = { session, grant, expiresAt: Date.now() + grant.ttlMs,
        active: 0, requestsStarted: 0, stopPeer };
      const stop = () => {
        if (grants.get(session.sessionId) !== active) return;
        grants.delete(session.sessionId);
        if (active.expiry) clearTimeout(active.expiry);
        stopPeer();
        endSession(session);
      };
      grants.set(session.sessionId, active);
      const timer = setTimeout(stop, grant.ttlMs);
      timer.unref();
      active.expiry = timer;
      return stop;
    },
    async close() {
      if (closed) return;
      closed = true;
      for (const active of grants.values()) {
        if (active.expiry) clearTimeout(active.expiry);
        active.stopPeer();
        endSession(active.session);
      }
      grants.clear();
      await peer.close();
      http.closeAllConnections();
      await Promise.all([...pendingSessionEnds]);
      try {
        await options.approval.retryPendingSessionEnds?.();
      } catch (error) {
        sessionEndErrors.push(error instanceof Error ? error : new Error(String(error)));
      }
      if (sessionEndErrors.length) {
        throw new AggregateError(sessionEndErrors, "Model relay session-end audit failed.");
      }
    }
  };
}
