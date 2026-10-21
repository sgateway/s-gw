import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { Socket } from "node:net";
import type { VerifiedAgentPrincipal } from "./agent-context.js";
import { modelRoute, relayModelRequest, type ModelProvider, type ModelUpstreamRequest } from "./model-relay-transport.js";
import { startVerifiedPeerServer, type PeerSession, type VerifiedPeerServerOptions } from "./peer-identity.js";
import type { SecretStore } from "./store.js";

export const SGW_MODEL_RELAY_COMMAND = "s-gw:model-relay";

export interface ModelRelayGrant {
  provider: ModelProvider;
  handle: string;
  ttlMs: number;
  workspaceId?: string;
  organizationId?: string;
  projectId?: string;
  anthropicVersion?: string;
  allowedBetaValues?: readonly string[];
}

export interface ModelRelayApproval {
  assertAuthorized(principal: VerifiedAgentPrincipal, grant: Readonly<ModelRelayGrant>): Promise<void>;
}

export interface ModelRelayServerOptions extends Pick<VerifiedPeerServerOptions, "socketPath" | "socketMode" | "socketGid"> {
  store: SecretStore;
  approval: ModelRelayApproval;
  maxActiveRequestsPerSession?: number;
  maxPendingBrokerOperations?: number;
  requestUpstream?: ModelUpstreamRequest;
}

export interface VerifiedModelRelayServer {
  registerSession(session: PeerSession, grant: ModelRelayGrant): () => void;
  close(): Promise<void>;
}

interface ActiveGrant {
  grant: Readonly<ModelRelayGrant>;
  expiresAt: number;
  active: number;
  stopPeer: () => void;
  expiry?: ReturnType<typeof setTimeout>;
}

const destinations: Record<ModelProvider, string> = {
  anthropic: "api.anthropic.com:443",
  openai: "api.openai.com:443"
};
const maxGrantMs = 30 * 60_000;
const headerDeadlineMs = 10_000;
const bodyIdleMs = 20_000;
const maxBodyDurationMs = 60_000;
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
  if (grant.provider !== "anthropic" && grant.provider !== "openai") throw new Error("Unsupported model provider.");
  if (typeof grant.handle !== "string" || !/^s-gw:api-token:[A-Za-z0-9_-]{1,128}$/.test(grant.handle)) {
    throw new Error("A model relay grant needs an API-token handle.");
  }
  if (!Number.isSafeInteger(grant.ttlMs) || grant.ttlMs < 1 || grant.ttlMs > maxGrantMs) {
    throw new Error("A model relay grant needs a finite lifetime of at most 30 minutes.");
  }
  for (const value of [grant.workspaceId, grant.organizationId, grant.projectId]) {
    if (value !== undefined && (typeof value !== "string" || value.length > 512 || /[\x00-\x1f\x7f]/.test(value))) {
      throw new Error("Invalid operator-owned model account ID.");
    }
  }
  if (grant.provider === "anthropic" && (grant.organizationId || grant.projectId)) {
    throw new Error("OpenAI account IDs cannot be used with Anthropic.");
  }
  if (grant.provider === "openai" && grant.workspaceId) {
    throw new Error("An Anthropic workspace ID cannot be used with OpenAI.");
  }
  if (grant.anthropicVersion !== undefined &&
      (grant.provider !== "anthropic" || !/^\d{4}-\d{2}-\d{2}$/.test(grant.anthropicVersion))) {
    throw new Error("Invalid operator-owned Anthropic API version.");
  }
  const beta = grant.allowedBetaValues ?? [];
  if (!Array.isArray(beta) || beta.length > 16 || beta.some(value =>
    typeof value !== "string" || value.length < 1 || value.length > 512 || /[\x00-\x1f\x7f]/.test(value))) {
    throw new Error("Invalid operator-owned model beta values.");
  }
  return Object.freeze({ ...grant, allowedBetaValues: Object.freeze([...beta]) });
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

  const grants = new Map<string, ActiveGrant>();
  let activeRequests = 0;
  let pendingBrokerOperations = 0;
  let closed = false;
  const principals = new WeakMap<Socket, VerifiedAgentPrincipal>();
  const headers = new WeakMap<Socket, ReturnType<typeof setTimeout>>();
  const http = createServer((req, res) => { void handleRequest(req, res); });
  http.headersTimeout = headerDeadlineMs;
  http.requestTimeout = maxBodyDurationMs;
  http.maxHeadersCount = 40;
  http.maxRequestsPerSocket = 1;
  http.keepAliveTimeout = 1000;
  http.on("clientError", (_error, socket) => socket.destroy());

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
    try {
      modelRoute(active.grant.provider, req.method, req.url);
    } catch {
      deny(res, 404, "Unsupported model relay route.");
      return;
    }
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
      await assertAuthorized(principal, active);
      const credential = await brokerOperation(() => options.store.revealSecretForLocalUse(active.grant.handle, undefined, {
        cache: false
      }), 30_000);
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
    requireLinuxPeerPidfd: true,
    onConnection(socket, principal) {
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
    registerSession(session, input) {
      if (closed) throw new Error("Model relay listener is closed.");
      const grant = checkGrant(input);
      if (grants.has(session.sessionId)) throw new Error("This model relay session is already registered.");
      const stopPeer = peer.registerSession(session);
      const active: ActiveGrant = { grant, expiresAt: Date.now() + grant.ttlMs, active: 0, stopPeer };
      const stop = () => {
        if (grants.get(session.sessionId) !== active) return;
        grants.delete(session.sessionId);
        if (active.expiry) clearTimeout(active.expiry);
        stopPeer();
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
      }
      grants.clear();
      await peer.close();
      http.closeAllConnections();
    }
  };
}
