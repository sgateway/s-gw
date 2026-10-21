import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { request as httpRequest, type IncomingHttpHeaders } from "node:http";
import { createServer as createHttpsServer, request as httpsRequest, type Server as HttpsServer } from "node:https";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { SGW_MODEL_RELAY_COMMAND, startVerifiedModelRelayServer, type VerifiedModelRelayServer } from "../src/model-relay-server.js";
import { principalForVerifiedPeer } from "../src/agent-context.js";
import { registerDurableModelRelaySession, StoreBackedModelRelayApprovals } from "../src/model-relay-approval.js";
import type { ModelUpstreamRequest } from "../src/model-relay-transport.js";
import type { PeerSession } from "../src/peer-identity.js";
import { SecretStore } from "../src/store.js";
import { httpsFixture } from "./helpers/https-fixture.js";

const unix = process.platform === "darwin" || process.platform === "linux";
const hasCompiler = spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;
const linuxCgroup = process.platform === "linux"
  ? readFileSync("/proc/self/cgroup", "utf8").split("\n").find(line => line.startsWith("0::/"))?.slice(3)
  : undefined;
const canRegister = process.platform !== "linux" || !!linuxCgroup && linuxCgroup !== "/";
const peerScript = fileURLToPath(new URL("../scripts/build-peer-credentials.mjs", import.meta.url));
const credential = `synthetic-model-key-${randomUUID()}`;
let root = "";
let server: VerifiedModelRelayServer | undefined;
let upstream: HttpsServer | undefined;
let store: SecretStore;
let socketPath = "";
let upstreamPort = 0;
let upstreamCalls = 0;

beforeAll(() => {
  if (!unix || !hasCompiler) return;
  const build = spawnSync(process.execPath, [peerScript], { encoding: "utf8" });
  if (build.status !== 0) throw new Error(build.stderr || build.stdout);
});

beforeEach(async () => {
  root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-model-peer-")));
  socketPath = path.join(root, "model.sock");
  process.env.SGW_MASTER_PASSPHRASE = "synthetic relay test passphrase";
  process.env.SGW_RECOVERY_HOME = path.join(root, "recovery");
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
  store = new SecretStore(path.join(root, "store"));
  await store.init();
  upstreamCalls = 0;
});

afterEach(async () => {
  await server?.close();
  upstream?.closeAllConnections();
  if (upstream) await new Promise<void>(resolve => upstream!.close(() => resolve()));
  server = undefined;
  upstream = undefined;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_RECOVERY_HOME;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  delete process.env.SGW_DISABLE_ONEPASSWORD_BACKUP;
  if (root) await rm(root, { recursive: true, force: true });
  root = "";
});

async function ownSession(): Promise<PeerSession> {
  const session: PeerSession = { uid: process.getuid!(), gid: process.getgid!(), sessionId: "model-test-session", name: "Codex" };
  if (process.platform === "linux") session.linuxCgroup = linuxCgroup;
  return session;
}

async function registerOwn(handle: string, ttlMs = 30_000): Promise<() => void> {
  const session = await ownSession();
  const brokerUid = process.getuid!();
  const fake = brokerUid === 0 ? 1 : 0;
  const uid = vi.spyOn(process, "getuid").mockReturnValue(fake);
  const euid = vi.spyOn(process, "geteuid").mockReturnValue(fake);
  try {
    return server!.registerSession(session,
      { provider: "anthropic", handle, ttlMs });
  } finally {
    uid.mockRestore();
    euid.mockRestore();
  }
}

function send(route: string, body = "{}", headers: Record<string, string> = {}): Promise<{ status: number; body: string; headers: IncomingHttpHeaders }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ socketPath, path: route, method: "POST", headers: {
      "content-type": "application/json", ...headers
    } }, response => {
      const chunks: Buffer[] = [];
      let complete = false;
      response.on("data", chunk => chunks.push(Buffer.from(chunk)));
      response.once("end", () => {
        complete = true;
        resolve({ status: response.statusCode!, body: Buffer.concat(chunks).toString(), headers: response.headers });
      });
      response.once("close", () => { if (!complete) reject(new Error("Model stream closed before completion.")); });
    });
    req.once("error", reject);
    req.end(body);
  });
}

async function startProvider(handler: Parameters<typeof createHttpsServer>[1]) {
  const tls = await httpsFixture(root);
  upstream = createHttpsServer(tls, handler);
  await new Promise<void>(resolve => upstream!.listen(0, "127.0.0.1", resolve));
  const address = upstream.address();
  if (!address || typeof address === "string") throw new Error("HTTPS fixture port missing.");
  upstreamPort = address.port;
  const requestUpstream: ModelUpstreamRequest = (url, options, callback) => {
    upstreamCalls++;
    const local = new URL(url.pathname + url.search, `https://localhost:${upstreamPort}`);
    return httpsRequest(local, { ...options, ca: tls.cert, lookup: undefined }, callback);
  };
  return requestUpstream;
}

describe.skipIf(!unix || !hasCompiler || !canRegister)("verified model relay listener", () => {
  it("uses a durable manual approval bound to one verified session and route set", async () => {
    const requestUpstream = await startProvider(async (req, res) => {
      for await (const _chunk of req) {}
      res.writeHead(200, { "content-type": "application/json" }).end("{}");
    });
    const handle = (await store.addSecret({ name: "Durable model fixture", type: "api-token", value: credential,
      policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.anthropic.com:443"] } })).handle;
    const session = await ownSession();
    const principal = principalForVerifiedPeer(`${process.platform}:uid:${session.uid}`, session.name, session.sessionId);
    await store.addApprovalPolicyRule({ name: "Existing broad allow", decision: "allow",
      conditions: { handles: [handle], principalIds: [principal.id] } });
    const approvals = new StoreBackedModelRelayApprovals(store);
    const request = await store.createModelRelayRequest({
      provider: "anthropic", handle, ttlMs: 30_000,
      routes: ["POST /v1/messages"], workspaceId: "workspace-test",
      allowedBetaValues: ["test-feature"]
    }, principal);
    expect(request.state).toBe("pending");
    for (const mode of ["timed-session", "login-session", "always"] as const) {
      await expect(store.approveRequest(request.id, { mode })).rejects.toThrow(/only for this agent session/);
    }
    await expect(store.approveRequestWithScopedPolicy(request.id)).rejects.toThrow(/cannot become an allow policy/);
    await store.approveRequest(request.id, { mode: "per-transaction" });
    await expect(store.claimApprovedRequest(request.id, { managedPrincipal: principal })).rejects.toThrow(/verified relay launcher/);
    await expect(approvals.claim(request.id, { ...session, sessionId: "other-session" })).rejects.toThrow(/different verified agent session/);

    server = await startVerifiedModelRelayServer({ socketPath, store, requestUpstream, approval: approvals });
    const brokerUid = process.getuid!();
    const fake = brokerUid === 0 ? 1 : 0;
    const uid = vi.spyOn(process, "getuid").mockReturnValue(fake);
    const euid = vi.spyOn(process, "geteuid").mockReturnValue(fake);
    let stop: (() => void) | undefined;
    try {
      stop = await registerDurableModelRelaySession(server, approvals, session, request.id);
    } finally {
      uid.mockRestore();
      euid.mockRestore();
    }
    expect((await store.getRequest(request.id)).state).toBe("executing");
    expect((await send("/v1/messages")).status).toBe(200);
    expect((await send("/v1/messages/count_tokens")).status).toBe(404);
    expect(upstreamCalls).toBe(1);
    const deny = await store.addApprovalPolicyRule({ name: "Deny this relay", decision: "deny",
      conditions: { handles: [handle], principalIds: [principal.id], actionKinds: ["model_relay"] } });
    expect((await send("/v1/messages")).status).toBe(403);
    await store.deleteApprovalPolicyRule(deny.id);
    expect((await send("/v1/messages")).status).toBe(200);
    expect(upstreamCalls).toBe(2);
    await expect(store.assertModelRelayRequestAuthorized(request.id, principal, {
      provider: "anthropic", handle, ttlMs: 30_000, routes: ["POST /v1/messages"],
      workspaceId: "other-workspace", allowedBetaValues: ["test-feature"]
    })).rejects.toThrow(/differs from its approval/);
    await store.deleteSecret(handle);
    expect((await send("/v1/messages")).status).toBe(403);
    stop?.();
  });

  it("keeps a model relay approval durable across store reads and denies reuse after completion", async () => {
    const handle = (await store.addSecret({ name: "Persistent model fixture", type: "api-token", value: credential,
      policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.openai.com:443"] } })).handle;
    const session = await ownSession();
    const principal = principalForVerifiedPeer(`${process.platform}:uid:${session.uid}`, session.name, session.sessionId);
    const request = await store.createModelRelayRequest({ provider: "openai", handle, ttlMs: 20_000,
      routes: ["POST /v1/responses"], organizationId: "org-test" }, principal);
    await store.setApprovalSettings({ mode: "always", durationMs: 15 * 60_000 });
    await store.approveRequest(request.id);
    expect(await store.listApprovalGrants()).toHaveLength(0);
    const reopened = new SecretStore(path.join(root, "store"));
    const approvals = new StoreBackedModelRelayApprovals(reopened);
    const grant = await approvals.claim(request.id, session);
    await approvals.assertAuthorized(principal, grant);
    await approvals.onSessionEnded(session);
    expect((await reopened.getRequest(request.id)).state).toBe("executed");
    await expect(approvals.assertAuthorized(principal, grant)).rejects.toThrow(/no matching durable approval/);
    await expect(approvals.claim(request.id, session)).rejects.toThrow(/approved model relay request/);
  });

  it("retains a failed session-end write for retry without restoring access", async () => {
    const handle = (await store.addSecret({ name: "Retry model fixture", type: "api-token", value: credential,
      policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.openai.com:443"] } })).handle;
    const session = await ownSession();
    const principal = principalForVerifiedPeer(`${process.platform}:uid:${session.uid}`, session.name, session.sessionId);
    const request = await store.createModelRelayRequest({ provider: "openai", handle, ttlMs: 20_000,
      routes: ["POST /v1/responses"] }, principal);
    await store.approveRequest(request.id);
    const approvals = new StoreBackedModelRelayApprovals(store);
    const grant = await approvals.claim(request.id, session);
    const finish = vi.spyOn(store, "finishModelRelayRequest").mockRejectedValueOnce(new Error("synthetic disk error"));
    await expect(approvals.onSessionEnded(session)).rejects.toThrow("synthetic disk error");
    await expect(approvals.assertAuthorized(principal, grant)).rejects.toThrow(/no matching durable approval/);
    expect((await store.getRequest(request.id)).state).toBe("executing");
    finish.mockRestore();
    await approvals.retryPendingSessionEnds();
    expect((await store.getRequest(request.id)).state).toBe("executed");
    await approvals.retryPendingSessionEnds();
  });

  it("rejects unverified request identities and expires a claimed relay", async () => {
    const handle = (await store.addSecret({ name: "Expiring model fixture", type: "api-token", value: credential,
      policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.openai.com:443"] } })).handle;
    const session = await ownSession();
    const grant = { provider: "openai" as const, handle, ttlMs: 1, routes: ["POST /v1/responses"] };
    await expect(store.createModelRelayRequest(grant, {
      id: `${process.platform}:uid:${session.uid}`, name: session.name, sessionId: session.sessionId
    })).rejects.toThrow(/was not verified/);
    const principal = principalForVerifiedPeer(`${process.platform}:uid:${session.uid}`, session.name, session.sessionId);
    const request = await store.createModelRelayRequest(grant, principal);
    await store.approveRequest(request.id);
    const approvals = new StoreBackedModelRelayApprovals(store);
    const active = await approvals.claim(request.id, session);
    await new Promise(resolve => setTimeout(resolve, 20));
    await expect(approvals.assertAuthorized(principal, active)).rejects.toThrow(/expired/);
    await approvals.onSessionEnded(session);
  });

  it("surfaces a failed session-end audit when the listener closes", async () => {
    const report = vi.fn();
    server = await startVerifiedModelRelayServer({ socketPath, store,
      onSessionEndError: report,
      approval: {
        async assertAuthorized() {},
        async onSessionEnded() { throw new Error("synthetic audit failure"); }
      }
    });
    const stop = await registerOwn("s-gw:api-token:fixture");
    stop();
    await vi.waitFor(() => expect(report).toHaveBeenCalledWith("Model relay session-end audit failed."));
    await expect(server.close()).rejects.toThrow(/session-end audit failed/);
  });

  it("binds an API-token handle and fixed upstream to the verified session", async () => {
    const recorded: Record<string, unknown>[] = [];
    const requestUpstream = await startProvider(async (req, res) => {
      recorded.push(req.headers);
      for await (const _chunk of req) {}
      res.writeHead(200, { "content-type": "text/event-stream", "x-request-id": credential });
      res.end(`event: message\ndata: ${credential}\n\n`);
    });
    const handle = (await store.addSecret({ name: "Model fixture", type: "api-token", value: credential,
      policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.anthropic.com:443"] } })).handle;
    let approved = true;
    server = await startVerifiedModelRelayServer({ socketPath, store, requestUpstream,
      approval: { async assertAuthorized(principal, grant) {
        if (!approved || principal.id !== `${process.platform}:uid:${process.getuid!()}` ||
            principal.sessionId !== "model-test-session" || grant.handle !== handle) throw new Error("revoked");
      } }
    });
    await expect(send("/v1/messages")).rejects.toThrow();
    const stop = await registerOwn(handle);
    const result = await send("/v1/messages", "{}", {
      authorization: "Bearer agent-token", "x-api-key": "agent-key", "anthropic-version": "2023-06-01",
      "anthropic-unsafe-route": "agent-value", "x-s-gw-handle": "s-gw:api-token:other"
    });
    expect(result.status).toBe(200);
    expect(result.body).toContain("[s-gw withheld credential]");
    expect(result.body).not.toContain(credential);
    expect(result.headers["x-request-id"]).toBeUndefined();
    expect(recorded).toHaveLength(1);
    expect(recorded[0].authorization).toBe(`Bearer ${credential}`);
    expect(recorded[0]["x-api-key"]).toBeUndefined();
    expect(recorded[0]["anthropic-unsafe-route"]).toBeUndefined();
    expect(upstreamCalls).toBe(1);
    expect((await send("/v1/messages?handle=s-gw:api-token:other")).status).toBe(404);
    approved = false;
    expect((await send("/v1/messages")).status).toBe(403);
    expect(upstreamCalls).toBe(1);
    stop();
    await expect(send("/v1/messages")).rejects.toThrow();
  });

  it("requires both the relay command and exact provider destination in handle policy", async () => {
    const requestUpstream = await startProvider(async (req, res) => {
      for await (const _chunk of req) {}
      res.writeHead(200, { "content-type": "application/json" }).end("{}");
    });
    const handle = (await store.addSecret({ name: "No model permission", type: "api-token", value: credential,
      policy: { allowedCommands: ["s-gw:https-request"], allowedDestinations: ["api.openai.com:443"] } })).handle;
    server = await startVerifiedModelRelayServer({ socketPath, store, requestUpstream,
      approval: { async assertAuthorized() {} } });
    await registerOwn(handle);
    expect((await send("/v1/messages")).status).toBe(403);
    await store.allowCommand(handle, SGW_MODEL_RELAY_COMMAND);
    expect((await send("/v1/messages")).status).toBe(403);
    expect(upstreamCalls).toBe(0);
    await store.allowDestination(handle, "api.anthropic.com:443");
    expect((await send("/v1/messages")).status).toBe(200);
    expect(upstreamCalls).toBe(1);
  });

  it("rejects unsupported routes before resolving the credential", async () => {
    const handle = (await store.addSecret({ name: "Route fixture", type: "api-token", value: credential,
      policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.anthropic.com:443"] } })).handle;
    const reveal = vi.spyOn(store, "revealSecretForLocalUse");
    server = await startVerifiedModelRelayServer({ socketPath, store,
      approval: { async assertAuthorized() {} } });
    await registerOwn(handle);
    expect((await send("/v1/messages?upstream=https://other.test")).status).toBe(404);
    expect(reveal).not.toHaveBeenCalled();
  });

  it("keeps timed-out broker work inside its concurrency budget until it settles", async () => {
    const handle = (await store.addSecret({ name: "Pending fixture", type: "api-token", value: credential,
      policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.anthropic.com:443"] } })).handle;
    let entered: () => void = () => {};
    let release: () => void = () => {};
    const started = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    let checks = 0;
    server = await startVerifiedModelRelayServer({ socketPath, store,
      maxActiveRequestsPerSession: 2, maxPendingBrokerOperations: 1,
      approval: { async assertAuthorized() { checks++; entered(); await gate; } } });
    await registerOwn(handle);
    try {
      const first = send("/v1/messages");
      await started;
      expect((await send("/v1/messages")).status).toBe(403);
      expect((await first).status).toBe(403);
      expect((await send("/v1/messages")).status).toBe(403);
      expect(checks).toBe(1);
    } finally {
      release();
    }
  }, 10_000);

  it("bounds live requests and closes a stream when its session stops", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>(resolve => { release = resolve; });
    let started = 0;
    const requestUpstream = await startProvider(async (req, res) => {
      for await (const _chunk of req) {}
      started++;
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write("event: start\ndata: " + "x".repeat(100) + "\n\n");
      await gate;
      res.end("event: end\ndata: {}\n\n");
    });
    const handle = (await store.addSecret({ name: "Stream fixture", type: "api-token", value: credential,
      policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.anthropic.com:443"] } })).handle;
    server = await startVerifiedModelRelayServer({ socketPath, store, requestUpstream,
      approval: { async assertAuthorized() {} }, maxActiveRequestsPerSession: 1 });
    const stop = await registerOwn(handle);
    const first = send("/v1/messages").catch(error => error as Error);
    try {
      const deadline = Date.now() + 3000;
      while (!started && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
      expect(started).toBe(1);
      expect((await send("/v1/messages")).status).toBe(429);
      stop();
      const result = await first;
      expect(result).toBeInstanceOf(Error);
    } finally {
      release();
    }
  });

  it("does not open upstream TLS after a client disconnects during approval", async () => {
    const requestUpstream = await startProvider((_req, res) => res.end("unexpected"));
    const handle = (await store.addSecret({ name: "Disconnect fixture", type: "api-token", value: credential,
      policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.anthropic.com:443"] } })).handle;
    let entered: () => void = () => {};
    let release: () => void = () => {};
    const started = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { release = resolve; });
    server = await startVerifiedModelRelayServer({ socketPath, store, requestUpstream,
      approval: { async assertAuthorized() { entered(); await gate; } } });
    await registerOwn(handle);
    const client = httpRequest({ socketPath, path: "/v1/models", method: "GET" });
    client.on("error", () => {});
    client.end();
    await started;
    client.destroy();
    release();
    await new Promise(resolve => setTimeout(resolve, 100));
    expect(upstreamCalls).toBe(0);
  });
});
