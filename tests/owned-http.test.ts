import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type Server, type RequestListener } from "node:https";
import { lookup } from "node:dns/promises";
import path from "node:path";
import os from "node:os";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SecretStore } from "../src/store.js";
import { executeApprovedRequest } from "../src/executor.js";
import { buildHttpRequestAction, SGW_HTTP_COMMAND } from "../src/http-action.js";
import { httpAddressAllowed } from "../src/http-executor.js";
import { WITHHELD_HTTP_CREDENTIAL } from "../src/http-response.js";
import { httpsFixture } from "./helpers/https-fixture.js";
import type { HttpRequestSpec } from "../src/types.js";

vi.mock("node:dns/promises", async importOriginal => ({ ...await importOriginal<object>(), lookup: vi.fn() }));
const originalEnv = { ...process.env };
let root = "", server: Server | undefined;
afterEach(async () => {
  vi.restoreAllMocks(); process.env = { ...originalEnv };
  server?.closeAllConnections();
  if (server) await new Promise<void>(resolve => server!.close(() => resolve()));
  server = undefined;
  if (root) await rm(root, { recursive: true, force: true });
});

async function fixture(listener: RequestListener) {
  root = await mkdtemp(path.join(os.tmpdir(), "sgw-https-test-"));
  process.env.SGW_HOME = path.join(root, "store"); process.env.SGW_MASTER_PASSPHRASE = randomUUID();
  process.env.SGW_DISABLE_KEYCHAIN = "1"; process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
  process.env.SGW_DISABLE_PROCESS_AGENT_DETECTION = "1";
  const tls = await httpsFixture(root);
  server = createServer(tls, listener);
  await new Promise<void>(resolve => server!.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("TLS fixture port missing");
  const url = `https://127.0.0.1:${address.port}/operation`;
  const store = new SecretStore(); await store.init();
  const value = `synthetic HTTPS credential ${randomUUID()}`;
  const handle = await store.addSecret({ name: "owned HTTPS fixture", type: "api-token", value, policy: { allowedCommands: [SGW_HTTP_COMMAND], allowedDestinations: [`127.0.0.1:${address.port}`] } });
  const spec: HttpRequestSpec = { url, method: "GET", headers: {}, auth: { kind: "bearer" } };
  return { store, handle, value, spec, ca: tls.cert, port: address.port };
}

describe("owned HTTPS operations", () => {
  it("requires exact destination policy and rejects URL/header/body ambiguity", async () => {
    const f = await fixture((_req, res) => res.end("fixture"));
    await expect(f.store.createRequest(f.handle.handle, buildHttpRequestAction({ ...f.spec, url: "https://other.example.test/" }), "wrong destination")).rejects.toThrow("exact");
    for (const change of [{ url: "http://example.test" }, { url: "https://user:password@example.test/" }, { headers: { authorization: "untrusted header" } }, { body: "GET body" }]) {
      expect(() => buildHttpRequestAction({ ...f.spec, ...change })).toThrow();
    }
    expect(() => buildHttpRequestAction(f.spec, 0)).toThrow("timeout");
    expect(() => buildHttpRequestAction({ ...f.spec, method: "POST", body: "x".repeat(1_048_577) })).toThrow("1 MiB");
    expect(httpAddressAllowed("169.254.169.254", true)).toBe(false);
    expect(httpAddressAllowed("::ffff:a9fe:a9fe", true)).toBe(false);
    expect(httpAddressAllowed("127.0.0.1", false)).toBe(false);
    expect(httpAddressAllowed("127.0.0.1", true)).toBe(true);
  });

  it("authenticates directly after approval, redacts echoed credentials and prevents replay", async () => {
    const received: string[] = [];
    const f = await fixture((req, res) => { received.push(req.headers.authorization || ""); res.end(req.headers.authorization + " " + Buffer.from(req.headers.authorization!.slice(7)).toString("base64")); });
    const request = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "HTTP fixture");
    await expect(executeApprovedRequest(f.store, request.id, { http: { ca: f.ca } })).rejects.toThrow("approval");
    expect(received).toEqual([]);
    await f.store.approveRequest(request.id);
    const result = await executeApprovedRequest(f.store, request.id, { http: { ca: f.ca } });
    expect(received).toEqual([`Bearer ${f.value}`]);
    expect(result.stdout).not.toContain(f.value);
    expect(result.stdout).not.toContain(Buffer.from(f.value).toString("base64"));
    expect(result.sanitized).toBe(true);
    expect(JSON.parse(result.stdout).status).toBe(200);
    await expect(executeApprovedRequest(f.store, request.id)).rejects.toThrow("executed");
    expect((await f.store.getRequest(request.id)).state).toBe("executed");
    expect((await readFile(f.store.storePath, "utf8"))).not.toContain(f.value);
  });

  it("owns basic and API-key authentication and withholds credentials issued in JSON", async () => {
    const received: string[] = [];
    const issued = randomUUID();
    const f = await fixture((req, res) => {
      received.push(String(req.headers.authorization || req.headers["x-service-key"]));
      res.end(JSON.stringify({ result: "ok", echo: received.at(-1), nested: [{ access_token: issued }, { sessionId: issued }] }));
    });
    for (const auth of [{ kind: "basic" as const, username: "fixture" }, { kind: "header" as const, name: "X-Service-Key" }]) {
      const pending = await f.store.createRequest(f.handle.handle, buildHttpRequestAction({ ...f.spec, auth }), "auth fixture");
      await f.store.approveRequest(pending.id);
      const result = await executeApprovedRequest(f.store, pending.id, { http: { ca: f.ca } });
      expect(result.stdout).not.toContain(f.value);
      expect(result.stdout).not.toContain(issued);
      expect(result.stdout).toContain(WITHHELD_HTTP_CREDENTIAL);
      expect(result.stdout).not.toContain(Buffer.from(`fixture:${f.value}`).toString("base64"));
    }
    expect(received).toEqual([`Basic ${Buffer.from(`fixture:${f.value}`).toString("base64")}`, f.value]);
  });

  it("sends every supported HTTP method with the exact approved headers and body", async () => {
    const received: { method: string; body: string; operation: string }[] = [];
    const f = await fixture((req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", chunk => chunks.push(chunk));
      req.on("end", () => {
        received.push({ method: req.method!, body: Buffer.concat(chunks).toString(), operation: String(req.headers["x-operation"]) });
        res.end("method fixture");
      });
    });
    for (const method of ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] as const) {
      const body = ["GET", "HEAD"].includes(method) ? undefined : `approved ${method} body 😄`;
      const request = await f.store.createRequest(f.handle.handle, buildHttpRequestAction({ ...f.spec, method, body, headers: { "x-operation": method } }), "method fixture");
      await f.store.approveRequest(request.id);
      const result = await executeApprovedRequest(f.store, request.id, { http: { ca: f.ca } });
      expect(result.exitCode, `${method}: ${result.stderr} ${result.stdout}`).toBe(0);
      expect(received.at(-1)).toEqual({ method, body: body || "", operation: method });
    }
    expect(received).toHaveLength(6);
  });

  it("returns service failure statuses without retrying, then succeeds on a later request", async () => {
    let status = 401, hits = 0;
    const f = await fixture((_req, res) => { hits++; res.writeHead(status); res.end("service status fixture"); });
    for (const nextStatus of [401, 403, 404, 429, 500, 200]) {
      status = nextStatus;
      const request = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "status fixture");
      await f.store.approveRequest(request.id);
      const result = await executeApprovedRequest(f.store, request.id, { http: { ca: f.ca } });
      expect(result.exitCode).toBe(status === 200 ? 0 : 1);
      expect(JSON.parse(result.stdout).status).toBe(status);
      expect((await f.store.getRequest(request.id)).state).toBe("executed");
    }
    expect(hits).toBe(6);
  });

  it("binds method, body, headers and authentication to reusable approval", async () => {
    const f = await fixture((_req, res) => res.end("fixture"));
    const spec = { ...f.spec, method: "POST" as const, body: "first body", headers: { "x-operation": "first" } };
    const first = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(spec), "HTTP grant fixture");
    await f.store.approveRequest(first.id, { mode: "timed-session", durationMs: 60_000, agentScope: "any-agent" });
    expect((await f.store.createRequest(f.handle.handle, buildHttpRequestAction(spec), "same operation")).state).toBe("approved");
    for (const change of [{ method: "PUT" as const }, { body: "second body" }, { headers: { "x-operation": "second" } }, { auth: { kind: "header" as const, name: "x-service-key" } }]) {
      expect((await f.store.createRequest(f.handle.handle, buildHttpRequestAction({ ...spec, ...change }), "changed operation")).state).toBe("pending");
    }
  });

  it("keeps a permanent HTTPS approval bound to the exact operation after a fresh store instance", async () => {
    const f = await fixture((_req, res) => res.end("exact policy fixture"));
    const spec = { ...f.spec, method: "POST" as const, body: "approved body" };
    const pending = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(spec), "Codex exact policy fixture", { agentName: "Codex" });
    await f.store.approveRequestWithScopedPolicy(pending.id);
    const fresh = new SecretStore();
    expect((await fresh.createRequest(f.handle.handle, buildHttpRequestAction(spec), "Codex same fixture", { agentName: "Codex" })).state).toBe("approved");
    for (const change of [{ body: "changed body" }, { method: "DELETE" as const }, { headers: { "x-extra": "changed" } }, { url: spec.url + "?changed=1" }]) {
      expect((await fresh.createRequest(f.handle.handle, buildHttpRequestAction({ ...spec, ...change }), "Codex changed fixture", { agentName: "Codex" })).state).toBe("pending");
    }
    expect((await fresh.createRequest(f.handle.handle, buildHttpRequestAction(spec, 1000), "Codex timeout fixture", { agentName: "Codex" })).state).toBe("pending");
  });

  it("does not follow redirects or accept an untrusted TLS certificate", async () => {
    let hits = 0;
    const f = await fixture((_req, res) => { hits++; res.writeHead(302, { location: "https://other.example.test/" }); res.end("redirect fixture"); });
    const request = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "redirect fixture");
    await f.store.approveRequest(request.id);
    const result = await executeApprovedRequest(f.store, request.id, { http: { ca: f.ca } });
    expect(result.exitCode).toBe(1); expect(result.stderr).toContain("not followed"); expect(hits).toBe(1);
    const next = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "TLS rejection fixture");
    await f.store.approveRequest(next.id);
    await expect(executeApprovedRequest(f.store, next.id)).rejects.toThrow(/certificate/i);
    expect(hits).toBe(1);
  });

  it("rejects DNS rebinding to private addresses before sending authentication", async () => {
    const f = await fixture((_req, res) => res.end("unexpected"));
    await f.store.allowDestination(f.handle.handle, `service.example.test:${f.port}`);
    vi.mocked(lookup).mockResolvedValue([{ address: "127.0.0.1", family: 4 }] as never);
    const pending = await f.store.createRequest(f.handle.handle, buildHttpRequestAction({ ...f.spec, url: `https://service.example.test:${f.port}/` }), "DNS fixture");
    await f.store.approveRequest(pending.id);
    await expect(executeApprovedRequest(f.store, pending.id, { http: { ca: f.ca } })).rejects.toThrow("restricted address");
  });

  it("bounds an oversized response without returning a clipped credential", async () => {
    const f = await fixture((req, res) => res.end((req.headers.authorization || "").repeat(10000)));
    const request = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "bounded fixture");
    await f.store.approveRequest(request.id);
    const result = await executeApprovedRequest(f.store, request.id, { http: { ca: f.ca } });
    expect(JSON.parse(result.stdout).truncated).toBe(true); expect(result.stdout).not.toContain(f.value);
    expect(Buffer.byteLength(result.stdout)).toBeLessThan(20000);
  });

  it("times out safely, records failure, then executes a later safe request", async () => {
    const f = await fixture((req, res) => { if (req.url === "/safe") res.end("later safe response"); });
    const pending = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec, 150), "timeout fixture");
    await f.store.approveRequest(pending.id);
    await expect(executeApprovedRequest(f.store, pending.id, { http: { ca: f.ca } })).rejects.toThrow("timed out");
    expect((await f.store.getRequest(pending.id)).state).toBe("failed");
    const later = await f.store.createRequest(f.handle.handle, buildHttpRequestAction({ ...f.spec, url: f.spec.url.replace("operation", "safe") }), "later fixture");
    await f.store.approveRequest(later.id);
    expect((await executeApprovedRequest(f.store, later.id, { http: { ca: f.ca } })).stdout).toContain("later safe response");
  });

  it("rejects expired grants before credential use and revokes an operation in flight", async () => {
    let reached: () => void = () => {};
    const f = await fixture((_req, _res) => reached());
    const first = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "expiry fixture");
    await f.store.approveRequest(first.id, { mode: "timed-session", durationMs: 60_000, agentScope: "any-agent" });
    const RealDate = Date;
    const future = RealDate.now() + 65_000;
    vi.stubGlobal("Date", class extends RealDate {
      constructor(value?: string | number) { super(value === undefined ? future : value); }
      static now() { return future; }
    });
    try {
      await expect(executeApprovedRequest(f.store, first.id, { http: { ca: f.ca } })).rejects.toThrow(/expired|revoked/);
    } finally { vi.unstubAllGlobals(); }
    const next = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "revocation fixture");
    const approved = await f.store.approveRequest(next.id, { mode: "timed-session", durationMs: 60_000, agentScope: "any-agent" });
    const received = new Promise<void>(resolve => { reached = resolve; });
    const run = executeApprovedRequest(f.store, next.id, { http: { ca: f.ca } });
    const rejection = expect(run).rejects.toThrow("revoked");
    await received; await f.store.revokeApprovalGrant(approved.approvalGrantId!);
    await rejection; expect((await f.store.getRequest(next.id)).state).toBe("failed");
  });

  it("accepts manual approval of an ask policy and rejects a disabled allow policy before the wire", async () => {
    let hits = 0;
    const f = await fixture((_req, res) => { hits++; res.end("policy fixture"); });
    const ask = await f.store.addApprovalPolicyRule({ name: "HTTPS ask fixture", decision: "ask", conditions: { handles: [f.handle.handle], actionKinds: ["http_request"] } });
    const pending = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "ask fixture");
    expect(pending.state).toBe("pending"); await f.store.approveRequest(pending.id);
    expect((await executeApprovedRequest(f.store, pending.id, { http: { ca: f.ca } })).exitCode).toBe(0);
    await f.store.setApprovalPolicyRuleEnabled(ask.id, false);
    const allow = await f.store.addApprovalPolicyRule({ name: "HTTPS allow fixture", decision: "allow", conditions: { handles: [f.handle.handle], actionKinds: ["http_request"] } });
    const next = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "policy fixture");
    expect(next.state).toBe("approved"); await f.store.setApprovalPolicyRuleEnabled(allow.id, false);
    await expect(executeApprovedRequest(f.store, next.id, { http: { ca: f.ca } })).rejects.toThrow(/no longer|revoked/);
    await f.store.setApprovalPolicyRuleEnabled(allow.id, true);
    const changed = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "changed allow fixture");
    expect(changed.state).toBe("approved");
    await f.store.updateApprovalPolicyRule(allow.id, { decision: "ask" });
    await expect(executeApprovedRequest(f.store, changed.id, { http: { ca: f.ca } })).rejects.toThrow(/no longer|revoked/);
    expect(hits).toBe(1);
  });

  it("claims one approved request only once under concurrent execution", async () => {
    let hits = 0;
    const f = await fixture((_req, res) => { hits++; res.end("concurrent fixture"); });
    const pending = await f.store.createRequest(f.handle.handle, buildHttpRequestAction(f.spec), "concurrent fixture"); await f.store.approveRequest(pending.id);
    const results = await Promise.allSettled([executeApprovedRequest(f.store, pending.id, { http: { ca: f.ca } }), executeApprovedRequest(f.store, pending.id, { http: { ca: f.ca } })]);
    expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1); expect(hits).toBe(1);
  });
});
