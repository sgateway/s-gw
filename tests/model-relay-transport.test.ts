import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createHttpsServer, request as httpsRequest, type Server as HttpsServer } from "node:https";
import { connect } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { httpsFixture } from "./helpers/https-fixture.js";
import { modelAddressAllowed, relayModelRequest, type ModelProvider, type ModelUpstreamRequest } from "../src/model-relay-transport.js";

let home = "";
let provider: HttpsServer | undefined;
let gateway: HttpServer | undefined;
const key = `synthetic-provider-key-${randomUUID()}`;

afterEach(async () => {
  gateway?.closeAllConnections();
  provider?.closeAllConnections();
  if (gateway) await new Promise<void>(resolve => gateway!.close(() => resolve()));
  if (provider) await new Promise<void>(resolve => provider!.close(() => resolve()));
  gateway = undefined;
  provider = undefined;
  if (home) await rm(home, { recursive: true, force: true });
  home = "";
});

async function startFixture(
  modelProvider: ModelProvider,
  upstreamHandler: Parameters<typeof createHttpsServer>[1],
  authorized: () => Promise<void> = async () => {},
  allowedBetaValues: readonly string[] = [],
  bufferOwner?: string,
  credential = key
) {
  home = await mkdtemp(path.join(os.tmpdir(), "sgw-model-relay-"));
  const tls = await httpsFixture(home);
  provider = createHttpsServer(tls, upstreamHandler);
  await new Promise<void>(resolve => provider!.listen(0, "127.0.0.1", resolve));
  const providerAddress = provider.address();
  if (!providerAddress || typeof providerAddress === "string") throw new Error("HTTPS fixture port missing.");
  const outbound: string[] = [];
  const transport: ModelUpstreamRequest = (url, options, callback) => {
    outbound.push(url.href);
    // The test TLS server stands in for the fixed provider host; production has no URL override.
    const local = new URL(url.pathname + url.search, `https://localhost:${providerAddress.port}`);
    return httpsRequest(local, { ...options, ca: tls.cert, lookup: undefined }, callback);
  };
  gateway = createHttpServer((req, res) => {
    void relayModelRequest(req, res, {
      provider: modelProvider,
      credential,
      assertAuthorized: authorized,
      allowedBetaValues,
      bufferOwner,
      workspaceId: modelProvider === "anthropic" ? "wrkspc_test" : undefined,
      projectId: modelProvider === "openai" ? "proj_test" : undefined
    }, transport);
  });
  await new Promise<void>(resolve => gateway!.listen(0, "127.0.0.1", resolve));
  const gatewayAddress = gateway.address();
  if (!gatewayAddress || typeof gatewayAddress === "string") throw new Error("Gateway fixture port missing.");
  return { url: `http://127.0.0.1:${gatewayAddress.port}`, outbound };
}

describe("model relay transport", () => {
  it("refuses special-use DNS answers, including IPv4-mapped addresses", () => {
    for (const address of ["127.0.0.1", "198.18.0.1", "192.0.2.1", "198.51.100.1", "203.0.113.1",
      "::ffff:198.18.0.1", "::ffff:c612:1", "2001:db8::1", "2001::1", "2001:2::1",
      "2001:10::1", "2001:20::1", "2002:7f00:1::1", "3fff::1"]) {
      expect(modelAddressAllowed(address), address).toBe(false);
    }
    expect(modelAddressAllowed("8.8.8.8")).toBe(true);
    expect(modelAddressAllowed("2606:4700:4700::1111")).toBe(true);
  });

  it("streams Anthropic events over broker-owned TLS and replaces split credential echoes", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>(resolve => { release = resolve; });
    const received: { path: string; body: string; headers: Record<string, unknown> }[] = [];
    const fixture = await startFixture("anthropic", async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(chunk);
      received.push({ path: req.url!, body: Buffer.concat(chunks).toString(), headers: req.headers });
      res.writeHead(200, { "content-type": "text/event-stream", "x-request-id": key, "set-cookie": "provider-cookie=1" });
      res.write("event: message_start\ndata: {\"type\":\"message_start\"}\n\n" + "padding".repeat(12));
      await gate;
      const split = Math.floor(key.length / 2);
      res.write(`\nevent: content_block_delta\ndata: ${key.slice(0, split)}`);
      res.end(`${key.slice(split)}\n\nevent: message_stop\ndata: {}\n\n`);
    }, undefined, ["feature-test"]);
    const body = JSON.stringify({ model: "claude-fixture", max_tokens: 10, stream: true, messages: [{ role: "user", content: "hi" }] });
    const response = await fetch(fixture.url + "/v1/messages?beta=true", {
      method: "POST",
      headers: {
        authorization: "Bearer agent-visible-dummy",
        "x-api-key": "agent-visible-key",
        cookie: "agent-cookie=1",
        "proxy-authorization": "Basic agent-proxy",
        "anthropic-version": "2099-12-31",
        "anthropic-beta": "feature-test",
        "anthropic-workspace-id": "wrkspc_agent_override",
        "anthropic-api-key": "agent-visible-key",
        "content-type": "application/json"
      },
      body
    });
    expect(response.status).toBe(200);
    const reader = response.body!.getReader();
    const first = await reader.read();
    expect(new TextDecoder().decode(first.value)).toContain("message_start");
    release();
    const rest: Uint8Array[] = [];
    while (true) {
      const next = await reader.read();
      if (next.done) break;
      rest.push(next.value);
    }
    const output = new TextDecoder().decode(Buffer.concat([first.value!, ...rest]));
    expect(output).toContain("message_stop");
    expect(output).toContain("[s-gw withheld credential]");
    expect(output).not.toContain(key);
    expect(response.headers.get("x-request-id")).toBeNull();
    expect(response.headers.get("set-cookie")).toBeNull();
    expect(received).toHaveLength(1);
    expect(received[0].path).toBe("/v1/messages?beta=true");
    expect(received[0].body).toBe(body);
    expect(received[0].headers.authorization).toBe(`Bearer ${key}`);
    expect(received[0].headers["x-api-key"]).toBeUndefined();
    expect(received[0].headers.cookie).toBeUndefined();
    expect(received[0].headers["proxy-authorization"]).toBeUndefined();
    expect(received[0].headers["anthropic-api-key"]).toBeUndefined();
    expect(received[0].headers["anthropic-beta"]).toBe("feature-test");
    expect(received[0].headers["anthropic-version"]).toBe("2023-06-01");
    expect(received[0].headers["anthropic-workspace-id"]).toBe("wrkspc_test");
    expect(fixture.outbound).toEqual(["https://api.anthropic.com/v1/messages?beta=true"]);
  });

  it("streams OpenAI Responses without forwarding client authority headers", async () => {
    const received: Record<string, unknown>[] = [];
    const fixture = await startFixture("openai", async (req, res) => {
      received.push(req.headers);
      for await (const _chunk of req) {}
      res.writeHead(200, { "content-type": "text/event-stream", "x-ratelimit-limit-requests": "20" });
      res.write("event: response.output_text.delta\ndata: {\"delta\":\"hello\"}\n\n");
      res.end("event: response.completed\ndata: {}\n\n");
    }, undefined, ["responses=v1"]);
    const response = await fetch(fixture.url + "/v1/responses", {
      method: "POST",
      headers: {
        authorization: "Bearer agent-visible-dummy",
        "openai-organization": "org_agent_override",
        "openai-project": "proj_agent_override",
        "openai-beta": "responses=v1",
        "content-type": "application/json"
      },
      body: '{"model":"gpt-fixture","input":"hi","stream":true}'
    });
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("response.completed");
    expect(response.headers.get("x-ratelimit-limit-requests")).toBe("20");
    expect(received).toHaveLength(1);
    expect(received[0].authorization).toBe(`Bearer ${key}`);
    expect(received[0]["openai-project"]).toBe("proj_test");
    expect(received[0]["openai-organization"]).toBeUndefined();
    expect(received[0]["openai-beta"]).toBe("responses=v1");
    expect(fixture.outbound).toEqual(["https://api.openai.com/v1/responses"]);
  });

  it("redacts common URL and base64url renderings of a reflected credential", async () => {
    const credential = "synthetic:key/with+chars?";
    const escaped = encodeURIComponent(credential).replace(/%[0-9A-F]{2}/g, value => value.toLowerCase());
    const mixed = escaped.replace("%2f", "%2F").replace("%2b", "%2B");
    const encoded = Buffer.from(credential).toString("base64url");
    const fixture = await startFixture("anthropic", (_req, res) => {
      res.writeHead(200, { "content-type": "text/event-stream", "x-request-id": mixed });
      res.write(`data: ${escaped.slice(0, 11)}`);
      res.end(`${escaped.slice(11)}\n\ndata: ${encoded}\n\ndata: ${mixed}\n\n`);
    }, undefined, [], undefined, credential);

    const response = await fetch(fixture.url + "/v1/messages", {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}"
    });
    const body = await response.text();
    expect(response.status).toBe(200);
    expect(body).not.toContain(escaped);
    expect(body).not.toContain(encoded);
    expect(body).not.toContain(mixed);
    expect(response.headers.get("x-request-id")).toBeNull();
    expect(body).toContain("[s-gw withheld credential]");
  });

  it("refuses beta headers outside the broker grant before contacting the provider", async () => {
    const fixture = await startFixture("anthropic", (_req, res) => res.end("unexpected"));
    const response = await fetch(fixture.url + "/v1/messages", {
      method: "POST", headers: { "content-type": "application/json", "anthropic-beta": "unapproved-feature" }, body: "{}"
    });
    expect(response.status).toBe(403);
    expect(fixture.outbound).toEqual([]);
  });

  it("rejects arbitrary routes, methods, and queries before opening upstream TLS", async () => {
    const fixture = await startFixture("anthropic", (_req, res) => res.end("unexpected"));
    for (const route of ["/v1/embeddings", "/v1/messages?target=https://other.test",
      "/v1/messages?beta=true&beta=true", "/v1/messages/%2e%2e/models", "//other.test/v1/messages"]) {
      const response = await fetch(fixture.url + route, { method: "POST", body: "{}" });
      expect(response.status, route).toBe(404);
    }
    const connect = await fetch(fixture.url + "/v1/messages", { method: "PUT", body: "{}" });
    expect(connect.status).toBe(404);
    expect(fixture.outbound).toEqual([]);
  });

  it("supports fixed Anthropic token count and model discovery routes", async () => {
    const paths: string[] = [];
    const fixture = await startFixture("anthropic", async (req, res) => {
      paths.push(`${req.method} ${req.url}`);
      for await (const _chunk of req) {}
      res.writeHead(200, { "content-type": "application/json" }).end("{}");
    });
    const count = await fetch(fixture.url + "/v1/messages/count_tokens", {
      method: "POST", headers: { "content-type": "application/json" }, body: '{"model":"claude-fixture","messages":[]}'
    });
    expect(count.status).toBe(200);
    const models = await fetch(fixture.url + "/v1/models?limit=1000");
    expect(models.status).toBe(200);
    expect(paths).toEqual(["POST /v1/messages/count_tokens", "GET /v1/models?limit=1000"]);
    expect(fixture.outbound).toEqual([
      "https://api.anthropic.com/v1/messages/count_tokens",
      "https://api.anthropic.com/v1/models?limit=1000"
    ]);
  });

  it("rejects an untrusted upstream TLS certificate", async () => {
    const fixture = await startFixture("openai", (_req, res) => res.end("unexpected"));
    gateway?.closeAllConnections();
    if (gateway) await new Promise<void>(resolve => gateway!.close(() => resolve()));
    gateway = createHttpServer((req, res) => {
      const localProvider = provider!.address();
      if (!localProvider || typeof localProvider === "string") throw new Error("HTTPS fixture port missing.");
      const transport: ModelUpstreamRequest = (url, options, callback) => {
        return httpsRequest(new URL(url.pathname, `https://localhost:${localProvider.port}`),
          { ...options, ca: undefined, lookup: undefined }, callback);
      };
      void relayModelRequest(req, res, {
        provider: "openai", credential: key, assertAuthorized: async () => {}
      }, transport);
    });
    await new Promise<void>(resolve => gateway!.listen(0, "127.0.0.1", resolve));
    const address = gateway.address();
    if (!address || typeof address === "string") throw new Error("Gateway port missing.");
    const response = await fetch(`http://127.0.0.1:${address.port}/v1/responses`, {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}"
    });
    expect(response.status).toBe(502);
    expect(fixture.outbound).toEqual([]);
  });

  it("refuses redirects, encoded responses, and revoked authorization", async () => {
    let mode = "redirect";
    let hits = 0;
    let authorized = true;
    const fixture = await startFixture("anthropic", (_req, res) => {
      hits++;
      if (mode === "redirect") res.writeHead(302, { location: "https://other.test/steal" }).end();
      else res.writeHead(200, { "content-encoding": "gzip" }).end("compressed");
    }, async () => { if (!authorized) throw new Error("revoked"); });
    const request = () => fetch(fixture.url + "/v1/messages", {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}"
    });
    const redirected = await request();
    expect(redirected.status).toBe(502);
    expect(redirected.headers.get("location")).toBeNull();
    mode = "encoded";
    expect((await request()).status).toBe(502);
    authorized = false;
    expect((await request()).status).toBe(403);
    expect(hits).toBe(2);
  });

  it("does not forward a credential reflected in an upstream header name", async () => {
    const fixture = await startFixture("anthropic", (_req, res) => {
      res.writeHead(200, { [`x-ratelimit-${key}`]: "1", "x-ratelimit-limit-requests": "20" }).end("{}");
    });
    const response = await fetch(fixture.url + "/v1/messages", {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}"
    });
    expect(response.status).toBe(200);
    expect(response.headers.get(`x-ratelimit-${key}`)).toBeNull();
    expect(response.headers.get("x-ratelimit-limit-requests")).toBe("20");
  });

  it("closes a stalled partial request after authorization is revoked", async () => {
    let authorized = true;
    let checks = 0;
    const fixture = await startFixture("anthropic", (_req, res) => res.end("unexpected"), async () => {
      checks++;
      if (!authorized) throw new Error("revoked");
    });
    const port = Number(new URL(fixture.url).port);
    const socket = connect(port, "127.0.0.1");
    try {
      await new Promise<void>((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); });
      socket.write("POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{");
      const deadline = Date.now() + 1000;
      while (checks === 0 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 10));
      expect(checks).toBeGreaterThan(0);
      const closed = new Promise<void>(resolve => socket.once("close", () => resolve()));
      authorized = false;
      await Promise.race([closed, new Promise<never>((_resolve, reject) =>
        setTimeout(() => reject(new Error("Revoked partial request stayed open.")), 2500))]);
      expect(fixture.outbound).toEqual([]);
    } finally { socket.destroy(); }
  });

  it("bounds simultaneous request bodies and admits another after stalled clients leave", async () => {
    const fixture = await startFixture("anthropic", async (req, res) => {
      let bytes = 0;
      for await (const chunk of req) bytes += chunk.length;
      res.writeHead(200, { "content-type": "text/plain" }).end(String(bytes));
    });
    const endpoint = fixture.url + "/v1/messages";
    const fullBody = Buffer.alloc(32 * 1024 * 1024, 0x20);
    const full = await fetch(endpoint, {
      method: "POST", headers: { "content-type": "application/json" }, body: fullBody
    });
    expect(full.status).toBe(200);
    expect(await full.text()).toBe(String(fullBody.length));

    const port = Number(new URL(fixture.url).port);
    const stalled: ReturnType<typeof connect>[] = [];
    const partial = Buffer.alloc(31 * 1024 * 1024, 0x20);
    try {
      for (let i = 0; i < 2; i++) {
        const socket = connect(port, "127.0.0.1");
        socket.on("error", () => {});
        stalled.push(socket);
        await new Promise<void>((resolve, reject) => {
          socket.once("connect", resolve); socket.once("error", reject);
        });
        socket.write(`POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: ${fullBody.length}\r\n\r\n`);
        await new Promise<void>((resolve, reject) => socket.write(partial, error => error ? reject(error) : resolve()));
      }
      const crowded = await fetch(endpoint, {
        method: "POST", headers: { "content-type": "application/json" }, body: Buffer.alloc(3 * 1024 * 1024, 0x20)
      });
      expect(crowded.status).toBe(503);
      expect(fixture.outbound).toHaveLength(1);
    } finally {
      for (const socket of stalled) socket.destroy();
    }

    const recovered = await fetch(endpoint, {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}"
    });
    expect(recovered.status).toBe(200);
    expect(await recovered.text()).toBe("2");
  });

  it("limits one verified session's request buffers independently of the global budget", async () => {
    const fixture = await startFixture("anthropic", async (req, res) => {
      for await (const _chunk of req) {}
      res.writeHead(200, { "content-type": "application/json" }).end("{}");
    }, undefined, [], "agent-one");
    const port = Number(new URL(fixture.url).port);
    const socket = connect(port, "127.0.0.1");
    try {
      await new Promise<void>((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); });
      socket.write("POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: 33554432\r\n\r\n");
      await new Promise<void>((resolve, reject) => socket.write(Buffer.alloc(31 * 1024 * 1024, 0x20),
        error => error ? reject(error) : resolve()));
      const crowded = await fetch(fixture.url + "/v1/messages", {
        method: "POST", headers: { "content-type": "application/json" }, body: Buffer.alloc(2 * 1024 * 1024, 0x20)
      });
      expect(crowded.status).toBe(503);
      expect(fixture.outbound).toEqual([]);
    } finally {
      socket.destroy();
    }
    const recovered = await fetch(fixture.url + "/v1/messages", {
      method: "POST", headers: { "content-type": "application/json" }, body: "{}"
    });
    expect(recovered.status).toBe(200);
  });
});
