import { request as httpRequest, createServer as createHttpServer } from "node:http";
import { createServer as createHttpsServer } from "node:https";
import { connect as netConnect, createServer as createTcpServer, type Socket } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import { anthropicSandboxConfig } from "../src/anthropic-sandbox.js";
import { startManagedProxyServers, type ManagedProxyServers } from "../src/managed-proxy.js";
import { httpsFixture } from "./helpers/https-fixture.js";

const openProxies: ManagedProxyServers[] = [];
const publicAnswer = [{ address: "8.8.8.8", family: 4 }];

afterEach(async () => {
  await Promise.all(openProxies.splice(0).map(proxy => proxy.close()));
  vi.restoreAllMocks();
});

async function start(options: Parameters<typeof startManagedProxyServers>[0]) {
  const proxy = await startManagedProxyServers({ env: {}, ...options });
  openProxies.push(proxy);
  return proxy;
}

function proxyGet(port: number, target: string, headers: Record<string, string> = {}): Promise<{ code: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path: target, method: "GET", headers, agent: false }, res => {
      const chunks: Buffer[] = [];
      res.on("data", chunk => chunks.push(chunk));
      res.once("end", () => resolve({ code: res.statusCode || 0, body: Buffer.concat(chunks).toString() }));
      res.once("error", reject);
    });
    req.once("error", reject);
    req.end();
  });
}

function proxyPost(port: number, target: string, body: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path: target, method: "POST",
      headers: { "Content-Length": Buffer.byteLength(body) }, agent: false }, res => {
      res.resume();
      res.once("end", () => resolve(res.statusCode || 0));
      res.once("error", reject);
    });
    req.once("error", reject);
    req.end(body);
  });
}

function connectProxy(port: number, target: string): Promise<{ code: number; socket: Socket }> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: "127.0.0.1", port, path: target, method: "CONNECT", agent: false });
    req.once("connect", (res, socket) => resolve({ code: res.statusCode || 0, socket: socket as Socket }));
    req.once("error", reject);
    req.end();
  });
}

function readBytes(socket: Socket, count: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let data = Buffer.alloc(0);
    const got = (chunk: Buffer) => {
      data = Buffer.concat([data, chunk]);
      if (data.length < count) return;
      socket.off("data", got);
      socket.off("error", reject);
      resolve(data);
    };
    socket.on("data", got);
    socket.once("error", reject);
  });
}

async function socksConnect(port: number, host: string, destPort = 80): Promise<{ reply: number; socket: Socket }> {
  const socket = netConnect({ host: "127.0.0.1", port });
  await new Promise<void>((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); });
  socket.write(Buffer.from([5, 1, 0]));
  expect([...await readBytes(socket, 2)]).toEqual([5, 0]);
  const ip = /^\d+\.\d+\.\d+\.\d+$/.test(host) ? host.split(".").map(Number) : undefined;
  const name = Buffer.from(host);
  socket.write(Buffer.concat([ip ? Buffer.from([5, 1, 0, 1, ...ip]) : Buffer.concat([Buffer.from([5, 1, 0, 3, name.length]), name]),
    Buffer.from([destPort >> 8, destPort & 255])]));
  const result = await readBytes(socket, 10);
  return { reply: result[1], socket };
}

async function listeningPort(server: ReturnType<typeof createHttpServer> | ReturnType<typeof createHttpsServer> | ReturnType<typeof createTcpServer>): Promise<number> {
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Fixture has no port.");
  return address.port;
}

function fixtureConnector(port: number, seen: string[]) {
  return (address: string, _port: number, family: 4 | 6): Promise<Socket> => new Promise((resolve, reject) => {
    seen.push(`${address}/${family}`);
    const socket = netConnect({ host: "127.0.0.1", port });
    socket.once("connect", () => resolve(socket));
    socket.once("error", reject);
  });
}

describe("public-pinned managed proxy", () => {
  it("rejects unsupported launch platforms and parent proxy settings before listener setup", () => {
    expect(() => anthropicSandboxConfig(process.cwd(), "/tmp/sgw-managed-proxy-test",
      { pinPublicProxy: true }, {}, undefined, "darwin")).toThrow("supports Linux only");
    expect(() => anthropicSandboxConfig(process.cwd(), "/tmp/sgw-managed-proxy-test",
      { pinPublicProxy: true }, { HTTP_PROXY: "http://proxy.test:3128", NO_PROXY: "*" }, undefined, "linux"))
      .toThrow("parent proxy");
  });

  it("rejects an allowed name resolving to loopback through HTTP, CONNECT, and SOCKS", async () => {
    const connect = vi.fn(async () => { throw new Error("unexpected connection"); });
    const proxy = await start({ allowedDomains: ["allowed.test"], brokerPort: 62000,
      lookup: async () => [{ address: "127.0.0.1", family: 4 }], connect });
    expect((await proxyGet(proxy.httpPort, "http://allowed.test/data")).code).toBe(403);
    const tunnel = await connectProxy(proxy.httpPort, "allowed.test:443");
    expect(tunnel.code).toBe(403);
    tunnel.socket.destroy();
    const socks = await socksConnect(proxy.socksPort, "allowed.test", 443);
    expect(socks.reply).toBe(2);
    socks.socket.destroy();
    expect(connect).not.toHaveBeenCalled();
  });

  it("rejects mixed answers, then pins a later public answer across DNS changes", async () => {
    const echo = createTcpServer(socket => socket.pipe(socket));
    const echoPort = await listeningPort(echo);
    const seen: string[] = [];
    const lookup = vi.fn()
      .mockResolvedValueOnce([{ address: "8.8.8.8", family: 4 }, { address: "127.0.0.1", family: 4 }])
      .mockResolvedValueOnce(publicAnswer)
      .mockResolvedValueOnce([{ address: "127.0.0.1", family: 4 }]);
    try {
      const proxy = await start({ allowedDomains: ["allowed.test"], brokerPort: 62000,
        lookup, connect: fixtureConnector(echoPort, seen) });
      expect((await connectProxy(proxy.httpPort, "allowed.test:443")).code).toBe(403);
      expect(seen).toEqual([]);
      const tunnel = await connectProxy(proxy.httpPort, "allowed.test:443");
      expect(tunnel.code).toBe(200);
      tunnel.socket.write("pinned");
      expect((await readBytes(tunnel.socket, 6)).toString()).toBe("pinned");
      tunnel.socket.destroy();
      expect(seen).toEqual(["8.8.8.8/4"]);
      expect(lookup).toHaveBeenCalledTimes(2);
    } finally { await new Promise<void>(resolve => echo.close(() => resolve())); }
  });

  it("uses the absolute HTTP target, preserves Host, and dials an allowed public literal", async () => {
    const seen: string[] = [];
    const upstream = createHttpServer((req, res) => res.end(`${req.headers.host} ${req.url}`));
    const port = await listeningPort(upstream);
    try {
      const proxy = await start({ allowedDomains: ["8.8.8.8"], brokerPort: 62000,
        lookup: async () => { throw new Error("numeric host must not resolve"); },
        connect: fixtureConnector(port, seen) });
      const result = await proxyGet(proxy.httpPort, "http://8.8.8.8/path?q=1", { Host: "127.0.0.1" });
      expect(result).toEqual({ code: 200, body: "8.8.8.8 /path?q=1" });
      expect(seen).toEqual(["8.8.8.8/4"]);
      expect((await proxyGet(proxy.httpPort, "http://127.0.0.1/")).code).toBe(403);
      expect((await proxyGet(proxy.httpPort, "ftp://8.8.8.8/")).code).toBe(400);
      expect((await proxyGet(proxy.httpPort, "http://user:pass@8.8.8.8/")).code).toBe(400);
    } finally { await new Promise<void>(resolve => upstream.close(() => resolve())); }
  });

  it("verifies absolute HTTPS targets on a pinned socket without reusing TLS across hosts", async () => {
    const directory = await mkdtemp(path.join(os.tmpdir(), "sgw-pinned-tls-"));
    const { key, cert } = await httpsFixture(directory);
    const seenSni: string[] = [];
    const upstream = createHttpsServer({ key, cert }, (req, res) => res.end(`${req.headers.host} ${req.url}`));
    upstream.on("secureConnection", socket => seenSni.push(socket.servername));
    const port = await listeningPort(upstream);
    const seen: string[] = [];
    const lookup = vi.fn(async () => publicAnswer);
    try {
      const proxy = await start({ allowedDomains: ["localhost", "allowed.test"], brokerPort: 62000,
        lookup, connect: fixtureConnector(port, seen), tlsCa: cert });
      expect(await proxyGet(proxy.httpPort, "https://localhost:443/secure", { Host: "allowed.test" }))
        .toEqual({ code: 200, body: "localhost /secure" });
      expect((await proxyGet(proxy.httpPort, "https://allowed.test:443/secure")).code).toBe(502);
      expect(seen).toEqual(["8.8.8.8/4", "8.8.8.8/4"]);
      expect(lookup).toHaveBeenCalledTimes(2);
      expect(seenSni).toContain("localhost");
      const untrusted = await start({ allowedDomains: ["localhost"], brokerPort: 62000,
        lookup, connect: fixtureConnector(port, seen) });
      expect((await proxyGet(untrusted.httpPort, "https://localhost:443/secure")).code).toBe(502);
    } finally {
      await Promise.all([new Promise<void>(resolve => upstream.close(() => resolve())), rm(directory, { recursive: true, force: true })]);
    }
  });

  it("dials public SOCKS destinations without re-resolving", async () => {
    const echo = createTcpServer(socket => socket.pipe(socket));
    const port = await listeningPort(echo);
    const seen: string[] = [];
    const lookup = vi.fn(async () => publicAnswer);
    try {
      const proxy = await start({ allowedDomains: ["allowed.test", "8.8.8.8"], brokerPort: 62000,
        lookup, connect: fixtureConnector(port, seen) });
      const result = await socksConnect(proxy.socksPort, "allowed.test", 443);
      expect(result.reply).toBe(0);
      result.socket.write("hello");
      expect((await readBytes(result.socket, 5)).toString()).toBe("hello");
      result.socket.destroy();
      const numeric = await socksConnect(proxy.socksPort, "8.8.8.8", 443);
      expect(numeric.reply).toBe(0);
      numeric.socket.destroy();
      expect(seen).toEqual(["8.8.8.8/4", "8.8.8.8/4"]);
      expect(lookup).toHaveBeenCalledTimes(1);
    } finally { await new Promise<void>(resolve => echo.close(() => resolve())); }
  });

  it("limits HTTP request and response bodies and keeps the broker exception exact", async () => {
    const upstream = createHttpServer((_req, res) => res.end("long response"));
    const port = await listeningPort(upstream);
    const broker = createTcpServer(socket => socket.pipe(socket));
    const brokerPort = await listeningPort(broker);
    try {
      const proxy = await start({ allowedDomains: ["8.8.8.8", "127.0.0.1"], brokerPort,
        maxTransferBytes: 4, connect: fixtureConnector(port, []), env: {} });
      expect(await proxyPost(proxy.httpPort, "http://8.8.8.8/", "hello")).toBe(413);
      expect((await proxyGet(proxy.httpPort, "http://8.8.8.8/")).code).toBe(413);
      const permitted = await connectProxy(proxy.httpPort, `127.0.0.1:${brokerPort}`);
      expect(permitted.code).toBe(200);
      permitted.socket.write("okay");
      expect((await readBytes(permitted.socket, 4)).toString()).toBe("okay");
      permitted.socket.destroy();
      const blocked = await connectProxy(proxy.httpPort, "127.0.0.1:62000");
      expect(blocked.code).toBe(403);
      blocked.socket.destroy();
    } finally {
      await Promise.all([upstream, broker].map(server => new Promise<void>(resolve => server.close(() => resolve()))));
    }
  });

  it("rejects parent routes and keeps concurrent runs' allowlists separate", async () => {
    await expect(startManagedProxyServers({ allowedDomains: ["a.test"], brokerPort: 62000,
      env: { HTTPS_PROXY: "http://proxy.test:3128" } })).rejects.toThrow("parent proxy");
    await expect(startManagedProxyServers({ allowedDomains: ["a.test"], brokerPort: 62000,
      env: { HTTP_PROXY: "http://proxy.test:3128", NO_PROXY: "*" } })).rejects.toThrow("parent proxy");
    await expect(startManagedProxyServers({ allowedDomains: ["a.test"], brokerPort: 62000,
      env: {}, parentProxy: { http: "http://proxy.test:3128" } })).rejects.toThrow("parent proxy");
    const a = await start({ allowedDomains: ["a.test"], brokerPort: 62000 });
    const b = await start({ allowedDomains: ["b.test"], brokerPort: 62001 });
    const noProxy = await start({ allowedDomains: ["allowed.test"], brokerPort: 62002,
      env: { NO_PROXY: "*", no_proxy: "*" }, lookup: async () => [{ address: "127.0.0.1", family: 4 }] });
    expect((await proxyGet(noProxy.httpPort, "http://allowed.test/")).code).toBe(403);
    expect((await proxyGet(a.httpPort, "http://b.test/")).code).toBe(403);
    expect((await proxyGet(b.httpPort, "http://a.test/")).code).toBe(403);
    expect(a.httpPort).not.toBe(b.httpPort);
    expect(a.socksPort).not.toBe(b.socksPort);
  });

  it("caps live sockets and tears down listeners after an upstream error", async () => {
    const proxy = await start({ allowedDomains: ["allowed.test"], brokerPort: 62000,
      lookup: async () => publicAnswer, connect: async () => { throw new Error("fixture refused"); },
      maxLiveSockets: 2 });
    const first = netConnect({ host: "127.0.0.1", port: proxy.socksPort });
    const second = netConnect({ host: "127.0.0.1", port: proxy.socksPort });
    await Promise.all([first, second].map(socket => new Promise<void>(resolve => socket.once("connect", resolve))));
    const third = netConnect({ host: "127.0.0.1", port: proxy.socksPort });
    third.on("error", () => {});
    await new Promise<void>(resolve => third.once("close", resolve));
    first.destroy(); second.destroy();
    await vi.waitFor(async () => expect((await proxyGet(proxy.httpPort, "http://allowed.test/")).code).toBe(502));
    await proxy.close();
    await expect(proxyGet(proxy.httpPort, "http://allowed.test/")).rejects.toThrow();
  });

  it("counts an outbound connection while its dial is pending", async () => {
    const upstream = createTcpServer(socket => socket.pipe(socket));
    const port = await listeningPort(upstream);
    let releaseDial: (() => void) | undefined;
    const proxy = await start({ allowedDomains: ["allowed.test"], brokerPort: 62000,
      lookup: async () => publicAnswer, maxLiveSockets: 2,
      connect: () => new Promise<Socket>((resolve, reject) => {
        const socket = netConnect({ host: "127.0.0.1", port });
        socket.once("connect", () => { releaseDial = () => resolve(socket); });
        socket.once("error", reject);
      }) });
    const first = netConnect({ host: "127.0.0.1", port: proxy.socksPort });
    let second: Socket | undefined;
    try {
      await new Promise<void>((resolve, reject) => { first.once("connect", resolve); first.once("error", reject); });
      first.write(Buffer.from([5, 1, 0]));
      expect([...await readBytes(first, 2)]).toEqual([5, 0]);
      const name = Buffer.from("allowed.test");
      first.write(Buffer.concat([Buffer.from([5, 1, 0, 3, name.length]), name, Buffer.from([1, 187])]));
      await vi.waitFor(() => expect(releaseDial).toBeTypeOf("function"));

      second = netConnect({ host: "127.0.0.1", port: proxy.socksPort });
      second.on("error", () => {});
      await vi.waitFor(() => expect(second?.destroyed).toBe(true), { timeout: 2000 });

      releaseDial?.();
      expect((await readBytes(first, 10))[1]).toBe(0);
    } finally {
      first.destroy();
      second?.destroy();
      releaseDial?.();
      await proxy.close();
      await new Promise<void>(resolve => upstream.close(() => resolve()));
    }
  });

  it.skipIf(!["darwin", "linux"].includes(process.platform))("passes both external ports into the real SRT wrapper", async () => {
    const proxy = await start({ allowedDomains: ["allowed.test"], brokerPort: 62000 });
    const config = anthropicSandboxConfig(process.cwd(), "/tmp/sgw-managed-proxy-test", { strictEgress: true, allowHosts: ["allowed.test"] });
    config.network.httpProxyPort = proxy.httpPort;
    config.network.socksProxyPort = proxy.socksPort;
    try {
      await SandboxManager.initialize(config);
      expect(SandboxManager.getProxyPort()).toBe(proxy.httpPort);
      expect(SandboxManager.getSocksProxyPort()).toBe(proxy.socksPort);
      const wrapped = await SandboxManager.wrapWithSandbox("true", "/bin/bash");
      expect(wrapped).toContain(String(proxy.httpPort));
      expect(wrapped).toContain(String(proxy.socksPort));
    } finally { await SandboxManager.reset(); }
  });
});
