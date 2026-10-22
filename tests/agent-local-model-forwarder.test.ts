import { mkdtemp, rm } from "node:fs/promises";
import { request as httpRequest, createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createNetServer, Socket, type Server as NetServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { bridgeModelRelaySocket, checkLinuxForwarderBoundary,
  startLinuxAgentLocalModelForwarder, type LinuxForwarderAttestation,
  type LinuxForwarderSnapshot } from "../src/agent-local-model-forwarder.js";

const proof: LinuxForwarderAttestation = {
  version: 1, sessionId: "session-a", uid: 231001, gid: 231001, brokerUid: 1000,
  brokerSocketOwnerUid: 0, cgroup: "/system.slice/s-gw-agent-session-a.service",
  networkNamespace: "net:[5002]", hostNetworkNamespace: "net:[5001]",
  invocationId: "0123456789abcdef0123456789abcdef", mainPid: 412,
  brokerSocketDevice: "20", brokerSocketInode: "301"
};
const state: LinuxForwarderSnapshot = {
  uid: 231001, gid: 231001,
  status: "Uid:\t231001\t231001\t231001\t231001\nGid:\t231001\t231001\t231001\t231001\n" +
    "Groups:\t231001\nCapInh:\t0000000000000000\nCapPrm:\t0000000000000000\n" +
    "CapEff:\t0000000000000000\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n" +
    "NoNewPrivs:\t1\nSeccomp:\t2\n",
  cgroup: "0::/system.slice/s-gw-agent-session-a.service\n",
  networkNamespace: "net:[5002]",
  mountinfo: "31 21 0:18 / /run/s-gw/launch-gate ro,nosuid - tmpfs tmpfs rw\n",
  brokerSocketOwnerUid: 0, brokerSocketDevice: "20", brokerSocketInode: "301"
};

let root = "";
const services: Array<HttpServer | NetServer> = [];
const sockets = new Set<Socket>();

afterEach(async () => {
  for (const socket of sockets) socket.destroy();
  sockets.clear();
  for (const service of services) {
    await new Promise<void>(resolve => service.close(() => resolve()));
  }
  services.length = 0;
  if (root) await rm(root, { recursive: true, force: true });
  root = "";
});

async function unixBroker(handler: Parameters<typeof createHttpServer>[0]): Promise<string> {
  if (!root) root = await mkdtemp(path.join(os.tmpdir(), "sgw-forwarder-test-"));
  const socketPath = path.join(root, `broker-${services.length}.sock`);
  const service = createHttpServer(handler);
  service.on("connection", socket => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  services.push(service);
  await new Promise<void>(resolve => service.listen(socketPath, resolve));
  return socketPath;
}

async function syntheticBridge(socketPath: string): Promise<number> {
  const service = createNetServer({ allowHalfOpen: true, pauseOnConnect: true }, socket => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    bridgeModelRelaySocket(socket, socketPath);
  });
  services.push(service);
  await new Promise<void>(resolve => service.listen(0, "127.0.0.1", resolve));
  const address = service.address();
  if (!address || typeof address === "string") throw new Error("Test bridge has no TCP port.");
  return address.port;
}

function request(port: number, headers: Record<string, string> = {}): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const call = httpRequest({ host: "127.0.0.1", port, path: "/v1/messages",
      method: "POST", headers: { "content-type": "application/json", ...headers } }, response => {
      const chunks: Buffer[] = [];
      response.on("data", chunk => chunks.push(Buffer.from(chunk)));
      response.once("end", () => resolve({ status: response.statusCode!, body: Buffer.concat(chunks).toString() }));
      response.once("error", reject);
    });
    call.once("error", reject);
    call.end("{}");
  });
}

describe("Linux agent-local model forwarder boundary", () => {
  it("requires the gated launcher proof and checks the actual UID, network namespace and broker socket", () => {
    expect(checkLinuxForwarderBoundary(proof, state)).toEqual(proof);
    const model = { ...proof, socketPath: "/run/s-gw/model.sock" as const };
    expect(checkLinuxForwarderBoundary(model, state)).toEqual(model);
    expect(() => checkLinuxForwarderBoundary({ ...proof,
      socketPath: "/run/s-gw/agent-control.sock" }, state)).toThrow();
    const legacy = { ...proof, brokerSocketOwnerUid: proof.brokerUid };
    expect(checkLinuxForwarderBoundary(legacy,
      { ...state, brokerSocketOwnerUid: proof.brokerUid })).toEqual(legacy);
    expect(() => checkLinuxForwarderBoundary({ ...proof, brokerUid: proof.uid }, state)).toThrow();
    expect(() => checkLinuxForwarderBoundary(proof, { ...state, networkNamespace: proof.hostNetworkNamespace })).toThrow();
    expect(() => checkLinuxForwarderBoundary(proof, { ...state, cgroup: "0::/system.slice/other.service\n" })).toThrow();
    expect(() => checkLinuxForwarderBoundary(proof, { ...state, brokerSocketInode: "302" })).toThrow();
    expect(() => checkLinuxForwarderBoundary(proof,
      { ...state, mountinfo: state.mountinfo.replace(" ro,", " rw,") })).toThrow();
    expect(() => checkLinuxForwarderBoundary(proof,
      { ...state, status: state.status.replace("CapEff:\t0000000000000000", "CapEff:\t0000000000000001") })).toThrow();
  });

  it("does not start a production TCP listener without native launch evidence", async () => {
    await expect(startLinuxAgentLocalModelForwarder()).rejects.toThrow();
  });
});

describe.skipIf(process.platform === "win32")("agent-local model byte bridge (synthetic only)", () => {
  it("streams the first SSE event before the broker finishes the response", async () => {
    let release: () => void = () => {};
    const gate = new Promise<void>(resolve => { release = resolve; });
    const broker = await unixBroker(async (_req, res) => {
      res.writeHead(200, { "content-type": "text/event-stream", connection: "close" });
      res.write("event: first\ndata: one\n\n");
      await gate;
      res.end("event: second\ndata: two\n\n");
    });
    const port = await syntheticBridge(broker);
    let first: () => void = () => {};
    const sawFirst = new Promise<void>(resolve => { first = resolve; });
    let body = "";
    const done = new Promise<void>((resolve, reject) => {
      const call = httpRequest({ host: "127.0.0.1", port, path: "/v1/messages", method: "POST" }, response => {
        response.on("data", chunk => { body += String(chunk); if (body.includes("event: first")) first(); });
        response.once("end", resolve);
        response.once("error", reject);
      });
      call.once("error", reject);
      call.end("{}");
    });
    try {
      await sawFirst;
      expect(body).toContain("event: first");
      expect(body).not.toContain("event: second");
    } finally { release(); }
    await done;
    expect(body).toContain("event: second");
  });

  it("closes the broker Unix stream when the HTTP client cancels", async () => {
    let sawClose: () => void = () => {};
    const closed = new Promise<void>(resolve => { sawClose = resolve; });
    const broker = await unixBroker((_req, res) => {
      res.socket!.once("close", sawClose);
      res.writeHead(200, { "content-type": "text/event-stream" });
      res.write("event: first\ndata: one\n\n");
    });
    const port = await syntheticBridge(broker);
    await new Promise<void>((resolve, reject) => {
      const call = httpRequest({ host: "127.0.0.1", port, path: "/v1/messages", method: "POST" }, response => {
        response.once("data", () => { call.destroy(); resolve(); });
      });
      call.once("error", error => { if (error.message !== "socket hang up") reject(error); });
      call.end("{}");
    });
    await closed;
  });

  it("forwards a request and response when the client half-closes before Unix connect completes", async () => {
    if (!root) root = await mkdtemp(path.join(os.tmpdir(), "sgw-forwarder-test-"));
    const socketPath = path.join(root, "half-close.sock");
    let received = "";
    const broker = createNetServer({ allowHalfOpen: true }, socket => {
      sockets.add(socket);
      socket.once("close", () => sockets.delete(socket));
      socket.on("data", chunk => { received += String(chunk); });
      socket.on("end", () => socket.end("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"));
    });
    services.push(broker);
    await new Promise<void>(resolve => broker.listen(socketPath, resolve));
    const port = await syntheticBridge(socketPath);
    const response = await new Promise<string>((resolve, reject) => {
      const client = new Socket({ allowHalfOpen: true });
      let output = "";
      client.on("data", chunk => { output += String(chunk); });
      client.once("end", () => resolve(output));
      client.once("error", reject);
      client.connect(port, "127.0.0.1", () => {
        client.end("GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
      });
    });
    expect(received).toContain("GET /v1/models HTTP/1.1");
    expect(response).toContain("\r\n\r\nOK");
  });

  it("does not select another session's broker socket from an HTTP header", async () => {
    let otherCalls = 0;
    const own = await unixBroker((_req, res) => res.writeHead(200, { connection: "close" }).end("session-a"));
    await unixBroker((_req, res) => { otherCalls++; res.writeHead(200).end("session-b"); });
    const port = await syntheticBridge(own);
    const result = await request(port, { "x-s-gw-session": "session-b", "x-s-gw-broker-socket": "session-b" });
    expect(result).toEqual({ status: 200, body: "session-a" });
    expect(otherCalls).toBe(0);
  });
});
