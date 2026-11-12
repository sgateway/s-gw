import { Agent as HttpAgent, createServer as createHttpServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { Agent as HttpsAgent, request as httpsRequest } from "node:https";
import { createServer as createTcpServer, connect as netConnect, isIP, type Server, type Socket } from "node:net";
import { Transform } from "node:stream";
import { checkServerIdentity, connect as tlsConnect } from "node:tls";
import { canonicalizeHost, isValidHost, stripHopByHop } from "@anthropic-ai/sandbox-runtime/dist/sandbox/parent-proxy.js";
import { dialManagedProxyHost, type ManagedProxyDialOptions } from "./managed-proxy-dial.js";

const socketLimit = 128;
const transferLimit = 64 * 1024 * 1024;

export interface ManagedProxyOptions extends Pick<ManagedProxyDialOptions, "lookup" | "connect"> {
  allowedDomains: readonly string[];
  deniedDomains?: readonly string[];
  brokerPort: number;
  env?: NodeJS.ProcessEnv;
  parentProxy?: unknown;
  maxTransferBytes?: number;
  maxLiveSockets?: number;
  tlsCa?: string | Buffer;
}

export interface ManagedProxyServers {
  httpPort: number;
  socksPort: number;
  close(): Promise<void>;
}

export function rejectManagedProxyParentRoute(env: NodeJS.ProcessEnv, parentProxy?: unknown): void {
  const vars = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"];
  if (parentProxy || vars.some(name => Boolean(env[name]))) {
    throw new Error("Public-pinned proxy cannot use a parent proxy; remove parent proxy settings for this opt-in run.");
  }
}

class ByteLimit extends Transform {
  private seen: number;

  constructor(private readonly maxBytes: number, initialBytes = 0) {
    super();
    this.seen = initialBytes;
  }

  override _transform(chunk: Buffer, _encoding: BufferEncoding, done: (error?: Error | null, data?: Buffer) => void): void {
    this.seen += chunk.length;
    if (this.seen > this.maxBytes) done(new Error("Managed proxy transfer limit exceeded."));
    else done(null, chunk);
  }
}

function listen(server: Server | ReturnType<typeof createHttpServer>): Promise<number> {
  return new Promise((resolve, reject) => {
    const failed = (error: Error) => { server.off("listening", ready); reject(error); };
    const ready = () => {
      server.off("error", failed);
      const address = server.address();
      if (!address || typeof address === "string") reject(new Error("Managed proxy has no TCP port."));
      else resolve(address.port);
    };
    server.once("error", failed);
    server.once("listening", ready);
    server.listen(0, "127.0.0.1");
  });
}

function closeServer(server: Server | ReturnType<typeof createHttpServer>): Promise<void> {
  if (!server.listening) return Promise.resolve();
  return new Promise(resolve => server.close(() => resolve()));
}

function parseConnectTarget(raw: string | undefined): { host: string; port: number } | undefined {
  const match = /^\[([^\]]+)\]:(\d+)$/.exec(raw || "") || /^([^:]+):(\d+)$/.exec(raw || "");
  if (!match) return;
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) return;
  return { host: match[1], port };
}

function sendHttpError(res: ServerResponse, code: number): void {
  if (res.destroyed) return;
  if (res.headersSent) { res.destroy(); return; }
  res.writeHead(code, { "Content-Type": "text/plain", "Connection": "close" });
  res.end(code === 403 ? "Connection blocked by network policy" : code === 413 ? "Transfer limit exceeded" : code === 400 ? "Bad Request" : "Bad Gateway");
}

function sendConnectError(socket: Socket, code: number): void {
  if (socket.destroyed) return;
  socket.end(`HTTP/1.1 ${code} ${code === 403 ? "Forbidden" : code === 400 ? "Bad Request" : "Bad Gateway"}\r\nConnection: close\r\n\r\n`);
}

function socksReply(socket: Socket, code: number): void {
  if (!socket.destroyed) socket.write(Buffer.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0]));
}

function parseSocksHost(data: Buffer): string {
  if (data[3] === 1) return `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
  if (data[3] === 3) return new TextDecoder("utf-8", { fatal: true }).decode(data.subarray(5, 5 + data[4]));
  const groups: string[] = [];
  for (let at = 4; at < 20; at += 2) groups.push(data.readUInt16BE(at).toString(16));
  return groups.join(":");
}

export async function startManagedProxyServers(options: ManagedProxyOptions): Promise<ManagedProxyServers> {
  rejectManagedProxyParentRoute(options.env ?? process.env, options.parentProxy);
  const maxBytes = options.maxTransferBytes ?? transferLimit;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) throw new Error("Invalid managed proxy transfer limit.");
  const maxSockets = options.maxLiveSockets ?? socketLimit;
  if (!Number.isSafeInteger(maxSockets) || maxSockets < 2 || maxSockets > socketLimit) {
    throw new Error("Invalid managed proxy socket limit.");
  }
  if (!Number.isInteger(options.brokerPort) || options.brokerPort < 1 || options.brokerPort > 65_535) {
    throw new Error("Invalid managed proxy broker port.");
  }

  const allowedDomains = [...options.allowedDomains].map(item => item.toLowerCase());
  const deniedDomains = [...(options.deniedDomains || [])].map(item => item.toLowerCase());
  const sockets = new Set<Socket>();
  const stopping = new AbortController();
  let closed = false;
  let pendingDials = 0;

  const track = (socket: Socket): boolean => {
    if (sockets.has(socket)) return true;
    socket.on("error", () => {});
    if (closed || sockets.size + pendingDials >= maxSockets) { socket.destroy(); return false; }
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.setTimeout(5 * 60_000, () => socket.destroy());
    return true;
  };
  const permitted = (host: string, port: number): string | undefined => {
    if (!isValidHost(host)) return;
    const name = canonicalizeHost(host);
    if (!name) return;
    const matches = (pattern: string) => pattern.startsWith("*.")
      ? !isIP(name) && name.endsWith(pattern.slice(1))
      : name === pattern;
    if (deniedDomains.some(matches)) return;
    if (host === "127.0.0.1" && name === "127.0.0.1" && port === options.brokerPort) return name;
    if (!allowedDomains.some(matches)) return;
    return name;
  };
  const openBroker = (signal: AbortSignal): Promise<Socket> => new Promise((resolve, reject) => {
    if (signal.aborted) { reject(new Error("Managed proxy dial aborted.")); return; }
    const socket = netConnect({ host: "127.0.0.1", port: options.brokerPort });
    if (!track(socket)) { reject(new Error("Managed proxy socket capacity exceeded.")); return; }
    const finish = (error?: Error) => {
      clearTimeout(timer);
      signal.removeEventListener("abort", onAbort);
      socket.off("connect", onConnect);
      socket.off("error", onError);
      if (error) { socket.destroy(); reject(error); }
      else resolve(socket);
    };
    const onConnect = () => finish();
    const onError = (error: Error) => finish(error);
    const onAbort = () => finish(new Error("Managed proxy dial aborted."));
    const timer = setTimeout(() => finish(new Error("Managed proxy broker connection timed out.")), 5_000);
    socket.once("connect", onConnect);
    socket.once("error", onError);
    signal.addEventListener("abort", onAbort, { once: true });
  });
  const dial = async (host: string, port: number, signal: AbortSignal): Promise<Socket> => {
    if (host === "127.0.0.1" && port === options.brokerPort) return openBroker(signal);
    if (closed || sockets.size + pendingDials >= maxSockets) {
      throw new Error("Managed proxy socket capacity exceeded.");
    }
    pendingDials++;
    let socket: Socket;
    try {
      socket = (await dialManagedProxyHost(host, port, { signal, lookup: options.lookup, connect: options.connect })).socket;
    } finally {
      pendingDials--;
    }
    if (!track(socket)) throw new Error("Managed proxy socket capacity exceeded.");
    return socket;
  };
  const tunnel = (client: Socket, upstream: Socket, head = Buffer.alloc(0)) => {
    if (head.length > maxBytes) { client.destroy(); upstream.destroy(); return; }
    const toServer = new ByteLimit(maxBytes, head.length);
    const toClient = new ByteLimit(maxBytes);
    const fail = () => { client.destroy(); upstream.destroy(); };
    toServer.once("error", fail);
    toClient.once("error", fail);
    client.once("close", () => upstream.destroy());
    upstream.once("close", () => client.destroy());
    if (head.length) upstream.write(head);
    client.pipe(toServer).pipe(upstream);
    upstream.pipe(toClient).pipe(client);
    client.resume();
  };

  const http = createHttpServer();
  const socks = createTcpServer();
  http.on("connection", track);
  socks.on("connection", track);
  http.headersTimeout = 10_000;
  http.requestTimeout = 30_000;
  http.maxRequestsPerSocket = 32;
  http.on("connect", async (req, rawClient, head) => {
    const client = rawClient as Socket;
    const target = parseConnectTarget(req.url);
    if (!target) { sendConnectError(client, 400); return; }
    const host = permitted(target.host, target.port);
    if (!host) { sendConnectError(client, 403); return; }
    const cancel = new AbortController();
    const abort = () => cancel.abort();
    client.once("close", abort);
    stopping.signal.addEventListener("abort", abort, { once: true });
    try {
      const upstream = await dial(host, target.port, cancel.signal);
      if (client.destroyed || cancel.signal.aborted) { upstream.destroy(); return; }
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      tunnel(client, upstream, head);
    } catch (error) {
      sendConnectError(client, error instanceof Error && error.message.includes("restricted address") ? 403 : 502);
    } finally {
      client.off("close", abort);
      stopping.signal.removeEventListener("abort", abort);
    }
  });
  http.on("request", async (req: IncomingMessage, res: ServerResponse) => {
    req.once("error", () => res.destroy());
    req.pause();
    let target: URL;
    try { target = new URL(req.url || ""); }
    catch { sendHttpError(res, 400); return; }
    if (!["http:", "https:"].includes(target.protocol) || target.username || target.password || target.hash) {
      sendHttpError(res, 400);
      return;
    }
    const contentLength = req.headers["content-length"];
    if (contentLength !== undefined && (!/^\d+$/.test(contentLength) || Number(contentLength) > maxBytes)) {
      sendHttpError(res, 413);
      return;
    }
    const isHttps = target.protocol === "https:";
    const port = target.port ? Number(target.port) : isHttps ? 443 : 80;
    const host = permitted(target.hostname, port);
    if (!host) { sendHttpError(res, 403); return; }
    const cancel = new AbortController();
    const abort = () => cancel.abort();
    req.socket.once("close", abort);
    stopping.signal.addEventListener("abort", abort, { once: true });
    let upstream: Socket | undefined;
    try {
      upstream = await dial(host, port, cancel.signal);
      if (req.socket.destroyed || cancel.signal.aborted) { upstream.destroy(); return; }
      const headers = { ...stripHopByHop(req.headers), host: target.host, connection: "close" };
      const agent = isHttps ? new HttpsAgent({ keepAlive: false }) : new HttpAgent({ keepAlive: false });
      // A private agent makes Node use this vetted socket instead of resolving the hostname again.
      if (isHttps) {
        agent.createConnection = () => {
          const secure = tlsConnect({ socket: upstream, servername: isIP(host) ? undefined : host,
            rejectUnauthorized: true, checkServerIdentity: (_name, cert) => checkServerIdentity(host, cert),
            ...(options.tlsCa ? { ca: options.tlsCa } : {}) });
          secure.on("error", () => {});
          return secure;
        };
      } else agent.createConnection = () => upstream;
      const requestFn = isHttps ? httpsRequest : httpRequest;
      const request = requestFn({
        hostname: host, port, path: target.pathname + target.search, method: req.method,
        headers, agent
      }, (response: IncomingMessage) => {
        response.once("error", () => res.destroy());
        const responseLength = response.headers["content-length"];
        if (responseLength !== undefined && (!/^\d+$/.test(responseLength) || Number(responseLength) > maxBytes)) {
          sendHttpError(res, 413);
          response.destroy();
          request.destroy();
          return;
        }
        res.writeHead(response.statusCode || 502, stripHopByHop(response.headers));
        const limit = new ByteLimit(maxBytes);
        limit.once("error", () => { request.destroy(); res.destroy(); });
        response.pipe(limit).pipe(res);
      });
      const limit = new ByteLimit(maxBytes);
      limit.once("error", () => { sendHttpError(res, 413); request.destroy(); });
      request.once("error", () => { if (!res.writableEnded) sendHttpError(res, 502); });
      res.once("close", () => request.destroy());
      req.pipe(limit).pipe(request);
      req.resume();
    } catch (error) {
      upstream?.destroy();
      sendHttpError(res, error instanceof Error && error.message.includes("restricted address") ? 403 : 502);
    } finally {
      req.socket.off("close", abort);
      stopping.signal.removeEventListener("abort", abort);
    }
  });

  socks.on("connection", client => {
    let stage: "greeting" | "request" | "dialing" = "greeting";
    let pending = Buffer.alloc(0);
    const cancel = new AbortController();
    const abort = () => cancel.abort();
    client.once("close", abort);
    stopping.signal.addEventListener("abort", abort, { once: true });
    client.once("close", () => stopping.signal.removeEventListener("abort", abort));
    const reject = (code: number) => { socksReply(client, code); client.end(); };
    const onData = (chunk: Buffer) => {
      pending = Buffer.concat([pending, chunk]);
      if (pending.length > 65_536) { client.destroy(); return; }
      while (stage !== "dialing") {
        if (stage === "greeting") {
          if (pending.length < 2) return;
          const end = 2 + pending[1];
          if (pending[0] !== 5 || pending[1] === 0) { client.destroy(); return; }
          if (pending.length < end) return;
          if (!pending.subarray(2, end).includes(0)) { client.end(Buffer.from([5, 255])); return; }
          client.write(Buffer.from([5, 0]));
          pending = pending.subarray(end);
          stage = "request";
        }
        if (pending.length < 5) return;
        if (pending[0] !== 5 || pending[1] !== 1 || pending[2] !== 0) { reject(7); return; }
        const type = pending[3];
        const end = type === 1 ? 10 : type === 4 ? 22 : type === 3 ? 7 + pending[4] : 0;
        if (!end || (type === 3 && pending[4] === 0)) { reject(8); return; }
        if (pending.length < end) return;
        let host: string;
        try { host = parseSocksHost(pending); }
        catch { reject(8); return; }
        const port = pending.readUInt16BE(end - 2);
        const leftover = pending.subarray(end);
        stage = "dialing";
        client.off("data", onData);
        client.pause();
        const name = port ? permitted(host, port) : undefined;
        if (!name) { reject(2); return; }
        void dial(name, port, cancel.signal).then(upstream => {
          if (client.destroyed || cancel.signal.aborted) { upstream.destroy(); return; }
          socksReply(client, 0);
          tunnel(client, upstream, leftover);
        }, error => reject(error instanceof Error && error.message.includes("restricted address") ? 2 : 4));
      }
    };
    client.on("data", onData);
  });

  const close = async () => {
    if (closed) return;
    closed = true;
    stopping.abort();
    for (const socket of sockets) socket.destroy();
    await Promise.all([closeServer(http), closeServer(socks)]);
  };
  try {
    const httpPort = await listen(http);
    const socksPort = await listen(socks);
    return { httpPort, socksPort, close };
  } catch (error) {
    await close();
    throw error;
  }
}
