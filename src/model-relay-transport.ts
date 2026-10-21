import { lookup } from "node:dns/promises";
import { request as httpsRequest, type RequestOptions } from "node:https";
import { validateHeaderValue, type ClientRequest, type IncomingMessage, type ServerResponse } from "node:http";
import { isIP } from "node:net";
import { httpAddressAllowed } from "./http-executor.js";

export type ModelProvider = "anthropic" | "openai";

export interface ModelRelayAuthority {
  provider: ModelProvider;
  credential: string;
  assertAuthorized: () => Promise<void>;
  workspaceId?: string;
  organizationId?: string;
  projectId?: string;
  anthropicVersion?: string;
  allowedBetaValues?: readonly string[];
  bufferOwner?: string;
  ca?: string;
}

export type ModelUpstreamRequest = (
  url: URL, options: RequestOptions, callback: (response: IncomingMessage) => void
) => ClientRequest;

const destinations: Record<ModelProvider, string> = {
  anthropic: "api.anthropic.com",
  openai: "api.openai.com"
};
const maxBodyBytes = 32 * 1024 * 1024;
const maxBufferedBodyBytes = 2 * maxBodyBytes;
const maxResponseBytes = 64 * 1024 * 1024;
const marker = Buffer.from("[s-gw withheld credential]");
let bufferedBodyBytes = 0;
const bufferedByOwner = new Map<string, number>();

export function modelAddressAllowed(address: string): boolean {
  if (!httpAddressAllowed(address, false)) return false;
  const ip = address.toLowerCase();
  if (ip.startsWith("::ffff:")) {
    const tail = ip.slice(7);
    if (isIP(tail) === 4) return modelAddressAllowed(tail);
    const mapped = /^([a-f0-9]{1,4}):([a-f0-9]{1,4})$/.exec(tail);
    if (!mapped) return false;
    const high = Number.parseInt(mapped[1], 16), low = Number.parseInt(mapped[2], 16);
    return modelAddressAllowed(`${high >> 8}.${high & 255}.${low >> 8}.${low & 255}`);
  }
  if (isIP(ip) === 4) {
    const [a, b, c] = ip.split(".").map(Number);
    if (a === 192 && ((b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) return false;
    if (a === 198 && ((b === 18 || b === 19) || (b === 51 && c === 100))) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    return true;
  }
  if (isIP(ip) !== 6) return false;
  const [first, second] = ip.split(":").map(part => Number.parseInt(part || "0", 16));
  if (first < 0x2000 || first > 0x3fff) return false;
  if (first === 0x2001 && second < 0x200) return false;
  if (first === 0x2001 && second === 0xdb8) return false;
  if (first === 0x2002 || first === 0x3fff) return false;
  return true;
}

interface BufferedBody {
  data?: Buffer;
  release(): void;
}

class RelayError extends Error {
  constructor(readonly status: number, message: string) { super(message); }
}

export function modelRoute(provider: ModelProvider, method: string | undefined, target: string | undefined): URL {
  if (provider !== "anthropic" && provider !== "openai") {
    throw new RelayError(404, "Unsupported model provider.");
  }
  if (!target || !target.startsWith("/") || target.startsWith("//") || target.includes("\\") || target.includes("#")) {
    throw new RelayError(404, "Unsupported model relay route.");
  }
  const route = new URL(target, "http://localhost");
  if (route.origin !== "http://localhost") throw new RelayError(404, "Unsupported model relay route.");
  const pathname = route.pathname;
  const allowed = provider === "anthropic"
    ? (method === "POST" && ["/v1/messages", "/v1/messages/count_tokens"].includes(pathname)) ||
      (method === "GET" && pathname === "/v1/models")
    : method === "POST" && pathname === "/v1/responses";
  if (!allowed) throw new RelayError(404, "Unsupported model relay route.");

  const entries = [...route.searchParams.entries()];
  if (provider === "anthropic" && pathname === "/v1/messages" && entries.length === 1 &&
      entries[0][0] === "beta" && entries[0][1] === "true") {
    return new URL(target, `https://${destinations[provider]}`);
  }
  if (provider === "anthropic" && pathname === "/v1/models" && entries.length === 1 &&
      entries[0][0] === "limit" && /^\d{1,4}$/.test(entries[0][1]) &&
      Number(entries[0][1]) >= 1 && Number(entries[0][1]) <= 1000) {
    return new URL(target, `https://${destinations[provider]}`);
  }
  if (entries.length) throw new RelayError(404, "Unsupported model relay query.");
  return new URL(target, `https://${destinations[provider]}`);
}

function singleHeader(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  if (value === undefined) return;
  if (typeof value !== "string") throw new RelayError(400, `Invalid ${name} header.`);
  validateHeaderValue(name, value);
  return value;
}

function upstreamHeaders(req: IncomingMessage, authority: ModelRelayAuthority, bodyLength: number): Record<string, string> {
  const headers: Record<string, string> = {
    authorization: `Bearer ${authority.credential}`,
    "accept-encoding": "identity",
    accept: "application/json, text/event-stream",
    "user-agent": "s-gw-model-relay",
    "content-type": "application/json"
  };
  if (req.method !== "GET") headers["content-length"] = String(bodyLength);

  const encoding = singleHeader(req, "content-encoding");
  if (encoding && encoding !== "identity") throw new RelayError(415, "Encoded model requests are unsupported.");
  const contentType = singleHeader(req, "content-type");
  if (req.method !== "GET" && contentType && !/^application\/json(?:;\s*charset=utf-8)?$/i.test(contentType)) {
    throw new RelayError(415, "Model requests must use application/json.");
  }

  if (authority.provider === "anthropic") {
    const beta = singleHeader(req, "anthropic-beta");
    headers["anthropic-version"] = authority.anthropicVersion || "2023-06-01";
    if (beta) {
      if (!authority.allowedBetaValues?.includes(beta)) throw new RelayError(403, "Model beta feature is not approved.");
      headers["anthropic-beta"] = beta;
    }
    if (authority.workspaceId) headers["anthropic-workspace-id"] = authority.workspaceId;
    else delete headers["anthropic-workspace-id"];
  } else {
    const beta = singleHeader(req, "openai-beta");
    if (beta) {
      if (!authority.allowedBetaValues?.includes(beta)) throw new RelayError(403, "Model beta feature is not approved.");
      headers["openai-beta"] = beta;
    }
    if (authority.organizationId) headers["openai-organization"] = authority.organizationId;
    if (authority.projectId) headers["openai-project"] = authority.projectId;
  }

  for (const [name, value] of Object.entries(headers)) validateHeaderValue(name, value);
  return headers;
}

async function requestBody(req: IncomingMessage, signal: AbortSignal, owner?: string): Promise<BufferedBody> {
  if (req.method === "GET") {
    if (req.headers["transfer-encoding"] || (req.headers["content-length"] && req.headers["content-length"] !== "0")) {
      throw new RelayError(400, "GET model requests cannot have a body.");
    }
    return { data: Buffer.alloc(0), release() {} };
  }
  const parts: Buffer[] = [];
  let size = 0;
  let reserved = 0;
  const release = () => {
    bufferedBodyBytes -= reserved;
    if (owner) {
      const left = (bufferedByOwner.get(owner) || 0) - reserved;
      if (left > 0) bufferedByOwner.set(owner, left);
      else bufferedByOwner.delete(owner);
    }
    reserved = 0;
  };
  const onAbort = () => req.destroy(signal.reason instanceof Error ? signal.reason : new Error("Model request ended."));
  signal.addEventListener("abort", onAbort, { once: true });
  try {
    signal.throwIfAborted();
    for await (const part of req) {
      signal.throwIfAborted();
      const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part);
      size += chunk.length;
      if (size > maxBodyBytes) throw new RelayError(413, "Model request exceeds 32 MiB.");
      if (bufferedBodyBytes + chunk.length > maxBufferedBodyBytes) {
        throw new RelayError(503, "Model relay request buffer is full.");
      }
      if (owner && (bufferedByOwner.get(owner) || 0) + chunk.length > maxBodyBytes) {
        throw new RelayError(503, "Model relay session buffer is full.");
      }
      bufferedBodyBytes += chunk.length;
      if (owner) bufferedByOwner.set(owner, (bufferedByOwner.get(owner) || 0) + chunk.length);
      reserved += chunk.length;
      parts.push(chunk);
    }
    return { data: Buffer.concat(parts, size), release };
  } catch (error) {
    release();
    throw error;
  } finally {
    signal.removeEventListener("abort", onAbort);
  }
}

class StreamRedactor {
  private tail = Buffer.alloc(0);
  private readonly patterns: Buffer[];

  constructor(secret: string) {
    this.patterns = secretVariants(secret);
  }

  push(chunk: Buffer, finish = false): Buffer {
    const data = Buffer.concat([this.tail, chunk]);
    const keep = finish ? 0 : Math.max(...this.patterns.map(item => item.length)) - 1;
    const limit = Math.max(0, data.length - keep);
    const output: Buffer[] = [];
    let cursor = 0;
    while (cursor < limit) {
      let index = -1;
      let found: Buffer | undefined;
      for (const pattern of this.patterns) {
        const at = data.indexOf(pattern, cursor);
        if (at >= 0 && (index < 0 || at < index || (at === index && pattern.length > found!.length))) {
          index = at;
          found = pattern;
        }
      }
      if (index < 0 || index >= limit) break;
      output.push(data.subarray(cursor, index), marker);
      cursor = index + found!.length;
    }
    if (cursor < limit) { output.push(data.subarray(cursor, limit)); cursor = limit; }
    this.tail = data.subarray(cursor);
    return Buffer.concat(output);
  }
}

function secretVariants(secret: string): Buffer[] {
  const candidates = [secret, Buffer.from(secret).toString("base64"), encodeURIComponent(secret),
    JSON.stringify(secret).slice(1, -1)];
  return [...new Set(candidates)].filter(value => value.length > 0).map(value => Buffer.from(value));
}

function responseHeaders(upstream: IncomingMessage, credential: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const variants = secretVariants(credential).map(value => value.toString());
  for (const [name, value] of Object.entries(upstream.headers)) {
    if (typeof value !== "string" || variants.some(secret => name.includes(secret) || value.includes(secret))) continue;
    const rateLimit = /^(?:anthropic-ratelimit-(?:requests|tokens|input-tokens|output-tokens)-(?:limit|remaining|reset)|x-ratelimit-(?:limit|remaining|reset)-(?:requests|tokens))$/.test(name);
    if (name === "content-type" || name === "retry-after" || name === "x-should-retry" ||
        name === "x-request-id" || rateLimit) {
      validateHeaderValue(name, value);
      headers[name] = value;
    }
  }
  headers["cache-control"] = "no-store";
  return headers;
}

async function writeChunk(res: ServerResponse, chunk: Buffer, signal: AbortSignal): Promise<void> {
  if (!chunk.length) return;
  signal.throwIfAborted();
  if (res.write(chunk)) return;
  await new Promise<void>((resolve, reject) => {
    const onDrain = () => { cleanup(); resolve(); };
    const onClose = () => { cleanup(); reject(new Error("Model relay client disconnected.")); };
    const onAbort = () => { cleanup(); reject(signal.reason); };
    const cleanup = () => { res.off("drain", onDrain); res.off("close", onClose); signal.removeEventListener("abort", onAbort); };
    res.once("drain", onDrain);
    res.once("close", onClose);
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
}

export async function relayModelRequest(
  req: IncomingMessage, res: ServerResponse, authority: ModelRelayAuthority,
  requestUpstream: ModelUpstreamRequest = httpsRequest
): Promise<void> {
  const abort = new AbortController();
  const onClose = () => abort.abort(new Error("Model relay client disconnected."));
  req.once("aborted", onClose);
  res.once("close", onClose);
  const timeout = setTimeout(() => abort.abort(new Error("Model relay timed out.")), 30 * 60_000);
  let checking: Promise<void> | undefined;
  const check = async () => {
    if (!checking) {
      checking = Promise.resolve().then(authority.assertAuthorized).catch(() => {
        abort.abort(new Error("Model relay authorization ended."));
      }).finally(() => { checking = undefined; });
    }
    await checking;
  };
  const monitor = setInterval(() => { void check(); }, 1000);
  let buffered: BufferedBody | undefined;
  let outbound: ClientRequest | undefined;
  try {
    if (!authority.credential || authority.credential.length > 16_384) throw new RelayError(403, "Model relay credential is unavailable.");
    validateHeaderValue("authorization", authority.credential);
    const route = modelRoute(authority.provider, req.method, req.url);
    await check();
    abort.signal.throwIfAborted();
    buffered = await requestBody(req, abort.signal, authority.bufferOwner);
    const headers = upstreamHeaders(req, authority, buffered.data!.length);
    await check();
    abort.signal.throwIfAborted();

    const upstream = await new Promise<IncomingMessage>((resolve, reject) => {
      const call = requestUpstream(route, {
        method: req.method, headers, agent: false, signal: abort.signal, ca: authority.ca,
        rejectUnauthorized: true,
        lookup: (hostname, opts, callback) => {
          void lookup(hostname, { all: true }).then(addresses => {
            if (!addresses.length || addresses.some(item => !modelAddressAllowed(item.address))) {
              throw new Error("Model provider resolves to a restricted address.");
            }
            const chosen = addresses[0];
            if (opts.all) callback(null, [chosen]);
            else callback(null, chosen.address, chosen.family);
          }).catch(error => callback(error, "", 4));
        }
      }, resolve);
      outbound = call;
      call.once("finish", buffered!.release);
      call.once("close", buffered!.release);
      call.once("error", reject);
      call.end(buffered!.data);
      buffered!.data = undefined;
    });
    if (upstream.statusCode && upstream.statusCode >= 300 && upstream.statusCode < 400) {
      upstream.destroy();
      throw new RelayError(502, "Model provider redirect was refused.");
    }
    if (upstream.headers["content-encoding"] && upstream.headers["content-encoding"] !== "identity") {
      upstream.destroy();
      throw new RelayError(502, "Encoded model response was refused.");
    }
    await check();
    abort.signal.throwIfAborted();
    const onAbortUpstream = () => upstream.destroy(abort.signal.reason instanceof Error ? abort.signal.reason : new Error("Model relay ended."));
    abort.signal.addEventListener("abort", onAbortUpstream, { once: true });
    res.writeHead(upstream.statusCode || 502, responseHeaders(upstream, authority.credential));
    try {
      const redactor = new StreamRedactor(authority.credential);
      let received = 0;
      for await (const part of upstream) {
        abort.signal.throwIfAborted();
        received += part.length;
        if (received > maxResponseBytes) throw new RelayError(502, "Model response exceeded 64 MiB.");
        await check();
        abort.signal.throwIfAborted();
        await writeChunk(res, redactor.push(part), abort.signal);
      }
      await writeChunk(res, redactor.push(Buffer.alloc(0), true), abort.signal);
      res.end();
    } finally {
      abort.signal.removeEventListener("abort", onAbortUpstream);
    }
  } catch (error) {
    outbound?.destroy();
    if (res.headersSent) { res.destroy(); return; }
    const status = error instanceof RelayError ? error.status
      : abort.signal.aborted && abort.signal.reason instanceof Error && abort.signal.reason.message.includes("timed out") ? 504
        : abort.signal.aborted ? 403 : 502;
    const message = error instanceof RelayError ? error.message
      : status === 403 ? "Model relay authorization ended."
        : status === 504 ? "Model relay timed out." : "Model relay upstream failed.";
    res.writeHead(status, { "content-type": "text/plain", "cache-control": "no-store" });
    res.end(message);
  } finally {
    buffered?.release();
    clearTimeout(timeout);
    clearInterval(monitor);
    req.off("aborted", onClose);
    res.off("close", onClose);
  }
}
