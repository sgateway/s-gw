import { validateHeaderName, validateHeaderValue } from "node:http";
import type { CommandAction, HttpRequestSpec, SecretPolicy } from "./types.js";

export const SGW_HTTP_COMMAND = "s-gw:https-request";
export const MAX_HTTP_BODY_BYTES = 1_048_576;
const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
const RESERVED_HEADERS = new Set(["host", "authorization", "proxy-authorization", "connection", "transfer-encoding", "content-length", "upgrade", "cookie", "accept-encoding"]);

export function normalizeHttpRequest(input: HttpRequestSpec): HttpRequestSpec {
  if (!input || typeof input.url !== "string" || input.url.length > 8192) throw new Error("An HTTPS URL is required.");
  const url = new URL(input.url);
  if (url.protocol !== "https:" || url.username || url.password || url.hash) throw new Error("HTTPS operations require a URL without credentials or a fragment.");
  if (!METHODS.has(input.method)) throw new Error("Unsupported HTTPS method.");
  const auth = input.auth;
  if (!auth || !["bearer", "header", "basic"].includes(auth.kind)) throw new Error("Unsupported HTTPS authentication.");
  if (auth.kind === "header") {
    validateHeaderName(auth.name);
    if (RESERVED_HEADERS.has(auth.name.toLowerCase())) throw new Error("Use bearer or basic authentication for Authorization; transport headers cannot carry credentials.");
  }
  if (auth.kind === "basic" && (!auth.username || /[:\x00-\x1f\x7f]/.test(auth.username))) throw new Error("Invalid HTTP basic authentication username.");
  const headers: Record<string, string> = Object.create(null);
  const entries = Object.entries(input.headers || {});
  if (entries.length > 32) throw new Error("HTTPS operations allow at most 32 headers.");
  for (const [name, value] of entries.sort(([a], [b]) => a.localeCompare(b))) {
    validateHeaderName(name);
    if (typeof value !== "string") throw new Error("HTTPS header values must be strings.");
    validateHeaderValue(name, value);
    const lower = name.toLowerCase();
    if (RESERVED_HEADERS.has(lower) || (auth.kind === "header" && lower === auth.name.toLowerCase())) throw new Error("Authentication and transport headers are owned by s-gw.");
    if (Object.hasOwn(headers, lower)) throw new Error("Duplicate HTTPS header.");
    headers[lower] = value;
  }
  if (Buffer.byteLength(JSON.stringify(headers)) > 16_384) throw new Error("HTTPS headers are too large.");
  if (input.body !== undefined && (typeof input.body !== "string" || Buffer.byteLength(input.body) > MAX_HTTP_BODY_BYTES)) throw new Error("HTTPS request body exceeds 1 MiB.");
  if (["GET", "HEAD"].includes(input.method) && input.body !== undefined) throw new Error("GET and HEAD operations cannot have a body.");
  const normalizedAuth: HttpRequestSpec["auth"] = auth.kind === "header" ? { kind: "header", name: auth.name.toLowerCase() }
    : auth.kind === "basic" ? { kind: "basic", username: auth.username } : { kind: "bearer" };
  return { url: url.href, method: input.method, headers, ...(input.body !== undefined ? { body: input.body } : {}), auth: normalizedAuth };
}

export function buildHttpRequestAction(http: HttpRequestSpec, timeoutMs = 30_000, injectEnv = "SGW_HTTP_CREDENTIAL"): CommandAction {
  const normalized = normalizeHttpRequest(http);
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300_000) throw new Error("HTTPS timeout must be between 1 and 300000 ms.");
  return { kind: "http_request", command: SGW_HTTP_COMMAND, args: [normalized.method, normalized.url], injectEnv, env: [], timeoutMs, http: normalized };
}

export function assertHttpDestination(policy: SecretPolicy, http: HttpRequestSpec): void {
  const url = new URL(http.url);
  const host = url.hostname.toLowerCase();
  const destination = `${host}:${url.port || "443"}`;
  if (!(policy.allowedDestinations || []).some(rule => rule.toLowerCase() === destination)) {
    throw new Error(`HTTPS operations require an exact ${destination} destination in the handle policy.`);
  }
}
