import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import { request as httpsRequest } from "node:https";
import { validateHeaderValue } from "node:http";
import { assertHttpDestination, normalizeHttpRequest } from "./http-action.js";
import { captureHeadroomBytes, sanitizeCapturedOutput, SGW_OUTPUT_TRUNCATED } from "./output-redaction.js";
import { scanText, previewHandle } from "./scanner.js";
import { redactHttpCredentialFields } from "./http-response.js";
import type { SecretStore } from "./store.js";
import type { ExecutionSummary, RequestRecord, SecretRecord } from "./types.js";

export interface OwnedHttpOptions {
  ca?: string;
}

export async function runOwnedHttpRequest(store: SecretStore, record: RequestRecord, secret: SecretRecord, value: string, options: OwnedHttpOptions = {}): Promise<ExecutionSummary> {
  if (record.action.kind !== "http_request" || !record.action.http) throw new Error("An owned HTTPS action is required.");
  const spec = normalizeHttpRequest(record.action.http);
  assertHttpDestination(secret.policy, spec);
  const url = new URL(spec.url);
  const started = Date.now();
  const controller = new AbortController();
  const abort = (message: string) => controller.abort(new Error(message));
  let timedOut = false;
  const timeout = setTimeout(() => { timedOut = true; abort("HTTPS operation timed out."); }, record.action.timeoutMs);
  let checking = false;
  const checkAuthorization = async () => {
    if (checking) return;
    checking = true;
    try { await store.assertOwnedRequestAuthorized(record.id); }
    catch { abort("HTTPS authorization expired or was revoked."); }
    finally { checking = false; }
  };
  const monitor = setInterval(() => { void checkAuthorization(); }, 250);
  const headers: Record<string, string> = { ...spec.headers, "accept-encoding": "identity" };
  if (spec.body !== undefined) headers["content-length"] = String(Buffer.byteLength(spec.body));
  const pairs = [{ handle: record.handle, value },
    { handle: record.handle, value: Buffer.from(value).toString("base64") },
    { handle: record.handle, value: encodeURIComponent(value) }];
  const jsonValue = JSON.stringify(value).slice(1, -1);
  if (jsonValue !== value) pairs.push({ handle: record.handle, value: jsonValue });
  try {
    if (spec.auth.kind === "basic") {
      const encoded = Buffer.from(`${spec.auth.username}:${value}`).toString("base64");
      headers.authorization = `Basic ${encoded}`;
      pairs.push({ handle: record.handle, value: encoded });
    } else if (spec.auth.kind === "header") headers[spec.auth.name] = value;
    else headers.authorization = `Bearer ${value}`;
    for (const [name, header] of Object.entries(headers)) validateHeaderValue(name, header);
    if (Buffer.byteLength(JSON.stringify(headers)) > 32_768) throw new Error("HTTPS authentication headers exceed the size limit.");
    await store.assertOwnedRequestAuthorized(record.id);
    controller.signal.throwIfAborted();
    const host = url.hostname.replace(/^\[|\]$/g, "");
    const literal = isIP(host);
    const maxOutput = Math.min(secret.policy.maxOutputBytes || 16_384, 1_048_576);
    const captureLimit = maxOutput + captureHeadroomBytes(pairs.map(pair => pair.value));
    const result = await new Promise<{ status: number; body: string; truncated: boolean }>((resolve, reject) => {
      const req = httpsRequest(url, {
        method: spec.method, headers, agent: false, signal: controller.signal,
        rejectUnauthorized: true, ca: options.ca,
        lookup: (hostname, opts, callback) => {
          // Pin the validated result: TLS still verifies the requested hostname.
          void lookup(hostname, { all: true }).then(addresses => {
            if (!addresses.length || addresses.some(item => !httpAddressAllowed(item.address, false))) throw new Error("HTTPS destination resolves to a restricted address.");
            const chosen = addresses[0];
            if (opts.all) callback(null, [chosen]);
            else callback(null, chosen.address, chosen.family);
          }).catch(error => callback(error, "", 4));
        }
      }, response => {
        const chunks: Buffer[] = [];
        let size = 0;
        const status = response.statusCode || 0;
        const encoding = response.headers["content-encoding"];
        if (encoding && encoding !== "identity") {
          response.destroy(); reject(new Error("Compressed HTTPS responses are not supported.")); return;
        }
        response.on("data", (chunk: Buffer) => {
          const remaining = captureLimit - size;
          if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
          size += chunk.length;
          if (size > captureLimit) {
            resolve({ status, body: Buffer.concat(chunks).toString("utf8"), truncated: true }); response.destroy();
          }
        });
        response.once("end", () => resolve({ status, body: Buffer.concat(chunks).toString("utf8"), truncated: false }));
        response.once("error", reject);
        response.once("aborted", () => reject(new Error("HTTPS response was interrupted.")));
      });
      req.once("error", reject);
      if (literal && !httpAddressAllowed(host, true)) { req.destroy(); reject(new Error("HTTPS destination address is restricted.")); return; }
      req.end(spec.body);
    });
    controller.signal.throwIfAborted();
    await store.assertOwnedRequestAuthorized(record.id);
    // An incomplete JSON body cannot be inspected reliably for newly returned credentials.
    const fields = redactHttpCredentialFields(result.truncated ? "<SGW_RESPONSE_TRUNCATED>" : result.body);
    const scanned = await scanText(fields.body, candidate => pairs.find(pair => pair.value === candidate.value)?.handle || previewHandle(candidate));
    const output = sanitizeCapturedOutput(scanned.tokenizedText, pairs, maxOutput);
    const stderr = result.status >= 300 && result.status < 400 ? "HTTPS redirect was not followed." : "";
    const stdout = JSON.stringify({ status: result.status, body: output.text, truncated: result.truncated || output.text.endsWith(SGW_OUTPUT_TRUNCATED) });
    return {
      exitCode: result.status >= 200 && result.status < 300 ? 0 : 1, signal: null, stdout, stderr,
      proof: createHash("sha256").update(`${record.id}\n${record.handle}\n${stdout}\n${stderr}`).digest("hex"),
      durationMs: Date.now() - started, timeoutMs: record.action.timeoutMs, timedOut, sanitized: result.truncated || output.changed || fields.changed || scanned.findings.length > 0
    };
  } catch (error) {
    const message = controller.signal.aborted ? (controller.signal.reason as Error).message : error instanceof Error ? error.message : "HTTPS operation failed.";
    throw new Error(sanitizeCapturedOutput(message, pairs, 16_384).text);
  } finally { clearTimeout(timeout); clearInterval(monitor); }
}

export function httpAddressAllowed(address: string, literal: boolean): boolean {
  const ip = address.toLowerCase();
  const mappedHex = ip.match(/^::ffff:([a-f0-9]{1,4}):([a-f0-9]{1,4})$/);
  if (mappedHex) {
    const hi = parseInt(mappedHex[1], 16), lo = parseInt(mappedHex[2], 16);
    return httpAddressAllowed(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`, literal);
  }
  if (ip.startsWith("::ffff:")) return httpAddressAllowed(ip.slice(7), literal);
  if (isIP(ip) === 4) {
    const [a, b] = ip.split(".").map(Number);
    if (a === 0 || a >= 224 || (a === 169 && b === 254)) return false;
    return literal || !(a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127));
  }
  if (isIP(ip) !== 6 || ip === "::" || ip.startsWith("ff") || /^fe[89ab]/.test(ip)) return false;
  return literal || !(ip === "::1" || /^f[cd]/.test(ip));
}
