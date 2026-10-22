import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile, realpath } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  agentIntegrationStatus,
  installAgentIntegrations,
  mcpAuthorityEnvironment,
  resolvePackagedMcpCommand,
  uninstallAgentIntegrations,
  type AgentIntegrationOptions
} from "./agent-install.js";
import { consoleControlPath, consoleProofPath, startConsoleControl, startConsoleProofControl } from "./console-control.js";
import { executeApprovedRequest } from "./executor.js";
import { requestAgentName } from "./agent-context.js";
import {
  addLocalSecret,
  buildEnvCommandAction,
  preferredLocalSecretBackend,
  scanLocalText,
  type LocalSecretBackend
} from "./gateway.js";
import { getAgentCodeGuardPlan, listAgentProfiles, renderAgentMcpSnippet, resolveAgentProfile } from "./agents.js";
import { assertMacRuntimeForManagedSurfaces, getPackageLayout, readinessForUnlock } from "./install.js";
import { getSgwInstanceKey } from "./paths.js";
import { managedSshHostFingerprint, type ManagedSshRoute } from "./managed-ssh.js";
import { SecretStore, type AddApprovalPolicyRuleInput, type UpdateApprovalPolicyRuleInput } from "./store.js";
import { unlockStatus } from "./unlock.js";
import { ReleaseChecker, UPDATE_CHECK_INTERVAL_MS, type UpdateCheckResult } from "./update-check.js";
import { CURRENT_VERSION } from "./version.js";
import type {
  AuditEvent,
  ApprovalAgentScope,
  ApprovalMode,
  ApprovalPolicyActionKind,
  ApprovalPolicyConditions,
  ApprovalPolicyDecision,
  CommandEnvBinding,
  HandleSummary,
  RequestRecord,
  RequestState,
  SecretSeverity,
  SecretType
} from "./types.js";

const version = CURRENT_VERSION;
const maxBodyBytes = 1024 * 1024;
const operatorCodeLifetimeMs = 5 * 60 * 1000;
const operatorSessionLifetimeMs = 15 * 60 * 1000;
const operatorCookieName = "sgw_operator";
const verifiedOperatorBodies = new WeakMap<IncomingMessage, Buffer>();

interface OperatorSession {
  id: string;
  proof: string;
  expiresAt: number;
  usedNonces: Set<string>;
}

interface OperatorAuthState {
  code?: string;
  codeExpiresAt: number;
  attempts: number;
  attemptsResetAt: number;
  session?: OperatorSession;
  origin: string;
  statusKey?: Buffer;
  statusPort?: number;
  statusWindowStartedAt?: number;
  statusAttempts?: number;
  statusReservations?: Map<string, number>;
}

export interface ConsoleServerOptions {
  host?: string;
  port?: number;
  activatedFd?: number;
  store?: SecretStore;
  token?: string;
  uiDir?: string;
  updateChecker?: Pick<ReleaseChecker, "check" | "current">;
  agentHomeDir?: string;
  agentPathEnv?: string;
  agentSkillSourcePath?: string;
  operatorAuth?: { displayCode: (code: string) => void } | { background: true };
}

export interface RunningConsoleServer {
  url: string;
  token: string;
  server: Server;
  close: () => Promise<void>;
}

interface ProviderSummary {
  provider: string;
  label: string;
  prefix: string;
  secrets: number;
  severity: SecretSeverity;
  lastUsed?: string;
}

type UsageFlowNodeKind = "agent" | "auth" | "target";

interface UsageFlowNode {
  id: string;
  kind: UsageFlowNodeKind;
  label: string;
  detail?: string;
  count: number;
}

interface UsageFlowLink {
  source: string;
  target: string;
  value: number;
}

interface UsageFlowRow {
  agentId: string;
  agent: string;
  authTypeId: string;
  authType: string;
  targetTypeId: string;
  targetType: string;
  handle: string;
  credential: string;
  action: string;
  command: string;
  target: string;
  handles: string[];
  credentials: string[];
  actions: string[];
  targets: string[];
  count: number;
  lastSeen: string;
  states: Record<RequestState, number>;
}

interface UsageFlowEntry {
  requestId: string;
  agentId: string;
  agent: string;
  authTypeId: string;
  authType: string;
  targetTypeId: string;
  targetType: string;
  credential: string;
  action: string;
  command: string;
  target: string;
  state: RequestState;
  lastSeen: string;
}

interface UsageFlow {
  generatedAt: string;
  totalRequests: number;
  nodes: UsageFlowNode[];
  links: UsageFlowLink[];
  rows: UsageFlowRow[];
  entries: UsageFlowEntry[];
}

export async function startConsoleServer(options: ConsoleServerOptions = {}): Promise<RunningConsoleServer> {
  const host = options.host || "127.0.0.1";
  if (options.operatorAuth && host !== "127.0.0.1") {
    throw new Error("Protected operator console requires 127.0.0.1.");
  }
  const backgroundAuth = options.operatorAuth && "background" in options.operatorAuth;
  if (backgroundAuth && process.platform !== "darwin") {
    throw new Error("Background operator enrollment currently requires macOS peer verification.");
  }
  const port = options.port ?? 8718;
  if (options.activatedFd !== undefined && (!backgroundAuth || host !== "127.0.0.1" ||
      !Number.isInteger(port) || port < 1 || port > 65_535 ||
      !Number.isInteger(options.activatedFd) || options.activatedFd < 3)) {
    throw new Error("An inherited console listener requires a protected macOS background service and an exact port.");
  }
  const token = options.operatorAuth ? "" : options.token || randomBytes(24).toString("base64url");
  const operatorAuth: OperatorAuthState | undefined = options.operatorAuth ? {
    code: backgroundAuth ? undefined : randomBytes(24).toString("base64url"),
    codeExpiresAt: backgroundAuth ? 0 : Date.now() + operatorCodeLifetimeMs,
    attempts: 0,
    attemptsResetAt: 0,
    origin: "",
    statusKey: backgroundAuth ? randomBytes(32) : undefined
  } : undefined;
  const store = options.store || new SecretStore();
  const uiDir = options.uiDir || defaultUiDir();
  const updateChecker = options.updateChecker || new ReleaseChecker();
  const agentOptions: AgentIntegrationOptions = {
    homeDir: options.agentHomeDir,
    pathEnv: options.agentPathEnv,
    sgwHome: process.env.SGW_HOME,
    skillSourcePath: options.agentSkillSourcePath
  };

  await store.init();
  const instanceKey = getSgwInstanceKey(path.dirname(store.storePath));
  void updateChecker.check();
  const updateTimer = setInterval(() => void updateChecker.check(true), UPDATE_CHECK_INTERVAL_MS);
  updateTimer.unref();

  let listenerReady = false;
  const server = createServer((req, res) => {
    if (!listenerReady) {
      req.destroy();
      return;
    }
    handleRequest(req, res, store, token, uiDir, updateChecker, agentOptions, instanceKey, operatorAuth).catch((error) => {
      sendError(res, error);
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    const onListening = () => {
      server.off("error", reject);
      const boundAddress = server.address();
      if (!boundAddress || typeof boundAddress === "string" ||
          (options.activatedFd !== undefined &&
            (boundAddress.family !== "IPv4" || boundAddress.address !== "127.0.0.1" || boundAddress.port !== port))) {
        server.close();
        reject(new Error("Inherited console listener does not match the protected loopback endpoint."));
        return;
      }
      if (operatorAuth) {
        operatorAuth.origin = `http://127.0.0.1:${boundAddress.port}`;
        if (backgroundAuth) operatorAuth.statusPort = boundAddress.port;
      }
      listenerReady = true;
      resolve();
    };
    if (options.activatedFd === undefined) server.listen(port, host, onListening);
    else server.listen({ fd: options.activatedFd }, onListening);
  });

  let control: Awaited<ReturnType<typeof startConsoleControl>> | undefined;
  let proofControl: Awaited<ReturnType<typeof startConsoleProofControl>> | undefined;
  if (backgroundAuth && operatorAuth) {
    try {
      const address = server.address() as AddressInfo;
      control = await startConsoleControl(consoleControlPath(store.storePath, address.port), () => issueOperatorCode(operatorAuth));
      proofControl = await startConsoleProofControl(
        consoleProofPath(store.storePath, address.port),
        (port, nonce, proof) => verifyStatusProof(operatorAuth, instanceKey, port, nonce, proof),
        (port, nonce) => reserveStatusChallenge(operatorAuth, port, nonce)
      );
    } catch (error) {
      clearInterval(updateTimer);
      const cleanupErrors = await settleConsoleListeners(server, control, proofControl);
      if (cleanupErrors.length) {
        throw new AggregateError([error, ...cleanupErrors], "Could not start or close the protected console.");
      }
      throw error;
    }
  }

  if (options.operatorAuth && "displayCode" in options.operatorAuth && operatorAuth?.code) {
    try {
      options.operatorAuth.displayCode(operatorAuth.code);
    } catch (error) {
      clearInterval(updateTimer);
      await closeServer(server);
      throw error;
    }
  }

  const address = server.address() as AddressInfo;
  const shownHost = host === "0.0.0.0" || host === "::" ? "127.0.0.1" : host;
  const url = `http://${shownHost}:${address.port}/`;

  return {
    url,
    token,
    server,
    close: async () => {
      clearInterval(updateTimer);
      if (control && proofControl) {
        const cleanupErrors = await settleConsoleListeners(server, control, proofControl);
        if (cleanupErrors.length) throw new AggregateError(cleanupErrors, "Could not close the protected console.");
        return;
      }
      await closeServer(server);
    }
  };
}

async function settleConsoleListeners(
  server: Server,
  ...controls: Array<{ close: () => Promise<void> } | undefined>
): Promise<unknown[]> {
  const closing: Promise<void>[] = [closeServer(server)];
  for (const control of controls) {
    if (control) closing.push(control.close());
  }
  const results = await Promise.allSettled(closing);
  const failures: unknown[] = [];
  for (const result of results) {
    if (result.status === "rejected") failures.push(result.reason);
  }
  return failures;
}

function issueOperatorCode(auth: OperatorAuthState): string {
  if (auth.code && Date.now() < auth.codeExpiresAt) return auth.code;
  auth.code = randomBytes(24).toString("base64url");
  auth.codeExpiresAt = Date.now() + operatorCodeLifetimeMs;
  return auth.code;
}

function statusProof(auth: OperatorAuthState, instanceKey: string, port: number, nonce: string): string {
  if (!auth.statusKey || auth.statusPort !== port) throw new Error("Protected console listener is not ready.");
  return createHmac("sha256", auth.statusKey)
    .update("s-gw-console-status-v1\0")
    .update(instanceKey).update("\0")
    .update(String(port)).update("\0")
    .update(nonce)
    .digest("base64url");
}

function verifyStatusProof(
  auth: OperatorAuthState,
  instanceKey: string,
  port: number,
  nonce: string,
  proof: string
): boolean {
  if (!/^[A-Za-z0-9_-]{32}$/u.test(nonce) || !/^[A-Za-z0-9_-]{43}$/u.test(proof)) return false;
  if (auth.statusPort !== port) return false;
  const expected = statusProof(auth, instanceKey, port, nonce);
  return timingSafeEqual(Buffer.from(expected), Buffer.from(proof));
}

function reserveStatusChallenge(auth: OperatorAuthState, port: number, nonce: string): "ready" | "busy" | "denied" {
  if (auth.statusPort !== port || !/^[A-Za-z0-9_-]{32}$/u.test(nonce)) return "denied";
  const now = Date.now();
  const reservations = auth.statusReservations || new Map<string, number>();
  for (const [key, expiresAt] of reservations) {
    if (expiresAt <= now) reservations.delete(key);
  }
  if (reservations.size >= 64 && !reservations.has(nonce)) return "busy";
  reservations.set(nonce, now + 2_000);
  auth.statusReservations = reservations;
  return "ready";
}

function consumeStatusChallenge(auth: OperatorAuthState, nonce: string, now: number): boolean {
  const reservations = auth.statusReservations;
  if (!reservations) return false;
  const expiresAt = reservations.get(nonce);
  if (expiresAt === undefined) return false;
  reservations.delete(nonce);
  return expiresAt > now;
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((err) => (err ? reject(err) : resolve()));
    server.closeIdleConnections();
    setTimeout(() => {
      server.closeAllConnections();
    }, 250).unref();
  });
}

async function handleRequest(
  req: IncomingMessage,
  res: ServerResponse,
  store: SecretStore,
  token: string,
  uiDir: string,
  updateChecker: Pick<ReleaseChecker, "check" | "current">,
  agentOptions: AgentIntegrationOptions,
  instanceKey: string,
  operatorAuth?: OperatorAuthState
): Promise<void> {
  const url = new URL(req.url || "/", "http://127.0.0.1");
  if (operatorAuth) {
    await handleProtectedRequest(req, res, url, store, uiDir, updateChecker, agentOptions, instanceKey, operatorAuth);
    return;
  }

  if (req.method === "GET" && url.pathname === "/auth/status" && !url.search) {
    sendJson(res, 200, { ok: true, name: "s-gw", instanceKey });
    return;
  }

  if (url.pathname.startsWith("/api/")) {
    if (url.pathname !== "/api/health" && !validConsoleToken(req, token)) {
      throw new HttpError(403, "Missing or invalid local console token.");
    }

    await handleApi(req, res, url, store, updateChecker, agentOptions, instanceKey);
    return;
  }

  if (url.pathname === "/favicon.ico") {
    res.writeHead(204, { "Cache-Control": "no-store" });
    res.end();
    return;
  }

  await serveUi(req, res, url.pathname, uiDir, token);
}

async function handleProtectedRequest(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  store: SecretStore,
  uiDir: string,
  updateChecker: Pick<ReleaseChecker, "check" | "current">,
  agentOptions: AgentIntegrationOptions,
  instanceKey: string,
  auth: OperatorAuthState
): Promise<void> {
  if (req.headers.host !== auth.origin.slice("http://".length)) {
    throw new HttpError(403, "Invalid local console host.");
  }

  const origin = req.headers.origin;
  const unsafe = req.method !== "GET" && req.method !== "HEAD";
  if (Array.isArray(origin) || (origin && origin !== auth.origin) || (unsafe && origin !== auth.origin)) {
    throw new HttpError(403, "Invalid local console origin.");
  }

  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Cross-Origin-Resource-Policy", "same-origin");

  if (req.method === "GET" && url.pathname === "/auth/status") {
    if (!url.search) {
      sendJson(res, 200, { ok: true, name: "s-gw", instanceKey });
      return;
    }
    const nonce = url.searchParams.get("challenge");
    if (!auth.statusKey || !auth.statusPort || url.searchParams.size !== 1 ||
        !nonce || !/^[A-Za-z0-9_-]{32}$/u.test(nonce)) {
      throw new HttpError(400, "Invalid listener challenge.");
    }
    const now = Date.now();
    if (!consumeStatusChallenge(auth, nonce, now)) {
      if (!auth.statusWindowStartedAt || now - auth.statusWindowStartedAt >= 1_000) {
        auth.statusWindowStartedAt = now;
        auth.statusAttempts = 0;
      }
      auth.statusAttempts = (auth.statusAttempts || 0) + 1;
      if (auth.statusAttempts > 128) throw new HttpError(429, "Too many listener challenges.");
    }
    sendJson(res, 200, {
      ok: true, name: "s-gw", instanceKey,
      challenge: nonce,
      proof: statusProof(auth, instanceKey, auth.statusPort, nonce)
    });
    return;
  }

  if (url.pathname === "/auth/enroll") {
    if (req.method !== "POST" || url.search) {
      throw new HttpError(405, "Invalid operator enrollment request.");
    }
    await enrollOperator(req, res, auth);
    return;
  }

  const session = operatorSession(req, auth);
  if (!session) {
    if ((req.method === "GET" || req.method === "HEAD") && operatorUiRoute(url.pathname, uiDir)) {
      serveOperatorLogin(req, res);
      return;
    }
    throw new HttpError(401, "Operator sign-in required.");
  }

  if (url.pathname === "/auth/app") {
    await serveUi(req, res, "/", uiDir, "", true, session.proof);
    return;
  }

  if (url.pathname.startsWith("/api/")) {
    if (!validConsoleToken(req, session.proof) && !await validSignedOperatorRequest(req, url, session)) {
      throw new HttpError(403, "Invalid operator request token.");
    }
    await handleApi(req, res, url, store, updateChecker, agentOptions, instanceKey);
    return;
  }

  if ((req.method === "GET" || req.method === "HEAD") && operatorUiRoute(url.pathname, uiDir)) {
    serveOperatorLogin(req, res);
    return;
  }

  if (unsafe && !validConsoleToken(req, session.proof)) {
    throw new HttpError(403, "Invalid operator request token.");
  }

  if (url.pathname === "/favicon.ico") {
    res.writeHead(204);
    res.end();
    return;
  }

  await serveUi(req, res, url.pathname, uiDir, "", true);
}

function operatorUiRoute(pathname: string, uiDir: string): boolean {
  if (pathname.startsWith("/api/") || pathname.startsWith("/auth/")) return false;
  return pathname === "/" || pathname === "/index.html" || shouldServeSpaFallback(pathname, uiDir);
}

async function enrollOperator(req: IncomingMessage, res: ServerResponse, auth: OperatorAuthState): Promise<void> {
  const submitted = await readOperatorCode(req);
  const now = Date.now();
  if (auth.code && now < auth.codeExpiresAt && sameSecret(submitted, auth.code)) {
    auth.code = undefined;
    auth.session = {
      id: randomBytes(32).toString("base64url"),
      proof: randomBytes(24).toString("base64url"),
      expiresAt: now + operatorSessionLifetimeMs,
      usedNonces: new Set()
    };
    res.writeHead(200, {
      "Content-Type": "application/json; charset=utf-8",
      "Set-Cookie": `${operatorCookieName}=${auth.session.id}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${operatorSessionLifetimeMs / 1000}`
    });
    res.end(JSON.stringify({ proof: auth.session.proof }));
    return;
  }

  if (now >= auth.attemptsResetAt) {
    auth.attempts = 0;
    auth.attemptsResetAt = now + 60_000;
  }
  if (auth.attempts >= 5) {
    throw new HttpError(429, "Operator sign-in temporarily unavailable.");
  }
  auth.attempts += 1;
  throw new HttpError(401, "Invalid or expired operator code.");
}

async function readOperatorCode(req: IncomingMessage): Promise<string> {
  if (!/^application\/json(?:\s*;|$)/iu.test(req.headers["content-type"] || "")) {
    throw new HttpError(415, "Operator sign-in requires JSON.");
  }

  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const data = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += data.length;
    if (size > 1024) throw new HttpError(413, "Operator sign-in request is too large.");
    chunks.push(data);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, "Invalid operator sign-in request.");
  }
  const code = (parsed as { code?: unknown } | null)?.code;
  if (typeof code !== "string" || !/^[A-Za-z0-9_-]{32}$/u.test(code)) {
    throw new HttpError(400, "Invalid operator sign-in request.");
  }
  return code;
}

function operatorSession(req: IncomingMessage, auth: OperatorAuthState): OperatorSession | undefined {
  const session = auth.session;
  if (!session) return undefined;
  if (Date.now() >= session.expiresAt) {
    auth.session = undefined;
    return undefined;
  }

  const cookie = req.headers.cookie || "";
  const matches = cookie.split(";").map((part) => part.trim()).filter((part) => part.startsWith(`${operatorCookieName}=`));
  if (matches.length !== 1) return undefined;
  const value = matches[0].slice(operatorCookieName.length + 1);
  return sameSecret(value, session.id) ? session : undefined;
}

function sameSecret(value: string, expected: string): boolean {
  const actual = Buffer.from(value);
  const wanted = Buffer.from(expected);
  if (actual.length !== wanted.length) return false;
  return timingSafeEqual(actual, wanted);
}

function serveOperatorLogin(req: IncomingMessage, res: ServerResponse): void {
  const nonce = randomBytes(18).toString("base64");
  const html = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>s-gw operator sign-in</title>
<style>body{font:16px system-ui,sans-serif;max-width:32rem;margin:12vh auto;padding:1.5rem;background:#111827;color:#f9fafb}input,button{font:inherit;padding:.7rem;width:100%;box-sizing:border-box;margin:.5rem 0}input{background:#1f2937;border:1px solid #6b7280;color:inherit}button{background:#2563eb;border:0;color:white;cursor:pointer}p{line-height:1.5}</style></head>
<body><main><h1>s-gw operator sign-in</h1><p>Enter the one-time code shown by s-gw console enroll or in the foreground s-gw terminal. It expires after five minutes.</p>
<form id="login"><label for="code">One-time code</label><input id="code" type="password" autocomplete="off" required autofocus><button type="submit">Sign in</button></form><p id="error" role="alert"></p></main>
<script nonce="${nonce}">
(function () {
  const pageNonce = document.currentScript.nonce;
  document.getElementById("login").addEventListener("submit", async function (event) {
    event.preventDefault();
    const code = document.getElementById("code");
    const error = document.getElementById("error");
    error.textContent = "";

    try {
      const response = await fetch("/auth/enroll", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: code.value })
      });
      code.value = "";
      if (!response.ok) {
        error.textContent = "Sign-in failed. Check the code in the terminal.";
        return;
      }

      const body = await response.json();
      if (!body.proof) throw new Error("Missing operator proof.");
      const app = await fetch("/auth/app");
      if (!app.ok) throw new Error("Console unavailable.");
      const markup = await app.text();
      const signature = app.headers.get("X-SGW-App-Proof");
      if (!signature || !/^[A-Za-z0-9_-]{43}$/.test(signature)) throw new Error("Console proof missing.");
      const bytes = Uint8Array.from(atob(signature.replace(/-/g, "+").replace(/_/g, "/")), c => c.charCodeAt(0));
      const key = await crypto.subtle.importKey(
        "raw", new TextEncoder().encode(body.proof), { name: "HMAC", hash: "SHA-256" }, false, ["verify", "sign"]
      );
      if (!await crypto.subtle.verify("HMAC", key, bytes, new TextEncoder().encode(markup))) {
        throw new Error("Console proof invalid.");
      }

      const parsed = new DOMParser().parseFromString(markup, "text/html");
      const scripts = [...parsed.querySelectorAll("script")];
      window.SGW_OPERATOR_SIGN = async function (path, method, requestBody) {
        const target = new URL(path, location.href);
        if (target.origin !== location.origin || !target.pathname.startsWith("/api/")) {
          throw new Error("Invalid console request.");
        }
        const random = crypto.getRandomValues(new Uint8Array(16));
        const nonce = btoa(String.fromCharCode(...random)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
        const prefix = "sgw-operator-v1\\n" + method + "\\n" + target.pathname + target.search + "\\n" + nonce + "\\n";
        const signed = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(prefix + requestBody));
        const signature = btoa(String.fromCharCode(...new Uint8Array(signed)))
          .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
        return { "X-SGW-Console-Nonce": nonce, "X-SGW-Console-Signature": signature };
      };
      window.SGW_CONSOLE_TOKEN = body.proof;
      window.SGW_CONSOLE_LIVE = true;
      window.SGW_CONSOLE_OPERATOR_AUTH = true;

      // Keep the proof in this document; browser storage can persist to disk.
      document.head.replaceChildren(...[...parsed.head.childNodes]
        .filter((node) => node.nodeName !== "SCRIPT")
        .map((node) => document.importNode(node, true)));
      document.body.replaceChildren(...[...parsed.body.childNodes]
        .filter((node) => node.nodeName !== "SCRIPT")
        .map((node) => document.importNode(node, true)));

      for (const old of scripts) {
        const script = document.createElement("script");
        script.nonce = pageNonce;
        if (old.src) script.src = old.src;
        if (old.type) script.type = old.type;
        if (old.crossOrigin) script.crossOrigin = old.crossOrigin;
        if (old.integrity) script.integrity = old.integrity;
        if (!old.src) script.textContent = old.textContent;
        script.async = false;
        (old.parentElement === parsed.head ? document.head : document.body).appendChild(script);
      }
    } catch {
      code.value = "";
      error.textContent = "Sign-in failed. Restart the console and try again.";
    }
  });
})();
</script></body></html>`;
  res.writeHead(200, {
    "Content-Type": "text/html; charset=utf-8",
    "Content-Security-Policy": consoleContentSecurityPolicy(nonce),
    "Cache-Control": "no-store"
  });
  res.end(req.method === "HEAD" ? undefined : html);
}

async function handleApi(
  req: IncomingMessage,
  res: ServerResponse,
  url: URL,
  store: SecretStore,
  updateChecker: Pick<ReleaseChecker, "check" | "current">,
  agentOptions: AgentIntegrationOptions,
  instanceKey: string
): Promise<void> {
  if (req.method === "GET" && url.pathname === "/api/health") {
    sendJson(res, 200, {
      ok: true,
      name: "s-gw",
      version,
      instanceKey
    });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/state") {
    sendJson(res, 200, await buildState(store, updateChecker.current(), agentOptions));
    return;
  }

  const agentMatch = url.pathname.match(/^\/api\/agents\/([^/]+)\/(install|uninstall)$/);
  if (req.method === "POST" && agentMatch) {
    if (process.platform === "darwin") assertMacRuntimeForManagedSurfaces();
    const body = await readJson(req);
    const options = {
      ...agentOptions,
      agentIds: [decodeURIComponent(agentMatch[1])],
      dryRun: body.dryRun === true
    };
    const results = agentMatch[2] === "install"
      ? installAgentIntegrations(options)
      : uninstallAgentIntegrations(options);
    sendJson(res, 200, { ok: results[0]?.state !== "conflict", result: results[0] });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/audit.csv") {
    sendCsv(res, await auditCsv(store));
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/approval") {
    sendJson(res, 200, await store.getApprovalSettings());
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/approval/grants") {
    sendJson(res, 200, await store.listApprovalGrants());
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/approval/policies") {
    sendJson(res, 200, await store.listApprovalPolicyRules());
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/approval/policies") {
    const body = await readJson(req);
    sendJson(res, 200, await store.addApprovalPolicyRule(policyRuleInput(body)));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/approval/policies/arrange") {
    sendJson(res, 200, await store.arrangeApprovalPolicyRules());
    return;
  }

  if (req.method === "DELETE" && url.pathname === "/api/approval/grants") {
    sendJson(res, 200, await store.clearApprovalGrants());
    return;
  }

  const approvalGrantMatch = url.pathname.match(/^\/api\/approval\/grants\/([^/]+)$/);
  if (req.method === "DELETE" && approvalGrantMatch) {
    sendJson(res, 200, await store.revokeApprovalGrant(decodeURIComponent(approvalGrantMatch[1])));
    return;
  }

  const approvalPolicyMatch = url.pathname.match(/^\/api\/approval\/policies\/([^/]+)$/);
  if (approvalPolicyMatch) {
    const id = decodeURIComponent(approvalPolicyMatch[1]);
    if (req.method === "DELETE") {
      sendJson(res, 200, await store.deleteApprovalPolicyRule(id));
      return;
    }
    if (req.method === "PATCH") {
      const body = await readJson(req);
      if (typeof body.enabled !== "boolean") {
        throw new HttpError(400, "enabled must be a boolean.");
      }
      sendJson(res, 200, await store.setApprovalPolicyRuleEnabled(id, body.enabled));
      return;
    }
    if (req.method === "PUT") {
      const body = await readJson(req);
      sendJson(res, 200, await store.updateApprovalPolicyRule(id, policyRuleUpdateInput(body)));
      return;
    }
  }

  if (req.method === "POST" && url.pathname === "/api/approval") {
    const body = await readJson(req);
    if (body.requireVerifiedAgentForAutoApproval !== undefined &&
        body.requireVerifiedAgentForAutoApproval !== true) {
      throw new HttpError(400, "Automatic approval requires a verified agent.");
    }
    sendJson(
      res,
      200,
      await store.setApprovalSettings({
        mode: approvalMode(body.mode),
        durationMs: numberValue(body.durationMs, 15 * 60 * 1000),
        requireVerifiedAgentForAutoApproval: true
      })
    );
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/scan") {
    const body = await readJson(req);
    const text = stringValue(body.text, "text");
    const persist = body.persist === true;
    const source = optionalString(body.source);
    sendJson(res, 200, await scanLocalText(store, text, { persist, source, backend: localBackendValue(body.backend) }));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/secrets") {
    const body = await readJson(req);
    const record = await addLocalSecret(store, {
      name: stringValue(body.name, "name"),
      type: secretType(body.type),
      provider: optionalString(body.provider),
      value: stringValue(body.value, "value"),
      source: optionalString(body.source),
      service: optionalString(body.service),
      policy: {
        injectEnv: optionalString(body.injectEnv),
        allowedCommands: stringList(body.allowedCommands),
        maxOutputBytes: numberValue(body.maxOutputBytes, 16_384)
      }
    }, localBackendValue(body.backend));

    sendJson(res, 201, {
      handle: record.handle,
      name: record.name,
      type: record.type,
      provider: record.provider,
      backend: record.backend,
      policy: record.policy
    });
    return;
  }

  const secretMatch = url.pathname.match(/^\/api\/secrets\/([^/]+)$/);
  if (req.method === "DELETE" && secretMatch) {
    const handle = decodeURIComponent(secretMatch[1]);
    sendJson(res, 200, await store.deleteSecret(handle));
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/requests") {
    const body = await readJson(req);
    const action = buildEnvCommandAction({
      command: stringValue(body.command, "command"),
      args: stringList(body.args),
      injectEnv: stringValue(body.injectEnv, "injectEnv"),
      env: envBindingList(body.env),
      workingDir: optionalString(body.workingDir),
      timeoutMs: numberValue(body.timeoutMs, 30_000)
    });
    const request = await store.createRequest(
      stringValue(body.handle, "handle"),
      action,
      optionalString(body.reason) || "Local console request",
      {
        agentName: optionalString(body.agentName),
        env: {}
      }
    );

    sendJson(res, 201, request);
    return;
  }

  const match = url.pathname.match(/^\/api\/requests\/([^/]+)\/(approve|approve-policy|deny|execute|recover)$/);
  if (req.method === "POST" && match) {
    const id = decodeURIComponent(match[1]);
    const action = match[2];
    if (action === "approve") {
      const body = await readJson(req);
      sendJson(
        res,
        200,
        await store.approveRequest(id, {
          mode: optionalApprovalMode(body.mode),
          durationMs: optionalNumberValue(body.durationMs),
          agentScope: optionalApprovalAgentScope(body.agentScope)
        })
      );
      return;
    }

    if (action === "approve-policy") {
      sendJson(res, 200, await store.approveRequestWithScopedPolicy(id));
      return;
    }

    if (action === "deny") {
      sendJson(res, 200, await store.denyRequest(id));
      return;
    }

    if (action === "recover") {
      const recovered = await store.forceRecoverExecutions(id);
      sendJson(res, 200, recovered[0]);
      return;
    }

    sendJson(res, 200, await executeApprovedRequest(store, id));
    return;
  }

  throw new HttpError(404, "Unknown console API route.");
}

async function buildState(store: SecretStore, update: UpdateCheckResult | null, agentOptions: AgentIntegrationOptions) {
  const handles = await store.listHandles();
  const requests = await store.listRequests();
  const managedRoutes = await store.listManagedSshRoutes();
  const managedRoutesById = new Map(managedRoutes.map((route) => [route.id, route]));
  const audit = await store.auditLog();
  const approvalSettings = await store.getApprovalSettings();
  const approvalGrants = await store.listApprovalGrants();
  const approvalPolicyRules = await store.listApprovalPolicyRules();
  const pending = requests.filter((request) => request.state === "pending");
  const highRisk = handles.filter((handle) => handle.severity === "high" || handle.severity === "critical");
  const agents = listAgentProfiles();
  const integrations = agentIntegrationStatus(agentOptions);
  const integrationById = new Map(integrations.map((item) => [item.agentId, item]));
  const unlock = unlockStatus();
  const readiness = readinessForUnlock(unlock.activeSource !== "none");
  const usageFlow = buildUsageFlow(requests, handles);
  const mcp = consoleMcpSnippet(agentOptions);

  return {
    version,
    update,
    ready: readiness.ok,
    readiness,
    status: {
      daemonRunning: true,
      storePath: store.storePath,
      unlock
    },
    metrics: {
      localSecrets: handles.length,
      pendingApprovals: pending.length,
      activeAgents: integrations.filter((item) => item.mcp.state === "installed" || item.mcp.state === "existing").length,
      highRiskFindings: highRisk.length
    },
    handles,
    approvalSettings,
    approvalGrants,
    approvalPolicyRules,
    usageFlow,
    credentials: groupHandles(handles),
    requests: sortRequests(requests, managedRoutesById),
    pendingRequests: sortRequests(pending, managedRoutesById),
    audit: [...audit].reverse(),
    agents: agents.map((agent) => {
      const profile = resolveAgentProfile(agent.id);
      const integration = integrationById.get(agent.id);
      return {
        id: agent.id,
        name: agent.displayName,
        status: agent.mcpStatus,
        aliases: profile.aliases,
        integration,
        mcp: {
          supported: profile.mcp.supported,
          format: profile.mcp.snippet,
          writeMode: profile.mcp.writeMode,
          configPaths: profile.mcp.configPaths,
          notes: profile.mcp.notes,
          snippet: profile.mcp.supported ? renderAgentMcpSnippet(profile.id, mcp.options) : null
        },
        skills: profile.skills,
        plugins: profile.plugins,
        hooks: {
          supported: profile.hooks?.supported || false,
          kind: profile.hooks?.kind || "none",
          configPaths: profile.hooks?.configPaths || [],
          events: profile.hooks?.events || [],
          notes: profile.hooks?.notes || []
        },
        limitations: profile.limitations,
        codeGuard: getAgentCodeGuardPlan(profile.id),
        snippetCommand: `${mcp.cliCommand} agent mcp-snippet ${profile.id}`,
        guardCommand: `${mcp.cliCommand} run ${profile.id}`
      };
    })
  };
}

export function consoleMcpSnippet(
  agentOptions: AgentIntegrationOptions,
  layout: Pick<ReturnType<typeof getPackageLayout>, "packageRoot" | "nodePath" | "isSelfContainedMacApp" | "mcpPath"> = getPackageLayout()
): {
  options: { command: string; args: string[]; env?: Record<string, string> };
  cliCommand: string;
} {
  const launch = resolvePackagedMcpCommand(layout, {
    platform: agentOptions.platform || process.platform,
    pathEnv: agentOptions.pathEnv || process.env.PATH || "",
    env: process.env,
    mcpServerPath: layout.mcpPath
  });
  const env = mcpAuthorityEnvironment(agentOptions);
  const launcher = layout.isSelfContainedMacApp
    ? path.posix.join(path.posix.dirname(layout.packageRoot), "bin", "s-gw")
    : "s-gw";

  return {
    options: {
      command: launch.command,
      args: launch.args,
      env
    },
    cliCommand: shellCommandArg(launcher)
  };
}

function shellCommandArg(value: string): string {
  if (/^[A-Za-z0-9_./:=@%+-]+$/.test(value)) return value;
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function groupHandles(handles: HandleSummary[]): ProviderSummary[] {
  const grouped = new Map<string, ProviderSummary>();
  for (const handle of handles) {
    const provider = handle.provider || providerForType(handle.type);
    const existing = grouped.get(provider);
    if (!existing) {
      grouped.set(provider, {
        provider,
        label: providerLabel(provider),
        prefix: handlePrefix(provider, handle.type),
        secrets: 1,
        severity: handle.severity || "low",
        lastUsed: handle.updatedAt
      });
      continue;
    }

    existing.secrets += 1;
    existing.severity = higherSeverity(existing.severity, handle.severity || "low");
    if (!existing.lastUsed || handle.updatedAt > existing.lastUsed) {
      existing.lastUsed = handle.updatedAt;
    }
  }

  return [...grouped.values()].sort((a, b) => a.label.localeCompare(b.label));
}

function sortRequests(requests: RequestRecord[], routes: Map<string, { name: string; route: ManagedSshRoute }>) {
  return [...requests].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)).map((request) => {
    const route = request.action.ssh?.managed;
    if (!route) return request;
    const current = routes.get(request.action.ssh?.managedRouteId || "");
    return { ...request, managedSsh: {
      destination: managedSshDestination(route),
      hostKeyFingerprint: managedSshHostFingerprint(route),
      routeName: current?.name || request.action.ssh?.managedRouteId || "Unknown route",
      routeCurrent: Boolean(current && JSON.stringify(current.route) === JSON.stringify(route))
    } };
  });
}

function buildUsageFlow(requests: RequestRecord[], handles: HandleSummary[]): UsageFlow {
  const handlesById = new Map(handles.map((handle) => [handle.handle, handle]));
  const nodeCounts = new Map<string, UsageFlowNode>();
  const linkCounts = new Map<string, UsageFlowLink>();
  const rowCounts = new Map<string, UsageFlowRow>();
  const entries: UsageFlowEntry[] = [];

  for (const request of requests) {
    const handle = handlesById.get(request.handle);
    const agent = request.agentName || requestAgentName(request.reason);
    const credential = handle?.name || request.handle;
    const authType = authTypeLabel(handle);
    const authTypeId = `auth:${authTypeKey(handle)}`;
    const targetType = targetTypeLabel(request.action);
    const targetTypeId = `target:${targetTypeKey(request.action)}`;
    const action = actionLabel(request.action);
    const command = commandBase(request.action.command);
    const target = actionTarget(request.action);

    const agentId = `agent:${agent}`;
    bumpNode(nodeCounts, agentId, "agent", agent, "Requesting agent");
    bumpNode(nodeCounts, authTypeId, "auth", authType, authTypeDetail(handle));
    bumpNode(nodeCounts, targetTypeId, "target", targetType, targetTypeDetail(request.action));
    bumpLink(linkCounts, agentId, authTypeId);
    bumpLink(linkCounts, authTypeId, targetTypeId);

    entries.push({
      requestId: request.id,
      agentId,
      agent,
      authTypeId,
      authType,
      targetTypeId,
      targetType,
      credential,
      action,
      command,
      target,
      state: request.state,
      lastSeen: request.updatedAt
    });

    const rowKey = `${agent}\n${authType}\n${targetType}`;
    let row = rowCounts.get(rowKey);
    if (!row) {
      row = {
        agentId,
        agent,
        authTypeId,
        authType,
        targetTypeId,
        targetType,
        handle: request.handle,
        credential,
        action,
        command,
        target,
        handles: [],
        credentials: [],
        actions: [],
        targets: [],
        count: 0,
        lastSeen: request.updatedAt,
        states: emptyStateCounts()
      };
      rowCounts.set(rowKey, row);
    }

    row.count += 1;
    row.states[request.state] += 1;
    addFlowExample(row.handles, shortHandle(request.handle));
    addFlowExample(row.credentials, credential);
    addFlowExample(row.actions, action);
    addFlowExample(row.targets, target);
    if (request.updatedAt > row.lastSeen) {
      row.lastSeen = request.updatedAt;
    }
  }

  return {
    generatedAt: new Date().toISOString(),
    totalRequests: requests.length,
    nodes: [...nodeCounts.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)),
    links: [...linkCounts.values()].sort((a, b) => b.value - a.value || a.source.localeCompare(b.source)),
    rows: [...rowCounts.values()].sort((a, b) => b.count - a.count || b.lastSeen.localeCompare(a.lastSeen)),
    entries: entries.sort((a, b) => b.lastSeen.localeCompare(a.lastSeen))
  };
}

function emptyStateCounts(): Record<RequestState, number> {
  return {
    pending: 0,
    approved: 0,
    executing: 0,
    denied: 0,
    executed: 0,
    failed: 0
  };
}

function bumpNode(
  nodes: Map<string, UsageFlowNode>,
  id: string,
  kind: UsageFlowNodeKind,
  label: string,
  detail?: string
): void {
  const existing = nodes.get(id);
  if (existing) {
    existing.count += 1;
    return;
  }

  nodes.set(id, { id, kind, label, detail, count: 1 });
}

function bumpLink(links: Map<string, UsageFlowLink>, source: string, target: string): void {
  const key = `${source}\n${target}`;
  const existing = links.get(key);
  if (existing) {
    existing.value += 1;
    return;
  }

  links.set(key, { source, target, value: 1 });
}

function addFlowExample(values: string[], value: string): void {
  const cleaned = String(value || "").trim();
  if (!cleaned || values.includes(cleaned) || values.length >= 4) {
    return;
  }

  values.push(cleaned);
}

function authTypeKey(handle?: HandleSummary): string {
  return normalizeFlowKey(authTypeLabel(handle));
}

function authTypeLabel(handle?: HandleSummary): string {
  const provider = String(handle?.provider || "").toLowerCase();
  const name = String(handle?.name || "").toLowerCase();
  const source = String(handle?.source || "").toLowerCase();
  const envName = String(handle?.policy.injectEnv || "").toLowerCase();
  const haystack = `${provider} ${name} ${source} ${envName}`;

  if (provider === "aws" || handle?.type === "access-key" || /\baws\b|amazon|access[_ -]?key|secret[_ -]?access/.test(haystack)) {
    return "AWS access key";
  }
  if (provider === "github" || /\bgithub\b|\bgh\b|ghp_|github[_ -]?token/.test(haystack)) {
    return "GitHub token";
  }
  if (provider === "openai" || /openai|sk-/.test(haystack)) {
    return "OpenAI API key";
  }
  if (provider === "ssh" || /ssh|bastion|private[_ -]?key|rsa|ed25519/.test(haystack)) {
    return handle?.type === "password" ? "SSH password" : "SSH private key";
  }
  if (handle?.type === "private-key" || handle?.type === "ssh-key") {
    return "Private key";
  }
  if (handle?.type === "password") {
    return "Password";
  }
  if (handle?.type === "api-token") {
    return "API token";
  }
  if (handle?.type === "credential") {
    return "Credential pair";
  }
  return "Unknown credential";
}

function authTypeDetail(handle?: HandleSummary): string {
  const parts = [];
  if (handle?.severity) {
    parts.push(`${handle.severity} risk`);
  }
  if (handle?.backend) {
    parts.push(`stored in ${flowProviderLabel(handle.backend)}`);
  }
  return parts.join(" / ") || "Authentication type";
}

function targetTypeKey(action: RequestRecord["action"]): string {
  return normalizeFlowKey(targetTypeLabel(action));
}

function targetTypeLabel(action: RequestRecord["action"]): string {
  if (action.kind === "model_relay") return "Model API";
  if (sshDestination(action)) {
    return "SSH server";
  }

  const command = commandBase(action.command).toLowerCase();
  const target = actionTarget(action).toLowerCase();
  const args = action.args.join(" ").toLowerCase();
  const envName = action.injectEnv.toLowerCase();
  const haystack = `${command} ${target} ${args} ${envName}`;

  if (command === "aws" || /\baws\b|\bec2\b|\bs3\b|\bsts\b|cloudformation|securityhub|iam\b/.test(haystack)) {
    return "AWS API";
  }
  if (command === "gh" || command === "github" || /github|pull request|\brepo\b/.test(haystack)) {
    return "GitHub repository";
  }
  if (command === "kubectl" || /kubernetes|kubeconfig|namespace/.test(haystack)) {
    return "Kubernetes cluster";
  }
  if (command === "docker" || command === "podman" || /container|image|compose/.test(haystack)) {
    return "Container runtime";
  }
  if (command === "curl" || command === "wget" || target.startsWith("http://") || target.startsWith("https://") || args.includes("http://") || args.includes("https://")) {
    return "Web API";
  }
  if (command === "psql" || command === "mysql" || command === "redis-cli" || /database|postgres|mysql|redis/.test(haystack)) {
    return "Database";
  }
  if (/\bnas\b|network.?attached.?storage|storage.?appliance|file.?server/.test(haystack)) {
    return "NAS / appliance";
  }
  if (action.kind === "env_command") {
    return "Local command";
  }

  return "Other target";
}

function targetTypeDetail(action: RequestRecord["action"]): string {
  const target = actionTarget(action);
  if (target && target !== "local command") {
    return target;
  }
  return commandBase(action.command);
}

function flowProviderLabel(provider?: string): string {
  const value = provider || "generic";
  if (value === "aws") return "AWS";
  if (value === "github") return "GitHub";
  if (value === "openai") return "OpenAI";
  if (value === "ssh") return "SSH";
  if (value === "onepassword") return "1Password";
  if (value === "keychain" || value === "macos-keychain") return "macOS Keychain";
  if (value === "linux-secret-service") return "Linux Secret Service";
  if (value === "windows-credential-manager") return "Windows Credential Manager";
  return titleCase(value);
}

function normalizeFlowKey(value: string): string {
  return String(value || "unknown").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") || "unknown";
}

function titleCase(value: string): string {
  return String(value || "unknown")
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function actionLabel(action: RequestRecord["action"]): string {
  const command = action.kind === "ssh_session" ? "ssh" : commandBase(action.command);
  const target = actionTarget(action);
  if (!target || target === "local command") {
    return command;
  }

  return `${command} -> ${target}`;
}

function actionTarget(action: RequestRecord["action"]): string {
  if (action.kind === "model_relay") {
    if (action.model?.provider === "anthropic") return "api.anthropic.com";
    if (action.model?.provider === "openai") return "api.openai.com";
    return "model API";
  }
  const sshTarget = sshDestination(action);
  if (sshTarget) return sshTarget;

  if (action.workingDir) {
    return action.workingDir;
  }

  if (action.args[0] === "-e") {
    return `${commandBase(action.command)} inline script`;
  }

  for (const arg of action.args) {
    if (arg && !arg.startsWith("-")) {
      return arg;
    }
  }

  return action.injectEnv || "local command";
}

const sshOptionsWithValue = new Set([
  "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w"
]);

function sshDestination(action: RequestRecord["action"]): string | undefined {
  if (action.kind === "ssh_session" && action.ssh?.managed) return managedSshDestination(action.ssh.managed);
  if (action.kind === "ssh_session" && action.ssh?.target) {
    return action.ssh.port && action.ssh.port !== 22 ? `${action.ssh.target}:${action.ssh.port}` : action.ssh.target;
  }
  if (commandBase(action.command).toLowerCase() !== "ssh") return undefined;

  let skipNext = false;
  for (const arg of action.args) {
    if (skipNext) {
      skipNext = false;
      continue;
    }
    if (sshOptionsWithValue.has(arg)) {
      skipNext = true;
      continue;
    }
    if (arg === "--" || arg.startsWith("-")) continue;
    return arg;
  }
  return undefined;
}

function managedSshDestination(route: ManagedSshRoute): string {
  const host = route.host.includes(":") ? `[${route.host}]` : route.host;
  return `${route.user}@${host}:${route.port}`;
}

function commandBase(command: string): string {
  const normalized = String(command || "").replace(/\\/g, "/");
  const parts = normalized.split("/");
  return parts[parts.length - 1] || normalized || "local command";
}

function shortHandle(handle: string): string {
  if (handle.length <= 34) {
    return handle;
  }

  return `${handle.slice(0, 18)}...${handle.slice(-8)}`;
}

async function auditCsv(store: SecretStore): Promise<string> {
  const audit = await store.auditLog();
  const rows = [["time", "event", "handle", "request", "message"]];
  for (const event of audit) {
    rows.push([event.ts, event.type, event.handle || "", event.requestId || "", event.message]);
  }

  return rows.map((row) => row.map(csvCell).join(",")).join("\n") + "\n";
}

async function serveUi(
  req: IncomingMessage,
  res: ServerResponse,
  pathname: string,
  uiDir: string,
  token: string,
  operatorAuth = false,
  operatorProof?: string
): Promise<void> {
  if (req.method !== "GET" && req.method !== "HEAD") {
    throw new HttpError(405, "Only GET is supported for local console assets.");
  }

  const safeRoot = path.resolve(uiDir);
  let relative = uiRelativePath(pathname, uiDir);
  let target = path.resolve(uiDir, relative);
  if (target !== safeRoot && !target.startsWith(`${safeRoot}${path.sep}`)) {
    throw new HttpError(403, "Path is outside the local console directory.");
  }

  if (!existsSync(target) && shouldServeSpaFallback(pathname, uiDir)) {
    relative = "index.html";
    target = path.resolve(uiDir, relative);
  }

  if (operatorAuth) {
    const actualRoot = await realpath(safeRoot);
    const actualTarget = await realpath(target);
    if (actualTarget !== actualRoot && !actualTarget.startsWith(`${actualRoot}${path.sep}`)) {
      throw new HttpError(403, "Path is outside the protected console directory.");
    }
  }

  let body = await readFile(target);
  const scriptNonce = randomBytes(18).toString("base64");
  if (path.basename(target) === "local-console.html" || path.basename(target) === "index.html") {
    body = Buffer.from(injectConsoleToken(body.toString("utf8"), token, scriptNonce, operatorAuth));
  }

  if (operatorProof) {
    body = Buffer.from(await addUiIntegrity(body.toString("utf8"), uiDir));
    res.setHeader("X-SGW-App-Proof", createHmac("sha256", operatorProof).update(body).digest("base64url"));
  }

  res.writeHead(200, {
    "Content-Type": contentType(target),
    "Cache-Control": "no-store",
    "Content-Security-Policy": consoleContentSecurityPolicy(scriptNonce),
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff"
  });

  if (req.method === "HEAD") {
    res.end();
    return;
  }

  res.end(body);
}

async function addUiIntegrity(html: string, uiDir: string): Promise<string> {
  const tags = [...html.matchAll(/<(script|link)\b[^>]*>/giu)];
  const root = await realpath(uiDir);
  let result = html;
  for (let index = tags.length - 1; index >= 0; index--) {
    const match = tags[index];
    const tag = match[0];
    if (match[1].toLowerCase() === "link" && !/\brel=["']stylesheet["']/iu.test(tag)) continue;
    const asset = /\b(?:src|href)=["']([^"']+)["']/iu.exec(tag)?.[1];
    if (!asset) continue;
    const url = new URL(asset, "http://127.0.0.1/");
    if (url.origin !== "http://127.0.0.1") continue;
    const target = await realpath(path.resolve(uiDir, uiRelativePath(url.pathname, uiDir)));
    if (target !== root && !target.startsWith(`${root}${path.sep}`)) {
      throw new HttpError(403, "Protected console asset is outside its directory.");
    }
    const digest = createHash("sha256").update(await readFile(target)).digest("base64");
    const updated = tag.replace(/\s+integrity=["'][^"']*["']/iu, "")
      .replace(/>$/u, ` integrity="sha256-${digest}">`);
    result = result.slice(0, match.index) + updated + result.slice(match.index + tag.length);
  }
  return result;
}

function uiRelativePath(pathname: string, uiDir: string): string {
  if (pathname === "/" || pathname === "") {
    return existsSync(path.join(uiDir, "index.html")) ? "index.html" : "local-console.html";
  }

  let cleaned = decodeURIComponent(pathname).replace(/^\/+/, "");
  cleaned = cleaned.replace(/^docs\/ui\//, "");
  return cleaned || (existsSync(path.join(uiDir, "index.html")) ? "index.html" : "local-console.html");
}

function shouldServeSpaFallback(pathname: string, uiDir: string): boolean {
  if (!existsSync(path.join(uiDir, "index.html"))) {
    return false;
  }

  const cleaned = decodeURIComponent(pathname || "").replace(/^\/+/, "");
  if (!cleaned) {
    return true;
  }

  const ext = path.extname(cleaned);
  return ext === "";
}

function injectConsoleToken(html: string, token: string, nonce: string, operatorAuth: boolean): string {
  const withNonces = html.replace(/<script(?![^>]*\bnonce=)/giu, `<script nonce="${nonce}"`);
  const credential = operatorAuth
    ? 'window.SGW_CONSOLE_TOKEN||""'
    : JSON.stringify(token);
  const script = `<script nonce="${nonce}">window.SGW_CONSOLE_TOKEN=${credential};window.SGW_CONSOLE_LIVE=true;window.SGW_CONSOLE_OPERATOR_AUTH=${operatorAuth};</script>`;
  return withNonces.includes("</head>")
    ? withNonces.replace("</head>", `${script}\n</head>`)
    : `${script}\n${withNonces}`;
}

function consoleContentSecurityPolicy(nonce: string): string {
  return [
    "default-src 'self'",
    `script-src 'nonce-${nonce}'`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self' data:",
    "connect-src 'self'",
    "worker-src 'none'",
    "frame-src 'none'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'"
  ].join("; ");
}

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const body = verifiedOperatorBodies.get(req) || await readBody(req);
  verifiedOperatorBodies.delete(req);
  if (body.length === 0) return {};

  const parsed = JSON.parse(body.toString("utf8")) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new HttpError(400, "JSON body must be an object.");
  }

  return parsed as Record<string, unknown>;
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;

  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.byteLength;
    if (size > maxBodyBytes) {
      throw new HttpError(413, "Request body is too large.");
    }

    chunks.push(buffer);
  }

  return Buffer.concat(chunks);
}

async function validSignedOperatorRequest(req: IncomingMessage, url: URL, session: OperatorSession): Promise<boolean> {
  const nonce = req.headers["x-sgw-console-nonce"];
  const signature = req.headers["x-sgw-console-signature"];
  if (typeof nonce !== "string" || !/^[A-Za-z0-9_-]{22}$/u.test(nonce) ||
      typeof signature !== "string" || !/^[A-Za-z0-9_-]{43}$/u.test(signature) ||
      session.usedNonces.has(nonce) || session.usedNonces.size >= 20_000) return false;

  const body = await readBody(req);
  const prefix = `sgw-operator-v1\n${req.method}\n${url.pathname}${url.search}\n${nonce}\n`;
  const expected = createHmac("sha256", session.proof).update(prefix).update(body).digest("base64url");
  if (!sameSecret(signature, expected)) return false;
  session.usedNonces.add(nonce);
  verifiedOperatorBodies.set(req, body);
  return true;
}

function validConsoleToken(req: IncomingMessage, expected: string): boolean {
  const header = req.headers["x-sgw-console-token"];
  const token = Array.isArray(header) ? header[0] : header;
  return Boolean(token && sameSecret(token, expected));
}

function stringValue(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) {
    throw new HttpError(400, `${name} is required.`);
  }

  return value;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function localBackendValue(value: unknown): LocalSecretBackend {
  if (value === undefined || value === null || value === "") {
    return preferredLocalSecretBackend();
  }

  if (value === "local" || value === "keychain") {
    return value;
  }

  throw new HttpError(400, "backend must be either local or keychain.");
}

function stringList(value: unknown): string[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new HttpError(400, "Expected an array of strings.");
  }

  const out: string[] = [];
  for (const item of value) {
    if (typeof item !== "string") {
      throw new HttpError(400, "Expected an array of strings.");
    }
    out.push(item);
  }

  return out;
}

function envBindingList(value: unknown): CommandEnvBinding[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new HttpError(400, "env must be an array of {handle, injectEnv} objects.");
  }

  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new HttpError(400, "env must be an array of {handle, injectEnv} objects.");
    }

    const record = item as Record<string, unknown>;
    return {
      handle: stringValue(record.handle, "env.handle"),
      injectEnv: stringValue(record.injectEnv, "env.injectEnv")
    };
  });
}

function numberValue(value: unknown, fallback: number): number {
  if (value === undefined || value === null || value === "") {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new HttpError(400, "Expected a finite number.");
  }

  return parsed;
}

function secretType(input: unknown): SecretType {
  const allowed: SecretType[] = [
    "api-token",
    "ssh-key",
    "private-key",
    "password",
    "credential",
    "access-key",
    "unknown"
  ];

  return allowed.includes(input as SecretType) ? (input as SecretType) : "unknown";
}

function approvalMode(input: unknown): ApprovalMode {
  if (input === "per-transaction" || input === "timed-session" || input === "login-session" || input === "always") {
    return input;
  }

  throw new HttpError(400, "mode must be per-transaction, timed-session, login-session, or always.");
}

function approvalPolicyDecision(input: unknown): ApprovalPolicyDecision {
  if (input === "ask" || input === "allow" || input === "deny") {
    return input;
  }

  throw new HttpError(400, "decision must be ask, allow, or deny.");
}

function approvalPolicyActionKind(input: string): ApprovalPolicyActionKind {
  if (input === "env_command" || input === "env-command" || input === "command") {
    return "env_command";
  }
  if (input === "ssh_session" || input === "ssh-session" || input === "ssh") {
    return "ssh_session";
  }

  if (input === "http_request") return "http_request";
  if (input === "model_relay" || input === "model-relay") return "model_relay";
  throw new HttpError(400, "actionKinds must contain env_command, ssh_session, http_request or model_relay.");
}

function optionalApprovalMode(input: unknown): ApprovalMode | undefined {
  if (input === undefined || input === null || input === "") {
    return undefined;
  }

  return approvalMode(input);
}

function optionalApprovalAgentScope(input: unknown): ApprovalAgentScope | undefined {
  if (input === undefined || input === null || input === "") {
    return undefined;
  }

  if (input === "same-agent" || input === "any-agent") {
    return input;
  }

  throw new HttpError(400, "agentScope must be same-agent or any-agent.");
}

function optionalSecretSeverity(input: unknown): SecretSeverity | undefined {
  if (input === undefined || input === null || input === "") {
    return undefined;
  }

  if (input === "low" || input === "medium" || input === "high" || input === "critical") {
    return input;
  }

  throw new HttpError(400, "minSeverity must be low, medium, high, or critical.");
}

function policyStringArray(body: Record<string, unknown>, field: string): string[] {
  if (!hasBodyField(body, field)) {
    return [];
  }
  const value = body[field];
  if (Array.isArray(value) && value.every((item) => typeof item === "string" && item.trim())) {
    return value;
  }

  throw new HttpError(400, `${field} must be an array of non-empty strings.`);
}

function policyNumberArray(body: Record<string, unknown>, field: string): number[] {
  if (!hasBodyField(body, field)) {
    return [];
  }
  return numberArray(body[field], field);
}

function policyOptionalNumberValue(body: Record<string, unknown>, field: string): number | undefined {
  if (!hasBodyField(body, field)) {
    return undefined;
  }
  const value = body[field];
  if (value === null || (typeof value === "string" && !value.trim())) {
    throw new HttpError(400, `${field} must be a finite number.`);
  }
  if (typeof value !== "number" && typeof value !== "string") {
    throw new HttpError(400, `${field} must be a finite number.`);
  }
  return optionalNumberValue(value);
}

function optionalNumberValue(value: unknown): number | undefined {
  if (value === undefined || value === null || value === "") {
    return undefined;
  }

  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    throw new HttpError(400, "Expected a finite number.");
  }

  return parsed;
}

function policyRuleInput(body: Record<string, unknown>): AddApprovalPolicyRuleInput {
  assertKnownPolicyFields(body);
  return {
    name: hasBodyField(body, "name") ? policyNameValue(body.name) : undefined,
    enabled: booleanValue(body.enabled, "enabled", true),
    priority: policyOptionalNumberValue(body, "priority"),
    decision: approvalPolicyDecision(body.decision),
    expiresAt: policyExpiresAtValue(body, false) ?? undefined,
    durationMs: policyOptionalNumberValue(body, "durationMs"),
    conditions: policyConditionsFromBody(body)
  };
}

function policyRuleUpdateInput(body: Record<string, unknown>): UpdateApprovalPolicyRuleInput {
  assertKnownPolicyFields(body);
  const input: UpdateApprovalPolicyRuleInput = {};
  if (hasBodyField(body, "name")) input.name = policyNameValue(body.name);
  if (hasBodyField(body, "enabled")) input.enabled = booleanValue(body.enabled, "enabled");
  if (hasBodyField(body, "priority")) input.priority = policyOptionalNumberValue(body, "priority");
  if (hasBodyField(body, "decision")) input.decision = approvalPolicyDecision(body.decision);
  if (hasBodyField(body, "expiresAt")) input.expiresAt = policyExpiresAtValue(body, true);
  if (hasBodyField(body, "durationMs")) input.durationMs = policyOptionalNumberValue(body, "durationMs");

  const conditions = policyConditionPatchFromBody(body);
  if (conditions) input.conditions = conditions;
  if (Object.keys(input).length === 0) {
    throw new HttpError(400, "Approval policy update must include at least one change.");
  }
  return input;
}

function policyConditionsFromBody(body: Record<string, unknown>): ApprovalPolicyConditions {
  const conditions: ApprovalPolicyConditions = {
    handles: policyStringArray(body, "handles"),
    envBindings: policyEnvBindings(body.envBindings),
    secretTypes: policyStringArray(body, "secretTypes").map(policySecretType),
    providers: policyStringArray(body, "providers"),
    minSeverity: optionalSecretSeverity(body.minSeverity),
    agents: policyStringArray(body, "agents"),
    actionKinds: policyStringArray(body, "actionKinds").map(approvalPolicyActionKind),
    injectEnvs: policyStringArray(body, "injectEnvs"),
    workingDirs: policyStringArray(body, "workingDirs"),
    sshTargets: policyStringArray(body, "sshTargets"),
    sshPorts: policyNumberArray(body, "sshPorts")
  };
  if (hasBodyField(body, "commands")) conditions.commands = policyStringArray(body, "commands");
  if (hasBodyField(body, "resolvedCommands")) conditions.resolvedCommands = policyStringArray(body, "resolvedCommands");
  return conditions;
}

function policyConditionPatchFromBody(body: Record<string, unknown>): Partial<ApprovalPolicyConditions> | undefined {
  const fields = [
    "handles",
    "envBindings",
    "secretTypes",
    "providers",
    "minSeverity",
    "agents",
    "actionKinds",
    "commands",
    "resolvedCommands",
    "injectEnvs",
    "workingDirs",
    "sshTargets",
    "sshPorts"
  ];
  if (!fields.some((field) => hasBodyField(body, field))) {
    return undefined;
  }

  const patch: Partial<ApprovalPolicyConditions> = {};
  if (hasBodyField(body, "handles")) patch.handles = policyStringArray(body, "handles");
  if (hasBodyField(body, "envBindings")) patch.envBindings = policyEnvBindings(body.envBindings);
  if (hasBodyField(body, "secretTypes")) patch.secretTypes = policyStringArray(body, "secretTypes").map(policySecretType);
  if (hasBodyField(body, "providers")) patch.providers = policyStringArray(body, "providers");
  if (hasBodyField(body, "minSeverity")) patch.minSeverity = body.minSeverity === null ? undefined : optionalSecretSeverity(body.minSeverity);
  if (hasBodyField(body, "agents")) patch.agents = policyStringArray(body, "agents");
  if (hasBodyField(body, "actionKinds")) patch.actionKinds = policyStringArray(body, "actionKinds").map(approvalPolicyActionKind);
  if (hasBodyField(body, "commands")) patch.commands = policyStringArray(body, "commands");
  if (hasBodyField(body, "resolvedCommands")) patch.resolvedCommands = policyStringArray(body, "resolvedCommands");
  if (hasBodyField(body, "injectEnvs")) patch.injectEnvs = policyStringArray(body, "injectEnvs");
  if (hasBodyField(body, "workingDirs")) patch.workingDirs = policyStringArray(body, "workingDirs");
  if (hasBodyField(body, "sshTargets")) patch.sshTargets = policyStringArray(body, "sshTargets");
  if (hasBodyField(body, "sshPorts")) patch.sshPorts = policyNumberArray(body, "sshPorts");
  return patch;
}

function policyExpiresAtValue(body: Record<string, unknown>, allowClear: boolean): string | null | undefined {
  if (!hasBodyField(body, "expiresAt")) {
    return undefined;
  }
  if (body.expiresAt === null && allowClear) {
    return null;
  }
  if (typeof body.expiresAt !== "string") {
    throw new HttpError(400, "expiresAt must be an ISO timestamp.");
  }
  return body.expiresAt;
}

function policyNameValue(value: unknown): string {
  if (typeof value !== "string") {
    throw new HttpError(400, "name must be a string.");
  }
  return value;
}

function assertKnownPolicyFields(body: Record<string, unknown>): void {
  const known = new Set([
    "name",
    "enabled",
    "priority",
    "decision",
    "expiresAt",
    "durationMs",
    "handles",
    "envBindings",
    "secretTypes",
    "providers",
    "minSeverity",
    "agents",
    "actionKinds",
    "commands",
    "resolvedCommands",
    "injectEnvs",
    "workingDirs",
    "sshTargets",
    "sshPorts"
  ]);
  const unknown = Object.keys(body).filter((field) => !known.has(field));
  if (unknown.length) {
    throw new HttpError(400, `Unsupported approval policy field: ${unknown.join(", ")}.`);
  }
}

function booleanValue(value: unknown, field: string, fallback?: boolean): boolean {
  if (value === undefined && fallback !== undefined) {
    return fallback;
  }
  if (typeof value === "boolean") {
    return value;
  }
  throw new HttpError(400, `${field} must be a boolean.`);
}

function policySecretType(value: string): SecretType {
  const type = secretType(value);
  if (type === "unknown" && value !== "unknown") {
    throw new HttpError(400, `Unsupported secret type: ${value}.`);
  }
  return type;
}

function numberArray(value: unknown, field: string): number[] {
  if (!Array.isArray(value)) {
    throw new HttpError(400, `${field} must be an array of numbers.`);
  }

  return value.map((item) => {
    const number = typeof item === "number" || typeof item === "string" ? Number(item) : Number.NaN;
    if (!Number.isFinite(number)) {
      throw new HttpError(400, `${field} must contain finite numbers.`);
    }
    return number;
  });
}

function policyEnvBindings(value: unknown): CommandEnvBinding[] {
  if (value === undefined) {
    return [];
  }
  if (!Array.isArray(value)) {
    throw new HttpError(400, "envBindings must be an array of {handle, injectEnv} objects.");
  }

  return value.map((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      throw new HttpError(400, "envBindings must be an array of {handle, injectEnv} objects.");
    }
    const binding = item as Record<string, unknown>;
    return {
      handle: stringValue(binding.handle, "envBindings.handle"),
      injectEnv: stringValue(binding.injectEnv, "envBindings.injectEnv")
    };
  });
}

function hasBodyField(body: Record<string, unknown>, field: string): boolean {
  return Object.prototype.hasOwnProperty.call(body, field);
}

function providerForType(type: SecretType): string {
  if (type === "private-key" || type === "ssh-key") {
    return "ssh";
  }

  if (type === "unknown") {
    return "generic";
  }

  return type;
}

function providerLabel(provider: string): string {
  const known: Record<string, string> = {
    aws: "AWS",
    github: "GitHub",
    openai: "OpenAI",
    ssh: "SSH",
    "1password": "1Password",
    onepassword: "1Password",
    generic: "Generic",
    keychain: "macOS Keychain",
    "macos-keychain": "macOS Keychain",
    "linux-secret-service": "Linux Secret Service",
    "windows-credential-manager": "Windows Credential Manager",
    "api-token": "API Tokens",
    credential: "Credentials"
  };

  return known[provider] || provider.replace(/(^|-)([a-z])/g, (_match, dash: string, char: string) => {
    return `${dash ? " " : ""}${char.toUpperCase()}`;
  });
}

function handlePrefix(provider: string, type: SecretType): string {
  if (provider && provider !== "generic") {
    return `s-gw:${provider}`;
  }

  return `s-gw:${type}`;
}

function higherSeverity(a: SecretSeverity, b: SecretSeverity): SecretSeverity {
  const rank: Record<SecretSeverity, number> = {
    low: 0,
    medium: 1,
    high: 2,
    critical: 3
  };

  return rank[b] > rank[a] ? b : a;
}

function csvCell(value: string): string {
  return `"${value.replace(/"/g, '""')}"`;
}

function contentType(filePath: string): string {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".html") {
    return "text/html; charset=utf-8";
  }
  if (ext === ".css") {
    return "text/css; charset=utf-8";
  }
  if (ext === ".js") {
    return "text/javascript; charset=utf-8";
  }
  if (ext === ".png") {
    return "image/png";
  }
  if (ext === ".svg") {
    return "image/svg+xml";
  }
  if (ext === ".woff2") {
    return "font/woff2";
  }
  if (ext === ".md") {
    return "text/markdown; charset=utf-8";
  }

  return "application/octet-stream";
}

function defaultUiDir(): string {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const builtReactCandidates = [
    path.resolve(here, "console-ui"),
    path.resolve(here, "..", "dist", "console-ui")
  ];
  for (const candidate of builtReactCandidates) {
    if (isBuiltReactUi(candidate)) {
      return candidate;
    }
  }

  return path.resolve(here, "..", "docs", "ui");
}

function isBuiltReactUi(candidate: string): boolean {
  return existsSync(path.join(candidate, "index.html")) && existsSync(path.join(candidate, "assets"));
}

function sendJson(res: ServerResponse, status: number, value: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store"
  });
  res.end(`${JSON.stringify(value, null, 2)}\n`);
}

function sendCsv(res: ServerResponse, csv: string): void {
  res.writeHead(200, {
    "Content-Type": "text/csv; charset=utf-8",
    "Content-Disposition": 'attachment; filename="s-gw-audit.csv"',
    "Cache-Control": "no-store"
  });
  res.end(csv);
}

function sendError(res: ServerResponse, error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  const status = error instanceof HttpError ? error.status : statusForErrorMessage(message);
  sendJson(res, status, { error: message });
}

function statusForErrorMessage(message: string): number {
  if (/unknown (secret handle|request|approval policy)/i.test(message)) {
    return 404;
  }

  if (/approval|approved|pending|denied|executed|failed|takes precedence/i.test(message)) {
    return 409;
  }

  if (/not allowed|invalid|required|missing|empty|must be|must contain|must include|unsupported|expected/i.test(message)) {
    return 400;
  }

  return 500;
}

class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
}
