import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { createServer as createHttpServer, type Server as HttpServer } from "node:http";
import { createServer as createHttpsServer, request as httpsRequest, type Server as HttpsServer } from "node:https";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { createConnection, createServer as createTcpServer, type Server as TcpServer, type Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, it, vi } from "vitest";
import { principalForVerifiedPeer } from "../src/agent-context.js";
import { registerDurableModelRelaySession, StoreBackedModelRelayApprovals } from "../src/model-relay-approval.js";
import { SGW_MODEL_RELAY_COMMAND, startVerifiedModelRelayServer } from "../src/model-relay-server.js";
import type { ModelUpstreamRequest } from "../src/model-relay-transport.js";
import { principalIdForPeerSession, type PeerSession } from "../src/peer-identity.js";
import { SecretStore } from "../src/store.js";
import { httpsFixture } from "./helpers/https-fixture.js";

const peerScript = fileURLToPath(new URL("../scripts/build-peer-credentials.mjs", import.meta.url));
const sandboxProfile = '(version 1)(allow default)(deny network-outbound)(allow network-outbound (remote tcp "localhost:*"))';
const claudeCli = process.env.SGW_TEST_CLAUDE_CLI || (process.platform === "darwin"
  ? spawnSync("which", ["claude"], { encoding: "utf8" }).stdout?.trim() : "");
const enabled = process.platform === "darwin" && process.env.SGW_TEST_NATIVE_CLAUDE === "1" && !!claudeCli;
const clientKey = "synthetic-client-placeholder";

function sendAnswer(res: import("node:http").ServerResponse) {
  const events: Array<[string, Record<string, unknown>]> = [
    ["message_start", { type: "message_start", message: { id: "msg_synthetic", type: "message",
      role: "assistant", model: "claude-test", content: [], stop_reason: null, stop_sequence: null,
      usage: { input_tokens: 5, output_tokens: 0 } } }],
    ["content_block_start", { type: "content_block_start", index: 0,
      content_block: { type: "text", text: "" } }],
    ["content_block_delta", { type: "content_block_delta", index: 0,
      delta: { type: "text_delta", text: "HELLO" } }],
    ["content_block_stop", { type: "content_block_stop", index: 0 }],
    ["message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null },
      usage: { output_tokens: 1 } }],
    ["message_stop", { type: "message_stop" }]
  ];
  res.writeHead(200, { "content-type": "text/event-stream" });
  for (const [name, data] of events) res.write(`event: ${name}\ndata: ${JSON.stringify(data)}\n\n`);
  res.end();
}

function portOf(server: HttpServer | HttpsServer | TcpServer): number {
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Synthetic listener port is unavailable.");
  return address.port;
}

async function runClaude(baseUrl: string, directory: string): Promise<{ stdout: string; stderr: string; code: number | null }> {
  await mkdir(directory, { recursive: true });
  const env = {
    PATH: process.env.PATH,
    HOME: directory,
    CLAUDE_CONFIG_DIR: path.join(directory, "claude"),
    XDG_CONFIG_HOME: path.join(directory, "config"),
    XDG_CACHE_HOME: path.join(directory, "cache"),
    XDG_DATA_HOME: path.join(directory, "data"),
    ANTHROPIC_BASE_URL: baseUrl,
    ANTHROPIC_API_KEY: clientKey,
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    DISABLE_TELEMETRY: "1",
    NO_PROXY: "127.0.0.1,localhost"
  };
  const args = ["-p", "Reply exactly HELLO.", "--bare", "--no-session-persistence",
    "--output-format", "stream-json", "--verbose", "--model", "claude-test", "--max-turns", "1",
    "--tools", "", "--strict-mcp-config"];
  const child = spawn("/usr/bin/sandbox-exec", ["-p", sandboxProfile, claudeCli, ...args], {
    cwd: directory, env, stdio: ["ignore", "pipe", "pipe"]
  });
  let stdout = "", stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", part => { stdout += part; if (stdout.length > 1_000_000) child.kill("SIGKILL"); });
  child.stderr.on("data", part => { stderr += part; if (stderr.length > 1_000_000) child.kill("SIGKILL"); });
  const timeout = setTimeout(() => child.kill("SIGKILL"), 20_000);
  try {
    const code = await new Promise<number | null>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", code => resolve(code));
    });
    return { stdout, stderr, code };
  } finally {
    clearTimeout(timeout);
  }
}

function expectAnswer(output: { stdout: string; stderr: string; code: number | null }) {
  expect(output.code, output.stderr).toBe(0);
  const lines = output.stdout.trim().split("\n").map(line => JSON.parse(line));
  expect(lines.find(line => line.type === "system")?.apiKeySource).toBe("ANTHROPIC_API_KEY");
  expect(lines.find(line => line.type === "result")?.result).toBe("HELLO");
}

it.skipIf(!enabled)("runs native Claude Code through a durable strict broker model relay with synthetic credentials", async () => {
  const check = spawnSync("/usr/bin/sandbox-exec", ["-p", sandboxProfile, process.execPath, "-e",
    'const s=require("node:net").connect(443,"203.0.113.1");s.on("error",e=>{console.log(e.code);process.exit()});s.setTimeout(1000,()=>process.exit(2))'],
  { encoding: "utf8", timeout: 3000 });
  expect(check.status).toBe(0);
  expect(check.stdout.trim()).toBe("EPERM");
  const build = spawnSync(process.execPath, [peerScript], { encoding: "utf8" });
  expect(build.status, build.stderr || build.stdout).toBe(0);

  const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-native-claude-")));
  const savedEnv = new Map(["SGW_MASTER_PASSPHRASE", "SGW_RECOVERY_HOME", "SGW_DISABLE_KEYCHAIN",
    "SGW_DISABLE_ONEPASSWORD_BACKUP"].map(name => [name, process.env[name]]));
  let preflight: HttpServer | undefined;
  let upstream: HttpsServer | undefined;
  let bridge: TcpServer | undefined;
  const bridgeSockets = new Set<Socket>();
  let relay: Awaited<ReturnType<typeof startVerifiedModelRelayServer>> | undefined;
  try {
    process.env.SGW_MASTER_PASSPHRASE = "synthetic native Claude relay test passphrase";
    process.env.SGW_RECOVERY_HOME = path.join(root, "recovery");
    process.env.SGW_DISABLE_KEYCHAIN = "1";
    process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";

    let betaHeader: string | undefined;
    preflight = createHttpServer(async (req, res) => {
      for await (const _chunk of req) {}
      if (req.method === "POST" && req.url?.startsWith("/v1/messages")) {
        const header = req.headers["anthropic-beta"];
        if (typeof header === "string") betaHeader = header;
        sendAnswer(res);
        return;
      }
      res.writeHead(404).end();
    });
    await new Promise<void>(resolve => preflight!.listen(0, "127.0.0.1", resolve));
    const probe = await runClaude(`http://127.0.0.1:${portOf(preflight)}`, path.join(root, "preflight"));
    expectAnswer(probe);
    expect(betaHeader).toBeTruthy();
    preflight.closeAllConnections();
    await new Promise<void>(resolve => preflight!.close(() => resolve()));
    preflight = undefined;

    const tls = await httpsFixture(root);
    const seen: Array<{ method?: string; path?: string; headers: import("node:http").IncomingHttpHeaders; body: string }> = [];
    upstream = createHttpsServer(tls, async (req, res) => {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      seen.push({ method: req.method, path: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() });
      sendAnswer(res);
    });
    await new Promise<void>(resolve => upstream!.listen(0, "127.0.0.1", resolve));
    const requestUpstream: ModelUpstreamRequest = (url, options, callback) => {
      expect(url.host).toBe("api.anthropic.com");
      const local = new URL(url.pathname + url.search, `https://localhost:${portOf(upstream!)}`);
      return httpsRequest(local, { ...options, ca: tls.cert, lookup: undefined }, callback);
    };

    const store = new SecretStore(path.join(root, "store"));
    await store.init();
    const credential = `synthetic-broker-key-${randomUUID()}`;
    const handle = (await store.addSecret({ name: "Native Claude relay fixture", type: "api-token", value: credential,
      policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.anthropic.com:443"] } })).handle;
    const session: PeerSession = { uid: process.getuid!(), gid: process.getgid!(),
      sessionId: "native-claude-synthetic", name: "Claude Code" };
    const principal = principalForVerifiedPeer(principalIdForPeerSession(session), session.name, session.sessionId);
    const request = await store.createModelRelayRequest({ provider: "anthropic", handle, ttlMs: 30_000,
      routes: ["POST /v1/messages", "POST /v1/messages/count_tokens", "GET /v1/models"],
      payloadProfile: "strict", allowedModels: ["claude-test"], maxInputBytes: 16_384,
      maxOutputTokens: 32_000, maxRequests: 3, allowedBetaValues: [betaHeader!] }, principal);
    expect(request.state).toBe("pending");
    await store.approveRequest(request.id, { mode: "per-transaction" });
    const approvals = new StoreBackedModelRelayApprovals(store);
    const socketPath = path.join(root, "model.sock");
    relay = await startVerifiedModelRelayServer({ socketPath, store, approval: approvals, requestUpstream });
    const brokerUid = process.getuid!() === 0 ? 1 : 0;
    const uid = vi.spyOn(process, "getuid").mockReturnValue(brokerUid);
    const euid = vi.spyOn(process, "geteuid").mockReturnValue(brokerUid);
    let stop: (() => void) | undefined;
    try {
      stop = await registerDurableModelRelaySession(relay, approvals, session, request.id);
    } finally {
      uid.mockRestore();
      euid.mockRestore();
    }
    expect((await store.getRequest(request.id)).state).toBe("executing");

    // This local bridge supplies a native client's HTTP base URL; it is not a production isolation boundary.
    bridge = createTcpServer(client => {
      bridgeSockets.add(client);
      client.once("close", () => bridgeSockets.delete(client));
      const broker = createConnection(socketPath);
      bridgeSockets.add(broker);
      broker.once("close", () => bridgeSockets.delete(broker));
      client.once("error", () => broker.destroy());
      broker.once("error", () => client.destroy());
      client.pipe(broker).pipe(client);
    });
    await new Promise<void>(resolve => bridge!.listen(0, "127.0.0.1", resolve));
    const turn = await runClaude(`http://127.0.0.1:${portOf(bridge)}`, path.join(root, "relay-client"));
    expectAnswer(turn);
    expect(seen).toHaveLength(1);
    expect(seen[0].method).toBe("POST");
    expect(seen[0].path).toBe("/v1/messages?beta=true");
    expect(seen[0].headers.authorization).toBe(`Bearer ${credential}`);
    expect(seen[0].headers["x-api-key"]).toBeUndefined();
    expect(JSON.stringify(seen[0])).not.toContain(clientKey);
    expect(JSON.parse(seen[0].body).model).toBe("claude-test");
    expect(turn.stdout + turn.stderr).not.toContain(credential);
    stop?.();
    await relay.close();
    relay = undefined;
    expect((await store.getRequest(request.id)).state).toBe("executed");
  } finally {
    for (const socket of bridgeSockets) socket.destroy();
    if (bridge) await new Promise<void>(resolve => bridge!.close(() => resolve()));
    await relay?.close();
    preflight?.closeAllConnections();
    if (preflight) await new Promise<void>(resolve => preflight!.close(() => resolve()));
    upstream?.closeAllConnections();
    if (upstream) await new Promise<void>(resolve => upstream!.close(() => resolve()));
    for (const [name, value] of savedEnv) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await rm(root, { recursive: true, force: true });
  }
}, 60_000);
