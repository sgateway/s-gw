import { spawn, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { mkdtemp, mkdir, realpath, rm } from "node:fs/promises";
import type { ServerResponse } from "node:http";
import { createServer as createHttpsServer, request as httpsRequest, type Server as HttpsServer } from "node:https";
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

const codex = "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex";
const hasCompiler = spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;
const peerScript = fileURLToPath(new URL("../scripts/build-peer-credentials.mjs", import.meta.url));
const linuxCgroup = process.platform === "linux"
  ? readFileSync("/proc/self/cgroup", "utf8").split("\n").find(line => line.startsWith("0::/"))?.slice(3)
  : undefined;
const canRegister = process.platform !== "linux" || !!linuxCgroup && linuxCgroup !== "/";

function responseEvents(res: ServerResponse): void {
  const item = { id: "msg_synthetic", type: "message", role: "assistant", status: "completed",
    content: [{ type: "output_text", text: "HELLO", annotations: [] }] };
  const response = { id: "resp_synthetic", object: "response", created_at: Math.floor(Date.now() / 1000),
    status: "completed", model: "gpt-5.3-codex", output: [item],
    usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 } };
  res.writeHead(200, { "content-type": "text/event-stream", "cache-control": "no-cache" });
  let sequence_number = 0;
  const emit = (type: string, fields: Record<string, unknown>) => {
    res.write(`event: ${type}\ndata: ${JSON.stringify({ type, ...fields, sequence_number: ++sequence_number })}\n\n`);
  };
  emit("response.created", { response: { ...response, status: "in_progress", output: [] } });
  emit("response.output_item.added", { output_index: 0, item: { ...item, status: "in_progress", content: [] } });
  emit("response.content_part.added", { item_id: item.id, output_index: 0, content_index: 0,
    part: { ...item.content[0], text: "", logprobs: [] } });
  emit("response.output_text.delta", { item_id: item.id, output_index: 0, content_index: 0,
    delta: "HELLO", logprobs: [] });
  emit("response.output_text.done", { item_id: item.id, output_index: 0, content_index: 0,
    text: "HELLO", logprobs: [] });
  emit("response.content_part.done", { item_id: item.id, output_index: 0, content_index: 0,
    part: item.content[0] });
  emit("response.output_item.done", { output_index: 0, item });
  emit("response.completed", { response });
  res.end();
}

function runCodex(root: string, port: number): Promise<{ code: number | null; stdout: string; stderr: string }> {
  const args = ["exec", "--ephemeral", "--ignore-user-config", "--skip-git-repo-check",
    "--sandbox", "read-only", "--json", "-m", "gpt-5.3-codex",
    "-c", 'model_provider="fixture"',
    "-c", 'model_providers.fixture.name="Synthetic Fixture"',
    "-c", `model_providers.fixture.base_url="http://127.0.0.1:${port}/v1"`,
    "-c", 'model_providers.fixture.env_key="OPENAI_API_KEY"',
    "-c", 'model_providers.fixture.wire_api="responses"',
    "-c", "model_providers.fixture.requires_openai_auth=false",
    "-c", "model_providers.fixture.supports_websockets=false",
    "Reply exactly HELLO."];
  const child = spawn(codex, args, { cwd: root, stdio: ["ignore", "pipe", "pipe"], env: {
    PATH: process.env.PATH || "/usr/bin:/bin", HOME: root, CODEX_HOME: path.join(root, "codex"),
    TMPDIR: root, LANG: "en_US.UTF-8", OPENAI_API_KEY: "synthetic-client-placeholder"
  } });
  return new Promise((resolve, reject) => {
    let stdout = "", stderr = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); reject(new Error("Native Codex fixture timed out.")); }, 30_000);
    child.stdout.on("data", part => { stdout += part; if (stdout.length > 2_000_000) child.kill("SIGKILL"); });
    child.stderr.on("data", part => { stderr += part; if (stderr.length > 2_000_000) child.kill("SIGKILL"); });
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", code => { clearTimeout(timer); resolve({ code, stdout, stderr }); });
  });
}

it.skipIf(!existsSync(codex) || !hasCompiler || !canRegister)(
  "streams the native Codex protocol through a durable relay grant", async () => {
    const root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-native-codex-")));
    const socketPath = path.join(root, "model.sock");
    let relay: Awaited<ReturnType<typeof startVerifiedModelRelayServer>> | undefined;
    let bridge: TcpServer | undefined;
    const bridgeSockets = new Set<Socket>();
    let upstream: HttpsServer | undefined;
    let stop: (() => void) | undefined;
    process.env.SGW_MASTER_PASSPHRASE = "synthetic relay test passphrase";
    process.env.SGW_RECOVERY_HOME = path.join(root, "recovery");
    process.env.SGW_DISABLE_KEYCHAIN = "1";
    process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
    try {
      const build = spawnSync(process.execPath, [peerScript], { encoding: "utf8" });
      if (build.status !== 0) throw new Error(build.stderr || build.stdout);
      await mkdir(path.join(root, "codex"));
      const store = new SecretStore(path.join(root, "store"));
      await store.init();
      const brokerCredential = `synthetic-broker-key-${randomUUID()}`;
      const handle = (await store.addSecret({ name: "Native Codex synthetic provider",
        type: "api-token", value: brokerCredential,
        policy: { allowedCommands: [SGW_MODEL_RELAY_COMMAND], allowedDestinations: ["api.openai.com:443"] } })).handle;
      const tls = await httpsFixture(root);
      let upstreamCalls = 0;
      let upstreamPath = "";
      let upstreamAuth = "";
      let upstreamBody = "";
      upstream = createHttpsServer(tls, async (req, res) => {
        upstreamCalls++;
        upstreamPath = `${req.method} ${req.url}`;
        upstreamAuth = String(req.headers.authorization || "");
        for await (const part of req) upstreamBody += part;
        responseEvents(res);
      });
      await new Promise<void>(resolve => upstream!.listen(0, "127.0.0.1", resolve));
      const address = upstream.address();
      if (!address || typeof address === "string") throw new Error("Synthetic upstream port missing.");
      const upstreamPort = address.port;
      const requestUpstream: ModelUpstreamRequest = (url, options, callback) => {
        const local = new URL(url.pathname + url.search, `https://localhost:${upstreamPort}`);
        return httpsRequest(local, { ...options, ca: tls.cert, lookup: undefined }, callback);
      };
      const session: PeerSession = { uid: process.getuid!(), gid: process.getgid!(),
        sessionId: `codex-synthetic-${randomUUID()}`, name: "Codex" };
      if (process.platform === "linux") session.linuxCgroup = linuxCgroup;
      const principal = principalForVerifiedPeer(principalIdForPeerSession(session), session.name, session.sessionId);
      const request = await store.createModelRelayRequest({ provider: "openai", handle, ttlMs: 30_000,
        routes: ["POST /v1/responses"] }, principal);
      await store.approveRequest(request.id, { mode: "per-transaction" });
      const approvals = new StoreBackedModelRelayApprovals(store);
      relay = await startVerifiedModelRelayServer({ socketPath, store, approval: approvals, requestUpstream });
      const brokerUid = process.getuid!();
      const fakeUid = brokerUid === 0 ? 1 : 0;
      const uid = vi.spyOn(process, "getuid").mockReturnValue(fakeUid);
      const euid = vi.spyOn(process, "geteuid").mockReturnValue(fakeUid);
      try { stop = await registerDurableModelRelaySession(relay, approvals, session, request.id); }
      finally { uid.mockRestore(); euid.mockRestore(); }

      // This is a protocol bridge for the CLI fixture, not an agent identity boundary.
      bridge = createTcpServer(client => {
        const broker = createConnection(socketPath);
        bridgeSockets.add(client);
        bridgeSockets.add(broker);
        client.once("close", () => bridgeSockets.delete(client));
        broker.once("close", () => bridgeSockets.delete(broker));
        client.pipe(broker).pipe(client);
        client.on("error", () => broker.destroy());
        broker.on("error", () => client.destroy());
      });
      await new Promise<void>(resolve => bridge!.listen(0, "127.0.0.1", resolve));
      const bridgeAddress = bridge.address();
      if (!bridgeAddress || typeof bridgeAddress === "string") throw new Error("Synthetic bridge port missing.");
      const result = await runCodex(root, bridgeAddress.port);
      expect(result.code, `${result.stderr}\n${result.stdout}`).toBe(0);
      const events = result.stdout.split("\n").filter(Boolean).map(line => JSON.parse(line) as {
        type?: string; item?: { type?: string; text?: string }
      });
      expect(events.some(event => event.type === "item.completed" &&
        event.item?.type === "agent_message" && event.item.text === "HELLO")).toBe(true);
      expect(upstreamCalls).toBeGreaterThan(0);
      expect(upstreamPath).toBe("POST /v1/responses");
      expect(upstreamAuth).toBe(`Bearer ${brokerCredential}`);
      expect(upstreamBody).not.toContain("synthetic-client-placeholder");
      stop();
      stop = undefined;
      await relay.close();
      relay = undefined;
      expect((await store.getRequest(request.id)).state).toBe("executed");
    } finally {
      stop?.();
      for (const socket of bridgeSockets) socket.destroy();
      if (bridge) await new Promise<void>(resolve => bridge!.close(() => resolve()));
      await relay?.close();
      upstream?.closeAllConnections();
      if (upstream) await new Promise<void>(resolve => upstream!.close(() => resolve()));
      delete process.env.SGW_MASTER_PASSPHRASE;
      delete process.env.SGW_RECOVERY_HOME;
      delete process.env.SGW_DISABLE_KEYCHAIN;
      delete process.env.SGW_DISABLE_ONEPASSWORD_BACKUP;
      await rm(root, { recursive: true, force: true });
    }
  }, 40_000
);
