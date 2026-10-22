import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:https";
import { createConnection } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { principalForVerifiedPeer } from "../src/agent-context.js";
import { executeApprovedRequest } from "../src/executor.js";
import { buildHttpRequestAction, SGW_HTTP_COMMAND } from "../src/http-action.js";
import { SGW_SSH_SESSION_COMMAND } from "../src/ssh.js";
import { SecretStore } from "../src/store.js";
import { startVerifiedMcpServer, type VerifiedMcpServer } from "../src/verified-mcp-server.js";
import type { PeerSession } from "../src/peer-identity.js";
import { httpsFixture } from "./helpers/https-fixture.js";

const unix = process.platform === "darwin" || process.platform === "linux";
const hasCompiler = spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;
const linuxCgroup = process.platform === "linux"
  ? (await readFile("/proc/self/cgroup", "utf8")).split("\n").find(line => line.startsWith("0::/"))?.slice(3)
  : undefined;
const canRegister = process.platform !== "linux" || !!linuxCgroup && linuxCgroup !== "/";
const peerScript = fileURLToPath(new URL("../scripts/build-peer-credentials.mjs", import.meta.url));
const linuxScript = fileURLToPath(new URL("../scripts/build-linux-peer-identity.mjs", import.meta.url));
const tsxCli = path.join(process.cwd(), "node_modules", "tsx", "dist", "cli.mjs");
const originalEnv = { ...process.env };
let root = "";
let socketDir = "";
let socketPath = "";
let store: SecretStore;
let server: VerifiedMcpServer | undefined;
let upstream: Server | undefined;
let client: Client | undefined;

beforeAll(() => {
  if (!unix || !hasCompiler) return;
  for (const script of [peerScript, ...(process.platform === "linux" ? [linuxScript] : [])]) {
    const build = spawnSync(process.execPath, [script], { encoding: "utf8" });
    if (build.status !== 0) throw new Error(build.stderr || build.stdout);
  }
});

beforeEach(async () => {
  if (!unix || !hasCompiler || !canRegister) return;
  root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-verified-mcp-")));
  socketDir = process.platform === "darwin"
    ? await realpath(await mkdtemp(path.join(os.homedir(), ".sgw-verified-mcp-socket-")))
    : root;
  socketPath = path.join(socketDir, "mcp.sock");
  process.env.SGW_HOME = path.join(root, "store");
  process.env.SGW_MASTER_PASSPHRASE = `synthetic-${randomUUID()}`;
  process.env.SGW_RECOVERY_HOME = path.join(root, "recovery");
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
  store = new SecretStore(path.join(root, "store"));
  await store.init();
});

afterEach(async () => {
  await client?.close().catch(() => {});
  await server?.close();
  upstream?.closeAllConnections();
  if (upstream) await new Promise<void>(resolve => upstream!.close(() => resolve()));
  client = undefined;
  server = undefined;
  upstream = undefined;
  process.env = { ...originalEnv };
  if (root) await rm(root, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  if (socketDir && socketDir !== root) await rm(socketDir, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 });
  root = "";
  socketDir = "";
});

function ownSession(): PeerSession {
  return {
    uid: process.getuid!(), gid: process.getgid!(), sessionId: "verified-mcp-fixture", name: "Codex",
    ...(process.platform === "linux" ? { linuxCgroup } : {})
  };
}

function registerOwnSession(): () => void {
  const session = ownSession();
  const brokerUid = process.getuid!();
  const fakeUid = brokerUid === 0 ? 1 : 0;
  const getuid = vi.spyOn(process, "getuid").mockReturnValue(fakeUid);
  const geteuid = vi.spyOn(process, "geteuid").mockReturnValue(fakeUid);
  try { return server!.registerSession(session); }
  finally { getuid.mockRestore(); geteuid.mockRestore(); }
}

async function connectClient(): Promise<Client> {
  const transport = new StdioClientTransport({
    command: process.execPath, args: [tsxCli, "src/mcp-peer-bridge.ts", socketPath],
    cwd: process.cwd(), stderr: "pipe"
  });
  const connected = new Client({ name: "Forged client name", version: "0.0.1" });
  await connected.connect(transport);
  client = connected;
  return connected;
}

function disconnectProbe(): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    socket.once("error", reject);
    socket.once("close", () => resolve());
  });
}

describe.skipIf(!unix || !hasCompiler || !canRegister)("verified MCP transport", () => {
  it("binds owned requests to the kernel peer and rejects ordinary and wrong-session claims", async () => {
    const tls = await httpsFixture(root);
    let received = "";
    upstream = createServer(tls, (req, res) => {
      received = String(req.headers.authorization);
      res.end("approved fixture");
    });
    await new Promise<void>(resolve => upstream!.listen(0, "127.0.0.1", resolve));
    const address = upstream.address();
    if (!address || typeof address === "string") throw new Error("Fixture port missing.");
    const url = `https://127.0.0.1:${address.port}/operation`;
    const secretValue = `synthetic-verified-value-${randomUUID()}`;
    const handle = (await store.addSecret({ name: "Verified MCP fixture", type: "api-token", value: secretValue,
      policy: { allowedCommands: [SGW_HTTP_COMMAND], allowedDestinations: [`127.0.0.1:${address.port}`] } })).handle;

    server = await startVerifiedMcpServer({ socketPath, store, http: { ca: tls.cert } });
    await disconnectProbe();
    expect(() => server!.registerSession(ownSession())).toThrow(/broker's OS identity/);
    const stop = registerOwnSession();
    const mcp = await connectClient();
    const names = (await mcp.listTools()).tools.map(tool => tool.name);
    expect(names).toEqual(["sgw_list_handles", "sgw_describe_handle", "sgw_list_ssh_routes",
      "sgw_request_ssh_session", "sgw_request_http", "sgw_execute_request"]);
    expect(names).not.toContain("sgw_scan_file");
    expect(names).not.toContain("sgw_request_ssh_transfer");
    expect(names).not.toContain("sgw_request_execution");

    const pending = await mcp.callTool({ name: "sgw_request_http", arguments: {
      handle, url, method: "GET", auth: { kind: "bearer" }
    } });
    const request = JSON.parse(pending.content[0].text).request;
    expect(request).toMatchObject({ agentName: "Codex", agentSource: "managed-peer",
      principalId: `${process.platform}:uid:${process.getuid!()}`, agentSessionId: "verified-mcp-fixture", state: "pending" });
    expect(received).toBe("");
    await store.approveRequest(request.id, { mode: "per-transaction" });
    await expect(store.claimApprovedRequest(request.id, { mcpClientName: "Codex" })).rejects.toThrow(/different verified agent/);
    const wrong = principalForVerifiedPeer(`${process.platform}:uid:99999`, "Codex", "other-session");
    await expect(store.claimApprovedRequest(request.id, { managedPrincipal: wrong })).rejects.toThrow(/different verified agent/);

    const ordinary = await store.createRequest(handle, buildHttpRequestAction({
      url, method: "GET", headers: {}, auth: { kind: "bearer" }
    }), "ordinary request", { mcpClientName: "Codex" });
    await store.approveRequest(ordinary.id, { mode: "per-transaction" });
    const wrongDirection = await mcp.callTool({ name: "sgw_execute_request", arguments: { requestId: ordinary.id } });
    expect(wrongDirection.isError).toBe(true);
    expect(wrongDirection.content[0].text).toContain("different verified agent");
    expect((await store.getRequest(ordinary.id)).state).toBe("approved");

    const result = await mcp.callTool({ name: "sgw_execute_request", arguments: { requestId: request.id } });
    expect(result.isError).not.toBe(true);
    const summary = JSON.parse(result.content[0].text);
    expect(summary.stdout).toContain("approved fixture");
    expect(summary.stdout).not.toContain(secretValue);
    expect(received).toBe(`Bearer ${secretValue}`);
    stop();
    await expect(mcp.listTools()).rejects.toThrow();
    await disconnectProbe();
  }, 30_000);

  it("accepts only operator-managed SSH route requests on the verified endpoint", async () => {
    const handle = (await store.addSecret({ name: "Verified SSH fixture", type: "ssh-key", value: "synthetic-key",
      policy: { allowedCommands: [SGW_SSH_SESSION_COMMAND] } })).handle;
    const keyType = Buffer.from("ssh-ed25519");
    const keyBytes = Buffer.alloc(32, 7);
    const len = (size: number) => { const out = Buffer.alloc(4); out.writeUInt32BE(size); return out; };
    const hostPublicKey = `ssh-ed25519 ${Buffer.concat([
      len(keyType.length), keyType, len(keyBytes.length), keyBytes
    ]).toString("base64")}`;
    const route = await store.addManagedSshRoute({ name: "Build route", host: "build.example", user: "runner", port: 22, hostPublicKey });
    server = await startVerifiedMcpServer({ socketPath, store });
    registerOwnSession();
    const mcp = await connectClient();
    const result = await mcp.callTool({ name: "sgw_request_ssh_session", arguments: {
      handle, routeId: route.id, args: ["id"]
    } });
    const request = JSON.parse(result.content[0].text).request;
    expect(request).toMatchObject({ agentSource: "managed-peer", action: { kind: "ssh_session", owned: true } });
    expect(request.action.ssh.managedRouteId).toBe(route.id);
    const directTarget = await mcp.callTool({ name: "sgw_request_ssh_session", arguments: {
      handle, target: "attacker.example", args: ["id"]
    } });
    expect(directTarget.isError).toBe(true);
  }, 20_000);

  it("caps tool calls across one verified session", async () => {
    server = await startVerifiedMcpServer({ socketPath, store });
    registerOwnSession();
    const mcp = await connectClient();
    let entered = 0;
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    vi.spyOn(store, "listHandles").mockImplementation(async () => {
      entered++;
      await gate;
      return [];
    });
    const calls = Array.from({ length: 4 }, () => mcp.callTool({ name: "sgw_list_handles", arguments: {} }));
    try {
      for (let i = 0; i < 100 && entered < 4; i++) await new Promise(resolve => setTimeout(resolve, 10));
      expect(entered).toBe(4);
      const excess = await mcp.callTool({ name: "sgw_list_handles", arguments: {} });
      expect(excess.isError).toBe(true);
      expect(excess.content[0].text).toContain("session is busy");
      expect(entered).toBe(4);
    } finally { release(); }
    await Promise.all(calls);
    const again = await mcp.callTool({ name: "sgw_list_handles", arguments: {} });
    expect(again.isError).not.toBe(true);
  }, 20_000);

  it("does not claim an approved request after its session ends during a queued lookup", async () => {
    const handle = (await store.addSecret({ name: "Queued request", type: "api-token", value: "synthetic queued value",
      policy: { allowedCommands: [SGW_HTTP_COMMAND], allowedDestinations: ["example.test:443"] } })).handle;
    const principal = principalForVerifiedPeer(`${process.platform}:uid:${process.getuid!()}`, "Codex", "queued-session");
    const request = await store.createRequest(handle, buildHttpRequestAction({
      url: "https://example.test/", method: "GET", headers: {}, auth: { kind: "bearer" }
    }), "queued", { managedPrincipal: principal });
    await store.approveRequest(request.id, { mode: "per-transaction" });
    let entered!: () => void;
    const lookupEntered = new Promise<void>(resolve => { entered = resolve; });
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const originalGet = store.getRequest.bind(store);
    const lookup = vi.spyOn(store, "getRequest").mockImplementation(async id => {
      entered();
      await gate;
      return originalGet(id);
    });
    const claim = vi.spyOn(store, "claimApprovedRequest");
    const controller = new AbortController();
    const assertActive = () => { if (controller.signal.aborted) throw new Error("Verified agent session ended."); };
    const run = executeApprovedRequest(store, request.id, { operationsOnly: true,
      caller: { managedPrincipal: principal }, agentSession: { signal: controller.signal, assertActive } });
    await lookupEntered;
    controller.abort();
    release();
    await expect(run).rejects.toThrow("Verified agent session ended.");
    expect(claim).not.toHaveBeenCalled();
    lookup.mockRestore();
    expect((await store.getRequest(request.id)).state).toBe("approved");
  });

  it("does not create a request after revocation while its store mutation waits", async () => {
    const handle = (await store.addSecret({ name: "Queued creation", type: "api-token", value: "synthetic queued creation",
      policy: { allowedCommands: [SGW_HTTP_COMMAND], allowedDestinations: ["example.test:443"] } })).handle;
    const principal = principalForVerifiedPeer(`${process.platform}:uid:${process.getuid!()}`, "Codex", "creation-session");
    const action = buildHttpRequestAction({ url: "https://example.test/", method: "GET", headers: {}, auth: { kind: "bearer" } });
    let entered!: () => void;
    const mutationEntered = new Promise<void>(resolve => { entered = resolve; });
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    const mutable = store as unknown as { mutate<T>(update: (data: unknown) => T): Promise<T> };
    const originalMutate = mutable.mutate.bind(store);
    const delayed = vi.spyOn(mutable, "mutate").mockImplementation(async update => {
      entered();
      await gate;
      return originalMutate(update);
    });
    const controller = new AbortController();
    const assertActive = () => { if (controller.signal.aborted) throw new Error("Verified agent session ended."); };
    const create = store.createRequest(handle, action, "queued creation", { managedPrincipal: principal }, assertActive);
    await mutationEntered;
    controller.abort();
    release();
    await expect(create).rejects.toThrow("Verified agent session ended.");
    delayed.mockRestore();
    expect(await store.listRequests()).toEqual([]);
  });

  it("aborts an in-flight owned HTTPS request when the verified session ends", async () => {
    const tls = await httpsFixture(root);
    let received!: () => void;
    const requestReceived = new Promise<void>(resolve => { received = resolve; });
    let disconnected!: () => void;
    const closed = new Promise<void>(resolve => { disconnected = resolve; });
    upstream = createServer(tls, (req) => {
      req.socket.once("close", disconnected);
      received();
    });
    await new Promise<void>(resolve => upstream!.listen(0, "127.0.0.1", resolve));
    const address = upstream.address();
    if (!address || typeof address === "string") throw new Error("Fixture port missing.");
    const handle = (await store.addSecret({ name: "Interrupted HTTPS", type: "api-token", value: "synthetic interrupted value",
      policy: { allowedCommands: [SGW_HTTP_COMMAND], allowedDestinations: [`127.0.0.1:${address.port}`] } })).handle;
    const principal = principalForVerifiedPeer(`${process.platform}:uid:${process.getuid!()}`, "Codex", "interrupted-session");
    const request = await store.createRequest(handle, buildHttpRequestAction({
      url: `https://127.0.0.1:${address.port}/wait`, method: "GET", headers: {}, auth: { kind: "bearer" }
    }), "interrupt", { managedPrincipal: principal });
    await store.approveRequest(request.id, { mode: "per-transaction" });
    const controller = new AbortController();
    const assertActive = () => { if (controller.signal.aborted) throw new Error("Verified agent session ended."); };
    const run = executeApprovedRequest(store, request.id, { operationsOnly: true,
      caller: { managedPrincipal: principal }, http: { ca: tls.cert },
      agentSession: { signal: controller.signal, assertActive } });
    await requestReceived;
    controller.abort();
    await expect(run).rejects.toThrow("Verified agent session ended.");
    await closed;
    expect((await store.getRequest(request.id)).state).toBe("failed");
  }, 20_000);

  it("closes a verified MCP connection and cancels its HTTPS operation on session stop", async () => {
    const tls = await httpsFixture(root);
    let received!: () => void;
    const requestReceived = new Promise<void>(resolve => { received = resolve; });
    upstream = createServer(tls, () => { received(); });
    await new Promise<void>(resolve => upstream!.listen(0, "127.0.0.1", resolve));
    const address = upstream.address();
    if (!address || typeof address === "string") throw new Error("Fixture port missing.");
    const url = `https://127.0.0.1:${address.port}/wait`;
    const handle = (await store.addSecret({ name: "Stopped MCP", type: "api-token", value: "synthetic stopped value",
      policy: { allowedCommands: [SGW_HTTP_COMMAND], allowedDestinations: [`127.0.0.1:${address.port}`] } })).handle;
    server = await startVerifiedMcpServer({ socketPath, store, http: { ca: tls.cert } });
    const stop = registerOwnSession();
    const mcp = await connectClient();
    const pending = await mcp.callTool({ name: "sgw_request_http", arguments: {
      handle, url, method: "GET", auth: { kind: "bearer" }
    } });
    const requestId = JSON.parse(pending.content[0].text).request.id;
    await store.approveRequest(requestId, { mode: "per-transaction" });
    const execution = mcp.callTool({ name: "sgw_execute_request", arguments: { requestId } });
    await requestReceived;
    stop();
    await expect(execution).rejects.toThrow();
    let state = "";
    for (let i = 0; i < 100; i++) {
      state = (await store.getRequest(requestId)).state;
      if (state === "failed") break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    expect(state).toBe("failed");
  }, 20_000);

  it("stops an owned SSH process tree when its verified MCP session ends", async () => {
    const fakeSsh = path.join(root, "fake-ssh");
    const marker = path.join(root, "ssh-processes");
    await writeFile(fakeSsh, '#!/bin/sh\nkey=\nmarker=\nprev=\nfor item in "$@"; do\n  if [ "$prev" = "-i" ]; then key="$item"; fi\n  prev="$item"\n  marker="$item"\ndone\n/bin/cat "$key"\n/bin/sleep 30 &\nchild=$!\nprintf "%s %s\\n" "$$" "$child" > "$marker"\nwait "$child"\n', { mode: 0o755 });
    process.env.SGW_SSH_CLI = fakeSsh;
    const secretValue = `synthetic-mcp-ssh-key-${randomUUID()}`;
    const handle = (await store.addSecret({ name: "Stopped MCP SSH", type: "ssh-key", value: secretValue,
      policy: { allowedCommands: [SGW_SSH_SESSION_COMMAND] } })).handle;
    const keyType = Buffer.from("ssh-ed25519");
    const keyBytes = Buffer.alloc(32, 9);
    const len = (size: number) => { const out = Buffer.alloc(4); out.writeUInt32BE(size); return out; };
    const hostPublicKey = `ssh-ed25519 ${Buffer.concat([
      len(keyType.length), keyType, len(keyBytes.length), keyBytes
    ]).toString("base64")}`;
    const route = await store.addManagedSshRoute({ name: "Stopped MCP route", host: "build.example", user: "runner", port: 22, hostPublicKey });
    server = await startVerifiedMcpServer({ socketPath, store });
    const stop = registerOwnSession();
    const mcp = await connectClient();
    let processGroup = 0;
    let execution: Promise<unknown> | undefined;
    try {
      const pending = await mcp.callTool({ name: "sgw_request_ssh_session", arguments: {
        handle, routeId: route.id, args: [marker], timeoutMs: 30_000
      } });
      expect(JSON.stringify(pending)).not.toContain(secretValue);
      const requestId = JSON.parse(pending.content[0].text).request.id;
      await store.approveRequest(requestId, { mode: "per-transaction" });
      execution = mcp.callTool({ name: "sgw_execute_request", arguments: { requestId } });
      let childPid = 0;
      for (let i = 0; i < 200; i++) {
        const pids = (await readFile(marker, "utf8").catch(() => "")).trim().split(" ").map(Number);
        if (pids.length === 2 && pids.every(pid => pid > 0)) {
          [processGroup, childPid] = pids;
          break;
        }
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      expect(processGroup).toBeGreaterThan(0);
      expect(childPid).toBeGreaterThan(0);
      stop();
      const failure = await execution.then(() => "", error => String(error));
      expect(failure).not.toBe("");
      expect(failure).not.toContain(secretValue);

      let state = "";
      for (let i = 0; i < 100; i++) {
        state = (await store.getRequest(requestId)).state;
        if (state === "failed") break;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      expect(state).toBe("failed");
      const request = await store.getRequest(requestId);
      expect(JSON.stringify(request)).not.toContain(secretValue);
      expect(request.resultSummary).toBeUndefined();
      expect(JSON.stringify(await store.auditLog())).not.toContain(secretValue);
      expect((await readdir(store.home)).some(name => name.startsWith("ssh-credential-"))).toBe(false);

      for (let i = 0; i < 100; i++) {
        if (!await processIsRunning(processGroup) && !await processIsRunning(childPid)) break;
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      expect(await processIsRunning(processGroup)).toBe(false);
      expect(await processIsRunning(childPid)).toBe(false);
    } finally {
      stop();
      await execution?.catch(() => {});
      if (processGroup) {
        try { process.kill(-processGroup, "SIGKILL"); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error; }
      }
    }
  }, 20_000);

  it("kills an in-flight owned SSH process when the verified session ends", async () => {
    const fakeSsh = path.join(root, "fake-ssh");
    const marker = path.join(root, "ssh-pid");
    await writeFile(fakeSsh, '#!/bin/sh\nfor item in "$@"; do marker="$item"; done\nprintf "%s" "$$" > "$marker"\nexec /bin/sleep 30\n', { mode: 0o755 });
    process.env.SGW_SSH_CLI = fakeSsh;
    const handle = (await store.addSecret({ name: "Interrupted SSH", type: "ssh-key", value: "synthetic ssh key",
      policy: { allowedCommands: [SGW_SSH_SESSION_COMMAND] } })).handle;
    const keyType = Buffer.from("ssh-ed25519");
    const keyBytes = Buffer.alloc(32, 8);
    const len = (size: number) => { const out = Buffer.alloc(4); out.writeUInt32BE(size); return out; };
    const hostPublicKey = `ssh-ed25519 ${Buffer.concat([
      len(keyType.length), keyType, len(keyBytes.length), keyBytes
    ]).toString("base64")}`;
    const route = await store.addManagedSshRoute({ name: "Interrupted route", host: "build.example", user: "runner", port: 22, hostPublicKey });
    const principal = principalForVerifiedPeer(`${process.platform}:uid:${process.getuid!()}`, "Codex", "ssh-session");
    const request = await store.createManagedSshRequest(handle, route.id, {
      args: [marker], injectEnv: "SGW_SSH_PRIVATE_KEY", timeoutMs: 30_000
    }, "interrupt", { managedPrincipal: principal });
    await store.approveRequest(request.id, { mode: "per-transaction" });
    const controller = new AbortController();
    const assertActive = () => { if (controller.signal.aborted) throw new Error("Verified agent session ended."); };
    const run = executeApprovedRequest(store, request.id, { operationsOnly: true,
      caller: { managedPrincipal: principal }, agentSession: { signal: controller.signal, assertActive } });
    let pid = 0;
    for (let i = 0; i < 200; i++) {
      pid = Number(await readFile(marker, "utf8").catch(() => "0"));
      if (pid) break;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    expect(pid).toBeGreaterThan(0);
    controller.abort();
    await expect(run).rejects.toThrow("Verified agent session ended.");
    expect(() => process.kill(pid, 0)).toThrow();
    expect((await store.getRequest(request.id)).state).toBe("failed");
  }, 20_000);
});

async function processIsRunning(pid: number): Promise<boolean> {
  try { process.kill(pid, 0); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ESRCH") return false;
    throw error;
  }
  if (process.platform !== "linux") return true;
  const status = await readFile(`/proc/${pid}/status`, "utf8").catch(() => "");
  if (!status) return false;
  return !/^State:\s+[ZX]/m.test(status);
}
