import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile, chmod } from "node:fs/promises";
import { createConnection, Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { requestAgentIdentity } from "../src/agent-context.js";
import { PeerSessionRegistry, startVerifiedPeerServer, type PeerSession } from "../src/peer-identity.js";

const unix = process.platform === "darwin" || process.platform === "linux";
const hasCompiler = spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;
const script = fileURLToPath(new URL("../scripts/build-peer-credentials.mjs", import.meta.url));
let tmpDir = "";
const servers: Array<{ close(): Promise<void> }> = [];

beforeAll(() => {
  if (!unix || !hasCompiler) return;
  const build = spawnSync(process.execPath, [script], { encoding: "utf8" });
  if (build.status !== 0) throw new Error(build.stderr || build.stdout);
});

afterEach(async () => {
  for (const server of servers.splice(0)) await server.close();
  if (tmpDir) await rm(tmpDir, { recursive: true, force: true });
  tmpDir = "";
});

async function socketPath(): Promise<string> {
  const parent = process.platform === "darwin" ? os.homedir() : os.tmpdir();
  tmpDir = await realpath(await mkdtemp(path.join(parent, ".sgw-peer-test-")));
  return path.join(tmpDir, "broker.sock");
}

async function ownSession(sessionId = "session-a"): Promise<PeerSession> {
  const base: PeerSession = { uid: process.getuid!(), gid: process.getgid!(), sessionId, name: "Codex" };
  if (process.platform === "linux") {
    const content = await readFile("/proc/self/cgroup", "utf8");
    base.linuxCgroup = content.split("\n").find(line => line.startsWith("0::/"))?.slice(3);
  }
  return base;
}

function registerOwnSession(register: (session: PeerSession) => () => void, session: PeerSession): () => void {
  // The native probe runs under the test user, so only this registration skips the broker-UID guard.
  const brokerUid = process.getuid!();
  const getuid = vi.spyOn(process, "getuid").mockReturnValue(brokerUid === 0 ? 1 : 0);
  const geteuid = vi.spyOn(process, "geteuid").mockReturnValue(brokerUid === 0 ? 1 : 0);
  try { return register(session); }
  finally { getuid.mockRestore(); geteuid.mockRestore(); }
}

function connectAndRead(location: string, body = "", allowReset = false): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(location);
    let data = "";
    socket.once("error", error => {
      if (allowReset && (error as NodeJS.ErrnoException).code === "ECONNRESET") { resolve(""); return; }
      reject(error);
    });
    socket.on("data", chunk => { data += String(chunk); });
    socket.once("close", () => resolve(data));
    socket.once("connect", () => { if (body) socket.write(body); });
  });
}

describe.skipIf(!unix || !hasCompiler)("native Unix peer identity", () => {
  it("requires a dedicated UID and a nonempty session ID", async () => {
    const registry = new PeerSessionRegistry();
    const session = await ownSession();
    expect(() => registry.register(session)).toThrow("cannot use the broker's OS identity");
    const otherUid = session.uid === 0 ? 1 : 0;
    expect(() => registry.register({ ...session, uid: otherUid, sessionId: "" })).toThrow("nonempty session ID");
    expect(() => registry.register({ ...session, uid: otherUid, sessionId: undefined as unknown as string }))
      .toThrow("nonempty session ID");
    const realUid = vi.spyOn(process, "getuid").mockReturnValue(otherUid);
    try {
      expect(() => registry.register(session)).toThrow("cannot use the broker's OS identity");
    } finally { realUid.mockRestore(); }
  });

  it("takes identity from the kernel rather than a forged request field", async () => {
    if (process.platform === "linux" && (await ownSession()).linuxCgroup === "/") return;
    const location = await socketPath();
    const server = await startVerifiedPeerServer({
      socketPath: location,
      onConnection(socket, principal, peer) {
        socket.once("data", () => {
          const identity = requestAgentIdentity("claimed by another agent", { managedPrincipal: principal, env: {} });
          socket.end(JSON.stringify({ uid: peer.uid, gid: peer.gid, pid: peer.pid, identity }));
        });
        socket.resume();
      }
    });
    servers.push(server);
    registerOwnSession(server.registerSession, await ownSession());

    const result = JSON.parse(await connectAndRead(location, '{"uid":999999,"name":"Other"}\n'));
    expect(result.uid).toBe(process.getuid!());
    expect(result.gid).toBe(process.getgid!());
    if (process.platform === "linux") expect(result.pid).toBe(process.pid);
    expect(result.identity).toMatchObject({
      name: "Codex", source: "managed-peer", agentSessionId: "session-a",
      principalId: `${process.platform}:uid:${process.getuid!()}`
    });
  });

  it.skipIf(process.platform !== "linux")("uses the generation without accepting an agent's claimed identity", async () => {
    const session = await ownSession();
    if (session.linuxCgroup === "/") return;
    const location = await socketPath();
    const first = await startVerifiedPeerServer({ socketPath: location,
      onConnection(socket, principal) {
        socket.end(JSON.stringify(requestAgentIdentity("claim", {
          managedPrincipal: principal, env: { SGW_AGENT_NAME: "Replacement" }
        })));
      }
    });
    servers.push(first);
    registerOwnSession(first.registerSession, { ...session,
      linuxIdentityGeneration: "a".repeat(32) });
    const identity = JSON.parse(await connectAndRead(location));
    expect(identity).toMatchObject({ name: "Codex", source: "managed-peer",
      principalId: `linux:managed:${"a".repeat(32)}`, agentSessionId: session.sessionId });
    expect(identity.principalId).not.toBe(`linux:uid:${session.uid}`);

    const invalid = new PeerSessionRegistry();
    expect(() => registerOwnSession(item => invalid.register(item), { ...session,
      linuxIdentityGeneration: "forged" })).toThrow("valid generation");
  });

  it("denies an unregistered peer and ends an active peer when its session ends", async () => {
    if (process.platform === "linux" && (await ownSession()).linuxCgroup === "/") return;
    const location = await socketPath();
    const accepted: Socket[] = [];
    const server = await startVerifiedPeerServer({
      socketPath: location,
      onConnection(socket) { accepted.push(socket); socket.resume(); socket.write("accepted"); }
    });
    servers.push(server);
    expect(await connectAndRead(location, "", true)).toBe("");
    const stop = registerOwnSession(server.registerSession, await ownSession());
    const connection = createConnection(location);
    let output = "";
    connection.on("data", chunk => { output += String(chunk); });
    await new Promise<void>((resolve, reject) => {
      connection.once("error", reject);
      connection.once("data", () => resolve());
    });
    expect(accepted).toHaveLength(1);
    const closed = new Promise<void>(resolve => connection.once("close", () => resolve()));
    stop();
    await closed;
    expect(accepted[0].destroyed).toBe(true);
  });

  it("caps active connections per session and frees a slot on close", async () => {
    if (process.platform === "linux" && (await ownSession()).linuxCgroup === "/") return;
    const location = await socketPath();
    const accepted: Socket[] = [];
    const server = await startVerifiedPeerServer({
      socketPath: location,
      onConnection(socket) { accepted.push(socket); socket.resume(); socket.write("accepted"); }
    });
    servers.push(server);
    registerOwnSession(server.registerSession, await ownSession());
    const clients: Socket[] = [];
    const connect = () => new Promise<Socket>((resolve, reject) => {
      const socket = createConnection(location);
      socket.once("error", reject);
      socket.once("data", () => { socket.off("error", reject); resolve(socket); });
    });
    try {
      for (let i = 0; i < 8; i++) clients.push(await connect());
      const extra = createConnection(location);
      extra.on("error", () => {});
      clients.push(extra);
      await new Promise<void>(resolve => extra.once("close", () => resolve()));
      expect(accepted).toHaveLength(8);

      const closed = new Promise<void>(resolve => accepted[0].once("close", () => resolve()));
      clients[0].destroy();
      await closed;
      clients.push(await connect());
      expect(accepted).toHaveLength(9);
    } finally {
      for (const socket of clients) socket.destroy();
    }
  });

  it("closes an authenticated connection that never starts a request", async () => {
    if (process.platform === "linux" && (await ownSession()).linuxCgroup === "/") return;
    const location = await socketPath();
    let accepted = 0;
    const server = await startVerifiedPeerServer({
      socketPath: location, idleTimeoutMs: 200,
      onConnection(socket) { accepted++; socket.resume(); }
    });
    servers.push(server);
    registerOwnSession(server.registerSession, await ownSession());
    const client = createConnection(location);
    client.on("error", () => {});
    await new Promise<void>(resolve => client.once("close", () => resolve()));
    expect(accepted).toBe(1);
  });

  it("closes a partial request after its connection goes idle", async () => {
    if (process.platform === "linux" && (await ownSession()).linuxCgroup === "/") return;
    const location = await socketPath();
    const server = await startVerifiedPeerServer({
      socketPath: location, idleTimeoutMs: 200,
      onConnection(socket) { socket.resume(); }
    });
    servers.push(server);
    registerOwnSession(server.registerSession, await ownSession());
    const client = createConnection(location);
    client.on("error", () => {});
    await new Promise<void>((resolve, reject) => { client.once("connect", resolve); client.once("error", reject); });
    client.write("{");
    await new Promise<void>(resolve => client.once("close", resolve));
  });

  it("does not retain a socket that closed during peer verification", async () => {
    const session = await ownSession();
    if (process.platform === "linux" && session.linuxCgroup === "/") return;
    const registry = new PeerSessionRegistry();
    registerOwnSession(item => registry.register(item), session);
    const closed = new Socket();
    if (process.platform === "darwin") closed.destroy();
    const auth = registry.authenticate({ uid: session.uid, gid: session.gid!, pid: process.pid },
      closed, registry.snapshot());
    closed.destroy();
    await expect(auth).rejects.toThrow("closed during peer verification");
  });

  it("rejects duplicate identities, stale registration, and an untrusted socket directory", async () => {
    const registry = new PeerSessionRegistry();
    const session = await ownSession();
    if (process.platform === "linux" && session.linuxCgroup === "/") session.linuxCgroup = "/synthetic.slice/agent.scope";
    const stop = registerOwnSession(item => registry.register(item), session);
    expect(() => registerOwnSession(item => registry.register(item),
      { ...session, sessionId: "session-b" })).toThrow("already has a live");
    expect(() => registry.register({ ...session, uid: session.uid + 1 })).toThrow("already registered");
    const snapshot = registry.snapshot();
    await expect(registry.authenticate({ uid: session.uid, gid: session.gid! + 1 }, new Socket(), snapshot))
      .rejects.toThrow("group does not match");
    stop();
    expect(() => registerOwnSession(item => registry.register(item), session)).toThrow("OS identity cannot be reused");
    expect(() => registerOwnSession(item => registry.register(item), { ...session, sessionId: "session-b" }))
      .toThrow("OS identity cannot be reused");
    await expect(registry.authenticate({ uid: session.uid, gid: session.gid! }, new Socket(), snapshot))
      .rejects.toThrow("Unknown or ended");

    const location = await socketPath();
    await chmod(tmpDir, 0o777);
    await expect(startVerifiedPeerServer({ socketPath: location, onConnection() {} }))
      .rejects.toThrow("not writable by agents");
    await chmod(tmpDir, 0o700);
    await writeFile(location, "occupied");
    await expect(startVerifiedPeerServer({ socketPath: location, onConnection() {} }))
      .rejects.toThrow("already exists");
  });

  it("rejects an unsafe socket mode supplied by a JavaScript caller", async () => {
    const location = await socketPath();
    await expect(startVerifiedPeerServer({ socketPath: location, socketMode: 0o666 as 0o600, onConnection() {} }))
      .rejects.toThrow("Invalid broker socket mode");
  });

  it("rejects a symlinked broker socket directory", async () => {
    const location = await socketPath();
    const linkPath = `${tmpDir}-link`;
    await symlink(tmpDir, linkPath);
    try {
      await expect(startVerifiedPeerServer({ socketPath: path.join(linkPath, path.basename(location)), onConnection() {} }))
        .rejects.toThrow();
    } finally {
      await rm(linkPath);
    }
  });

  it.skipIf(process.platform !== "darwin")("rejects an extended ACL grant on the broker socket directory", async () => {
    const location = await socketPath();
    const acl = spawnSync("/bin/chmod", ["+a", "everyone allow read,write,execute", tmpDir], { encoding: "utf8" });
    expect(acl.status, acl.stderr).toBe(0);
    await expect(startVerifiedPeerServer({ socketPath: location, onConnection() {} }))
      .rejects.toThrow("extended ACL allow");
  });

  it.skipIf(process.platform !== "darwin")("rejects an extended ACL grant on a broker socket ancestor", async () => {
    const location = await socketPath();
    const parent = path.join(tmpDir, "parent");
    const child = path.join(parent, "private");
    await mkdir(child, { recursive: true, mode: 0o700 });
    const acl = spawnSync("/bin/chmod", ["+a", "everyone allow read,write,execute", parent], { encoding: "utf8" });
    expect(acl.status, acl.stderr).toBe(0);
    await expect(startVerifiedPeerServer({ socketPath: path.join(child, path.basename(location)), onConnection() {} }))
      .rejects.toThrow("extended ACL allow");
  });

  it("requires a connected Unix socket on the native helper's fd 3", () => {
    const helper = fileURLToPath(new URL(`../dist/native/${process.platform}-${process.arch}/s-gw-peer-credentials`, import.meta.url));
    const result = spawnSync(helper, [], { encoding: "utf8" });
    expect(result.status).not.toBe(0);
    expect(result.stdout).toBe("");
  });

  it.skipIf(process.platform !== "linux")("rejects a peer outside the registered Linux cgroup", async () => {
    const registry = new PeerSessionRegistry();
    registerOwnSession(item => registry.register(item), { uid: process.getuid!(), gid: process.getgid!(), name: "Codex",
      sessionId: "cgroup-test", linuxCgroup: "/synthetic.scope" });
    await expect(registry.authenticate({ uid: process.getuid!(), gid: process.getgid!(), pid: process.pid },
      new Socket(), registry.snapshot())).rejects.toThrow("outside its registered cgroup");
  });
});
