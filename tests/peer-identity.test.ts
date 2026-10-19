import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, realpath, rm, symlink, writeFile, chmod } from "node:fs/promises";
import { createConnection, Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
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
  tmpDir = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-peer-test-")));
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
    server.registerSession(await ownSession());

    const result = JSON.parse(await connectAndRead(location, '{"uid":999999,"name":"Other"}\n'));
    expect(result.uid).toBe(process.getuid!());
    expect(result.gid).toBe(process.getgid!());
    if (process.platform === "linux") expect(result.pid).toBe(process.pid);
    expect(result.identity).toMatchObject({
      name: "Codex", source: "managed-peer", agentSessionId: "session-a",
      principalId: `${process.platform}:uid:${process.getuid!()}`
    });
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
    const stop = server.registerSession(await ownSession());
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

  it("rejects duplicate identities, stale registration, and an untrusted socket directory", async () => {
    const registry = new PeerSessionRegistry();
    const session = await ownSession();
    if (process.platform === "linux" && session.linuxCgroup === "/") session.linuxCgroup = "/synthetic.slice/agent.scope";
    const stop = registry.register(session);
    expect(() => registry.register({ ...session, sessionId: "session-b" })).toThrow("already has a live");
    expect(() => registry.register({ ...session, uid: session.uid + 1 })).toThrow("already registered");
    const snapshot = registry.snapshot();
    await expect(registry.authenticate({ uid: session.uid, gid: session.gid! + 1 }, new Socket(), snapshot))
      .rejects.toThrow("group does not match");
    stop();
    registry.register({ ...session, sessionId: "session-b" });
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

  it("requires a connected Unix socket on the native helper's fd 3", () => {
    const helper = fileURLToPath(new URL(`../dist/native/${process.platform}-${process.arch}/s-gw-peer-credentials`, import.meta.url));
    const result = spawnSync(helper, [], { encoding: "utf8" });
    expect(result.status).not.toBe(0);
    expect(result.stdout).toBe("");
  });

  it.skipIf(process.platform !== "linux")("rejects a peer outside the registered Linux cgroup", async () => {
    const registry = new PeerSessionRegistry();
    registry.register({ uid: process.getuid!(), gid: process.getgid!(), name: "Codex",
      sessionId: "cgroup-test", linuxCgroup: "/synthetic.scope" });
    await expect(registry.authenticate({ uid: process.getuid!(), gid: process.getgid!(), pid: process.pid },
      new Socket(), registry.snapshot())).rejects.toThrow("outside its registered cgroup");
  });
});
