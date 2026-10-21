import { spawn } from "node:child_process";
import { chmod, chown, lstat, readFile, realpath } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { principalForVerifiedPeer, type VerifiedAgentPrincipal } from "./agent-context.js";
import { checkLinuxActivatedSocket } from "./linux-activated-socket.js";
import { checkLinuxPeerVerifier, verifyLinuxPeerProcess } from "./linux-peer-identity.js";
import { assertNoMacAclAllow } from "./macos-path-acl.js";

export interface UnixPeer {
  uid: number;
  gid: number;
  pid?: number;
}

export interface PeerSession {
  uid: number;
  gid?: number;
  sessionId: string;
  name: string;
  linuxCgroup?: string;
}

interface LiveSession extends PeerSession {
  sockets: Set<Socket>;
}

const maxSessionConnections = 8;
const maxPendingConnections = 32;
const defaultIdleTimeoutMs = 35 * 60_000;

export class PeerSessionRegistry {
  constructor(private readonly requireLinuxPeerPidfd = false) {}

  private readonly sessions = new Map<number, LiveSession>();
  private readonly usedSessionIds = new Set<string>();
  private readonly usedUids = new Set<number>();

  register(session: PeerSession): () => void {
    if (!Number.isSafeInteger(session.uid) || session.uid < 0 ||
        (session.gid !== undefined && (!Number.isSafeInteger(session.gid) || session.gid < 0))) {
      throw new Error("A managed peer needs a valid OS UID and GID.");
    }
    if ((typeof process.getuid === "function" && session.uid === process.getuid()) ||
        (typeof process.geteuid === "function" && session.uid === process.geteuid())) {
      throw new Error("A managed peer cannot use the broker's OS identity.");
    }
    if (typeof session.sessionId !== "string" || !session.sessionId.trim()) {
      throw new Error("A managed peer needs a nonempty session ID.");
    }
    if (this.sessions.has(session.uid)) throw new Error("This OS identity already has a live agent session.");
    if (this.usedUids.has(session.uid)) throw new Error("This agent OS identity cannot be reused by this broker.");
    if (this.usedSessionIds.has(session.sessionId)) throw new Error("This agent session ID was already registered.");
    principalForVerifiedPeer(principalId(session.uid), session.name, session.sessionId);
    if (process.platform === "linux" && (!session.linuxCgroup || !validCgroupPath(session.linuxCgroup))) {
      throw new Error("Linux peer sessions require an absolute cgroup v2 path.");
    }
    if (process.platform !== "linux" && session.linuxCgroup !== undefined) {
      throw new Error("A Linux cgroup cannot identify a peer on this platform.");
    }

    const live: LiveSession = { ...session, sockets: new Set() };
    this.sessions.set(session.uid, live);
    this.usedUids.add(session.uid);
    this.usedSessionIds.add(session.sessionId);
    return () => {
      if (this.sessions.get(session.uid) !== live) return;
      this.sessions.delete(session.uid);
      for (const socket of live.sockets) socket.destroy();
    };
  }

  snapshot(): Map<number, PeerSession> {
    return new Map(this.sessions);
  }

  async authenticate(peer: UnixPeer, socket: Socket, accepted: Map<number, PeerSession>): Promise<VerifiedAgentPrincipal> {
    const session = this.sessions.get(peer.uid);
    if (!session || accepted.get(peer.uid) !== session) throw new Error("Unknown or ended agent OS identity.");
    if (session.gid !== undefined && session.gid !== peer.gid) throw new Error("Agent OS group does not match the launch record.");
    if (process.platform === "linux") {
      if (this.requireLinuxPeerPidfd) {
        const live = await verifyLinuxPeerProcess(socket, session.linuxCgroup!);
        if (live.uid !== peer.uid || live.gid !== peer.gid || live.pid !== peer.pid) {
          throw new Error("Linux peer credentials changed during verification.");
        }
      } else if (!await isInCgroup(peer.pid, session.linuxCgroup!)) {
        throw new Error("Agent process is outside its registered cgroup.");
      }
    }
    if (this.sessions.get(peer.uid) !== session) throw new Error("Agent session ended during peer verification.");
    if (socket.destroyed) throw new Error("Agent socket closed during peer verification.");
    if (session.sockets.size >= maxSessionConnections) throw new Error("Agent session has too many open connections.");
    session.sockets.add(socket);
    socket.once("close", () => session.sockets.delete(socket));
    return principalForVerifiedPeer(principalId(peer.uid), session.name, session.sessionId);
  }
}

export interface VerifiedPeerServer {
  registerSession(session: PeerSession): () => void;
  assertSocketBinding(): Promise<void>;
  close(): Promise<void>;
}

export interface VerifiedPeerServerOptions {
  socketPath: string;
  socketMode?: 0o600 | 0o660;
  socketGid?: number;
  activatedFd?: number;
  idleTimeoutMs?: number;
  requireLinuxPeerPidfd?: boolean;
  onConnection(socket: Socket, principal: VerifiedAgentPrincipal, peer: UnixPeer): void | Promise<void>;
}

export async function startVerifiedPeerServer(options: VerifiedPeerServerOptions): Promise<VerifiedPeerServer> {
  if (process.platform !== "darwin" && process.platform !== "linux") {
    throw new Error("Native Unix peer verification is unavailable on this platform.");
  }
  await checkedPeerHelper(true);
  if (process.platform === "linux" && options.requireLinuxPeerPidfd) await checkLinuxPeerVerifier();
  const activated = options.activatedFd !== undefined;
  if (activated && (process.platform !== "linux" || options.socketGid === undefined || options.socketMode !== undefined)) {
    throw new Error("An activated Linux socket needs its agent GID and systemd-owned mode.");
  }
  const socketPath = activated ? options.socketPath : await checkedSocketPath(options.socketPath);
  if (activated) await checkLinuxActivatedSocket(socketPath, options.activatedFd!, options.socketGid!);
  const idleTimeoutMs = options.idleTimeoutMs ?? defaultIdleTimeoutMs;
  if (!Number.isSafeInteger(idleTimeoutMs) || idleTimeoutMs < 1 || idleTimeoutMs > 35 * 60_000) {
    throw new Error("Invalid broker connection idle deadline.");
  }
  const socketMode = options.socketMode ?? 0o600;
  if (socketMode !== 0o600 && socketMode !== 0o660) throw new Error("Invalid broker socket mode.");
  const registry = new PeerSessionRegistry(options.requireLinuxPeerPidfd === true);
  const sockets = new Set<Socket>();
  const pending = new Set<Socket>();
  const server = createServer(socket => {
    if (pending.size >= maxPendingConnections) { socket.destroy(); return; }
    socket.pause();
    socket.on("error", () => socket.destroy());
    sockets.add(socket);
    pending.add(socket);
    socket.setTimeout(idleTimeoutMs, () => socket.destroy());
    socket.once("close", () => { sockets.delete(socket); pending.delete(socket); });
    const accepted = registry.snapshot();
    void (activated ? checkLinuxActivatedSocket(socketPath, options.activatedFd!, options.socketGid!) : Promise.resolve())
      .then(() => readUnixPeer(socket)).then(async peer => {
      if (socket.destroyed) return;
      const principal = await registry.authenticate(peer, socket, accepted);
      pending.delete(socket);
      if (socket.destroyed) return;
      await options.onConnection(socket, principal, peer);
    }).catch(() => socket.destroy());
  });

  try {
    if (activated) {
      await listenFd(server, options.activatedFd!);
      await checkLinuxActivatedSocket(socketPath, options.activatedFd!, options.socketGid!);
    } else {
      await listen(server, socketPath);
      if (options.socketGid !== undefined) {
        if (!Number.isSafeInteger(options.socketGid) || options.socketGid < 0) throw new Error("Invalid broker socket GID.");
        await chown(socketPath, process.getuid!(), options.socketGid);
      }
      await chmod(socketPath, socketMode);
    }
  } catch (error) {
    await closeServer(server, sockets);
    throw error;
  }

  return {
    registerSession: session => registry.register(session),
    assertSocketBinding: () => activated
      ? checkLinuxActivatedSocket(socketPath, options.activatedFd!, options.socketGid!)
      : Promise.reject(new Error("This broker listener has no activated socket binding.")),
    close: () => closeServer(server, sockets)
  };
}

async function readUnixPeer(socket: Socket): Promise<UnixPeer> {
  const helper = await checkedPeerHelper(false);
  return new Promise((resolve, reject) => {
    const child = spawn(helper, [], { stdio: ["ignore", "pipe", "pipe", socket], env: {}, timeout: 1500 });
    let output = "";
    let failed = false;
    child.stdout!.on("data", chunk => {
      output += String(chunk);
      if (output.length > 80) { failed = true; child.kill(); }
    });
    child.once("error", reject);
    child.once("close", code => {
      if (failed || code !== 0) { reject(new Error("Could not verify Unix peer credentials.")); return; }
      const match = /^(\d+) (\d+) (\d+)\n$/.exec(output);
      if (!match) { reject(new Error("Invalid Unix peer-credential response.")); return; }
      const [uid, gid, pid] = match.slice(1).map(Number);
      if (![uid, gid, pid].every(Number.isSafeInteger)) { reject(new Error("Invalid Unix peer-credential values.")); return; }
      resolve({ uid, gid, pid: pid || undefined });
    });
  });
}

async function checkedPeerHelper(checkAcl: boolean): Promise<string> {
  const helper = fileURLToPath(new URL(`../dist/native/${process.platform}-${process.arch}/s-gw-peer-credentials`, import.meta.url));
  const stat = await lstat(helper);
  if (await realpath(helper) !== helper || !stat.isFile() || (stat.mode & 0o022) !== 0 || (stat.mode & 0o111) === 0 ||
      (stat.uid !== process.getuid!() && stat.uid !== 0)) {
    throw new Error("The Unix peer-credential helper is not a trusted executable.");
  }
  if (checkAcl) await assertNoMacAclAllow(helper);
  await checkedDirectoryChain(path.dirname(helper), checkAcl);
  return helper;
}

function principalId(uid: number): string {
  return `${process.platform}:uid:${uid}`;
}

function validCgroupPath(value: string): boolean {
  return value.startsWith("/") && value !== "/" && path.posix.normalize(value) === value && !value.includes("\0");
}

async function isInCgroup(pid: number | undefined, expected: string): Promise<boolean> {
  if (!pid || !Number.isSafeInteger(pid)) return false;
  let content: string;
  try { content = await readFile(`/proc/${pid}/cgroup`, "utf8"); }
  catch { return false; }
  const actual = content.split("\n").find(line => line.startsWith("0::/"))?.slice(3);
  return actual === expected || actual?.startsWith(`${expected}/`) === true;
}

async function checkedSocketPath(value: string): Promise<string> {
  if (!path.isAbsolute(value)) throw new Error("Broker socket path must be absolute.");
  const socketPath = path.resolve(value);
  const parent = path.dirname(socketPath);
  const info = await lstat(parent);
  if (!info.isDirectory() || info.uid !== process.getuid!() || (info.mode & 0o022) !== 0 ||
      await realpath(parent) !== parent) {
    throw new Error("Broker socket directory must be owned by the broker and not writable by agents.");
  }
  await assertNoMacAclAllow(parent);
  await checkedDirectoryChain(path.dirname(parent), true);
  try { await lstat(socketPath); throw new Error("Broker socket path already exists."); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  return socketPath;
}

async function checkedDirectoryChain(start: string, checkAcl: boolean): Promise<void> {
  let current = start;
  while (true) {
    const info = await lstat(current);
    const rootSticky = info.uid === 0 && (info.mode & 0o1000) !== 0;
    if (!info.isDirectory() || (info.uid !== 0 && info.uid !== process.getuid!()) ||
        ((info.mode & 0o022) !== 0 && !rootSticky)) {
      throw new Error("Broker executable or socket has an untrusted parent directory.");
    }
    if (checkAcl) await assertNoMacAclAllow(current);
    const next = path.dirname(current);
    if (next === current) return;
    current = next;
  }
}

function listen(server: Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => { server.off("error", reject); resolve(); });
  });
}

function listenFd(server: Server, fd: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen({ fd }, () => { server.off("error", reject); resolve(); });
  });
}

function closeServer(server: Server, sockets: Set<Socket>): Promise<void> {
  for (const socket of sockets) socket.destroy();
  return new Promise((resolve, reject) => {
    if (!server.listening) { resolve(); return; }
    server.close(error => error ? reject(error) : resolve());
  });
}
