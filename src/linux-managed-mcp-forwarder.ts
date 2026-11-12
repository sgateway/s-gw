#!/usr/bin/env node
import { constants } from "node:fs";
import { lstat, open, readFile, readlink, realpath } from "node:fs/promises";
import { createServer, Socket, type Server } from "node:net";
import path from "node:path";
import { Transform } from "node:stream";
import { fileURLToPath } from "node:url";

const proofPath = "/run/s-gw/forwarder-attestation.json";
const brokerPath = "/run/s-gw/broker.sock";
const fixedPort = 43871;
const maxConnections = 8;
const maxStreamBytes = 64 * 1024 * 1024;
const idleMs = 35 * 60_000;

export interface ManagedMcpForwarderProof {
  version: 1;
  sessionId: string;
  uid: number;
  gid: number;
  agentUid: number;
  brokerUid: number;
  cgroup: string;
  networkNamespace: string;
  hostNetworkNamespace: string;
  pidNamespace: string;
  agentPidNamespace: string;
  ipcNamespace: string;
  agentIpcNamespace: string;
  mountNamespace: string;
  agentMountNamespace: string;
  brokerSocketDevice: string;
  brokerSocketInode: string;
}

export interface ManagedMcpForwarderState {
  uid: number;
  gid: number;
  status: string;
  cgroup: string;
  networkNamespace: string;
  pidNamespace: string;
  ipcNamespace: string;
  mountNamespace: string;
  brokerSocketUid: number;
  brokerSocketGid: number;
  brokerSocketMode: number;
  brokerSocketDevice: string;
  brokerSocketInode: string;
}

export function checkManagedMcpForwarderBoundary(raw: unknown,
  state: ManagedMcpForwarderState): ManagedMcpForwarderProof {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("Missing managed MCP forwarder attestation.");
  }
  const proof = raw as ManagedMcpForwarderProof;
  const name = /^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/;
  if (proof.version !== 1 || typeof proof.sessionId !== "string" || !name.test(proof.sessionId) ||
      ![proof.uid, proof.gid, proof.agentUid, proof.brokerUid].every(value =>
        Number.isSafeInteger(value) && value > 0) ||
      proof.uid === proof.agentUid || proof.uid === proof.brokerUid || proof.agentUid === proof.brokerUid ||
      proof.cgroup !== `/system.slice/s-gw-forwarder-${proof.sessionId}.service` ||
      !/^net:\[\d+\]$/.test(proof.networkNamespace) ||
      !/^net:\[\d+\]$/.test(proof.hostNetworkNamespace) ||
      proof.networkNamespace === proof.hostNetworkNamespace ||
      !/^pid:\[\d+\]$/.test(proof.pidNamespace) ||
      !/^pid:\[\d+\]$/.test(proof.agentPidNamespace) ||
      proof.pidNamespace === proof.agentPidNamespace ||
      !/^ipc:\[\d+\]$/.test(proof.ipcNamespace) ||
      !/^ipc:\[\d+\]$/.test(proof.agentIpcNamespace) ||
      proof.ipcNamespace === proof.agentIpcNamespace ||
      !/^mnt:\[\d+\]$/.test(proof.mountNamespace) ||
      !/^mnt:\[\d+\]$/.test(proof.agentMountNamespace) ||
      proof.mountNamespace === proof.agentMountNamespace ||
      !/^[0-9]+$/.test(proof.brokerSocketDevice) ||
      !/^[0-9]+$/.test(proof.brokerSocketInode)) {
    throw new Error("Invalid managed MCP forwarder attestation.");
  }
  const uids = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(state.status);
  const gids = /^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(state.status);
  const groups = /^Groups:[ \t]*([0-9 \t]*)$/m.exec(state.status)?.[1].trim();
  const noCaps = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"].every(field => {
    const value = new RegExp(`^${field}:\\s+([0-9a-fA-F]+)$`, "m").exec(state.status)?.[1];
    return Boolean(value && /^0+$/.test(value));
  });
  const cgroup = state.cgroup.split("\n").find(line => line.startsWith("0::"))?.slice(3);
  if (state.uid !== proof.uid || state.gid !== proof.gid || !uids || !gids ||
      uids.slice(1).some(value => Number(value) !== proof.uid) ||
      gids.slice(1).some(value => Number(value) !== proof.gid) ||
      (groups !== "" && groups !== String(proof.gid)) || !noCaps ||
      !/^NoNewPrivs:\s+1$/m.test(state.status) || !/^Seccomp:\s+2$/m.test(state.status) ||
      cgroup !== proof.cgroup || state.networkNamespace !== proof.networkNamespace ||
      state.pidNamespace !== proof.pidNamespace ||
      state.ipcNamespace !== proof.ipcNamespace ||
      state.mountNamespace !== proof.mountNamespace ||
      state.brokerSocketUid !== 0 || state.brokerSocketGid !== proof.gid ||
      state.brokerSocketMode !== 0o660 ||
      state.brokerSocketDevice !== proof.brokerSocketDevice ||
      state.brokerSocketInode !== proof.brokerSocketInode) {
    throw new Error("Managed MCP forwarder is outside its attested boundary.");
  }
  return proof;
}

export interface ManagedMcpForwarder {
  port: number;
  close(): Promise<void>;
}

export interface ManagedMcpForwarderOptions {
  socketPath: string;
  port: number;
  assertBoundary(): Promise<void>;
}

function byteLimit(): Transform {
  let total = 0;
  return new Transform({
    transform(chunk: Buffer, _encoding, done) {
      total += chunk.length;
      if (total > maxStreamBytes) done(new Error("Managed MCP stream limit exceeded."));
      else done(null, chunk);
    }
  });
}

export async function startManagedMcpForwarder(options: ManagedMcpForwarderOptions): Promise<ManagedMcpForwarder> {
  if (!path.isAbsolute(options.socketPath) || path.resolve(options.socketPath) !== options.socketPath ||
      !Number.isSafeInteger(options.port) || options.port < 0 || options.port > 65535) {
    throw new Error("Invalid managed MCP forwarder endpoint.");
  }
  await options.assertBoundary();
  const clients = new Set<Socket>();
  const upstreams = new Set<Socket>();
  let closed = false;
  const server: Server = createServer({ allowHalfOpen: true, pauseOnConnect: true }, client => {
    if (closed || clients.size >= maxConnections) { client.destroy(); return; }
    clients.add(client);
    client.once("close", () => clients.delete(client));
    client.on("error", () => client.destroy());
    client.setTimeout(idleMs, () => client.destroy());
    void options.assertBoundary().then(() => {
      if (closed || client.destroyed) { client.destroy(); return; }
      const broker = new Socket({ allowHalfOpen: true });
      const outbound = byteLimit(), inbound = byteLimit();
      upstreams.add(broker);
      const stop = () => { client.destroy(); broker.destroy(); outbound.destroy(); inbound.destroy(); };
      broker.once("close", () => { upstreams.delete(broker); stop(); });
      client.once("close", stop);
      broker.on("error", stop);
      outbound.on("error", stop);
      inbound.on("error", stop);
      broker.setTimeout(idleMs, stop);
      outbound.on("end", () => broker.end());
      inbound.on("end", () => client.end());
      broker.connect(options.socketPath, () => {
        if (closed || client.destroyed) { stop(); return; }
        client.pipe(outbound).pipe(broker, { end: false });
        broker.pipe(inbound).pipe(client, { end: false });
        client.resume();
      });
    }).catch(() => client.destroy());
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen({ host: "127.0.0.1", port: options.port, backlog: maxConnections }, () => {
        server.off("error", reject);
        resolve();
      });
    });
  } catch (error) {
    server.close();
    throw error;
  }
  const address = server.address();
  if (!address || typeof address === "string") {
    server.close();
    throw new Error("Managed MCP forwarder has no loopback address.");
  }
  let stopping: Promise<void> | undefined;
  const close = () => stopping ??= new Promise<void>((resolve, reject) => {
    closed = true;
    for (const client of clients) client.destroy();
    for (const broker of upstreams) broker.destroy();
    server.close(error => error ? reject(error) : resolve());
  });
  server.on("error", () => { void close().catch(() => {}); });
  return { port: address.port, close };
}

async function rootOwned(filePath: string, kind: "file" | "socket"): Promise<void> {
  let parent = path.dirname(filePath);
  while (true) {
    const item = await lstat(parent);
    const stickyRun = parent === "/run" && (item.mode & 0o7777) === 0o1777;
    if (!item.isDirectory() || item.uid !== 0 || ((item.mode & 0o022) !== 0 && !stickyRun)) {
      throw new Error("Managed MCP forwarder path is not root controlled.");
    }
    const next = path.dirname(parent);
    if (next === parent) break;
    parent = next;
  }
  const item = await lstat(filePath);
  if (kind === "file" && (!item.isFile() || item.uid !== 0 || item.nlink !== 1 ||
      (item.mode & 0o022) !== 0 || item.size < 1 || item.size > 2048)) {
    throw new Error("Managed MCP forwarder proof is not root controlled.");
  }
  if (kind === "socket" && (!item.isSocket() || item.uid !== 0 ||
      (item.mode & 0o777) !== 0o660)) {
    throw new Error("Managed MCP forwarder socket is not root controlled.");
  }
}

async function installedBoundary(): Promise<ManagedMcpForwarderProof> {
  if (process.platform !== "linux" || !process.getuid || !process.getgid ||
      !process.geteuid || process.getuid() !== process.geteuid()) {
    throw new Error("Managed MCP forwarder needs a dedicated Linux UID.");
  }
  await rootOwned(proofPath, "file");
  const file = await open(proofPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let raw: unknown;
  try {
    const item = await file.stat();
    if (!item.isFile() || item.uid !== 0 || item.nlink !== 1 || item.size < 1 || item.size > 2048) {
      throw new Error("Managed MCP forwarder proof changed during open.");
    }
    raw = JSON.parse(await file.readFile("utf8"));
  } finally { await file.close(); }
  await rootOwned(brokerPath, "socket");
  const socket = await lstat(brokerPath);
  const [status, cgroup, networkNamespace, pidNamespace, ipcNamespace, mountNamespace] = await Promise.all([
    readFile("/proc/self/status", "utf8"), readFile("/proc/self/cgroup", "utf8"),
    readlink("/proc/self/ns/net"), readlink("/proc/self/ns/pid"),
    readlink("/proc/self/ns/ipc"), readlink("/proc/self/ns/mnt")
  ]);
  return checkManagedMcpForwarderBoundary(raw, {
    uid: process.getuid(), gid: process.getgid(), status, cgroup, networkNamespace,
    pidNamespace, ipcNamespace, mountNamespace,
    brokerSocketUid: socket.uid, brokerSocketGid: socket.gid,
    brokerSocketMode: socket.mode & 0o777,
    brokerSocketDevice: String(socket.dev), brokerSocketInode: String(socket.ino)
  });
}

export async function startInstalledManagedMcpForwarder(): Promise<ManagedMcpForwarder> {
  const first = await installedBoundary();
  return startManagedMcpForwarder({
    socketPath: brokerPath, port: fixedPort,
    assertBoundary: async () => {
      const current = await installedBoundary();
      if (JSON.stringify(current) !== JSON.stringify(first)) {
        throw new Error("Managed MCP forwarder attestation changed.");
      }
    }
  });
}

const entryFile = process.argv[1] ? await realpath(process.argv[1]).catch(() => undefined) : undefined;
if (entryFile && entryFile === await realpath(fileURLToPath(import.meta.url))) {
  if (process.argv.length !== 2) {
    process.stderr.write("Managed MCP forwarder takes no agent-selected arguments.\n");
    process.exitCode = 2;
  } else {
    void startInstalledManagedMcpForwarder().catch(error => {
      process.stderr.write(`Managed MCP forwarder refused launch: ${error instanceof Error ? error.message : "unknown error"}\n`);
      process.exitCode = 1;
    });
  }
}
