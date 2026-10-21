import { constants } from "node:fs";
import { lstat, open, readFile, readlink } from "node:fs/promises";
import { createServer, Socket, type Server } from "node:net";
import path from "node:path";

const attestationPath = "/run/s-gw/launch-gate/forwarder-attestation.json";
const brokerSocketPath = "/run/s-gw/broker.sock";
const maxConnections = 8;

export interface LinuxForwarderAttestation {
  version: 1;
  sessionId: string;
  uid: number;
  gid: number;
  brokerUid: number;
  brokerSocketOwnerUid: number;
  cgroup: string;
  networkNamespace: string;
  hostNetworkNamespace: string;
  invocationId: string;
  mainPid: number;
  brokerSocketDevice: string;
  brokerSocketInode: string;
}

export interface LinuxForwarderSnapshot {
  uid: number;
  gid: number;
  status: string;
  cgroup: string;
  networkNamespace: string;
  mountinfo: string;
  brokerSocketOwnerUid: number;
  brokerSocketDevice: string;
  brokerSocketInode: string;
}

export interface AgentLocalModelForwarder {
  address: string;
  close(): Promise<void>;
}

export function checkLinuxForwarderBoundary(raw: unknown, state: LinuxForwarderSnapshot): LinuxForwarderAttestation {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("Missing Linux forwarder attestation.");
  const proof = raw as LinuxForwarderAttestation;
  if (proof.version !== 1 || !/^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(proof.sessionId) ||
      !Number.isSafeInteger(proof.uid) || proof.uid < 1 || !Number.isSafeInteger(proof.gid) || proof.gid < 1 ||
      !Number.isSafeInteger(proof.brokerUid) || proof.brokerUid < 1 || proof.brokerUid === proof.uid ||
      (proof.brokerSocketOwnerUid !== 0 && proof.brokerSocketOwnerUid !== proof.brokerUid) ||
      proof.cgroup !== `/system.slice/s-gw-agent-${proof.sessionId}.service` ||
      !/^net:\[\d+\]$/.test(proof.networkNamespace) ||
      !/^net:\[\d+\]$/.test(proof.hostNetworkNamespace) ||
      proof.networkNamespace === proof.hostNetworkNamespace ||
      !/^[a-f0-9]{32}$/.test(proof.invocationId) ||
      !Number.isSafeInteger(proof.mainPid) || proof.mainPid < 1 ||
      !/^[0-9]+$/.test(proof.brokerSocketDevice) || !/^[0-9]+$/.test(proof.brokerSocketInode)) {
    throw new Error("Invalid Linux forwarder attestation.");
  }
  const ids = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(state.status);
  const gids = /^Gid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(state.status);
  const groups = /^Groups:[ \t]*([0-9 \t]*)$/m.exec(state.status)?.[1].trim();
  const noCapabilities = ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"].every(name => {
    const value = new RegExp(`^${name}:\\s+([0-9a-fA-F]+)$`, "m").exec(state.status)?.[1];
    return Boolean(value && /^0+$/.test(value));
  });
  const actualCgroup = state.cgroup.split("\n").find(line => line.startsWith("0::"))?.slice(3);
  const readOnlyGate = state.mountinfo.split("\n").some(line => {
    const fields = line.split(" ");
    return fields[4] === "/run/s-gw/launch-gate" && fields[5]?.split(",").includes("ro");
  });
  if (state.uid !== proof.uid || state.gid !== proof.gid ||
      !ids || ids.slice(1).some(value => Number(value) !== proof.uid) ||
      !gids || gids.slice(1).some(value => Number(value) !== proof.gid) ||
      (groups !== "" && groups !== String(proof.gid)) || !noCapabilities ||
      !/^NoNewPrivs:\s+1$/m.test(state.status) || !/^Seccomp:\s+2$/m.test(state.status) ||
      (actualCgroup !== proof.cgroup && !actualCgroup?.startsWith(`${proof.cgroup}/`)) ||
      state.networkNamespace !== proof.networkNamespace || !readOnlyGate ||
      state.brokerSocketOwnerUid !== proof.brokerSocketOwnerUid ||
      state.brokerSocketDevice !== proof.brokerSocketDevice ||
      state.brokerSocketInode !== proof.brokerSocketInode) {
    throw new Error("Linux forwarder is outside its attested agent boundary.");
  }
  return proof;
}

async function rootOwnedPath(filePath: string, kind: "file" | "socket"): Promise<void> {
  let current = path.dirname(filePath);
  while (true) {
    const info = await lstat(current);
    if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0) {
      throw new Error("Linux forwarder path is not controlled by the launcher.");
    }
    const next = path.dirname(current);
    if (next === current) break;
    current = next;
  }
  const info = await lstat(filePath);
  if ((kind === "file" && (!info.isFile() || info.uid !== 0 || info.nlink !== 1 ||
      (info.mode & 0o022) !== 0 || info.size < 1 || info.size > 1024)) ||
      (kind === "socket" && (!info.isSocket() || (info.mode & 0o007) !== 0))) {
    throw new Error("Linux forwarder file or broker socket is not trusted.");
  }
}

async function currentBoundary(): Promise<LinuxForwarderAttestation> {
  if (process.platform !== "linux" || !process.getuid || !process.geteuid || !process.getgid ||
      process.getuid() !== process.geteuid()) {
    throw new Error("A Linux agent UID is required for this forwarder.");
  }
  await rootOwnedPath(attestationPath, "file");
  await rootOwnedPath(brokerSocketPath, "socket");
  const proofFile = await open(attestationPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let raw: unknown;
  try {
    const info = await proofFile.stat();
    if (!info.isFile() || info.uid !== 0 || info.nlink !== 1 ||
        (info.mode & 0o022) !== 0 || info.size < 1 || info.size > 1024) {
      throw new Error("Linux forwarder attestation changed while reading.");
    }
    raw = JSON.parse(await proofFile.readFile("utf8"));
  } finally { await proofFile.close(); }
  const socket = await lstat(brokerSocketPath);
  const [status, cgroup, networkNamespace, mountinfo] = await Promise.all([
    readFile("/proc/self/status", "utf8"), readFile("/proc/self/cgroup", "utf8"),
    readlink("/proc/self/ns/net"), readFile("/proc/self/mountinfo", "utf8")
  ]);
  return checkLinuxForwarderBoundary(raw, {
    uid: process.getuid(), gid: process.getgid(), status, cgroup,
    networkNamespace, mountinfo, brokerSocketOwnerUid: socket.uid,
    brokerSocketDevice: String(socket.dev), brokerSocketInode: String(socket.ino)
  });
}

// This copies bytes only. The verified Unix listener, not an HTTP header, decides the session.
export function bridgeModelRelaySocket(client: Socket, socketPath: string): void {
  const broker = new Socket({ allowHalfOpen: true });
  const closeBoth = () => { client.destroy(); broker.destroy(); };
  client.on("error", closeBoth);
  broker.on("error", closeBoth);
  client.on("close", () => broker.destroy());
  broker.on("close", () => client.destroy());
  client.on("end", () => broker.end());
  broker.on("end", () => client.end());
  broker.connect(socketPath, () => {
    if (client.destroyed) { broker.destroy(); return; }
    client.pipe(broker, { end: false });
    broker.pipe(client, { end: false });
    client.resume();
  });
}

export async function startLinuxAgentLocalModelForwarder(port = 0): Promise<AgentLocalModelForwarder> {
  if (!Number.isSafeInteger(port) || port < 0 || port > 65535) {
    throw new Error("Invalid agent-local model port.");
  }
  const first = await currentBoundary();
  const sockets = new Set<Socket>();
  let closed = false;
  const server: Server = createServer({ allowHalfOpen: true, pauseOnConnect: true }, client => {
    if (closed || sockets.size >= maxConnections) { client.destroy(); return; }
    sockets.add(client);
    client.once("close", () => sockets.delete(client));
    void currentBoundary().then(proof => {
      if (closed || client.destroyed || JSON.stringify(proof) !== JSON.stringify(first)) {
        client.destroy();
        return;
      }
      bridgeModelRelaySocket(client, brokerSocketPath);
    }).catch(() => client.destroy());
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen({ host: "127.0.0.1", port, backlog: maxConnections }, () => {
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
    throw new Error("Agent-local model listener has no TCP address.");
  }
  const close = () => new Promise<void>((resolve, reject) => {
    if (closed) { resolve(); return; }
    closed = true;
    for (const socket of sockets) socket.destroy();
    server.close(error => error ? reject(error) : resolve());
  });
  server.on("error", () => {
    void close().catch(() => {
      process.emitWarning("Agent-local model forwarder could not close cleanly.", {
        code: "SGW_MODEL_FORWARDER"
      });
    });
  });
  return { address: `http://127.0.0.1:${address.port}`, close };
}
