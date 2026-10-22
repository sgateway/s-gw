import { spawn } from "node:child_process";
import { lstat, readFile, readlink, realpath, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const socketPrefix = "/run/s-gw/agents/";

export function systemdAgentSocketFd(sessionId: string, env: NodeJS.ProcessEnv = process.env): number {
  if (!/^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$/.test(sessionId)) {
    throw new Error("Invalid Linux agent socket session ID.");
  }
  if (env.LISTEN_PID !== String(process.pid) || !/^[1-9]\d*$/.test(env.LISTEN_FDS || "")) {
    throw new Error("No systemd socket descriptors were passed to this broker process.");
  }
  const count = Number(env.LISTEN_FDS);
  if (!Number.isSafeInteger(count) || count > 64) throw new Error("Invalid systemd socket descriptor count.");
  const names = (env.LISTEN_FDNAMES || "").split(":");
  if (names.length !== count) throw new Error("Systemd socket descriptor names do not match their count.");
  const wanted = `s-gw-agent-${sessionId}`;
  const matching = names.map((name, index) => name === wanted ? index : -1).filter(index => index !== -1);
  if (matching.length !== 1) throw new Error("Expected exactly one named systemd socket for this agent session.");
  return 3 + matching[0];
}

export function systemdManagedSocketFds(sessionId: string,
  env: NodeJS.ProcessEnv = process.env): { mcp: number; model: number } {
  const mcp = systemdAgentSocketFd(sessionId, env);
  if (env.LISTEN_FDS !== "2") {
    throw new Error("Managed model relay needs exactly two activated sockets.");
  }
  const names = (env.LISTEN_FDNAMES || "").split(":");
  const modelName = `s-gw-model-${sessionId}`;
  if (names.filter(name => name === modelName).length !== 1 ||
      names.some(name => name !== `s-gw-agent-${sessionId}` && name !== modelName)) {
    throw new Error("Managed model relay socket names do not match this agent session.");
  }
  return { mcp, model: 3 + names.indexOf(modelName) };
}

export async function checkLinuxActivatedSocket(socketPath: string, fd: number, agentGid: number): Promise<void> {
  if (process.platform !== "linux") throw new Error("Linux socket activation is unavailable on this platform.");
  if (!Number.isSafeInteger(fd) || fd < 3 || fd > 66 ||
      !Number.isSafeInteger(agentGid) || agentGid < 1 ||
      !/^\/run\/s-gw\/agents\/[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?\/(?:broker|model)\.sock$/.test(socketPath) ||
      path.posix.normalize(socketPath) !== socketPath || !socketPath.startsWith(socketPrefix)) {
    throw new Error("Invalid activated Linux agent socket plan.");
  }
  const parent = path.dirname(socketPath);
  const [socket, directory, descriptor, link, unixSockets] = await Promise.all([
    lstat(socketPath), lstat(parent), stat(`/proc/self/fd/${fd}`),
    readlink(`/proc/self/fd/${fd}`), readFile("/proc/net/unix", "utf8")
  ]);
  if (!socket.isSocket() || socket.uid !== 0 || socket.gid !== agentGid ||
      (socket.mode & 0o777) !== 0o660 || socket.nlink !== 1 ||
      !directory.isDirectory() || directory.uid !== 0 || (directory.mode & 0o777) !== 0o711 ||
      await realpath(parent) !== parent || !descriptor.isSocket()) {
    throw new Error("Activated Linux agent socket is not root owned and privately staged.");
  }
  let current = path.dirname(parent);
  while (true) {
    const info = await lstat(current);
    if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0) {
      throw new Error("Activated Linux agent socket has an untrusted parent directory.");
    }
    const next = path.dirname(current);
    if (next === current) break;
    current = next;
  }
  const inode = /^socket:\[(\d+)\]$/.exec(link)?.[1];
  if (!inode || !linuxListenerRecordMatches(unixSockets, inode, socketPath)) {
    throw new Error("Inherited descriptor is not the expected listening Unix socket.");
  }
  await verifyCurrentSocketNode(socketPath, fd);
}

async function verifyCurrentSocketNode(socketPath: string, fd: number): Promise<void> {
  const helper = await checkedHelper();
  await new Promise<void>((resolve, reject) => {
    const child = spawn(helper, [socketPath], {
      stdio: ["ignore", "ignore", "ignore", fd], env: {}, timeout: 1500
    });
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve() :
      reject(new Error("Inherited listener no longer matches the current socket node.")));
  });
}

async function checkedHelper(): Promise<string> {
  const helper = fileURLToPath(new URL(`../dist/native/linux-${process.arch}/s-gw-linux-activated-socket`, import.meta.url));
  const info = await lstat(helper);
  const brokerUid = process.geteuid!();
  if (await realpath(helper) !== helper || !info.isFile() || (info.mode & 0o022) !== 0 ||
      (info.mode & 0o111) === 0 || (info.uid !== brokerUid && info.uid !== 0)) {
    throw new Error("The Linux activated-socket verifier is not a trusted executable.");
  }
  let parent = path.dirname(helper);
  while (true) {
    const item = await lstat(parent);
    const rootSticky = item.uid === 0 && (item.mode & 0o1000) !== 0;
    if (!item.isDirectory() || (item.uid !== 0 && item.uid !== brokerUid) ||
        ((item.mode & 0o022) !== 0 && !rootSticky)) {
      throw new Error("The Linux activated-socket verifier has an untrusted parent directory.");
    }
    const next = path.dirname(parent);
    if (next === parent) return helper;
    parent = next;
  }
}

export function linuxListenerRecordMatches(table: string, inode: string, socketPath: string): boolean {
  if (!/^\d+$/.test(inode)) return false;
  for (const line of table.split("\n").slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (fields.length !== 8 || fields[5] !== "01" || fields[6] !== inode || fields[7] !== socketPath ||
        !/^[0-9a-fA-F]+:$/.test(fields[0]) || !/^[0-9a-fA-F]+$/.test(fields[3]) ||
        !/^[0-9a-fA-F]+$/.test(fields[4])) continue;
    if (Number.parseInt(fields[4], 16) === 1 && (Number.parseInt(fields[3], 16) & 0x10000) !== 0) return true;
  }
  return false;
}
