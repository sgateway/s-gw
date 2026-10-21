#!/usr/bin/env node
import { spawn } from "node:child_process";
import { chmod, chown, lstat, readFile, realpath, unlink } from "node:fs/promises";
import { createConnection, createServer, type Socket } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { lifecyclePlanKey, SystemdRunAgentUnitManager, validateLinuxAgentPlan,
  type LinuxAgentUnitManager, type LinuxAgentUnitPlan, type LinuxAgentUnitState } from "./linux-agent-unit.js";

const controlSocket = "/run/s-gw/agent-control.sock";
const runtimeDir = path.dirname(fileURLToPath(import.meta.url));
const rootPeerHelper = path.join(path.dirname(runtimeDir), "peer-credentials");
const maxFrame = 32 * 1024;

type Method = "start" | "inspect" | "release" | "stop";
interface ControlCall {
  id: number;
  method: Method;
  plan: LinuxAgentUnitPlan;
  state?: LinuxAgentUnitState;
}

export function validateLinuxManagedPlan(plan: LinuxAgentUnitPlan, brokerUid: number, brokerGid: number): void {
  validateLinuxAgentPlan(plan);
  if (!Number.isSafeInteger(brokerUid) || brokerUid < 1 ||
      !Number.isSafeInteger(brokerGid) || brokerGid < 1 ||
      plan.brokerUid !== brokerUid || plan.uid === brokerUid || plan.gid === brokerGid ||
      plan.launchGate !== true || plan.activatedSocket !== true ||
      plan.isolatedSharedMemory !== true || plan.serializedLifecycle !== true ||
      plan.sealedStdio !== true || plan.supervisedControlUnit !== true) {
    throw new Error("Managed Linux MCP needs the dedicated, supervised agent profile.");
  }
}

async function checkedRootFile(filename: string): Promise<void> {
  const value = await lstat(filename);
  if (!value.isFile() || value.uid !== 0 || (value.mode & 0o022) !== 0 ||
      await realpath(filename) !== filename) {
    throw new Error(`Untrusted privileged Linux file: ${filename}`);
  }
  let parent = path.dirname(filename);
  while (true) {
    const info = await lstat(parent);
    if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0 ||
        await realpath(parent) !== parent) {
      throw new Error(`Untrusted privileged Linux parent: ${parent}`);
    }
    const next = path.dirname(parent);
    if (next === parent) return;
    parent = next;
  }
}

async function checkedRootRuntime(): Promise<void> {
  if (process.platform !== "linux" || process.geteuid?.() !== 0 || process.getuid?.() !== 0) {
    throw new Error("The Linux agent control service must run as root.");
  }
  const cgroup = await readFile("/proc/self/cgroup", "utf8");
  if (!cgroup.split("\n").includes("0::/system.slice/s-gw-agent-control.service")) {
    throw new Error("The Linux agent control service needs its systemd unit.");
  }
  for (const filename of [fileURLToPath(import.meta.url), path.join(runtimeDir, "linux-agent-unit.js"),
    path.join(runtimeDir, "linux-peer-identity.js"), path.join(runtimeDir, "package.json"),
    rootPeerHelper, await realpath(process.execPath)]) {
    await checkedRootFile(filename);
  }
  const parent = await lstat(path.dirname(controlSocket));
  if (!parent.isDirectory() || parent.uid !== 0 || (parent.mode & 0o022) !== 0) {
    throw new Error("The Linux control socket directory must be root-owned.");
  }
}

async function readPeer(socket: Socket, helper: string): Promise<{ uid: number; gid: number; pid: number }> {
  return new Promise((resolve, reject) => {
    const child = spawn(helper, [], { stdio: ["ignore", "pipe", "ignore", socket], env: {}, timeout: 1500 });
    let output = "";
    child.stdout!.on("data", chunk => {
      output += String(chunk);
      if (output.length > 80) child.kill();
    });
    child.once("error", reject);
    child.once("close", code => {
      const match = /^(\d+) (\d+) (\d+)\n$/.exec(output);
      if (code !== 0 || !match) { reject(new Error("Could not verify Linux control peer.")); return; }
      const [uid, gid, pid] = match.slice(1).map(Number);
      if (![uid, gid, pid].every(Number.isSafeInteger) || pid < 1) {
        reject(new Error("Invalid Linux control peer."));
        return;
      }
      resolve({ uid, gid, pid });
    });
  });
}

function readFrames(socket: Socket, onFrame: (value: unknown) => void): void {
  let pending = Buffer.alloc(0);
  socket.on("data", chunk => {
    pending = Buffer.concat([pending, chunk]);
    if (pending.length > maxFrame * 2) { socket.destroy(); return; }
    while (true) {
      const end = pending.indexOf(10);
      if (end < 0) break;
      if (end > maxFrame) { socket.destroy(); return; }
      let value: unknown;
      try { value = JSON.parse(pending.subarray(0, end).toString("utf8")); }
      catch { socket.destroy(); return; }
      pending = pending.subarray(end + 1);
      onFrame(value);
    }
  });
}

function sendFrame(socket: Socket, value: unknown): void {
  const frame = JSON.stringify(value) + "\n";
  if (Buffer.byteLength(frame) > maxFrame) throw new Error("Linux control response is too large.");
  socket.write(frame);
}

function controlCall(value: unknown): ControlCall {
  if (!value || typeof value !== "object") throw new Error("Invalid Linux control call.");
  const call = value as ControlCall;
  if (!Number.isSafeInteger(call.id) || call.id < 1 ||
      !["start", "inspect", "release", "stop"].includes(call.method) || !call.plan) {
    throw new Error("Invalid Linux control call.");
  }
  return call;
}

export interface LinuxAgentControlService {
  close(): Promise<void>;
}

export async function startLinuxAgentControlService(brokerUid: number, brokerGid: number): Promise<LinuxAgentControlService> {
  await checkedRootRuntime();
  if (!Number.isSafeInteger(brokerUid) || brokerUid < 1 ||
      !Number.isSafeInteger(brokerGid) || brokerGid < 1) {
    throw new Error("A dedicated broker UID and GID are required.");
  }
  const manager = new SystemdRunAgentUnitManager();
  let owner: Socket | undefined;
  let draining = false;
  let cleanup = Promise.resolve();
  const plans = new Map<string, LinuxAgentUnitPlan>();
  const server = createServer(socket => {
    socket.pause();
    socket.on("error", () => socket.destroy());
    void readPeer(socket, rootPeerHelper).then(peer => {
      if (socket.destroyed || owner || draining || peer.uid !== brokerUid || peer.gid !== brokerGid) {
        socket.destroy();
        return;
      }
      owner = socket;
      let queued = 0;
      let chain = Promise.resolve();
      readFrames(socket, raw => {
        if (++queued > 8) { socket.destroy(); return; }
        chain = chain.then(async () => {
          const call = controlCall(raw);
          validateLinuxManagedPlan(call.plan, brokerUid, brokerGid);
          const old = plans.get(call.plan.sessionId);
          if (call.method === "start") {
            if (old) throw new Error("This Linux agent session was already launched.");
            plans.set(call.plan.sessionId, call.plan);
            await manager.start(call.plan);
            return undefined;
          }
          if (!old || lifecyclePlanKey(old) !== lifecyclePlanKey(call.plan)) {
            throw new Error("Linux control plan changed after launch.");
          }
          if (call.method === "inspect") return manager.inspect(old);
          if (call.method === "release") {
            if (!call.state) throw new Error("Linux gate release needs its attested unit state.");
            await manager.release!(old, call.state);
          } else {
            await manager.stop(old);
            plans.delete(call.plan.sessionId);
          }
          return undefined;
        }).then(value => {
          const id = (raw as ControlCall)?.id;
          if (!socket.destroyed) sendFrame(socket, { id, ok: true, value });
        }).catch(error => {
          const id = (raw as ControlCall)?.id;
          if (!socket.destroyed) sendFrame(socket, { id, ok: false, error: String(error) });
        }).finally(() => { queued--; });
      });
      socket.once("close", () => {
        if (owner !== socket) return;
        owner = undefined;
        draining = true;
        cleanup = chain.then(async () => {
          for (const plan of [...plans.values()].reverse()) {
            await manager.stop(plan);
            plans.delete(plan.sessionId);
          }
          draining = false;
        }).catch(error => {
          process.stderr.write(`Linux control teardown failed: ${String(error)}\n`);
          process.exit(1);
        });
      });
      socket.resume();
    }).catch(() => socket.destroy());
  });
  const oldMask = process.umask(0o117);
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(controlSocket, () => { server.off("error", reject); resolve(); });
    });
  } finally { process.umask(oldMask); }
  await chown(controlSocket, 0, brokerGid);
  await chmod(controlSocket, 0o660);
  const node = await lstat(controlSocket);
  return {
    async close() {
      if (owner) {
        const socket = owner;
        const ended = new Promise<void>(resolve => socket.once("close", resolve));
        socket.destroy();
        await ended;
      }
      await cleanup;
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
      try {
        const current = await lstat(controlSocket);
        if (current.dev !== node.dev || current.ino !== node.ino) {
          throw new Error("Linux control socket changed before cleanup.");
        }
        await unlink(controlSocket);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
  };
}

export interface LinuxAgentControlClient extends LinuxAgentUnitManager {
  signal: AbortSignal;
  close(): Promise<void>;
}

export async function connectLinuxAgentControl(brokerGid: number): Promise<LinuxAgentControlClient> {
  if (process.platform !== "linux" || process.geteuid?.() === 0 ||
      process.getgid?.() !== brokerGid) {
    throw new Error("A separate Linux broker identity is required.");
  }
  const node = await lstat(controlSocket);
  if (!node.isSocket() || node.uid !== 0 || node.gid !== brokerGid ||
      (node.mode & 0o777) !== 0o660) {
    throw new Error("Linux root control socket ownership changed.");
  }
  const helper = fileURLToPath(new URL(`../dist/native/linux-${process.arch}/s-gw-peer-credentials`, import.meta.url));
  const binary = await lstat(helper);
  if (!binary.isFile() || (binary.uid !== process.getuid?.() && binary.uid !== 0) ||
      (binary.mode & 0o022) !== 0 || await realpath(helper) !== helper) {
    throw new Error("Untrusted Linux broker peer helper.");
  }
  let parent = path.dirname(helper);
  while (true) {
    const info = await lstat(parent);
    const stickyRoot = info.uid === 0 && (info.mode & 0o1000) !== 0;
    if (!info.isDirectory() || (info.uid !== 0 && info.uid !== process.getuid?.()) ||
        ((info.mode & 0o022) !== 0 && !stickyRoot)) {
      throw new Error("Untrusted Linux broker peer-helper parent.");
    }
    const next = path.dirname(parent);
    if (next === parent) break;
    parent = next;
  }
  const socket = createConnection(controlSocket);
  await new Promise<void>((resolve, reject) => {
    socket.once("connect", resolve);
    socket.once("error", reject);
  });
  socket.pause();
  try {
    const peer = await readPeer(socket, helper);
    if (peer.uid !== 0 || peer.gid !== 0) throw new Error("Linux control server is not root.");
  } catch (error) { socket.destroy(); throw error; }
  let nextId = 0;
  const lost = new AbortController();
  let pending: { id: number; resolve(value: unknown): void; reject(error: Error): void } | undefined;
  readFrames(socket, raw => {
    const reply = raw as { id?: number; ok?: boolean; value?: unknown; error?: string };
    if (!pending || reply.id !== pending.id || typeof reply.ok !== "boolean") {
      socket.destroy();
      return;
    }
    const current = pending;
    pending = undefined;
    if (reply.ok) current.resolve(reply.value);
    else current.reject(new Error(reply.error || "Linux control request failed."));
  });
  socket.once("close", () => {
    lost.abort();
    pending?.reject(new Error("Linux root control service disconnected."));
    pending = undefined;
  });
  socket.resume();
  const call = async (method: Method, plan: LinuxAgentUnitPlan, state?: LinuxAgentUnitState): Promise<unknown> => {
    if (socket.destroyed || pending) throw new Error("Linux root control service is unavailable or busy.");
    const id = ++nextId;
    return new Promise((resolve, reject) => {
      pending = { id, resolve, reject };
      try { sendFrame(socket, { id, method, plan, state }); }
      catch (error) { pending = undefined; reject(error as Error); }
    });
  };
  return {
    signal: lost.signal,
    start: async plan => { await call("start", plan); },
    inspect: async plan => await call("inspect", plan) as LinuxAgentUnitState,
    release: async (plan, state) => { await call("release", plan, state); },
    stop: async plan => { await call("stop", plan); },
    close: async () => {
      if (socket.destroyed) return;
      socket.end();
      await new Promise<void>(resolve => socket.once("close", resolve));
    }
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 5 || process.argv[2] !== "--serve") {
    throw new Error("Usage: linux-agent-control --serve <broker-uid> <broker-gid>");
  }
  const brokerUid = Number(process.argv[3]);
  const brokerGid = Number(process.argv[4]);
  const service = await startLinuxAgentControlService(brokerUid, brokerGid);
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(signal, () => {
      void service.close().then(() => { process.exitCode = 0; }, error => {
        process.stderr.write(`${String(error)}\n`);
        process.exitCode = 1;
      });
    });
  }
}
