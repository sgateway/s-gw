import { spawn } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import type { Socket } from "node:net";
import path from "node:path";
import type { Readable, Writable } from "node:stream";
import { fileURLToPath } from "node:url";

export interface LinuxMessageGate {
  input: Readable;
  output: Writable;
}

export async function prepareLinuxMessageListener(fd: number): Promise<void> {
  if (process.platform !== "linux" || !Number.isSafeInteger(fd) || fd < 3) {
    throw new Error("Linux MCP message gate needs an activated listener.");
  }
  const helper = await checkedHelper();
  await new Promise<void>((resolve, reject) => {
    const child = spawn(helper, ["prepare"], {
      stdio: ["ignore", "ignore", "ignore", fd], env: {}, timeout: 1500
    });
    child.once("error", reject);
    child.once("close", code => code === 0 ? resolve() :
      reject(new Error("Activated Linux MCP listener lacks per-message credentials.")));
  });
}

export async function startLinuxMessageGate(socket: Socket, uid: number, gid: number,
  cgroup: string, mode?: "http"): Promise<LinuxMessageGate> {
  if (process.platform !== "linux" || socket.destroyed || !Number.isSafeInteger(uid) || uid < 1 ||
      !Number.isSafeInteger(gid) || gid < 1 ||
      typeof cgroup !== "string" || !cgroup.startsWith("/")) {
    throw new Error("Invalid Linux MCP message-gate session.");
  }
  const helper = await checkedHelper();
  if (socket.destroyed) throw new Error("Agent socket closed before message gate started.");
  const args = ["run", String(uid), String(gid), cgroup];
  if (mode === "http") args.push("http");
  const child = spawn(helper, args, {
    stdio: ["pipe", "pipe", "ignore", socket], env: {}
  });
  socket.setTimeout(0);
  child.once("error", () => socket.destroy());
  child.once("close", () => socket.destroy());
  socket.once("close", () => child.kill());
  child.stdin!.on("error", () => socket.destroy());
  child.stdout!.on("error", () => socket.destroy());
  if (socket.destroyed) child.kill();
  return { input: child.stdout!, output: child.stdin! };
}

async function checkedHelper(): Promise<string> {
  const helper = fileURLToPath(new URL(`../dist/native/linux-${process.arch}/s-gw-linux-message-gate`, import.meta.url));
  const info = await lstat(helper);
  const brokerUid = process.geteuid!();
  if (await realpath(helper) !== helper || !info.isFile() || (info.mode & 0o022) !== 0 ||
      (info.mode & 0o111) === 0 || (info.uid !== brokerUid && info.uid !== 0)) {
    throw new Error("The Linux MCP message gate is not a trusted executable.");
  }
  let parent = path.dirname(helper);
  while (true) {
    const stat = await lstat(parent);
    const rootSticky = stat.uid === 0 && (stat.mode & 0o1000) !== 0;
    if (!stat.isDirectory() || (stat.uid !== 0 && stat.uid !== brokerUid) ||
        ((stat.mode & 0o022) !== 0 && !rootSticky)) {
      throw new Error("The Linux MCP message gate has an untrusted parent directory.");
    }
    const next = path.dirname(parent);
    if (next === parent) return helper;
    parent = next;
  }
}
