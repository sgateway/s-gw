import { spawn } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { type Socket } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface LinuxPeerProcess {
  uid: number;
  gid: number;
  pid: number;
}

export class LinuxPeerPidfdUnavailableError extends Error {
  constructor() { super("This Linux kernel does not support SO_PEERPIDFD."); }
}

export function validLinuxCgroupPath(value: string): boolean {
  return typeof value === "string" && value.startsWith("/") && value !== "/" &&
    path.posix.normalize(value) === value && !value.endsWith("/") && !value.includes("\0");
}

export async function checkLinuxPeerVerifier(): Promise<void> {
  if (process.platform !== "linux") throw new Error("Linux peer-process verification is unavailable on this platform.");
  await checkedHelper();
}

export async function verifyLinuxPeerProcess(socket: Socket, expectedCgroup: string): Promise<LinuxPeerProcess> {
  if (process.platform !== "linux") throw new Error("Linux peer-process verification is unavailable on this platform.");
  if (!validLinuxCgroupPath(expectedCgroup)) throw new Error("A registered Linux cgroup v2 path is required.");
  if (socket.destroyed) throw new Error("Agent socket closed before peer-process verification.");
  const helper = await checkedHelper();
  return new Promise((resolve, reject) => {
    const child = spawn(helper, [expectedCgroup], {
      stdio: ["ignore", "pipe", "ignore", socket], env: {}, timeout: 1500
    });
    let output = "";
    let tooLong = false;
    child.stdout!.on("data", chunk => {
      output += String(chunk);
      if (output.length > 80) { tooLong = true; child.kill(); }
    });
    child.once("error", reject);
    child.once("close", code => {
      if (code === 2) { reject(new LinuxPeerPidfdUnavailableError()); return; }
      if (tooLong || code !== 0) { reject(new Error("Could not verify live Linux peer in its cgroup.")); return; }
      const match = /^(\d+) (\d+) (\d+)\n$/.exec(output);
      if (!match) { reject(new Error("Invalid Linux peer-process response.")); return; }
      const [uid, gid, pid] = match.slice(1).map(Number);
      if (![uid, gid, pid].every(Number.isSafeInteger) || pid < 1) {
        reject(new Error("Invalid Linux peer-process values."));
        return;
      }
      resolve({ uid, gid, pid });
    });
  });
}

async function checkedHelper(): Promise<string> {
  const helper = fileURLToPath(new URL(`../dist/native/linux-${process.arch}/s-gw-linux-peer-identity`, import.meta.url));
  const info = await lstat(helper);
  const brokerUid = process.geteuid!();
  if (await realpath(helper) !== helper || !info.isFile() || (info.mode & 0o022) !== 0 ||
      (info.mode & 0o111) === 0 || (info.uid !== brokerUid && info.uid !== 0)) {
    throw new Error("The Linux peer-process verifier is not a trusted executable.");
  }
  let parent = path.dirname(helper);
  while (true) {
    const stat = await lstat(parent);
    const rootSticky = stat.uid === 0 && (stat.mode & 0o1000) !== 0;
    if (!stat.isDirectory() || (stat.uid !== 0 && stat.uid !== brokerUid) ||
        ((stat.mode & 0o022) !== 0 && !rootSticky)) {
      throw new Error("The Linux peer-process verifier has an untrusted parent directory.");
    }
    const next = path.dirname(parent);
    if (next === parent) return helper;
    parent = next;
  }
}
