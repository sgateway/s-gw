import { existsSync } from "node:fs";
import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { fileURLToPath } from "node:url";
import { attachLinuxCgroup, killLinuxCgroup, releaseLinuxCgroup, linuxCgroupRequired, writableCgroupRoot } from "./linux-cgroup.js";

const windowsJobs = new WeakMap<ChildProcess, ChildProcess>();

export function spawnIsolated(command: string, args: string[], options: SpawnOptions): ChildProcess {
  const cgroupRoot = process.platform === "linux" ? writableCgroupRoot() : undefined;
  if (linuxCgroupRequired() && !cgroupRoot) {
    throw new Error("Linux child isolation requires a writable cgroup v2. Set SGW_ALLOW_NO_CGROUP=1 only for tests.");
  }
  const child = spawn(command, args, {
    ...options,
    shell: false,
    detached: process.platform !== "win32",
    windowsHide: process.platform === "win32" ? true : options.windowsHide
  });
  if (process.platform === "win32" && child.pid) {
    attachWindowsJob(child);
  }
  if (process.platform === "linux" && child.pid && cgroupRoot) {
    try { attachLinuxCgroup(child.pid, cgroupRoot); }
    catch (error) { killProcessTree(child, "SIGKILL"); throw error; }
    child.once("close", () => releaseLinuxCgroup(child.pid!));
  }
  return child;
}

export function killProcessTree(child: ChildProcess, signal: NodeJS.Signals = "SIGTERM"): void {
  const holder = windowsJobs.get(child);
  if (holder) {
    holder.stdin?.end();
    try {
      holder.kill();
    } catch {
      // The job holder may already have exited with the child.
    }
    windowsJobs.delete(child);
  }

  if (child.pid) {
    killLinuxCgroup(child.pid);
  }

  if (!child.pid) {
    child.kill(signal);
    return;
  }

  if (process.platform === "win32") {
    spawn("taskkill", ["/PID", String(child.pid), "/T", "/F"], { stdio: "ignore" }).unref();
    return;
  }

  try {
    process.kill(-child.pid, signal);
  } catch {
    child.kill(signal);
  }
}

function attachWindowsJob(child: ChildProcess): void {
  const core = rustCoreBinary();
  if (!existsSync(core) || !child.pid) {
    return;
  }
  const holder = spawn(core, ["hold-job", String(child.pid)], {
    stdio: ["pipe", "ignore", "ignore"],
    windowsHide: true
  });
  windowsJobs.set(child, holder);
  const release = () => {
    holder.stdin?.end();
    windowsJobs.delete(child);
  };
  child.once("exit", release);
  child.once("error", release);
}

function rustCoreBinary(): string {
  const extension = process.platform === "win32" ? ".exe" : "";
  return fileURLToPath(new URL(`../dist/native/${process.platform}-${process.arch}/s-gw-core${extension}`, import.meta.url));
}
