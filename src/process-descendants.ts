import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";

// Absolute on purpose: a PATH lookup could run an attacker-planted ps.
const PS_BINARY = "/bin/ps";
const PS_TIMEOUT_MS = 1_000;

export function listDescendantPids(rootPid: number): number[] {
  if (process.platform === "win32" || !Number.isInteger(rootPid) || rootPid <= 0) {
    return [];
  }
  try {
    const parents = process.platform === "linux" ? parentsFromProc() : parentsFromPs();
    return collectDescendants(rootPid, parents);
  } catch {
    return [];
  }
}

export function signalPids(pids: number[], signal: NodeJS.Signals): void {
  for (const pid of new Set(pids)) {
    if (!Number.isInteger(pid) || pid <= 1 || pid === process.pid) {
      continue;
    }
    try {
      process.kill(pid, signal);
    } catch {
      // Already gone, or not ours to signal.
    }
  }
}

function collectDescendants(rootPid: number, parents: Map<number, number>): number[] {
  const children = new Map<number, number[]>();
  for (const [pid, ppid] of parents) {
    const siblings = children.get(ppid);
    if (siblings) siblings.push(pid);
    else children.set(ppid, [pid]);
  }

  const found: number[] = [];
  const seen = new Set<number>([rootPid]);
  const queue = [rootPid];
  while (queue.length > 0) {
    for (const pid of children.get(queue.shift()!) || []) {
      if (seen.has(pid)) continue;
      seen.add(pid);
      found.push(pid);
      queue.push(pid);
    }
  }
  return found;
}

function parentsFromProc(): Map<number, number> {
  const parents = new Map<number, number>();
  for (const entry of readdirSync("/proc")) {
    if (!/^\d+$/.test(entry)) continue;
    const ppid = procParent(entry);
    if (ppid !== undefined) parents.set(Number(entry), ppid);
  }
  return parents;
}

function procParent(entry: string): number | undefined {
  let stat = "";
  try {
    stat = readFileSync(`/proc/${entry}/stat`, "utf8");
  } catch {
    // The process exited between the directory listing and this read.
    return undefined;
  }
  // comm may itself contain spaces and parens, so only trust what follows the last ")".
  const close = stat.lastIndexOf(")");
  if (close < 0) return undefined;
  const ppid = Number(stat.slice(close + 1).trim().split(/\s+/)[1]);
  return Number.isInteger(ppid) ? ppid : undefined;
}

function parentsFromPs(): Map<number, number> {
  const listing = execFileSync(PS_BINARY, ["-axo", "pid=,ppid="], {
    encoding: "utf8",
    env: { LC_ALL: "C" },
    maxBuffer: 16 * 1024 * 1024,
    stdio: ["ignore", "pipe", "ignore"],
    timeout: PS_TIMEOUT_MS
  });
  const parents = new Map<number, number>();
  for (const line of listing.split("\n")) {
    const match = /^\s*(\d+)\s+(\d+)\s*$/.exec(line);
    if (match) parents.set(Number(match[1]), Number(match[2]));
  }
  return parents;
}
