import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmdirSync, writeFileSync } from "node:fs";
import path from "node:path";

const attachments = new Map<number, string>();

export function linuxCgroupRequired(): boolean {
  return process.platform === "linux" && process.env.SGW_ALLOW_NO_CGROUP !== "1";
}

export function attachLinuxCgroup(pid: number, root = writableCgroupRoot()): string | undefined {
  if (process.platform !== "linux" || !pid) {
    return undefined;
  }
  if (!root) {
    if (linuxCgroupRequired()) {
      throw new Error("Linux child isolation requires a writable cgroup v2. Set SGW_ALLOW_NO_CGROUP=1 only for tests.");
    }
    return undefined;
  }
  const dir = mkdtempSync(path.join(root, "sgw-XXXXXX"));
  try {
    writeFileSync(path.join(dir, "cgroup.procs"), String(pid));
  } catch (error) {
    removeEmptyCgroup(dir);
    throw error;
  }
  attachments.set(pid, dir);
  return dir;
}

export function killLinuxCgroup(pid: number): void {
  const dir = attachments.get(pid);
  if (!dir) {
    return;
  }
  try {
    writeFileSync(path.join(dir, "cgroup.kill"), "1");
  } catch {
    // The cgroup may already be empty.
  }
  removeEmptyCgroup(dir);
  attachments.delete(pid);
}

export function releaseLinuxCgroup(pid: number): void {
  const dir = attachments.get(pid);
  if (!dir) return;
  removeEmptyCgroup(dir, 100, false, () => {
    if (attachments.get(pid) === dir) attachments.delete(pid);
  });
}

function removeEmptyCgroup(dir: string, retries = 8, keepAlive = true, removed?: () => void): void {
  try {
    removeCgroupDirectories(dir);
    removed?.();
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT") removed?.();
    if (["EBUSY", "ENOTEMPTY"].includes(code || "") && retries > 0) {
      const timer = setTimeout(() => removeEmptyCgroup(dir, retries - 1, keepAlive, removed), 50);
      if (!keepAlive) timer.unref();
    }
  }
}

function removeCgroupDirectories(dir: string): void {
  // Kernel control files disappear with rmdir; they cannot be unlinked recursively.
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) removeCgroupDirectories(path.join(dir, entry.name));
  }
  rmdirSync(dir);
}

export function writableCgroupRoot(): string | undefined {
  if (process.platform !== "linux") {
    return undefined;
  }
  try {
    const controllers = readFileSync("/sys/fs/cgroup/cgroup.controllers", "utf8");
    if (!controllers.trim()) {
      return undefined;
    }
  } catch {
    return undefined;
  }
  const self = readSelfCgroup();
  const candidates = [
    self,
    `/sys/fs/cgroup/user.slice/user-${process.getuid?.() ?? 0}.slice`,
    "/sys/fs/cgroup"
  ].filter((item): item is string => Boolean(item));
  for (const candidate of candidates) {
    if (canCreateCgroup(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

function readSelfCgroup(): string | undefined {
  try {
    const line = readFileSync("/proc/self/cgroup", "utf8").split("\n").find((item) => item.startsWith("0::"));
    if (!line) {
      return undefined;
    }
    return path.join("/sys/fs/cgroup", line.slice(3).replace(/^\//, ""));
  } catch {
    return undefined;
  }
}

function canCreateCgroup(dir: string): boolean {
  try {
    const probe = path.join(dir, `.sgw-probe-${process.pid}`);
    mkdirSync(probe);
    rmdirSync(probe);
    return true;
  } catch {
    return false;
  }
}
