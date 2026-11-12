import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, realpath, readlink } from "node:fs/promises";
import path from "node:path";

export interface LinuxForwarderElfFile {
  sourcePath: string;
  targetPath: string;
  sha256: string;
  mode: number;
}

export interface LinuxForwarderElfClosure {
  interpreter: string;
  files: LinuxForwarderElfFile[];
}

interface ElfInfo {
  machine: string;
  endian: string;
  interpreter?: string;
  needed: string[];
}

interface TrustedFile { filename: string; mode: number; dev: number; ino: number; size: number;
  mtimeMs: number; ctimeMs: number }

const archNames: Record<string, [string, string]> = {
  x64: ["Advanced Micro Devices X86-64", "little endian"],
  arm64: ["AArch64", "little endian"]
};
const maxFiles = 64;
const maxFileBytes = 256 * 1024 * 1024;
const maxTotalBytes = 768 * 1024 * 1024;
const safeName = /^[A-Za-z0-9][A-Za-z0-9_.+@-]{0,255}$/;

function command(filename: string, args: string[], maxBuffer: number): string {
  const result = spawnSync(filename, args, {
    encoding: "utf8", timeout: 10_000, maxBuffer,
    env: { PATH: "/usr/bin:/bin", LANG: "C", LC_ALL: "C" }
  });
  if (result.error || result.status !== 0 || result.signal || typeof result.stdout !== "string") {
    throw new Error(`Linux ELF inspection failed: ${path.posix.basename(filename)}.`);
  }
  return result.stdout;
}

function systemPath(filename: string): boolean {
  return filename === "/" || filename === "/usr" ||
    ["/lib", "/lib64", "/usr/lib", "/usr/lib64"].some(root =>
      filename === root || filename.startsWith(`${root}/`));
}

function toolPath(filename: string): boolean {
  return filename === "/" || filename === "/usr" ||
    ["/bin", "/sbin", "/usr/bin", "/usr/sbin"].some(root =>
      filename === root || filename.startsWith(`${root}/`));
}

function absolutePath(filename: string): void {
  if (!filename.startsWith("/") || path.posix.normalize(filename) !== filename ||
      filename.length > 4096 || filename.includes("\0") || filename.includes("\n")) {
    throw new Error("Linux ELF path is not absolute and normalized.");
  }
}

async function trustedFile(filename: string, kind: "node" | "library" | "tool"):
  Promise<TrustedFile> {
  absolutePath(filename);
  const allowed = kind === "library" ? systemPath : kind === "tool" ? toolPath : undefined;
  if (allowed && !allowed(filename)) {
    throw new Error("Linux ELF path is outside its trusted directories.");
  }
  const root = await lstat("/");
  if (!root.isDirectory() || root.uid !== 0 || (root.mode & 0o022) !== 0) {
    throw new Error("Linux ELF path has an untrusted root directory.");
  }
  let at = "/";
  let pending = filename.split("/").filter(Boolean);
  let links = 0;
  while (pending.length > 0) {
    const part = pending.shift()!;
    if (part === "." || part === "") continue;
    if (part === "..") {
      at = path.posix.dirname(at);
      continue;
    }
    const candidate = path.posix.join(at, part);
    if (allowed && !allowed(candidate)) {
      throw new Error("Linux ELF dependency crosses an untrusted directory.");
    }
    const item = await lstat(candidate);
    if (item.uid !== 0) throw new Error("Linux ELF path is not root-owned.");
    if (item.isSymbolicLink()) {
      if (kind === "node" || ++links > 32) {
        throw new Error("Linux ELF path has an unsafe symlink.");
      }
      const link = await readlink(candidate);
      if (!link || link.includes("\0") || link.includes("\n")) {
        throw new Error("Linux ELF path has an invalid symlink.");
      }
      pending = [...link.split("/").filter(Boolean), ...pending];
      if (link.startsWith("/")) at = "/";
      continue;
    }
    if (item.isDirectory()) {
      const mode = item.mode & 0o7777;
      if ((mode & 0o022) !== 0 && !(candidate === "/run" && mode === 0o1777)) {
        throw new Error("Linux ELF path has a writable directory.");
      }
      at = candidate;
      continue;
    }
    if (!item.isFile() || pending.length > 0 || item.nlink !== 1 ||
        (item.mode & 0o6022) !== 0 || item.size <= 0 || item.size > maxFileBytes) {
      throw new Error("Linux ELF path is not a trusted regular file.");
    }
    const canonical = await realpath(filename);
    if (canonical !== candidate || (allowed && !allowed(canonical))) {
      throw new Error("Linux ELF path changed during resolution.");
    }
    if (kind === "tool" && (item.mode & 0o111) === 0) {
      throw new Error("Linux ELF inspection tool is not executable.");
    }
    return { filename: canonical, mode: item.mode & 0o777, dev: item.dev, ino: item.ino,
      size: item.size, mtimeMs: item.mtimeMs, ctimeMs: item.ctimeMs };
  }
  throw new Error("Linux ELF path is not a regular file.");
}

function parseElf(output: string): ElfInfo {
  if (!/^\s*Class:\s+ELF64\s*$/m.test(output)) {
    throw new Error("Linux forwarder requires ELF64 files.");
  }
  const machine = /^\s*Machine:\s+(.+?)\s*$/m.exec(output)?.[1];
  const endian = /^\s*Data:\s+2's complement, (little endian|big endian)\s*$/m.exec(output)?.[1];
  if (!machine || !endian) throw new Error("Linux ELF header is incomplete.");
  const interpreters = [...output.matchAll(/\[Requesting program interpreter: ([^\]\n]+)\]/g)];
  if (interpreters.length > 1) throw new Error("Linux ELF has multiple interpreters.");
  const needed: string[] = [];
  for (const line of output.split("\n")) {
    if (/\((?:RPATH|RUNPATH|AUDIT|DEPAUDIT|FILTER|AUXILIARY)\)/.test(line) ||
        /\(FLAGS_1\).*\bNODEFLIB\b/.test(line)) {
      throw new Error("Linux ELF has an unsupported loader directive.");
    }
    if (!/\(NEEDED\)/.test(line)) continue;
    const name = /Shared library: \[([^\]\n]+)\]/.exec(line)?.[1];
    if (!name || !safeName.test(name) || name === "." || name === "..") {
      throw new Error("Linux ELF has an unsafe dependency name.");
    }
    if (!needed.includes(name)) needed.push(name);
  }
  return { machine, endian, interpreter: interpreters[0]?.[1], needed };
}

function inspectElf(filename: string): ElfInfo {
  return parseElf(command("/usr/bin/readelf", ["-hW", "-lW", "-dW", "--", filename], 512 * 1024));
}

function requireArch(info: ElfInfo): void {
  const expected = archNames[process.arch];
  if (!expected || info.machine !== expected[0] || info.endian !== expected[1]) {
    throw new Error("Linux ELF machine does not match this host.");
  }
}

interface CacheEntry { abi: string; target: string }

function cacheAbi(annotations: string): "matching" | "wrong" {
  const parts = annotations.split(",").map(part => part.trim());
  if (parts[0] !== "libc6") throw new Error("Linux library cache has an unknown ABI.");
  const expected: Record<string, string[]> = {
    x64: ["x86-64"], arm64: ["AArch64"]
  };
  const known = new Set(["x86-64", "AArch64", "64bit", "RISC-V", "riscv64",
    "x32", "i386", "hard-float", "soft-float"]);
  const arch = parts[1];
  if (!expected[process.arch] || (arch && !known.has(arch)) ||
      parts.slice(2).some(part => !part.startsWith("hwcap:") && !part.startsWith("OS ABI:"))) {
    throw new Error("Linux library cache has an unknown ABI.");
  }
  return arch && expected[process.arch].includes(arch) ? "matching" : "wrong";
}

function libraryCache(): Map<string, CacheEntry[]> {
  const result = new Map<string, CacheEntry[]>();
  const output = command("/usr/sbin/ldconfig", ["-p"], 4 * 1024 * 1024);
  for (const line of output.split("\n")) {
    if (!line.includes("=>")) continue;
    const match = /^\s*(\S+)\s+\(([^)]*)\)\s+=>\s+(\S+)\s*$/.exec(line);
    if (!match || !safeName.test(match[1]) || match[1] === "." || match[1] === "..") {
      throw new Error("Linux library cache contains an invalid entry.");
    }
    const paths = result.get(match[1]) || [];
    if (!paths.some(item => item.abi === match[2] && item.target === match[3])) {
      paths.push({ abi: match[2], target: match[3] });
    }
    result.set(match[1], paths);
  }
  return result;
}

async function fileHash(file: TrustedFile): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file.filename)) hash.update(chunk);
  const after = await lstat(file.filename);
  if (!after.isFile() || after.uid !== 0 || after.dev !== file.dev || after.ino !== file.ino ||
      after.size !== file.size || after.mtimeMs !== file.mtimeMs || after.ctimeMs !== file.ctimeMs) {
    throw new Error("Linux ELF source changed during inspection.");
  }
  return hash.digest("hex");
}

export async function discoverLinuxForwarderElfClosure(nodePath: string):
  Promise<LinuxForwarderElfClosure> {
  if (process.platform !== "linux" || process.getuid?.() !== 0 || process.geteuid?.() !== 0) {
    throw new Error("Linux ELF discovery requires a root Linux operator.");
  }
  await trustedFile("/usr/bin/readelf", "tool");
  await trustedFile("/usr/sbin/ldconfig", "tool");
  const node = await trustedFile(nodePath, "node");
  const nodeInfo = inspectElf(node.filename);
  requireArch(nodeInfo);
  const interpreter = nodeInfo.interpreter;
  if (!interpreter) throw new Error("Linux Node runtime has no ELF interpreter.");
  absolutePath(interpreter);
  if (!systemPath(interpreter)) throw new Error("Linux ELF interpreter is outside system libraries.");
  const cache = libraryCache();
  const files: LinuxForwarderElfFile[] = [];
  const needed = [...nodeInfo.needed];
  const seenNames = new Set<string>();
  const targets = new Map<string, string>();
  let totalBytes = 0;

  async function addFile(targetPath: string, source: TrustedFile, info: ElfInfo): Promise<void> {
    requireArch(info);
    if (info.interpreter) throw new Error("Linux ELF library has its own interpreter.");
    const old = targets.get(targetPath);
    if (old && old !== source.filename) throw new Error("Linux ELF target resolves ambiguously.");
    if (old) return;
    totalBytes += source.size;
    if (files.length >= maxFiles || totalBytes > maxTotalBytes) {
      throw new Error("Linux ELF dependency closure is too large.");
    }
    targets.set(targetPath, source.filename);
    files.push({ sourcePath: source.filename, targetPath, sha256: await fileHash(source),
      mode: source.mode });
    for (const name of info.needed) needed.push(name);
  }

  const loader = await trustedFile(interpreter, "library");
  await addFile(interpreter, loader, inspectElf(loader.filename));
  while (needed.length > 0) {
    const name = needed.shift()!;
    if (seenNames.has(name)) continue;
    seenNames.add(name);
    const paths = cache.get(name);
    if (!paths?.length) throw new Error(`Linux ELF dependency is unavailable: ${name}`);
    let chosen: { target: string; source: TrustedFile; info: ElfInfo } | undefined;
    for (const entry of paths) {
      if (cacheAbi(entry.abi) === "wrong") continue;
      const target = entry.target;
      absolutePath(target);
      if (!systemPath(target) || path.posix.basename(target) !== name) {
        throw new Error(`Linux ELF dependency has a non-system lookup path: ${name}`);
      }
      const source = await trustedFile(target, "library");
      const info = inspectElf(source.filename);
      requireArch(info);
      if (chosen && chosen.source.filename !== source.filename) {
        throw new Error(`Linux ELF dependency is ambiguous: ${name}`);
      }
      if (!chosen) chosen = { target, source, info };
    }
    if (!chosen) throw new Error(`Linux ELF dependency has no matching ABI: ${name}`);
    await addFile(chosen.target, chosen.source, chosen.info);
  }
  return { interpreter, files };
}
