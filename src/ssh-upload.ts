import { createHash, randomUUID } from "node:crypto";
import { constants, createWriteStream, createReadStream, open as openFd, fstat, read, close } from "node:fs";
import { lstat, realpath, open, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import { setTimeout as pause } from "node:timers/promises";
import { containsGlobChars, globToRegex, normalizePathForSandbox } from "@anthropic-ai/sandbox-runtime/dist/sandbox/sandbox-utils.js";
import { sensitiveChildPaths } from "./sandbox-paths.js";
import type { SshTransferSpec } from "./types.js";

const spoolMaxBytes = 32 * 1024 * 1024;
const spoolWaitMs = 30_000;
const spoolLifetimeMs = 60 * 60 * 1000;
const spoolSlots = 8;
const spoolIdPattern = /^slot([0-7])-([a-f0-9-]{36})$/;

export interface UploadPrepareOptions {
  pipeMode?: "path-stream" | "spooled-content-sha256";
  spoolTimeoutMs?: number;
}

interface SpoolMetadata {
  id: string;
  sourcePath: string;
  destinationPath: string;
  sha256: string;
  expiresAt: string;
}

async function readSpoolMetadata(file: string): Promise<SpoolMetadata> {
  const fd = await open(file, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
  try {
    const info = await fd.stat();
    if (!info.isFile() || info.size > 4096 || (info.mode & 0o077) ||
        (process.getuid && info.uid !== process.getuid())) {
      throw new Error("SSH upload spool metadata changed.");
    }
    return JSON.parse(await fd.readFile("utf8")) as SpoolMetadata;
  } finally { await fd.close(); }
}

export async function hashUpload(file: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

export async function prepareUpload(sourcePath: string, destinationPath: string, home: string,
  options: UploadPrepareOptions = {}): Promise<SshTransferSpec> {
  if (options.pipeMode && options.pipeMode !== "path-stream" && options.pipeMode !== "spooled-content-sha256") {
    throw new Error("Invalid SSH named-pipe approval mode.");
  }
  if (!path.isAbsolute(sourcePath) || !destinationPath || /[\x00\r\n]/.test(destinationPath)) throw new Error("SSH upload paths are required.");
  const source = normalizePathForSandbox(await realpath(sourcePath));
  const explicit: string[] = JSON.parse(process.env.SGW_SANDBOX_DENY_READ || "[]");
  const protectedPaths = sensitiveChildPaths(home);
  const uploadWorkspace = process.env.SGW_SANDBOX_UPLOAD_WORKSPACE
    ? normalizePathForSandbox(await realpath(process.env.SGW_SANDBOX_UPLOAD_WORKSPACE)) : "";
  for (const [index, file] of [...protectedPaths, ...explicit].entries()) {
    let denied = normalizePathForSandbox(path.resolve(file));
    if (containsGlobChars(denied)) {
      const prefix = denied.split(/[*?[\]]/)[0];
      const base = prefix.endsWith(path.sep) ? prefix.slice(0, -1) || path.sep : path.dirname(prefix);
      try { denied = normalizePathForSandbox(await realpath(base)) + denied.slice(base.length); }
      catch (error) { if (!["ENOENT", "ENOTDIR"].includes((error as NodeJS.ErrnoException).code || "")) throw error; }
      if (new RegExp(globToRegex(denied)).test(source)) throw new Error("SSH upload source is denied by the credential read policy.");
    } else {
      try { denied = normalizePathForSandbox(await realpath(denied)); }
      catch (error) { if (!["ENOENT", "ENOTDIR"].includes((error as NodeJS.ErrnoException).code || "")) throw error; }
      if (source !== denied && !source.startsWith(denied.endsWith(path.sep) ? denied : denied + path.sep)) continue;
      if (index >= protectedPaths.length && uploadWorkspace &&
          uploadWorkspace.startsWith(denied.endsWith(path.sep) ? denied : denied + path.sep) &&
          (source === uploadWorkspace || source.startsWith(uploadWorkspace + path.sep))) continue;
      throw new Error("SSH upload source is denied by the credential read policy.");
    }
  }
  const info = await lstat(source);
  if (!info.isFile() && !info.isFIFO()) throw new Error("SSH upload source must be a regular file or named pipe.");
  if (info.isFile()) {
    if (options.pipeMode === "spooled-content-sha256") throw new Error("Spool mode requires a named pipe.");
    return { direction: "upload", sourcePath: source, destinationPath,
      approvalScope: "content-sha256", sha256: await hashUpload(source) };
  }
  if (options.pipeMode === "spooled-content-sha256") {
    const timeout = options.spoolTimeoutMs ?? spoolWaitMs;
    if (!Number.isInteger(timeout) || timeout < 1 || timeout > spoolWaitMs) {
      throw new Error("Invalid SSH named-pipe spool timeout.");
    }
    return spoolPipe(source, destinationPath, home, timeout);
  }
  return { direction: "upload", sourcePath: source, destinationPath, approvalScope: "path-stream" };
}

export async function openApprovedUpload(transfer: SshTransferSpec, home: string) {
  if (transfer.approvalScope === "spooled-content-sha256") {
    const source = await approvedSpoolPath(transfer, home);
    const snapshot = await snapshotApprovedUpload(source, transfer.sha256!, home);
    return { stream: snapshot.stream, cleanup: async () => {
      await snapshot.cleanup();
      await rm(path.dirname(source), { recursive: true, force: true });
    } };
  }
  const current = await prepareUpload(transfer.sourcePath, transfer.destinationPath, home);
  const approvedScope = transfer.approvalScope || (transfer.sha256 ? "content-sha256" : "path-stream");
  if (current.sourcePath !== transfer.sourcePath || current.sha256 !== transfer.sha256 ||
      current.approvalScope !== approvedScope) throw new Error("SSH upload changed after approval.");
  if (!transfer.sha256) {
    const stream = approvedPipeStream(current.sourcePath);
    return { stream, cleanup: async () => {} };
  }

  return snapshotApprovedUpload(current.sourcePath, transfer.sha256, home);
}

export async function discardPreparedSpool(transfer: SshTransferSpec, home: string): Promise<void> {
  if (transfer.approvalScope !== "spooled-content-sha256") return;
  const payload = await approvedSpoolPath(transfer, home);
  await rm(path.dirname(payload), { recursive: true, force: true });
}

async function snapshotApprovedUpload(source: string, sha256: string, home: string) {
  // Keep a verified copy outside the agent's writable tree before opening the connection.
  const parent = path.join(home, "uploads");
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const dir = await mkdtemp(path.join(parent, "approved-"));
  const file = path.join(dir, "payload");
  const cleanup = () => rm(dir, { recursive: true, force: true });
  try {
    const hash = createHash("sha256");
    const digest = new Transform({ transform(chunk, _encoding, done) { hash.update(chunk); done(null, chunk); } });
    const input = await open(source, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    if (!(await input.stat()).isFile()) { await input.close(); throw new Error("SSH upload changed after approval."); }
    await pipeline(input.createReadStream(), digest,
      createWriteStream(file, { flags: "wx", mode: 0o600 }));
    if (hash.digest("hex") !== sha256) throw new Error("SSH upload changed after approval.");
    return { stream: createReadStream(file), cleanup };
  } catch (error) { await cleanup(); throw error; }
}

async function privateSpoolRoot(home: string): Promise<string> {
  const uploads = path.join(home, "uploads");
  const root = path.join(uploads, "spooled");
  await mkdir(root, { recursive: true, mode: 0o700 });
  for (const dir of [home, uploads, root]) {
    const info = await lstat(dir);
    if (!info.isDirectory() || (info.mode & 0o077) ||
        (process.getuid && info.uid !== process.getuid())) {
      throw new Error("SSH upload spool storage is not private to the broker.");
    }
  }
  return root;
}

async function allocateSpool(root: string): Promise<{ id: string; dir: string }> {
  for (let index = 0; index < spoolSlots; index++) {
    const dir = path.join(root, `slot${index}`);
    try {
      await mkdir(dir, { mode: 0o700 });
      return { id: `slot${index}-${randomUUID()}`, dir };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const info = await lstat(dir);
      if (!info.isDirectory() || (info.mode & 0o077) ||
          (process.getuid && info.uid !== process.getuid())) throw new Error("SSH upload spool storage changed.");
      if (Date.now() - info.mtimeMs < spoolLifetimeMs + spoolWaitMs) continue;
      let expiresAt = 0;
      try {
        const metadata = await readSpoolMetadata(path.join(dir, "metadata.json"));
        expiresAt = Date.parse(metadata.expiresAt);
      } catch { /* An abandoned spool has no completed metadata. */ }
      if (expiresAt && expiresAt > Date.now()) continue;
      await rm(dir, { recursive: true, force: true });
      index--;
    }
  }
  throw new Error("SSH upload spool storage is full (8 pending streams, 32 MiB each).");
}

async function spoolPipe(sourcePath: string, destinationPath: string, home: string, timeoutMs: number): Promise<SshTransferSpec> {
  const { id, dir } = await allocateSpool(await privateSpoolRoot(home));
  const payloadPath = path.join(dir, "payload");
  const hash = createHash("sha256");
  const started = performance.now();
  let total = 0;
  let sawBytes = false;
  try {
    const source = await open(sourcePath, constants.O_RDONLY | constants.O_NONBLOCK | (constants.O_NOFOLLOW || 0));
    try {
      const output = await open(payloadPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW || 0), 0o600);
      try {
        if (!(await source.stat()).isFIFO()) throw new Error("SSH named pipe changed before spooling.");
        const buffer = Buffer.allocUnsafe(64 * 1024);
        while (true) {
          if (performance.now() - started >= timeoutMs) throw new Error("SSH named-pipe spool timed out.");
          let count = 0;
          let wouldBlock = false;
          try { count = (await source.read(buffer, 0, buffer.length, null)).bytesRead; }
          catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "EAGAIN") throw error;
            wouldBlock = true;
          }
          if (count > 0) {
            if (total + count > spoolMaxBytes) throw new Error("SSH named-pipe spool exceeds 32 MiB.");
            let offset = 0;
            while (offset < count) {
              const written = (await output.write(buffer, offset, count - offset)).bytesWritten;
              if (!written) throw new Error("SSH upload spool write failed.");
              offset += written;
            }
            hash.update(buffer.subarray(0, count));
            total += count;
            sawBytes = true;
            continue;
          }
          if (sawBytes && !wouldBlock) break;
          await pause(20);
        }
        await output.sync();
      } finally { await output.close(); }
    } finally { await source.close(); }
    const sha256 = hash.digest("hex");
    const expiresAt = new Date(Date.now() + spoolLifetimeMs).toISOString();
    const metadata: SpoolMetadata = { id, sourcePath, destinationPath, sha256, expiresAt };
    await writeFile(path.join(dir, "metadata.json"), JSON.stringify(metadata), { flag: "wx", mode: 0o600 });
    return { direction: "upload", sourcePath, destinationPath, approvalScope: "spooled-content-sha256",
      sha256, spoolId: id, spoolExpiresAt: expiresAt };
  } catch (error) { await rm(dir, { recursive: true, force: true }); throw error; }
}

async function approvedSpoolPath(transfer: SshTransferSpec, home: string): Promise<string> {
  const match = transfer.spoolId && spoolIdPattern.exec(transfer.spoolId);
  if (!match || !transfer.sha256 || !transfer.spoolExpiresAt ||
      !/^[a-f0-9]{64}$/.test(transfer.sha256)) throw new Error("Invalid approved SSH spool.");
  const root = await privateSpoolRoot(home);
  const dir = path.join(root, `slot${match[1]}`);
  const info = await lstat(dir);
  if (!info.isDirectory() || (info.mode & 0o077) ||
      (process.getuid && info.uid !== process.getuid())) throw new Error("SSH upload spool storage changed.");
  const metadata = await readSpoolMetadata(path.join(dir, "metadata.json"));
  if (metadata.id !== transfer.spoolId || metadata.sourcePath !== transfer.sourcePath ||
      metadata.destinationPath !== transfer.destinationPath || metadata.sha256 !== transfer.sha256 ||
      metadata.expiresAt !== transfer.spoolExpiresAt || Date.parse(metadata.expiresAt) <= Date.now()) {
    throw new Error("SSH upload spool changed or expired after approval.");
  }
  const payload = path.join(dir, "payload");
  const payloadInfo = await lstat(payload);
  if (!payloadInfo.isFile() || (payloadInfo.mode & 0o077) ||
      (process.getuid && payloadInfo.uid !== process.getuid()) || payloadInfo.size > spoolMaxBytes) {
    throw new Error("SSH upload spool storage changed.");
  }
  return payload;
}

export function uploadCommand(destination: string): string {
  return "cat > '" + destination.replaceAll("'", "'\\''") + "'";
}

export function approvedPipeStream(sourcePath: string) {
  return createReadStream(sourcePath, { fs: {
      read, close,
      open(file, _flags, mode, callback) {
        openFd(file, constants.O_RDONLY | (constants.O_NOFOLLOW || 0), mode, (error, fd) => {
          if (error) { callback(error, fd); return; }
          fstat(fd, (error, info) => {
            if (!error && info.isFIFO()) { callback(null, fd); return; }
            close(fd, () => callback(error || new Error("Approved SSH named pipe changed before execution."), fd));
          });
        });
      }
    } });
}
