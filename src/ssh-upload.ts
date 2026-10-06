import { createHash } from "node:crypto";
import { constants, createWriteStream, createReadStream, open as openFd, fstat, read, close } from "node:fs";
import { lstat, realpath, open, mkdir, mkdtemp, rm } from "node:fs/promises";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { Transform } from "node:stream";
import { containsGlobChars, globToRegex, normalizePathForSandbox } from "@anthropic-ai/sandbox-runtime/dist/sandbox/sandbox-utils.js";
import { sensitiveChildPaths } from "./sandbox-paths.js";
import type { SshTransferSpec } from "./types.js";

export async function hashUpload(file: string): Promise<string> {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(file)) hash.update(chunk);
  return hash.digest("hex");
}

export async function prepareUpload(sourcePath: string, destinationPath: string, home: string): Promise<SshTransferSpec> {
  if (!path.isAbsolute(sourcePath) || !destinationPath || /[\x00\r\n]/.test(destinationPath)) throw new Error("SSH upload paths are required.");
  const source = normalizePathForSandbox(await realpath(sourcePath));
  const explicit: string[] = JSON.parse(process.env.SGW_SANDBOX_DENY_READ || "[]");
  for (const file of [...sensitiveChildPaths(home), ...explicit]) {
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
      if (source === denied || source.startsWith(denied.endsWith(path.sep) ? denied : denied + path.sep)) throw new Error("SSH upload source is denied by the credential read policy.");
    }
  }
  const info = await lstat(source);
  if (!info.isFile() && !info.isFIFO()) throw new Error("SSH upload source must be a regular file or named pipe.");
  return { direction: "upload", sourcePath: source, destinationPath,
    ...(info.isFile() ? { sha256: await hashUpload(source) } : {}) };
}

export async function openApprovedUpload(transfer: SshTransferSpec, home: string) {
  const current = await prepareUpload(transfer.sourcePath, transfer.destinationPath, home);
  if (current.sourcePath !== transfer.sourcePath || current.sha256 !== transfer.sha256) throw new Error("SSH upload changed after approval.");
  if (!transfer.sha256) {
    const stream = approvedPipeStream(current.sourcePath);
    return { stream, cleanup: async () => {} };
  }

  // Keep a verified copy outside the agent's writable tree before opening the connection.
  const parent = path.join(home, "uploads");
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const dir = await mkdtemp(path.join(parent, "approved-"));
  const file = path.join(dir, "payload");
  const cleanup = () => rm(dir, { recursive: true, force: true });
  try {
    const hash = createHash("sha256");
    const digest = new Transform({ transform(chunk, _encoding, done) { hash.update(chunk); done(null, chunk); } });
    const input = await open(current.sourcePath, constants.O_RDONLY | (constants.O_NOFOLLOW || 0));
    await pipeline(input.createReadStream(), digest,
      createWriteStream(file, { flags: "wx", mode: 0o600 }));
    if (hash.digest("hex") !== transfer.sha256) throw new Error("SSH upload changed after approval.");
    return { stream: createReadStream(file), cleanup };
  } catch (error) { await cleanup(); throw error; }
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
