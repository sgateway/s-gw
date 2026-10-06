import { createHash } from "node:crypto";
import { constants, createWriteStream, createReadStream } from "node:fs";
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
      if (new RegExp(globToRegex(denied)).test(source)) throw new Error("SSH upload source is denied by the credential read policy.");
    } else {
      try { denied = normalizePathForSandbox(await realpath(denied)); }
      catch (error) { if (!["ENOENT", "ENOTDIR"].includes((error as NodeJS.ErrnoException).code || "")) throw error; }
      if (source === denied || source.startsWith(denied.endsWith(path.sep) ? denied : denied + path.sep)) throw new Error("SSH upload source is denied by the credential read policy.");
    }
  }
  const info = await lstat(sourcePath);
  if (!info.isFile() && !info.isFIFO()) throw new Error("SSH upload source must be a regular file or named pipe.");
  return { direction: "upload", sourcePath: source, destinationPath,
    ...(info.isFile() ? { sha256: await hashUpload(source) } : {}) };
}

export async function openApprovedUpload(transfer: SshTransferSpec, home: string) {
  const current = await prepareUpload(transfer.sourcePath, transfer.destinationPath, home);
  if (current.sourcePath !== transfer.sourcePath || current.sha256 !== transfer.sha256) throw new Error("SSH upload changed after approval.");
  if (!transfer.sha256) return { stream: createReadStream(current.sourcePath), cleanup: async () => {} };

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
