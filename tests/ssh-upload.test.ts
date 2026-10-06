import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createWriteStream, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { approvedPipeStream, hashUpload, openApprovedUpload, prepareUpload, uploadCommand } from "../src/ssh-upload.js";
let root = "";
const saved = process.env.SGW_SANDBOX_DENY_READ;
beforeEach(async () => { root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-upload-"))); delete process.env.SGW_SANDBOX_DENY_READ; });
afterEach(async () => { if (saved === undefined) delete process.env.SGW_SANDBOX_DENY_READ; else process.env.SGW_SANDBOX_DENY_READ = saved; await rm(root, { recursive: true, force: true }); });

it("approves and snapshots files without imposing an upload size limit", async () => {
  const source = path.join(root, "input.bin"), home = path.join(root, "store");
  const bytes = Buffer.alloc(17 * 1024 * 1024, 65);
  await writeFile(source, bytes);
  const transfer = await prepareUpload(source, "/tmp/output", home);
  expect(transfer.sha256).toBe(await hashUpload(source));
  const upload = await openApprovedUpload(transfer, home);
  await writeFile(source, "changed after snapshot");
  try {
    const chunks: Buffer[] = [];
    for await (const chunk of upload.stream) chunks.push(chunk as Buffer);
    expect(createHash("sha256").update(Buffer.concat(chunks)).digest("hex")).toBe(transfer.sha256);
  } finally { upload.stream.destroy(); await upload.cleanup(); }
  expect(await readdir(path.join(home, "uploads"))).toEqual([]);
  await expect(openApprovedUpload(transfer, home)).rejects.toThrow("changed after approval");
});

it("denies credential paths, explicit parents, root, globs, and credential symbolic links", async () => {
  const home = path.join(root, "store"); await mkdir(home);
  const source = path.join(root, "payload"); await writeFile(source, "public input");
  const sensitive = path.join(home, "credential"); await writeFile(sensitive, "synthetic credential");
  await expect(prepareUpload(sensitive, "/tmp/output", home)).rejects.toThrow("denied");
  for (const deny of [source, root, path.parse(root).root, path.join(root, "pay*")]) {
    process.env.SGW_SANDBOX_DENY_READ = JSON.stringify([deny]);
    await expect(prepareUpload(source, "/tmp/output", home)).rejects.toThrow("denied");
  }
  delete process.env.SGW_SANDBOX_DENY_READ;
  if (process.platform !== "win32") {
    const alias = path.join(root, "alias"); await symlink(source, alias);
    expect((await prepareUpload(alias, "/tmp/output", home)).sourcePath).toBe(source);
    const directoryAlias = path.join(root, "directory-alias"); await symlink(root, directoryAlias);
    process.env.SGW_SANDBOX_DENY_READ = JSON.stringify([path.join(directoryAlias, "pay*")]);
    await expect(prepareUpload(source, "/tmp/output", home)).rejects.toThrow("denied");
    delete process.env.SGW_SANDBOX_DENY_READ;
    const credentialAlias = path.join(root, "credential-alias"); await symlink(sensitive, credentialAlias);
    await expect(prepareUpload(credentialAlias, "/tmp/output", home)).rejects.toThrow("denied");
  }
});

it.skipIf(process.platform === "win32")("preserves named pipe uploads and quotes a remote destination safely", async () => {
  const source = path.join(root, "input.pipe"); execFileSync("mkfifo", [source]);
  const transfer = await prepareUpload(source, "/tmp/output", path.join(root, "store"));
  expect(transfer.sha256).toBeUndefined();
  const upload = await openApprovedUpload(transfer, path.join(root, "store"));
  const writer = createWriteStream(source); writer.end("streamed bytes");
  const chunks: Buffer[] = [];
  for await (const chunk of upload.stream) chunks.push(chunk as Buffer);
  expect(Buffer.concat(chunks).toString()).toBe("streamed bytes"); await upload.cleanup();
  const destination = path.join(root, "quoted 'file' $(touch injected).bin");
  execFileSync("sh", ["-c", uploadCommand(destination)], { cwd: root, input: "exact bytes" });
  expect(await readFile(destination, "utf8")).toBe("exact bytes");
  expect(await readdir(root)).not.toContain("injected");
});

it.skipIf(process.platform === "win32")("rejects a named pipe replaced by a regular file before its descriptor opens", async () => {
  const source = path.join(root, "replaced.pipe"), home = path.join(root, "store");
  execFileSync("mkfifo", [source]);
  await prepareUpload(source, "/tmp/output", home);
  const stream = approvedPipeStream(source);
  rmSync(source); writeFileSync(source, "must not upload");
  try {
    await expect((async () => { for await (const _chunk of stream) {} })()).rejects.toThrow("named pipe changed");
  } finally { stream.destroy(); }
});
