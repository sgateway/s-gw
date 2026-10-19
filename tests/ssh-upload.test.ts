import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createWriteStream, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { approvedPipeStream, hashUpload, openApprovedUpload, prepareUpload, uploadCommand } from "../src/ssh-upload.js";
import { buildSshSessionAction, normalizeSshTransfer } from "../src/ssh.js";
import { SecretStore } from "../src/store.js";
let root = "";
const saved = process.env.SGW_SANDBOX_DENY_READ;
const savedWorkspace = process.env.SGW_SANDBOX_UPLOAD_WORKSPACE;
beforeEach(async () => { root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-upload-"))); delete process.env.SGW_SANDBOX_DENY_READ; delete process.env.SGW_SANDBOX_UPLOAD_WORKSPACE; });
afterEach(async () => {
  if (saved === undefined) delete process.env.SGW_SANDBOX_DENY_READ; else process.env.SGW_SANDBOX_DENY_READ = saved;
  if (savedWorkspace === undefined) delete process.env.SGW_SANDBOX_UPLOAD_WORKSPACE; else process.env.SGW_SANDBOX_UPLOAD_WORKSPACE = savedWorkspace;
  await rm(root, { recursive: true, force: true });
});

it("approves and snapshots files without imposing an upload size limit", async () => {
  const source = path.join(root, "input.bin"), home = path.join(root, "store");
  const bytes = Buffer.alloc(17 * 1024 * 1024, 65);
  await writeFile(source, bytes);
  const transfer = await prepareUpload(source, "/tmp/output", home);
  expect(transfer.approvalScope).toBe("content-sha256");
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

it("allows an isolated workspace beneath a denied home without exposing siblings or protected paths", async () => {
  const workspace = path.join(root, "workspace"), home = path.join(workspace, "store");
  await mkdir(workspace); await mkdir(home);
  const source = path.join(workspace, "payload"); await writeFile(source, "approved workspace bytes");
  const sibling = path.join(root, "private"); await writeFile(sibling, "must remain private");
  const protectedSource = path.join(home, "credential"); await writeFile(protectedSource, "must remain private");
  process.env.SGW_SANDBOX_DENY_READ = JSON.stringify([root]);
  await expect(prepareUpload(source, "/tmp/output", home)).rejects.toThrow("denied");

  process.env.SGW_SANDBOX_UPLOAD_WORKSPACE = workspace;
  expect((await prepareUpload(source, "/tmp/output", home)).sourcePath).toBe(source);
  await expect(prepareUpload(sibling, "/tmp/output", home)).rejects.toThrow("denied");
  await expect(prepareUpload(protectedSource, "/tmp/output", home)).rejects.toThrow("denied");

  process.env.SGW_SANDBOX_DENY_READ = JSON.stringify([root, source]);
  await expect(prepareUpload(source, "/tmp/output", home)).rejects.toThrow("denied");
  process.env.SGW_SANDBOX_DENY_READ = JSON.stringify([root, path.join(workspace, "pay*")]);
  await expect(prepareUpload(source, "/tmp/output", home)).rejects.toThrow("denied");
});

it.skipIf(process.platform === "win32")("preserves named pipe uploads and quotes a remote destination safely", async () => {
  const source = path.join(root, "input.pipe"); execFileSync("mkfifo", [source]);
  const transfer = await prepareUpload(source, "/tmp/output", path.join(root, "store"));
  expect(transfer.approvalScope).toBe("path-stream");
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

it("rejects a claimed upload scope that disagrees with its digest, while accepting old records", () => {
  const sourcePath = path.join(root, "payload");
  const oldPipe = { direction: "upload" as const, sourcePath, destinationPath: "/tmp/output" };
  const oldFile = { ...oldPipe, sha256: "a".repeat(64) };
  expect(normalizeSshTransfer(oldPipe)?.approvalScope).toBe("path-stream");
  expect(normalizeSshTransfer(oldFile)?.approvalScope).toBe("content-sha256");
  expect(() => normalizeSshTransfer({ ...oldPipe, approvalScope: "content-sha256" })).toThrow("scope");
  expect(() => normalizeSshTransfer({ ...oldFile, approvalScope: "path-stream" })).toThrow("scope");
});

it.skipIf(process.platform === "win32")("persists named-pipe scope in requests and approval audit records", async () => {
  const source = path.join(root, "audit.pipe"), home = path.join(root, "store");
  execFileSync("mkfifo", [source]);
  const oldPassphrase = process.env.SGW_MASTER_PASSPHRASE;
  const oldBackend = process.env.SGW_SECRET_BACKEND;
  const oldKeychain = process.env.SGW_DISABLE_KEYCHAIN;
  process.env.SGW_MASTER_PASSPHRASE = "synthetic upload audit passphrase";
  process.env.SGW_SECRET_BACKEND = "local";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  try {
    const store = new SecretStore(home);
    const secret = await store.addSecret({ name: "Synthetic SSH upload", type: "password", value: "synthetic-only",
      policy: { allowedCommands: ["s-gw:ssh-session"] } });
    const action = buildSshSessionAction({ target: "fixture@example.test" });
    action.owned = true;
    action.ssh!.transfer = await prepareUpload(source, "/tmp/output", home);
    const request = await store.createRequest(secret.handle, action, "Synthetic named-pipe upload");
    expect(request.action.ssh?.transfer?.approvalScope).toBe("path-stream");
    expect(request.action.ssh?.transfer?.sha256).toBeUndefined();
    await store.approveRequest(request.id, { mode: "timed-session", durationMs: 60_000, agentScope: "same-agent" });
    const audit = (await store.auditLog()).filter((event) => event.requestId === request.id);
    expect(audit.map((event) => event.type)).toEqual(["request.created", "approval.grant.created", "request.approved"]);
    expect(audit.map((event) => event.uploadApprovalScope)).toEqual(["path-stream", "path-stream", "path-stream"]);
    expect(audit.every((event) => event.message.includes("producer supplies bytes during execution"))).toBe(true);

    const oldAction = structuredClone(action);
    delete oldAction.ssh!.transfer!.approvalScope;
    const reused = await store.createRequest(secret.handle, oldAction, "Legacy pipe request with the same scope");
    expect(reused.state).toBe("approved");
    expect(reused.action.ssh?.transfer?.approvalScope).toBe("path-stream");
    expect((await store.auditLog()).find((event) => event.requestId === reused.id)?.uploadApprovalScope).toBe("path-stream");
  } finally {
    if (oldPassphrase === undefined) delete process.env.SGW_MASTER_PASSPHRASE; else process.env.SGW_MASTER_PASSPHRASE = oldPassphrase;
    if (oldBackend === undefined) delete process.env.SGW_SECRET_BACKEND; else process.env.SGW_SECRET_BACKEND = oldBackend;
    if (oldKeychain === undefined) delete process.env.SGW_DISABLE_KEYCHAIN; else process.env.SGW_DISABLE_KEYCHAIN = oldKeychain;
  }
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
