import { createHash, generateKeyPairSync, randomUUID } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtemp, writeFile, readFile, rm, realpath, readdir } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import os from "node:os";
import { afterEach, expect, it } from "vitest";
import { prepareUpload } from "../src/ssh-upload.js";
import { SecretStore } from "../src/store.js";
import { executeApprovedRequest } from "../src/executor.js";
import { buildSshSessionAction, closeOwnedSshSession } from "../src/ssh.js";

const { Server, utils } = createRequire(import.meta.url)("ssh2");
const previousEnv = { ...process.env };
let root = "";
afterEach(async () => {
  process.env = { ...previousEnv };
  if (root) {
    const hash = createHash("sha256").update(path.join(root, "store")).digest("hex").slice(0, 12);
    await rm(path.join(process.platform === "darwin" ? "/private/tmp" : "/tmp", `sgw-ssh-${process.getuid?.() ?? "user"}-${hash}`), { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
});

async function sshFixture(authKind: "password" | "private-key") {
  root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-real-ssh-")));
  process.env.SGW_HOME = path.join(root, "store"); process.env.SGW_MASTER_PASSPHRASE = randomUUID();
  process.env.SGW_ALLOW_NO_CGROUP = "1";
  process.env.SGW_DISABLE_KEYCHAIN = "1"; process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
  const store = new SecretStore(); await store.init();
  let credential = `synthetic SSH protocol password ${randomUUID()}`;
  let publicKeyData: Buffer | undefined;
  if (authKind === "private-key") {
    const keyPath = path.join(root, "fixture-key");
    execFileSync("ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-f", keyPath]);
    credential = await readFile(keyPath, "utf8");
    publicKeyData = utils.parseKey(credential).getPublicSSH();
    await rm(keyPath); await rm(keyPath + ".pub");
  }
  const handle = await store.addSecret({ name: "SSH protocol fixture", type: authKind, value: credential, policy: { allowedCommands: ["s-gw:ssh-session"] } });
  const hostKey = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ format: "pem", type: "pkcs1" });
  const publicKey = utils.parseKey(hostKey).getPublicSSH().toString("base64");
  const clients = new Set<any>();
  let authentications = 0;
  const commands: string[] = [];
  const uploads: Buffer[] = [];
  const server = new Server({ hostKeys: [hostKey] }, (client: any) => {
    clients.add(client); client.on("error", () => {}); client.once("close", () => clients.delete(client));
    client.on("authentication", (context: any) => {
      if (context.username !== "fixture") { context.reject(); return; }
      if (authKind === "password" && context.method === "password" && context.password === credential) {
        authentications++; context.accept(); return;
      }
      if (authKind === "private-key" && context.method === "publickey" && context.key.data.equals(publicKeyData)) {
        const key = utils.parseKey(credential);
        if (!context.signature || key.verify(context.blob, context.signature, context.hashAlgo) === true) {
          if (context.signature) authentications++;
          context.accept(); return;
        }
      }
      context.reject([authKind === "password" ? "password" : "publickey"]);
    });
    client.on("ready", () => client.on("session", (accept: any) => {
      const session = accept();
      session.on("exec", (acceptExec: any, _reject: any, info: { command: string }) => {
        commands.push(info.command);
        const stream = acceptExec();
        if (info.command.includes("cat >")) {
          const chunks: Buffer[] = [];
          stream.on("data", (chunk: Buffer) => chunks.push(chunk));
          stream.on("end", () => { uploads.push(Buffer.concat(chunks)); stream.write("upload complete\n"); stream.exit(0); stream.end(); });
          return;
        }
        stream.write(`remote SSH fixture: ${info.command}\n${credential}\n`); stream.exit(0); stream.end();
      });
    }));
  });
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const knownHosts = path.join(root, "known_hosts");
  await writeFile(knownHosts, `[127.0.0.1]:${port} ssh-rsa ${publicKey}\n`);
  const helper = path.join(store.home, "real-ssh.cjs");
  await writeFile(helper, `#!${process.execPath}\nconst {spawnSync}=require('node:child_process'); const result=spawnSync('/usr/bin/ssh', ['-F','/dev/null','-o',${JSON.stringify(`UserKnownHostsFile=${knownHosts}`)},...process.argv.slice(2)], {stdio:'inherit'}); process.exit(result.status ?? 1);\n`, { mode: 0o700 });
  process.env.SGW_SSH_CLI = helper;
  return { store, handle, credential, port, knownHosts, commands, uploads, clients,
    authentications: () => authentications,
    close: async () => {
      await closeOwnedSshSession({ handle: handle.handle, target: "fixture@127.0.0.1", port, home: store.home });
      for (const client of clients) client.end();
      await new Promise<void>(resolve => server.close(resolve));
    } };
}

it.skipIf(process.platform === "win32")("uses real OpenSSH authentication and an owned session per action without exposing the password", async () => {
  const f = await sshFixture("password");
  try {
    for (const command of ["hostname", "uptime"]) {
      const action = buildSshSessionAction({ target: "fixture@127.0.0.1", port: f.port, args: [command], timeoutMs: 10000 });
      action.owned = true;
      const request = await f.store.createRequest(f.handle.handle, action, "Real SSH fixture");
      await f.store.approveRequest(request.id);
      const result = await executeApprovedRequest(f.store, request.id);
      expect(result.exitCode).toBe(0); expect(result.stdout).toContain(`remote SSH fixture: ${command}`); expect(result.stdout).not.toContain(f.credential);
    }
    expect(f.authentications()).toBe(2); expect(f.commands).toEqual(["hostname", "uptime"]);
  } finally { await f.close(); }
});

it.skipIf(process.platform === "win32")("authenticates a real private key and uploads exact bytes only after approval", async () => {
  const f = await sshFixture("private-key");
  const bytes = Buffer.from([0, 1, 2, 255, 10, 39, 34, 36]);
  const sourcePath = path.join(root, "upload fixture.bin");
  await writeFile(sourcePath, bytes);
  try {
    const action = buildSshSessionAction({ target: "fixture@127.0.0.1", port: f.port, timeoutMs: 10000 });
    action.owned = true;
    action.ssh!.transfer = await prepareUpload(sourcePath, "/tmp/quoted 'upload'.bin", f.store.home);
    const request = await f.store.createRequest(f.handle.handle, action, "real upload fixture");
    await expect(executeApprovedRequest(f.store, request.id)).rejects.toThrow("approval");
    expect(f.authentications()).toBe(0); expect(f.uploads).toEqual([]);
    await f.store.approveRequest(request.id);
    const result = await executeApprovedRequest(f.store, request.id);
    expect(result.exitCode).toBe(0); expect(result.stdout).toContain("upload complete");
    expect(f.authentications()).toBe(1); expect(f.uploads).toEqual([bytes]);
    expect(f.commands[0]).toContain("quoted");
    await expect(executeApprovedRequest(f.store, request.id)).rejects.toThrow("executed");
    expect(f.uploads).toHaveLength(1);
    expect(await readdir(path.join(f.store.home, "ssh-control")).catch(() => [])).toEqual([]);
  } finally { await f.close(); }
});

it.skipIf(process.platform === "win32")("rejects a wrong real SSH host key before authentication and recovers on a later request", async () => {
  const f = await sshFixture("password");
  const trusted = await readFile(f.knownHosts);
  const wrong = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey.export({ format: "pem", type: "pkcs1" });
  await writeFile(f.knownHosts, `[127.0.0.1]:${f.port} ssh-rsa ${utils.parseKey(wrong).getPublicSSH().toString("base64")}\n`);
  try {
    const action = buildSshSessionAction({ target: "fixture@127.0.0.1", port: f.port, args: ["hostname"], timeoutMs: 10000 });
    action.owned = true;
    const first = await f.store.createRequest(f.handle.handle, action, "wrong host fixture");
    await f.store.approveRequest(first.id);
    const failed = await executeApprovedRequest(f.store, first.id);
    expect(failed.exitCode).toBe(255);
    expect(failed.stderr).toMatch(/HOST IDENTIFICATION|Host key verification/i);
    expect(f.authentications()).toBe(0); expect(f.commands).toEqual([]);
    expect((await f.store.getRequest(first.id)).state).toBe("executed");
    await writeFile(f.knownHosts, trusted);
    const later = await f.store.createRequest(f.handle.handle, action, "trusted host fixture");
    await f.store.approveRequest(later.id);
    expect((await executeApprovedRequest(f.store, later.id)).exitCode).toBe(0);
    expect(f.authentications()).toBe(1);
  } finally { await f.close(); }
});
