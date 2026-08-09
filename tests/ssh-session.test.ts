import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { execFile } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeApprovedRequest } from "../src/executor.js";
import { buildSshSessionAction } from "../src/gateway.js";
import {
  closeOwnedSshSession,
  SGW_SSH_SESSION_COMMAND,
  WINDOWS_SSH_CLOSE_MESSAGE,
  WINDOWS_SSH_KEY_ONLY_ERROR
} from "../src/ssh.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";
const originalPlatform = process.platform;
const windowsSshTestTimeout = originalPlatform === "win32" ? 300_000 : 30_000;
const savedEnvKeys = ["SystemRoot", "WINDIR", "USERPROFILE", "TEMP", "TMP", "TMPDIR", "NODE_OPTIONS", "PATH", "SGW_TEST_HOME_ROOT"] as const;
let savedEnv: Partial<Record<(typeof savedEnvKeys)[number], string>> = {};
const unixIt = originalPlatform === "win32" ? it.skip : it;

beforeEach(async () => {
  savedEnv = {};
  for (const key of savedEnvKeys) {
    if (process.env[key] !== undefined) savedEnv[key] = process.env[key];
  }
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-ssh-test-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_RECOVERY_HOME = `${tmpHome}-recovery`;
  process.env.SGW_MASTER_PASSPHRASE = "ssh test passphrase";
  process.env.SGW_SSH_CONTROL_DIR = path.join(tmpHome, "ssh-control");
});

afterEach(async () => {
  delete process.env.SGW_HOME;
  delete process.env.SGW_RECOVERY_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_SSH_CONTROL_DIR;
  delete process.env.SGW_SSH_CLI;
  delete process.env.SGW_FAKE_SSH_LOG;
  delete process.env.SGW_FAKE_ACL_LOG;
  for (const key of savedEnvKeys) {
    const value = savedEnv[key];
    if (value === undefined) {
      delete process.env[key];
    } else {
      process.env[key] = value;
    }
  }
  Object.defineProperty(process, "platform", { value: originalPlatform });
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
  }
});

describe.sequential("s-gw-owned SSH sessions", () => {
  it("reuses approval for the same SSH target but not a different target", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "owned ssh key",
      type: "private-key",
      value: fakePrivateKey(),
      policy: {
        injectEnv: "SGW_SSH_PRIVATE_KEY",
        allowedCommands: [SGW_SSH_SESSION_COMMAND]
      }
    });

    const first = await store.createRequest(
      record.handle,
      buildSshSessionAction({
        target: "ubuntu@example.test",
        port: 2222,
        args: ["hostname"],
        injectEnv: "SGW_SSH_PRIVATE_KEY"
      }),
      "Codex owned ssh first command"
    );
    expect(first.state).toBe("pending");

    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });

    const sameTarget = await store.createRequest(
      record.handle,
      buildSshSessionAction({
        target: "ubuntu@example.test",
        port: 2222,
        args: ["uptime"],
        injectEnv: "SGW_SSH_PRIVATE_KEY"
      }),
      "Codex owned ssh follow-up"
    );
    expect(sameTarget.state).toBe("approved");
    expect(sameTarget.approvalGrantId).toBe(approved.approvalGrantId);

    const otherTarget = await store.createRequest(
      record.handle,
      buildSshSessionAction({
        target: "ubuntu@other.example.test",
        port: 2222,
        args: ["uptime"],
        injectEnv: "SGW_SSH_PRIVATE_KEY"
      }),
      "Codex owned ssh other host"
    );
    expect(otherTarget.state).toBe("pending");
  });

  it("keeps SSH one-shot execution durable after reusable approval", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "durable ssh one-shot key",
      type: "private-key",
      value: fakePrivateKey(),
      policy: {
        injectEnv: "SGW_SSH_PRIVATE_KEY",
        allowedCommands: [SGW_SSH_SESSION_COMMAND]
      }
    });
    const firstAction = buildSshSessionAction({
      target: "ubuntu@example.test",
      args: ["hostname"],
      injectEnv: "SGW_SSH_PRIVATE_KEY"
    });
    const first = await store.createRequest(record.handle, firstAction, "Codex durable ssh first run");
    await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });

    const admission = await store.prepareOneShotExecution(
      record.handle,
      buildSshSessionAction({
        target: "ubuntu@example.test",
        args: ["uptime"],
        injectEnv: "SGW_SSH_PRIVATE_KEY"
      }),
      "Codex durable ssh follow-up"
    );

    expect(admission.kind).toBe("request");
    if (admission.kind !== "request") throw new Error("Expected a durable SSH request.");
    expect(admission.request.state).toBe("approved");
    expect((await store.listRequests()).filter((request) => request.handle === record.handle)).toHaveLength(2);
  });

  unixIt("opens one ControlMaster and runs later commands over the s-gw control socket", async () => {
    const fake = await writeFakeSsh();
    process.env.SGW_SSH_CLI = fake.bin;
    process.env.SGW_FAKE_SSH_LOG = fake.log;

    const store = new SecretStore();
    const secret = fakePrivateKey();
    const record = await store.addSecret({
      name: "executor owned ssh key",
      type: "private-key",
      value: secret,
      policy: {
        injectEnv: "SGW_SSH_PRIVATE_KEY",
        allowedCommands: [SGW_SSH_SESSION_COMMAND],
        maxOutputBytes: 4096
      }
    });

    const first = await store.createRequest(
      record.handle,
      buildSshSessionAction({
        target: "ubuntu@example.test",
        port: 2222,
        args: ["hostname"],
        injectEnv: "SGW_SSH_PRIVATE_KEY"
      }),
      "Codex owned ssh execute"
    );
    await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });

    const summary = await executeApprovedRequest(store, first.id);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).toContain("remote:hostname");
    expect(summary.stdout).not.toContain(secret);

    let calls = await readFakeSshLog(fake.log);
    expect(calls.filter((call) => call.args.includes("-M"))).toHaveLength(1);
    expect(calls.some((call) => call.args.includes("-S") && call.args.includes("BatchMode=yes"))).toBe(true);
    expect(calls.every((call) => !call.env.SGW_SSH_PRIVATE_KEY && !call.env.SGW_SSH_PASSWORD)).toBe(true);

    const openCall = calls.find((call) => call.args.includes("-M"));
    const identityIndex = openCall?.args.indexOf("-i") ?? -1;
    expect(identityIndex).toBeGreaterThanOrEqual(0);
    const keyPath = openCall!.args[identityIndex + 1];
    expect(existsSync(keyPath)).toBe(false);

    const second = await store.createRequest(
      record.handle,
      buildSshSessionAction({
        target: "ubuntu@example.test",
        port: 2222,
        args: ["uptime"],
        injectEnv: "SGW_SSH_PRIVATE_KEY"
      }),
      "Codex owned ssh execute again"
    );
    expect(second.state).toBe("approved");
    const secondSummary = await executeApprovedRequest(store, second.id);
    expect(secondSummary.exitCode).toBe(0);
    expect(secondSummary.stdout).toContain("remote:uptime");

    calls = await readFakeSshLog(fake.log);
    expect(calls.filter((call) => call.args.includes("-M"))).toHaveLength(1);
    expect(calls.filter((call) => call.args.includes("-O") && call.args.includes("check"))).toHaveLength(1);
  });

  unixIt("sanitizes a ControlMaster connection error before throwing or persisting it", async () => {
    const secret = fakePrivateKey();
    const fake = await writeFakeSsh({ openExitCode: 23, openStderr: `open failed ${secret}` });
    process.env.SGW_SSH_CLI = fake.bin;
    process.env.SGW_FAKE_SSH_LOG = fake.log;

    const store = new SecretStore();
    const record = await store.addSecret({
      name: "sanitized SSH open failure",
      type: "private-key",
      value: secret,
      policy: { injectEnv: "SGW_SSH_PRIVATE_KEY", allowedCommands: [SGW_SSH_SESSION_COMMAND] }
    });
    const request = await store.createRequest(
      record.handle,
      buildSshSessionAction({
        target: "ubuntu@example.test",
        injectEnv: "SGW_SSH_PRIVATE_KEY"
      }),
      "Sanitized SSH open failure"
    );
    await store.approveRequest(request.id);

    const failure = await executeApprovedRequest(store, request.id).then(
      () => undefined,
      (error: unknown) => error
    );
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toContain(record.handle);
    expect((failure as Error).message).not.toContain(secret);
    expect(JSON.stringify(await store.getRequest(request.id))).not.toContain(secret);
    expect(JSON.stringify(await store.auditLog())).not.toContain(secret);

    const call = (await readFakeSshLog(fake.log)).find((entry) => entry.args.includes("-M"));
    const keyPath = call!.args[call!.args.indexOf("-i") + 1];
    expect(existsSync(keyPath)).toBe(false);
  });

  it("can add the owned SSH virtual command to an existing handle policy", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "legacy ssh handle",
      type: "password",
      value: "ssh-password-secret-123456789",
      policy: { injectEnv: "SGW_SSH_PASSWORD", allowedCommands: ["/tmp/old-wrapper"] }
    });

    const updated = await store.allowCommand(record.handle, SGW_SSH_SESSION_COMMAND);
    expect(updated.policy.allowedCommands).toEqual(expect.arrayContaining(["/tmp/old-wrapper", SGW_SSH_SESSION_COMMAND]));

    const request = await store.createRequest(
      record.handle,
      buildSshSessionAction({
        target: "ubuntu@example.test",
        args: ["true"],
        injectEnv: "SGW_SSH_PASSWORD"
      }),
      "Codex upgraded owned ssh"
    );
    expect(request.state).toBe("pending");
  });

  it("runs a Windows private key as one hardened command and removes all temporary state", async () => {
    Object.defineProperty(process, "platform", { value: "win32" });
    const windows = await writeFakeWindowsTools();
    const fake = await writeFakeSsh();
    process.env.SGW_SSH_CLI = fake.bin;
    process.env.SGW_FAKE_SSH_LOG = fake.log;

    const store = new SecretStore();
    const secret = fakePrivateKey();
    const record = await store.addSecret({
      name: "Windows one-shot SSH key",
      type: "private-key",
      value: secret,
      policy: {
        injectEnv: "SGW_SSH_PRIVATE_KEY",
        allowedCommands: [SGW_SSH_SESSION_COMMAND],
        maxOutputBytes: 4096
      }
    });
    const request = await store.createRequest(
      record.handle,
      buildSshSessionAction({
        target: "administrator@example.test",
        port: 2222,
        args: ["hostname"],
        injectEnv: "SGW_SSH_PRIVATE_KEY"
      }),
      "Windows one-shot SSH"
    );
    await store.approveRequest(request.id);

    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).toContain("remote:hostname");

    const calls = await readFakeSshLog(fake.log);
    expect(calls).toHaveLength(1);
    const call = calls[0];
    expect(call.args).toEqual(expect.arrayContaining([
      "-T", "-F", "none",
      "ClearAllForwardings=yes",
      "ForwardAgent=no",
      "ForwardX11=no",
      "PermitLocalCommand=no",
      "IdentityAgent=none",
      "PasswordAuthentication=no",
      "KbdInteractiveAuthentication=no",
      "GSSAPIAuthentication=no",
      "HostbasedAuthentication=no",
      "PubkeyAuthentication=yes",
      "StrictHostKeyChecking=accept-new",
      "BatchMode=yes",
      "IdentitiesOnly=yes"
    ]));
    expect(call.args.some((arg) => ["-M", "-S", "-O", "-f"].includes(arg))).toBe(false);
    expect(call.args.some((arg) => arg.startsWith("ControlMaster=") || arg.startsWith("ControlPath=") || arg.startsWith("ControlPersist="))).toBe(false);
    expect(call.env.SGW_SSH_PRIVATE_KEY).toBe("");
    expect(call.env.SGW_SSH_PASSWORD).toBe("");
    expect(call.env.SGW_ASKPASS_FILE).toBe("");
    expect(call.env.SystemRoot).toBe(windows.root);
    expect(call.env.WINDIR).toBe(windows.root);
    expect(call.env.USERPROFILE).toBe(process.env.USERPROFILE);
    expect(call.env.TEMP).toBe(process.env.TEMP);
    expect(call.env.TMP).toBe(process.env.TMP);
    expect(call.env.PATH).toBe(`${path.join(windows.root, "System32")};${windows.root}`);

    const identityIndex = call.args.indexOf("-i");
    expect(identityIndex).toBeGreaterThanOrEqual(0);
    const keyPath = call.args[identityIndex + 1];
    expect(existsSync(keyPath)).toBe(false);
    expect(existsSync(path.dirname(keyPath))).toBe(false);
    expect(existsSync(process.env.SGW_SSH_CONTROL_DIR!)).toBe(false);

    if (windows.aclLog) {
      const aclCalls = await readJsonLines(windows.aclLog);
      expect(aclCalls.map((entry) => entry.mode)).toEqual([
        "create-directory",
        "verify-directory", "verify-file",
        "verify-directory", "verify-file"
      ]);
      expect(path.dirname(aclCalls[0].target)).toBe(windows.temp);
      expect(path.basename(aclCalls[0].target)).toMatch(/^s-gw-ssh-[0-9a-f]{32}$/);
      expect(aclCalls[2].target).toBe(keyPath);
    }

    const beforeCloseCalls = calls.length;
    const closed = await closeOwnedSshSession({ handle: record.handle, target: "administrator@example.test", port: 2222 });
    expect(closed).toMatchObject({ exitCode: 0, timedOut: false, stdout: `${WINDOWS_SSH_CLOSE_MESSAGE}\n` });
    expect((await readFakeSshLog(fake.log))).toHaveLength(beforeCloseCalls);
    expect(existsSync(process.env.SGW_SSH_CONTROL_DIR!)).toBe(false);
  }, windowsSshTestTimeout);

  it.skipIf(originalPlatform === "win32")(
    "rejects a Windows private key replaced before spawn",
    async () => {
      Object.defineProperty(process, "platform", { value: "win32" });
      const windows = await writeFakeWindowsTools();
      const fake = await writeFakeSsh();
      process.env.SGW_SSH_CLI = fake.bin;
      process.env.SGW_FAKE_SSH_LOG = fake.log;
      await writeFile(windows.replaceMarker!, "replace on pre-spawn validation\n");

      const { store, requestId } = await approvedWindowsKeyRequest(2_000);
      await expect(executeApprovedRequest(store, requestId))
        .rejects.toThrow(/changed while its access was secured/i);

      expect(existsSync(fake.log)).toBe(false);
      const aclCalls = await readJsonLines(windows.aclLog!);
      expect(aclCalls.map((entry) => entry.mode)).toEqual([
        "create-directory",
        "verify-directory", "verify-file",
        "verify-directory"
      ]);
      const keyPath = aclCalls.find((entry) => entry.mode === "verify-file")!.target;
      expect(existsSync(keyPath)).toBe(false);
      expect(existsSync(path.dirname(keyPath))).toBe(false);
      expect(await windowsAuthDirs(windows.temp)).toEqual([]);
      expect((await store.getRequest(requestId)).state).toBe("failed");
    },
    windowsSshTestTimeout
  );

  it("rejects Windows password SSH before revealing or materializing the secret", async () => {
    Object.defineProperty(process, "platform", { value: "win32" });
    const windows = await writeFakeWindowsTools();
    const fake = await writeFakeSsh();
    process.env.SGW_SSH_CLI = fake.bin;
    process.env.SGW_FAKE_SSH_LOG = fake.log;

    const store = new SecretStore();
    const rawSecret = "windows-password-must-not-be-revealed-123456789";
    const record = await store.addSecret({
      name: "Unsupported Windows SSH password",
      type: "password",
      value: rawSecret,
      policy: { injectEnv: "SGW_SSH_PASSWORD", allowedCommands: [SGW_SSH_SESSION_COMMAND] }
    });
    const request = await store.createRequest(
      record.handle,
      buildSshSessionAction({ target: "administrator@example.test", injectEnv: "SGW_SSH_PASSWORD" }),
      "Unsupported Windows SSH password"
    );
    await store.approveRequest(request.id);
    const reveal = vi.spyOn(store, "revealSecretForLocalUse");

    await expect(executeApprovedRequest(store, request.id)).rejects.toThrow(WINDOWS_SSH_KEY_ONLY_ERROR);
    expect(reveal).not.toHaveBeenCalled();
    expect(existsSync(fake.log)).toBe(false);
    if (windows.aclLog) expect(existsSync(windows.aclLog)).toBe(false);
    expect(existsSync(process.env.SGW_SSH_CONTROL_DIR!)).toBe(false);
    expect((await readdir(windows.temp)).filter((name) => name.startsWith("s-gw-ssh-"))).toEqual([]);

    const failed = await store.getRequest(request.id);
    expect(failed.state).toBe("failed");
    expect(failed.error).toBe(WINDOWS_SSH_KEY_ONLY_ERROR);
    expect(JSON.stringify(failed)).not.toContain(rawSecret);
    expect(JSON.stringify(await store.auditLog())).not.toContain(rawSecret);
  }, windowsSshTestTimeout);

  it("sanitizes a Windows SSH nonzero result before persisting it and still cleans up the key", async () => {
    Object.defineProperty(process, "platform", { value: "win32" });
    await writeFakeWindowsTools();
    const secret = fakePrivateKey();
    const fake = await writeFakeSsh({ exitCode: 17, stderr: `remote rejected ${secret}` });
    process.env.SGW_SSH_CLI = fake.bin;
    process.env.SGW_FAKE_SSH_LOG = fake.log;

    const store = new SecretStore();
    const record = await store.addSecret({
      name: "Windows SSH sanitized failure",
      type: "ssh-key",
      value: secret,
      policy: { injectEnv: "SGW_SSH_PRIVATE_KEY", allowedCommands: [SGW_SSH_SESSION_COMMAND] }
    });
    const request = await store.createRequest(
      record.handle,
      buildSshSessionAction({
        target: "administrator@example.test",
        args: ["false"],
        injectEnv: "SGW_SSH_PRIVATE_KEY"
      }),
      "Windows SSH sanitized failure"
    );
    await store.approveRequest(request.id);

    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(17);
    expect(summary.stderr).toContain(record.handle);
    expect(summary.stderr).not.toContain(secret);
    expect(summary.sanitized).toBe(true);

    const call = (await readFakeSshLog(fake.log))[0];
    const keyPath = call.args[call.args.indexOf("-i") + 1];
    expect(existsSync(keyPath)).toBe(false);
    expect(JSON.stringify(await store.getRequest(request.id))).not.toContain(secret);
    expect(JSON.stringify(await store.auditLog())).not.toContain(secret);
  }, windowsSshTestTimeout);

  it("removes the Windows private key after an SSH timeout", async () => {
    Object.defineProperty(process, "platform", { value: "win32" });
    await writeFakeWindowsTools();
    const fake = await writeFakeSsh({ delayMs: 2_000 });
    process.env.SGW_SSH_CLI = fake.bin;
    process.env.SGW_FAKE_SSH_LOG = fake.log;

    const { store, requestId } = await approvedWindowsKeyRequest(1_000);
    const summary = await executeApprovedRequest(store, requestId);
    expect(summary).toMatchObject({ exitCode: 124, timedOut: true });

    const call = (await readFakeSshLog(fake.log))[0];
    const keyPath = call.args[call.args.indexOf("-i") + 1];
    expect(existsSync(keyPath)).toBe(false);
    expect(existsSync(path.dirname(keyPath))).toBe(false);
  }, windowsSshTestTimeout);

  it("removes the Windows private key when the configured client cannot start", async () => {
    Object.defineProperty(process, "platform", { value: "win32" });
    const windows = await writeFakeWindowsTools();
    const before = await windowsAuthDirs(windows.temp);
    const broken = path.join(tmpHome, "broken-ssh.exe");
    await writeFile(broken, "not an executable\n");
    process.env.SGW_SSH_CLI = await realpath(broken);

    const { store, requestId } = await approvedWindowsKeyRequest(1_000);
    await expect(executeApprovedRequest(store, requestId)).rejects.toThrow();
    expect(await windowsAuthDirs(windows.temp)).toEqual(before);
    if (windows.aclLog) {
      const keyCall = (await readJsonLines(windows.aclLog)).find((entry) => entry.mode === "verify-file");
      expect(keyCall).toBeDefined();
      expect(existsSync(keyCall!.target)).toBe(false);
      expect(existsSync(path.dirname(keyCall!.target))).toBe(false);
    }
    expect((await store.getRequest(requestId)).state).toBe("failed");
  }, windowsSshTestTimeout);
});

function fakePrivateKey(): string {
  return [
    ["-----BEGIN OPEN", "SSH PRIVATE KEY-----"].join(""),
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA=",
    ["-----END OPEN", "SSH PRIVATE KEY-----"].join("")
  ].join("\n");
}

async function approvedWindowsKeyRequest(timeoutMs: number): Promise<{ store: SecretStore; requestId: string }> {
  const store = new SecretStore();
  const record = await store.addSecret({
    name: "Windows SSH cleanup key",
    type: "private-key",
    value: fakePrivateKey(),
    policy: { injectEnv: "SGW_SSH_PRIVATE_KEY", allowedCommands: [SGW_SSH_SESSION_COMMAND] }
  });
  const request = await store.createRequest(
    record.handle,
    buildSshSessionAction({
      target: "administrator@example.test",
      args: ["hostname"],
      injectEnv: "SGW_SSH_PRIVATE_KEY",
      timeoutMs
    }),
    "Windows SSH cleanup"
  );
  await store.approveRequest(request.id);
  return { store, requestId: request.id };
}

async function windowsAuthDirs(temp: string): Promise<string[]> {
  return (await readdir(temp)).filter((name) => name.startsWith("s-gw-ssh-")).sort();
}

interface FakeSshOptions {
  exitCode?: number;
  stderr?: string;
  delayMs?: number;
  openExitCode?: number;
  openStderr?: string;
}

async function writeFakeSsh(options: FakeSshOptions = {}): Promise<{ bin: string; log: string }> {
  if (originalPlatform === "win32") {
    return writeWindowsFakeSsh(options);
  }

  const bin = path.join(tmpHome, "fake-ssh.js");
  const log = path.join(tmpHome, "fake-ssh.log");
  await writeFile(bin, `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
const log = ${JSON.stringify(log)};
function valueAfter(flag) {
  const index = args.indexOf(flag);
  return index >= 0 ? args[index + 1] : undefined;
}
function optionValue(prefix) {
  const item = args.find((arg) => arg.startsWith(prefix));
  return item ? item.slice(prefix.length) : undefined;
}
const socket = valueAfter('-S') || optionValue('ControlPath=');
fs.appendFileSync(log, JSON.stringify({
  args,
  env: {
    SGW_SSH_PRIVATE_KEY: process.env.SGW_SSH_PRIVATE_KEY || '',
    SGW_SSH_PASSWORD: process.env.SGW_SSH_PASSWORD || '',
    SGW_ASKPASS_FILE: process.env.SGW_ASKPASS_FILE || '',
    SystemRoot: process.env.SystemRoot || '',
    WINDIR: process.env.WINDIR || '',
    USERPROFILE: process.env.USERPROFILE || '',
    TEMP: process.env.TEMP || '',
    TMP: process.env.TMP || '',
    PATH: process.env.PATH || ''
  }
}) + '\\n');
if (args.includes('-O') && args.includes('check')) {
  process.exit(socket && fs.existsSync(socket) ? 0 : 255);
}
if (args.includes('-O') && args.includes('exit')) {
  if (socket) fs.rmSync(socket, { force: true });
  process.exit(0);
}
if (args.includes('-M')) {
  ${options.openStderr ? `process.stderr.write(${JSON.stringify(`${options.openStderr}\n`)});` : ""}
  ${options.openExitCode ? `process.exit(${options.openExitCode});` : ""}
  if (socket) {
    fs.mkdirSync(require('node:path').dirname(socket), { recursive: true });
    fs.writeFileSync(socket, 'master');
  }
  process.exit(0);
}
const portIndex = args.lastIndexOf('-p');
const afterPort = portIndex >= 0 ? portIndex + 2 : 0;
const remote = args.slice(afterPort + 1).join(' ') || 'true';
${options.stderr ? `process.stderr.write(${JSON.stringify(`${options.stderr}\n`)});` : ""}
${options.delayMs ? `Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ${options.delayMs});` : ""}
${options.exitCode ? `process.exit(${options.exitCode});` : ""}
console.log('remote:' + remote);
process.exit(0);
`);
  await chmod(bin, 0o755);
  return { bin: await realpath(bin), log };
}

async function readFakeSshLog(log: string): Promise<Array<{ args: string[]; env: Record<string, string> }>> {
  const text = await readFile(log, "utf8");
  const envKeys = [
    "SGW_SSH_PRIVATE_KEY", "SGW_SSH_PASSWORD", "SGW_ASKPASS_FILE",
    "SystemRoot", "WINDIR", "USERPROFILE", "TEMP", "TMP", "PATH"
  ];
  return text.trim().split("\n").filter(Boolean).map((line) => {
    if (line.startsWith("{")) return JSON.parse(line);
    const [args64, env64] = line.split("|");
    const values = Buffer.from(env64, "base64").toString("utf8").split("\0");
    return {
      args: Buffer.from(args64, "base64").toString("utf8").split("\0").filter(Boolean),
      env: Object.fromEntries(envKeys.map((key, index) => [key, values[index] || ""]))
    };
  });
}

async function writeFakeWindowsTools(): Promise<{
  root: string;
  temp: string;
  aclLog?: string;
  replaceMarker?: string;
}> {
  const temp = await realpath(tmpHome);
  process.env.TEMP = temp;
  process.env.TMP = temp;
  process.env.SGW_TEST_HOME_ROOT = temp;
  process.env.SGW_HOME = path.join(temp, "home");
  process.env.SGW_RECOVERY_HOME = path.join(temp, "recovery");

  if (originalPlatform === "win32") {
    const root = savedEnv.SystemRoot || savedEnv.WINDIR;
    if (!root) throw new Error("Windows test requires SystemRoot or WINDIR.");
    process.env.SystemRoot = root;
    process.env.WINDIR = root;
    return { root, temp };
  }

  const root = path.join(await realpath(tmpHome), "Windows");
  const powershell = path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const aclLog = path.join(tmpHome, "fake-acl.log");
  const replaceMarker = path.join(tmpHome, "replace-key-before-spawn");
  await mkdir(path.dirname(powershell), { recursive: true });
  await writeFile(powershell, `#!${process.execPath}
const fs = require('node:fs');
const path = require('node:path');
const sid = 'S-1-5-21-1000-1000-1000-1001';
if (process.env.SGW_WINDOWS_ACL_EXPECTED_SID && process.env.SGW_WINDOWS_ACL_EXPECTED_SID !== sid) {
  process.stderr.write('identity mismatch');
  process.exit(1);
}
const mode = process.env.SGW_WINDOWS_ACL_MODE;
let target = process.env.SGW_WINDOWS_ACL_PATH || '';
if (mode === 'create-directory') {
  const root = process.env.SGW_WINDOWS_ACL_TEST_ROOT || process.env.TEMP;
  target = path.join(root, 's-gw-ssh-' + require('node:crypto').randomBytes(16).toString('hex'));
  fs.mkdirSync(target);
}
const logPath = ${JSON.stringify(aclLog)};
let priorDirectoryCalls = 0;
if (fs.existsSync(logPath)) {
  priorDirectoryCalls = fs.readFileSync(logPath, 'utf8').trim().split(String.fromCharCode(10)).filter(Boolean)
    .map((line) => JSON.parse(line))
    .filter((entry) => entry.mode === 'verify-directory').length;
}
fs.appendFileSync(logPath, JSON.stringify({
  mode,
  target,
  expectedSid: process.env.SGW_WINDOWS_ACL_EXPECTED_SID || ''
}) + '\\n');
if (mode === 'verify-directory' && priorDirectoryCalls > 0 && fs.existsSync(${JSON.stringify(replaceMarker)})) {
  const keyPath = path.join(target, 'identity');
  fs.renameSync(keyPath, keyPath + '.original');
  fs.writeFileSync(keyPath, 'replacement private key material');
}
const result = { verified: true, sid, rules: 2 };
if (mode === 'create-directory') result.path = target;
process.stdout.write(JSON.stringify(result) + '\\n');
`);
  await chmod(powershell, 0o755);
  process.env.SystemRoot = root;
  process.env.WINDIR = root;
  process.env.USERPROFILE = path.join(tmpHome, "user-profile");
  return { root, temp, aclLog, replaceMarker };
}

async function writeWindowsFakeSsh(options: FakeSshOptions): Promise<{ bin: string; log: string }> {
  const root = savedEnv.SystemRoot || savedEnv.WINDIR;
  if (!root) throw new Error("Windows test requires SystemRoot or WINDIR.");
  const powershell = path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const bin = path.join(tmpHome, "fake-ssh.exe");
  const log = path.join(tmpHome, "fake-ssh.log");
  const source = `
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

public static class FakeSsh {
  private static string Decode(string value) {
    return Encoding.UTF8.GetString(Convert.FromBase64String(value));
  }

  private static string Encode(string value) {
    return Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
  }

  public static void Main(string[] args) {
    string logPath = Decode(${JSON.stringify(Buffer.from(log).toString("base64"))});
    string[] envKeys = new string[] {
      "SGW_SSH_PRIVATE_KEY", "SGW_SSH_PASSWORD", "SGW_ASKPASS_FILE",
      "SystemRoot", "WINDIR", "USERPROFILE", "TEMP", "TMP", "PATH"
    };
    var envValues = new List<string>();
    foreach (string key in envKeys) envValues.Add(Environment.GetEnvironmentVariable(key) ?? "");
    File.AppendAllText(
      logPath,
      Encode(String.Join("\\0", args)) + "|" + Encode(String.Join("\\0", envValues)) + Environment.NewLine,
      new UTF8Encoding(false)
    );
    Thread.Sleep(${options.delayMs || 0});
    string stderr = ${JSON.stringify(Buffer.from(options.stderr || "").toString("base64"))};
    if (stderr.Length > 0) Console.Error.WriteLine(Decode(stderr));
    int exitCode = ${options.exitCode || 0};
    if (exitCode != 0) Environment.Exit(exitCode);

    int portIndex = Array.LastIndexOf(args, "-p");
    int remoteStart = portIndex >= 0 ? portIndex + 3 : 0;
    var remote = new List<string>();
    for (int index = remoteStart; index < args.Length; index++) remote.Add(args[index]);
    Console.WriteLine("remote:" + (remote.Count > 0 ? String.Join(" ", remote) : "true"));
  }
}
`;
  const command = [
    "$ErrorActionPreference='Stop'",
    "$source=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SGW_TEST_CSHARP_SOURCE))",
    "Add-Type -TypeDefinition $source -Language CSharp -OutputAssembly $env:SGW_TEST_CSHARP_OUTPUT -OutputType ConsoleApplication"
  ].join(";");
  const encoded = Buffer.from(command, "utf16le").toString("base64");
  await execFilePromise(powershell, [
    "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded
  ], {
    ...process.env,
    SGW_TEST_CSHARP_SOURCE: Buffer.from(source).toString("base64"),
    SGW_TEST_CSHARP_OUTPUT: bin
  });
  return { bin: await realpath(bin), log };
}

async function execFilePromise(command: string, args: string[], env: NodeJS.ProcessEnv): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    execFile(command, args, { env, windowsHide: true, timeout: 20_000 }, (error, _stdout, stderr) => {
      if (!error) {
        resolve();
        return;
      }
      reject(new Error(stderr.trim() || error.message));
    });
  });
}

async function readJsonLines(filePath: string): Promise<Array<Record<string, string>>> {
  const text = await readFile(filePath, "utf8");
  return text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}
