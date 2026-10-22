import { existsSync } from "node:fs";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { principalForVerifiedPeer } from "../src/agent-context.js";
import { executeApprovedRequest, executeReusablePermit } from "../src/executor.js";
import { buildEnvCommandAction, buildSshSessionAction } from "../src/gateway.js";
import { SGW_SSH_SESSION_COMMAND } from "../src/ssh.js";
import { SecretStore } from "../src/store.js";

let testHome = "";
let testRoot = "";
const unixIt = process.platform === "win32" ? it.skip : it;

beforeEach(async () => {
  testRoot = await mkdtemp(path.join(os.tmpdir(), "sgw-legacy-revoke-"));
  testHome = path.join(testRoot, "home");
  await mkdir(testHome);
  process.env.SGW_HOME = testHome;
  process.env.SGW_RECOVERY_HOME = path.join(testRoot, "recovery");
  process.env.SGW_MASTER_PASSPHRASE = "legacy revocation test passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
});

afterEach(async () => {
  for (const name of ["SGW_HOME", "SGW_RECOVERY_HOME", "SGW_MASTER_PASSPHRASE", "SGW_DISABLE_KEYCHAIN",
    "SGW_TEST_MODE", "SGW_TEST_HOME_ROOT", "SGW_SSH_CLI", "SGW_SSH_CONTROL_DIR"]) delete process.env[name];
  await rm(testRoot, { recursive: true, force: true });
});

describe.sequential("opt-in legacy in-flight revocation", () => {
  it("leaves a running legacy command unchanged when strict revocation is off", async () => {
    const { store, handle, requestId, ready } = await envRequest(500);
    const running = executeApprovedRequest(store, requestId, { engine: "typescript" });
    await vi.waitFor(() => expect(existsSync(ready)).toBe(true), { timeout: 5_000 });
    await denyHandle(store, handle, "env_command");

    expect((await running).exitCode).toBe(0);
    expect((await store.getRequest(requestId)).state).toBe("executed");
  }, 15_000);

  it("stops a TypeScript environment command when a deny is added", async () => {
    const { store, handle, requestId, ready } = await envRequest();
    const running = executeApprovedRequest(store, requestId, { engine: "typescript", strictLegacyRevocation: true });
    await vi.waitFor(() => expect(existsSync(ready)).toBe(true), { timeout: 5_000 });
    const revokedAt = Date.now();
    await denyHandle(store, handle, "env_command");

    await expect(running).rejects.toThrow(/denied by the current policy/i);
    expect(Date.now() - revokedAt).toBeLessThan(2_500);
    expect((await store.getRequest(requestId)).state).toBe("failed");
  }, 15_000);

  it("stops a TypeScript environment command when its handle is deleted", async () => {
    const { store, handle, requestId, ready } = await envRequest();
    const running = executeApprovedRequest(store, requestId, { engine: "typescript", strictLegacyRevocation: true });
    await vi.waitFor(() => expect(existsSync(ready)).toBe(true), { timeout: 5_000 });
    const revokedAt = Date.now();
    await store.deleteSecret(handle);

    await expect(running).rejects.toThrow(/authorization is no longer active/i);
    expect(Date.now() - revokedAt).toBeLessThan(2_500);
    expect((await store.getRequest(requestId)).state).toBe("failed");
  }, 15_000);

  it("stops a reusable policy execution when its authorization changes", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "strict reusable token", type: "api-token", value: "reusable-secret-value-123456789",
      policy: { allowedCommands: [process.execPath], injectEnv: "SGW_REUSABLE_TOKEN" }
    });
    const caller = { managedPrincipal: principalForVerifiedPeer("test:strict-revoke", "Codex"), env: {} };
    await store.addApprovalPolicyRule({
      name: "Allow strict reusable", decision: "allow", conditions: {
        handles: [record.handle], principalIds: ["test:strict-revoke"], commands: [process.execPath],
        resolvedCommands: [await realpath(process.execPath)]
      }
    });
    const ready = path.join(testHome, "reusable-ready");
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", `require('node:fs').writeFileSync(${JSON.stringify(ready)}, 'ready'); setInterval(() => {}, 1000);`],
      injectEnv: "SGW_REUSABLE_TOKEN", timeoutMs: 8_000
    });
    const admission = await store.prepareOneShotExecution(record.handle, action, "Strict reusable command", caller);
    expect(admission.kind).toBe("reusable");
    if (admission.kind !== "reusable") throw new Error("Expected reusable execution permit.");
    const running = executeReusablePermit(store, admission.permit, {
      caller, engine: "typescript", strictLegacyRevocation: true
    });
    await vi.waitFor(() => expect(existsSync(ready)).toBe(true), { timeout: 5_000 });
    const revokedAt = Date.now();
    await denyHandle(store, record.handle, "env_command");

    await expect(running).rejects.toThrow(/authorization changed|denied/i);
    expect(Date.now() - revokedAt).toBeLessThan(2_500);
  }, 15_000);

  for (const cause of ["deny", "handle deletion"] as const) {
    unixIt(`stops the Rust engine wrapper and descendants after ${cause}`, async () => {
      const { store, handle, requestId } = await envRequest();
      const ready = path.join(testHome, "rust-ready");
      const late = path.join(testHome, "rust-child-late");
      const core = path.join(testHome, "fake-core");
      const childScript = `setTimeout(() => require('node:fs').writeFileSync(${JSON.stringify(late)}, 'late'), 1200)`;
      await writeFile(core, [
        `#!${process.execPath}`,
        "const fs = require('node:fs');",
        "const { spawn } = require('node:child_process');",
        "process.stdin.resume();",
        `spawn(process.execPath, ['-e', ${JSON.stringify(childScript)}], { stdio: 'ignore' });`,
        `fs.writeFileSync(${JSON.stringify(ready)}, String(process.pid));`,
        "setInterval(() => {}, 1000);"
      ].join("\n"), { mode: 0o700 });
      await chmod(core, 0o700);

      const running = executeApprovedRequest(store, requestId, {
        engine: "rust", coreBinary: core, strictLegacyRevocation: true
      });
      await vi.waitFor(() => expect(existsSync(ready)).toBe(true), { timeout: 5_000 });
      const revokedAt = Date.now();
      if (cause === "deny") await denyHandle(store, handle, "env_command");
      else await store.deleteSecret(handle);

      await expect(running).rejects.toThrow(cause === "deny" ? /denied by the current policy/i : /authorization is no longer active/i);
      expect(Date.now() - revokedAt).toBeLessThan(2_500);
      await new Promise(resolve => setTimeout(resolve, 1_400));
      expect(existsSync(late)).toBe(false);
      expect((await store.getRequest(requestId)).state).toBe("failed");
    }, 15_000);
  }

  for (const cause of ["deny", "handle deletion"] as const) {
    unixIt(`closes a prior ControlMaster and cancels SSH after ${cause}`, async () => {
      const { store, handle, log, ready } = await legacySshFixture();
      const first = await sshRequest(store, handle, "fast");
      expect((await executeApprovedRequest(store, first.id)).exitCode).toBe(0);
      const second = await sshRequest(store, handle, "slow");
      const running = executeApprovedRequest(store, second.id, { strictLegacyRevocation: true });
      await vi.waitFor(() => expect(existsSync(ready)).toBe(true), { timeout: 5_000 });
      const revokedAt = Date.now();
      if (cause === "deny") await denyHandle(store, handle, "ssh_session");
      else await store.deleteSecret(handle);

      await expect(running).rejects.toThrow(cause === "deny" ? /denied by the current policy/i : /authorization is no longer active/i);
      expect(Date.now() - revokedAt).toBeLessThan(2_500);
      const calls = (await readFile(log, "utf8")).trim().split("\n").map(line => JSON.parse(line) as string[]);
      expect(calls.filter(args => args.includes("-M"))).toHaveLength(1);
      expect(calls.some(args => args.includes("-O") && args.includes("exit"))).toBe(true);
      expect(calls.some(args => args.includes("slow") && args.includes("ControlPath=none"))).toBe(true);
      expect((await store.getRequest(second.id)).state).toBe("failed");
    }, 15_000);
  }

  unixIt("refuses strict SSH when an existing ControlMaster cannot be verified", async () => {
    const { store, handle, log, ready, badCheck } = await legacySshFixture();
    const first = await sshRequest(store, handle, "fast");
    expect((await executeApprovedRequest(store, first.id)).exitCode).toBe(0);
    await writeFile(badCheck, "ambiguous check");

    const second = await sshRequest(store, handle, "slow");
    await expect(executeApprovedRequest(store, second.id, { strictLegacyRevocation: true }))
      .rejects.toThrow(/could not verify the existing legacy ssh controlmaster/i);
    expect(existsSync(ready)).toBe(false);
    const calls = (await readFile(log, "utf8")).trim().split("\n").map(line => JSON.parse(line) as string[]);
    expect(calls.some(args => args.includes("slow"))).toBe(false);
    expect((await store.getRequest(second.id)).state).toBe("failed");
  }, 15_000);
});

async function legacySshFixture() {
  process.env.SGW_TEST_MODE = "1";
  process.env.SGW_TEST_HOME_ROOT = await realpath(testRoot);
  process.env.SGW_SSH_CONTROL_DIR = path.join(testHome, "ssh-control");
  const fake = path.join(testHome, "fake-ssh");
  const log = path.join(testHome, "ssh.log");
  const ready = path.join(testHome, "ssh-ready");
  const badCheck = path.join(testHome, "bad-ssh-check");
  await writeFile(fake, [
    `#!${process.execPath}`,
    "const fs = require('node:fs');",
    "const args = process.argv.slice(2);",
    `fs.appendFileSync(${JSON.stringify(log)}, JSON.stringify(args) + '\\n');`,
    "const socket = args.includes('-S') ? args[args.indexOf('-S') + 1] : args.find(arg => arg.startsWith('ControlPath='))?.slice(12);",
    `if (args.includes('-O') && args.includes('check')) process.exit(fs.existsSync(${JSON.stringify(badCheck)}) ? 255 : socket && fs.existsSync(socket) ? 0 : 255);`,
    "if (args.includes('-O') && args.includes('exit')) { if (socket) fs.rmSync(socket, { force: true }); process.exit(0); }",
    "if (args.includes('-M')) { fs.writeFileSync(socket, 'master'); process.exit(0); }",
    `if (args.includes('slow')) { fs.writeFileSync(${JSON.stringify(ready)}, 'ready'); setInterval(() => {}, 1000); }`,
    "console.log('remote:fast');"
  ].join("\n"), { mode: 0o700 });
  await chmod(fake, 0o700);
  process.env.SGW_SSH_CLI = await realpath(fake);

  const store = new SecretStore();
  const record = await store.addSecret({
    name: "legacy SSH key", type: "private-key", value: fakePrivateKey(),
    policy: { allowedCommands: [SGW_SSH_SESSION_COMMAND], injectEnv: "SGW_SSH_PRIVATE_KEY" }
  });
  return { store, handle: record.handle, log, ready, badCheck };
}

async function envRequest(finishAfterMs?: number) {
  const store = new SecretStore();
  const record = await store.addSecret({
    name: "revocable environment token", type: "api-token", value: "test-token-value-123456789",
    policy: { allowedCommands: [process.execPath], injectEnv: "SGW_TEST_TOKEN" }
  });
  const ready = path.join(testHome, "command-ready");
  const finish = finishAfterMs
    ? `setTimeout(() => process.stdout.write('finished'), ${finishAfterMs});`
    : "setInterval(() => {}, 1000);";
  const script = `require('node:fs').writeFileSync(${JSON.stringify(ready)}, String(process.pid)); ${finish}`;
  const request = await store.createRequest(record.handle, buildEnvCommandAction({
    command: process.execPath, args: ["-e", script], injectEnv: "SGW_TEST_TOKEN", timeoutMs: 8_000
  }), "Revocable environment command");
  await store.approveRequest(request.id);
  return { store, handle: record.handle, requestId: request.id, ready };
}

async function sshRequest(store: SecretStore, handle: string, command: string) {
  const request = await store.createRequest(handle, buildSshSessionAction({
    target: "ubuntu@example.test", args: [command], injectEnv: "SGW_SSH_PRIVATE_KEY", timeoutMs: 8_000
  }), `Legacy SSH ${command}`);
  await store.approveRequest(request.id);
  return request;
}

async function denyHandle(store: SecretStore, handle: string, kind: "env_command" | "ssh_session") {
  await store.addApprovalPolicyRule({
    name: `Deny running ${kind}`, decision: "deny", conditions: { handles: [handle], actionKinds: [kind] }
  });
}

function fakePrivateKey(): string {
  return "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA=\n-----END OPENSSH PRIVATE KEY-----";
}
