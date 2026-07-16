import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeApprovedRequest } from "../src/executor.js";
import { buildSshSessionAction } from "../src/gateway.js";
import { SGW_SSH_SESSION_COMMAND } from "../src/ssh.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";

beforeEach(async () => {
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
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
  }
});

describe("s-gw-owned SSH sessions", () => {
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

  it("opens one ControlMaster and runs later commands over the s-gw control socket", async () => {
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
});

function fakePrivateKey(): string {
  return [
    ["-----BEGIN OPEN", "SSH PRIVATE KEY-----"].join(""),
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA=",
    ["-----END OPEN", "SSH PRIVATE KEY-----"].join("")
  ].join("\n");
}

async function writeFakeSsh(): Promise<{ bin: string; log: string }> {
  const bin = path.join(tmpHome, "fake-ssh.js");
  const log = path.join(tmpHome, "fake-ssh.log");
  await writeFile(bin, `#!/usr/bin/env node
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
    SGW_ASKPASS_FILE: process.env.SGW_ASKPASS_FILE || ''
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
  if (socket) {
    fs.mkdirSync(require('node:path').dirname(socket), { recursive: true });
    fs.writeFileSync(socket, 'master');
  }
  process.exit(0);
}
const portIndex = args.lastIndexOf('-p');
const afterPort = portIndex >= 0 ? portIndex + 2 : 0;
const remote = args.slice(afterPort + 1).join(' ') || 'true';
console.log('remote:' + remote);
process.exit(0);
`);
  await chmod(bin, 0o755);
  return { bin, log };
}

async function readFakeSshLog(log: string): Promise<Array<{ args: string[]; env: Record<string, string> }>> {
  const text = await readFile(log, "utf8");
  return text.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
}
