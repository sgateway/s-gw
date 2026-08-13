import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { buildEnvCommandAction } from "../src/gateway.js";
import { SecretStore } from "../src/store.js";

const repoRoot = process.cwd();
const tsxCli = path.join(repoRoot, "node_modules", "tsx", "dist", "cli.mjs");
const requesterSession = "requester-session-a";
const approverSession = "approver-session-b";
const eightHoursMs = 8 * 60 * 60 * 1000;

let testHome = "";
let recoveryHome = "";
let previousEnv: Record<string, string | undefined> = {};

beforeEach(async () => {
  previousEnv = {
    SGW_HOME: process.env.SGW_HOME,
    SGW_RECOVERY_HOME: process.env.SGW_RECOVERY_HOME,
    SGW_MASTER_PASSPHRASE: process.env.SGW_MASTER_PASSPHRASE,
    SGW_LOGIN_SESSION_ID: process.env.SGW_LOGIN_SESSION_ID
  };
  testHome = await mkdtemp(path.join(os.tmpdir(), "sgw-requester-session-"));
  recoveryHome = `${testHome}-recovery`;
  process.env.SGW_HOME = testHome;
  process.env.SGW_RECOVERY_HOME = recoveryHome;
  process.env.SGW_MASTER_PASSPHRASE = "requester session test passphrase";
  process.env.SGW_LOGIN_SESSION_ID = requesterSession;
});

afterEach(async () => {
  await rm(testHome, { recursive: true, force: true });
  await rm(recoveryHome, { recursive: true, force: true });
  for (const [name, value] of Object.entries(previousEnv)) {
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }
});

describe("reusable approvals from a separate approval process", () => {
  it.each([
    {
      label: "8-hour timed",
      args: ["--mode", "timed-session", "--agent-scope", "same-agent", "--duration-ms", String(eightHoursMs)],
      mode: "timed-session",
      expires: true
    },
    {
      label: "login-session",
      args: ["--mode", "login-session", "--agent-scope", "same-agent"],
      mode: "login-session",
      expires: false
    }
  ])("binds an explicit $label CLI approval to requester session A, not approver session B", async ({ args, mode, expires }) => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "requester session token",
      type: "api-token",
      value: "requester-session-secret-value-123456789",
      policy: {
        injectEnv: "SGW_REQUESTER_SESSION_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "process.stdout.write('ok')"],
      injectEnv: "SGW_REQUESTER_SESSION_TOKEN"
    });
    const agentContext = { mcpClientName: "Codex", env: {} };

    const first = await store.createRequest(secret.handle, action, "Codex requester session", agentContext);
    expect(first.loginSessionId).toBe(requesterSession);
    expect(first.state).toBe("pending");

    const approved = approveThroughCli(first.id, args, approverSession);
    expect(approved.state).toBe("approved");

    const grant = (await store.listApprovalGrants()).find((item) => item.id === approved.approvalGrantId);
    if (!grant) {
      throw new Error("Expected the CLI approval to create a reusable grant.");
    }
    expect(grant).toMatchObject({
      mode,
      agentScope: "same-agent",
      agentName: "Codex",
      loginSessionId: requesterSession,
      lastRequestId: first.id
    });
    if (expires) {
      expect(Date.parse(grant.expiresAt!) - Date.parse(grant.updatedAt)).toBe(eightHoursMs);
    } else {
      expect(grant.expiresAt).toBeUndefined();
    }

    process.env.SGW_LOGIN_SESSION_ID = approverSession;
    const fromApproverSession = await store.createRequest(secret.handle, action, "Codex approver session", agentContext);
    expect(fromApproverSession.state).toBe("pending");
    expect(fromApproverSession.approvalGrantId).toBeUndefined();

    process.env.SGW_LOGIN_SESSION_ID = requesterSession;
    const fromRequesterSession = await store.createRequest(secret.handle, action, "Codex requester retry", agentContext);
    expect(fromRequesterSession.state).toBe("approved");
    expect(fromRequesterSession.approvalSource).toBe("grant");
    expect(fromRequesterSession.approvalGrantId).toBe(grant.id);
  });
});

function approveThroughCli(requestId: string, choiceArgs: string[], loginSessionId: string) {
  const output = execFileSync(process.execPath, [tsxCli, "src/cli.ts", "approve", requestId, ...choiceArgs], {
    cwd: repoRoot,
    env: { ...process.env, SGW_LOGIN_SESSION_ID: loginSessionId },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  return JSON.parse(output) as {
    id: string;
    state: string;
    approvalGrantId?: string;
  };
}
