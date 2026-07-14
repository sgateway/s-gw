import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeApprovedRequest } from "../src/executor.js";
import { buildEnvCommandAction, scanLocalText } from "../src/gateway.js";
import { tokenForHandle } from "../src/scanner.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";

function fakeAwsAccessKey(): string {
  return ["A", "KIA", "IOSFODNN7EXAMPLE"].join("");
}

function fakeOpenAiToken(label: string): string {
  return ["sk", "-proj-", label, "_1234567890abcdef"].join("");
}

function onePasswordFixtureRef(): string {
  return ["op://", "Example", "/e2e-token/credential"].join("");
}

beforeEach(async () => {
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-test-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_MASTER_PASSPHRASE = "local test passphrase";
});

afterEach(async () => {
  delete process.env.SGW_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_OP_CLI;
  delete process.env.SGW_ONEPASSWORD_TIMEOUT_MS;
  delete process.env.SGW_KEYCHAIN_HELPER;
  delete process.env.SGW_SECRET_KEYCHAIN_SERVICE;
  delete process.env.SGW_LOGIN_SESSION_ID;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true });
  }
});

describe("SecretStore", () => {
  it("stores encrypted secret values and lists only handle metadata", async () => {
    const store = new SecretStore();
    await store.init();

    const rawSecret = fakeOpenAiToken("test_secret");
    const record = await store.addSecret({
      name: "openai test",
      type: "api-token",
      value: rawSecret,
      policy: {
        injectEnv: "API_TOKEN",
        allowedCommands: [process.execPath]
      }
    });

    const storeText = await readFile(store.storePath, "utf8");
    expect(storeText).not.toContain(rawSecret);
    expect(record.handle).toMatch(/^s-gw:api-token:/);

    const handles = await store.listHandles();
    expect(handles).toHaveLength(1);
    expect(JSON.stringify(handles)).not.toContain(rawSecret);
    expect(handles[0].policy.injectEnv).toBe("API_TOKEN");
  });

  it("updates the injection environment without reading the secret", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "policy update token",
      type: "api-token",
      value: fakeOpenAiToken("policy_update"),
      policy: { injectEnv: "OLD_TOKEN" }
    });

    const updated = await store.setInjectEnv(record.handle, "NODE_AUTH_TOKEN");
    expect(updated.policy.injectEnv).toBe("NODE_AUTH_TOKEN");
    await expect(store.setInjectEnv(record.handle, "invalid-name")).rejects.toThrow(/invalid environment/i);

    const stored = await store.getHandle(record.handle);
    expect(stored?.policy.injectEnv).toBe("NODE_AUTH_TOKEN");
  });

  it("rejects invalid injection environment names during enrollment", async () => {
    const store = new SecretStore();
    await expect(store.addSecret({
      name: "invalid env token",
      type: "api-token",
      value: fakeOpenAiToken("invalid_env"),
      policy: { injectEnv: "invalid-name" }
    })).rejects.toThrow(/invalid environment/i);
  });

  it("keeps encrypted store backups before ledger overwrites", async () => {
    const store = new SecretStore();
    const firstSecret = "first-backup-secret-value-123456789";
    const secondSecret = "second-backup-secret-value-123456789";
    await store.addSecret({
      name: "first backup token",
      type: "credential",
      value: firstSecret,
      policy: { injectEnv: "FIRST_BACKUP_TOKEN", allowedCommands: [process.execPath] }
    });
    await store.addSecret({
      name: "second backup token",
      type: "credential",
      value: secondSecret,
      policy: { injectEnv: "SECOND_BACKUP_TOKEN", allowedCommands: [process.execPath] }
    });

    const backups = await store.listStoreBackups();
    expect(backups.length).toBeGreaterThan(0);
    const backupText = await readFile(backups[0].path, "utf8");
    expect(backupText).not.toContain(firstSecret);
    expect(backupText).not.toContain(secondSecret);
    expect(backupText).not.toContain("op://");
  });

  it("tokenizes local text with a unique handle representation", async () => {
    const store = new SecretStore();
    const secret = fakeOpenAiToken("local_scan");
    const result = await scanLocalText(store, `OPENAI_API_KEY=${secret}\n`, { persist: true, source: "unit-test" });

    expect(result.findings).toHaveLength(1);
    expect(result.tokenizedText).not.toContain(secret);
    expect(result.tokenizedText).toContain(tokenForHandle(result.findings[0].handle));

    const handles = await store.listHandles();
    expect(handles).toHaveLength(1);
    expect(handles[0].source).toBe("unit-test");
    expect(handles[0].provider).toBe("openai");
    expect(handles[0].ruleId).toBe("SEC-OPENAI-PROJECT");
    expect(handles[0].severity).toBe("critical");
  });

  it("requires local approval before executing a secret-backed command", async () => {
    const store = new SecretStore();
    const secret = "super-secret-value-123456789";
    const record = await store.addSecret({
      name: "exec token",
      type: "api-token",
      value: secret,
      policy: {
        injectEnv: "SGW_TEST_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "console.log(process.env.SGW_TEST_TOKEN)"],
        injectEnv: "SGW_TEST_TOKEN"
      }),
      "unit test"
    );

    await expect(executeApprovedRequest(store, request.id)).rejects.toThrow(/local approval/i);
    await store.approveRequest(request.id);

    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).not.toContain(secret);
    expect(summary.stdout).toContain(tokenForHandle(record.handle));
    expect(summary.proof).toMatch(/^s-gw-proof:/);
  });

  it("treats repeated approval as the same decision", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "repeat approval token",
      type: "api-token",
      value: "repeat-approval-secret-value-123456789",
      policy: {
        injectEnv: "SGW_REPEAT_APPROVAL_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "0"],
        injectEnv: "SGW_REPEAT_APPROVAL_TOKEN"
      }),
      "repeat approval test"
    );

    const first = await store.approveRequest(request.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    const repeated = await store.approveRequest(request.id, {
      mode: "per-transaction",
      agentScope: "same-agent"
    });

    expect(repeated.state).toBe("approved");
    expect(repeated.approvalGrantId).toBe(first.approvalGrantId);
    expect(await store.listApprovalGrants()).toHaveLength(1);
    expect((await store.auditLog()).filter((event) => event.type === "request.approved")).toHaveLength(1);
  });

  it("records the runtime agent for generic local CLI requests", async () => {
    const oldCodexShell = process.env.CODEX_SHELL;
    process.env.CODEX_SHELL = "1";

    try {
      const store = new SecretStore();
      const record = await store.addSecret({
        name: "generic cli token",
        type: "api-token",
        value: "generic-cli-secret-value-123456789",
        policy: {
          injectEnv: "SGW_GENERIC_TOKEN",
          allowedCommands: [process.execPath]
        }
      });
      const request = await store.createRequest(
        record.handle,
        buildEnvCommandAction({
          command: process.execPath,
          args: ["-e", "console.log(process.env.SGW_GENERIC_TOKEN)"],
          injectEnv: "SGW_GENERIC_TOKEN"
        }),
        "Local CLI request"
      );

      expect(request.agentName).toBe("Codex");
      expect((await store.getRequest(request.id)).agentName).toBe("Codex");
    } finally {
      if (oldCodexShell === undefined) {
        delete process.env.CODEX_SHELL;
      } else {
        process.env.CODEX_SHELL = oldCodexShell;
      }
    }
  });

  it("stores Keychain-backed secret values outside the encrypted ledger", async () => {
    if (process.platform !== "darwin") {
      return;
    }

    const fakeDb = path.join(tmpHome, "fake-keychain.json");
    process.env.SGW_KEYCHAIN_HELPER = await writeFakeKeychainHelper(fakeDb);
    process.env.SGW_SECRET_KEYCHAIN_SERVICE = "com.s-gw.test.secret";

    const store = new SecretStore();
    const secret = "keychain-secret-value-1234567890";
    const record = await store.addKeychainSecret({
      name: "keychain token",
      type: "api-token",
      value: secret,
      policy: {
        injectEnv: "SGW_KEYCHAIN_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const storeText = await readFile(store.storePath, "utf8");
    expect(storeText).not.toContain(secret);
    expect(record.backend).toBe("keychain");
    expect(record.provider).toBe("macos-keychain");

    const handles = await store.listHandles();
    expect(handles[0].backend).toBe("keychain");
    expect(handles[0].provider).toBe("macos-keychain");

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "console.log(process.env.SGW_KEYCHAIN_TOKEN)"],
        injectEnv: "SGW_KEYCHAIN_TOKEN"
      }),
      "Keychain unit test"
    );

    await store.approveRequest(request.id);
    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).not.toContain(secret);
    expect(summary.stdout).toContain(tokenForHandle(record.handle));

    const dbBeforeDelete = JSON.parse(await readFile(fakeDb, "utf8"));
    expect(Object.keys(dbBeforeDelete)).toHaveLength(1);

    await store.deleteSecret(record.handle);
    const dbAfterDelete = JSON.parse(await readFile(fakeDb, "utf8"));
    expect(Object.keys(dbAfterDelete)).toHaveLength(0);
  });

  it("does not pass unrelated parent-process secrets into approved commands", async () => {
    process.env.SGW_MASTER_PASSPHRASE = "master-passphrase-should-not-leak";
    process.env.AWS_SECRET_ACCESS_KEY = "aws-parent-secret-should-not-leak";

    const store = new SecretStore();
    const secret = "approved-command-secret-123456789";
    const record = await store.addSecret({
      name: "env isolation",
      type: "api-token",
      value: secret,
      policy: {
        injectEnv: "SGW_ALLOWED_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: [
          "-e",
          [
            "console.log(process.env.SGW_MASTER_PASSPHRASE || 'missing-master')",
            "console.log(process.env.AWS_SECRET_ACCESS_KEY || 'missing-aws')",
            "console.log(process.env.SGW_ALLOWED_TOKEN)"
          ].join(";")
        ],
        injectEnv: "SGW_ALLOWED_TOKEN"
      }),
      "env isolation test"
    );

    await store.approveRequest(request.id);
    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.stdout).toContain("missing-master");
    expect(summary.stdout).toContain("missing-aws");
    expect(summary.stdout).not.toContain("master-passphrase-should-not-leak");
    expect(summary.stdout).not.toContain("aws-parent-secret-should-not-leak");
    expect(summary.stdout).not.toContain(secret);
    expect(summary.stdout).toContain(tokenForHandle(record.handle));
  });

  it("injects multiple approved handles into one env-command and sanitizes each value", async () => {
    const store = new SecretStore();
    const accessKey = fakeAwsAccessKey();
    const secretKey = "aws-secret-access-key-value-123456789";
    const access = await store.addSecret({
      name: "aws access key id",
      type: "access-key",
      value: accessKey,
      policy: {
        injectEnv: "AWS_ACCESS_KEY_ID",
        allowedCommands: [process.execPath]
      }
    });
    const secret = await store.addSecret({
      name: "aws secret access key",
      type: "credential",
      value: secretKey,
      policy: {
        injectEnv: "AWS_SECRET_ACCESS_KEY",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const request = await store.createRequest(
      secret.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: [
          "-e",
          [
            "console.log(process.env.AWS_ACCESS_KEY_ID)",
            "console.log(process.env.AWS_SECRET_ACCESS_KEY)"
          ].join(";")
        ],
        injectEnv: "AWS_SECRET_ACCESS_KEY",
        env: [{ handle: access.handle, injectEnv: "AWS_ACCESS_KEY_ID" }]
      }),
      "Codex AWS credential pair"
    );

    await store.approveRequest(request.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).not.toContain(accessKey);
    expect(summary.stdout).not.toContain(secretKey);
    expect(summary.stdout).toContain(tokenForHandle(access.handle));
    expect(summary.stdout).toContain(tokenForHandle(secret.handle));
  });

  it("keeps long timeout requests explicit and supports no child-process timer", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "timeout token",
      type: "credential",
      value: "timeout-secret-value-123456789",
      policy: {
        injectEnv: "SGW_TIMEOUT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });

    const longRequest = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "0"],
        injectEnv: "SGW_TIMEOUT_TOKEN",
        timeoutMs: 1_800_000
      }),
      "Codex long EICE helper"
    );
    expect(longRequest.action.timeoutMs).toBe(1_800_000);

    const sessionRequest = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "0"],
        injectEnv: "SGW_TIMEOUT_TOKEN",
        timeoutMs: 0
      }),
      "Codex no timeout helper"
    );
    expect(sessionRequest.action.timeoutMs).toBe(0);
  });

  it("never leaks a partial secret when output is truncated across the byte cap", async () => {
    const store = new SecretStore();
    // A secret with no detector-recognizable shape, so only the exact-value
    // sanitizer can remove it — this is what protects us, not the scanner.
    const secret = "ZxQveryLongOpaqueCredentialValue1234567890abcdefXY";
    const record = await store.addSecret({
      name: "truncation leak",
      type: "credential",
      value: secret,
      policy: {
        injectEnv: "SGW_LEAK_TOKEN",
        allowedCommands: [process.execPath],
        // Tiny cap so the printed secret lands across the truncation boundary.
        maxOutputBytes: 24
      }
    });

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        // Pad before the secret so the cut falls in the middle of it.
        args: ["-e", "process.stdout.write('p'.repeat(18) + process.env.SGW_LEAK_TOKEN)"],
        injectEnv: "SGW_LEAK_TOKEN"
      }),
      "truncation leak test"
    );

    await store.approveRequest(request.id);
    const summary = await executeApprovedRequest(store, request.id);

    // No run of the secret (down to short prefixes) may survive the cap.
    for (let len = secret.length; len >= 6; len--) {
      for (let i = 0; i + len <= secret.length; i++) {
        expect(summary.stdout).not.toContain(secret.slice(i, i + len));
      }
    }
    expect(summary.stdout).not.toContain(secret);
  });

  it("recovers a request stranded in executing when the runner never reported back", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "stranded token",
      type: "api-token",
      value: "stranded-secret-value-123456789",
      policy: { injectEnv: "SGW_STRANDED_TOKEN", allowedCommands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_STRANDED_TOKEN)"],
      injectEnv: "SGW_STRANDED_TOKEN"
    });

    const request = await store.createRequest(record.handle, action, "stranded test");
    await store.approveRequest(request.id);
    await store.claimApprovedRequest(request.id);

    // Pretend the runner died ~20 minutes ago, well past the stale window.
    await backdateRequest(request.id, 20 * 60 * 1000);

    const recovered = await store.recoverStaleExecutions();
    expect(recovered.map((item) => item.id)).toEqual([request.id]);

    const after = await store.getRequest(request.id);
    expect(after.state).toBe("failed");
    expect(after.error).toMatch(/interrupted/i);

    // A stale executing request must not be claimable again.
    await expect(store.claimApprovedRequest(request.id)).rejects.toThrow(/failed/);
  });

  it("leaves a freshly executing request alone", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "fresh token",
      type: "api-token",
      value: "fresh-secret-value-123456789",
      policy: { injectEnv: "SGW_FRESH_TOKEN", allowedCommands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_FRESH_TOKEN)"],
      injectEnv: "SGW_FRESH_TOKEN"
    });

    const request = await store.createRequest(record.handle, action, "fresh test");
    await store.approveRequest(request.id);
    await store.claimApprovedRequest(request.id);

    const recovered = await store.recoverStaleExecutions();
    expect(recovered).toHaveLength(0);
    expect((await store.getRequest(request.id)).state).toBe("executing");
  });

  it("supersedes older duplicate pending requests and can clean stale approved work", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "duplicate pending token",
      type: "api-token",
      value: "duplicate-pending-secret-123456789",
      policy: {
        injectEnv: "SGW_DUP_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_DUP_TOKEN)"],
      injectEnv: "SGW_DUP_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex duplicate pending");
    const second = await store.createRequest(record.handle, action, "Codex duplicate pending");
    expect((await store.getRequest(first.id)).state).toBe("failed");
    expect((await store.getRequest(first.id)).error).toContain(second.id);
    expect(second.state).toBe("pending");

    await store.approveRequest(second.id);
    await backdateRequest(second.id, 2 * 60 * 60 * 1000, ["approvedAt", "createdAt"]);

    const cleaned = await store.cleanupRequests({
      approvedOlderThanMs: 60 * 60 * 1000,
      pendingOlderThanMs: 24 * 60 * 60 * 1000
    });
    expect(cleaned.requests.map((item) => item.id)).toContain(second.id);
    const after = await store.getRequest(second.id);
    expect(after.state).toBe("failed");
    expect(after.error).toMatch(/expired before execution/i);
  });

  it("force-recovers a freshly executing request on explicit user action", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "force recover token",
      type: "api-token",
      value: "force-recover-secret-123456789",
      policy: { injectEnv: "SGW_FORCE_TOKEN", allowedCommands: [process.execPath] }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_FORCE_TOKEN)"],
      injectEnv: "SGW_FORCE_TOKEN"
    });

    const request = await store.createRequest(record.handle, action, "force recover test");
    await store.approveRequest(request.id);
    await store.claimApprovedRequest(request.id);

    // No backdating: the request is still well inside the stale window, so the automatic
    // sweep would leave it. The explicit user-driven recovery should still clear it.
    const recovered = await store.forceRecoverExecutions(request.id);
    expect(recovered.map((item) => item.id)).toEqual([request.id]);

    const after = await store.getRequest(request.id);
    expect(after.state).toBe("failed");
    expect(after.error).toMatch(/recovered manually/i);
    await expect(store.claimApprovedRequest(request.id)).rejects.toThrow(/failed/);
  });

  it("refuses to force-recover a request that is not executing", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "non-executing token",
      type: "api-token",
      value: "non-executing-secret-123456789",
      policy: { injectEnv: "SGW_PENDING_TOKEN", allowedCommands: [process.execPath] }
    });
    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "0"],
        injectEnv: "SGW_PENDING_TOKEN"
      }),
      "still pending"
    );

    await expect(store.forceRecoverExecutions(request.id)).rejects.toThrow(/not executing/i);
    await expect(store.forceRecoverExecutions("req_missing")).rejects.toThrow(/unknown request/i);
  });

  it("claims an approved request before execution so concurrent calls run it once", async () => {
    const store = new SecretStore();
    const hitFile = path.join(tmpHome, "race-hits.txt");
    const record = await store.addSecret({
      name: "race token",
      type: "api-token",
      value: "race-secret-value-123456789",
      policy: {
        injectEnv: "SGW_RACE_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: [
          "-e",
          "require('node:fs').appendFileSync(process.argv[1], 'hit\\n'); console.log(process.env.SGW_RACE_TOKEN)",
          hitFile
        ],
        injectEnv: "SGW_RACE_TOKEN"
      }),
      "race test"
    );

    await store.approveRequest(request.id);
    const results = await Promise.allSettled([
      executeApprovedRequest(store, request.id),
      executeApprovedRequest(store, request.id)
    ]);

    expect(results.filter((item) => item.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((item) => item.status === "rejected")).toHaveLength(1);
    const hits = await readFile(hitFile, "utf8");
    expect(hits.trim().split("\n")).toHaveLength(1);
  });

  it("auto-approves the same action inside a timed approval session", async () => {
    const store = new SecretStore();
    await store.setApprovalSettings({ mode: "timed-session", durationMs: 15 * 60 * 1000 });
    const record = await store.addSecret({
      name: "timed token",
      type: "api-token",
      value: "timed-secret-value-123456789",
      policy: {
        injectEnv: "SGW_TIMED_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_TIMED_TOKEN)"],
      injectEnv: "SGW_TIMED_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "timed session first");
    expect(first.state).toBe("pending");
    const approved = await store.approveRequest(first.id);
    expect(approved.approvalGrantId).toMatch(/^grant_/);

    const second = await store.createRequest(record.handle, action, "timed session second");
    expect(second.state).toBe("approved");
    expect(second.approvalGrantId).toBe(approved.approvalGrantId);
  });

  it("scopes login-session approval reuse to the current login session id", async () => {
    process.env.SGW_LOGIN_SESSION_ID = "login-session-a";
    const store = new SecretStore();
    await store.setApprovalSettings({ mode: "login-session" });
    const record = await store.addSecret({
      name: "login token",
      type: "api-token",
      value: "login-secret-value-123456789",
      policy: {
        injectEnv: "SGW_LOGIN_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_LOGIN_TOKEN)"],
      injectEnv: "SGW_LOGIN_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "login session first");
    await store.approveRequest(first.id);
    const sameLogin = await store.createRequest(record.handle, action, "same login");
    expect(sameLogin.state).toBe("approved");

    process.env.SGW_LOGIN_SESSION_ID = "login-session-b";
    const differentLogin = await store.createRequest(record.handle, action, "different login");
    expect(differentLogin.state).toBe("pending");
  });

  it("can reuse an approval for the same agent and duration from the approval choice", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "codex timed token",
      type: "api-token",
      value: "codex-timed-secret-value-123456789",
      policy: {
        injectEnv: "SGW_CODEX_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_CODEX_TOKEN)"],
      injectEnv: "SGW_CODEX_TOKEN"
    });

    const first = await store.createRequest(
      record.handle,
      action,
      "Agent requested local secret-backed execution.",
      { mcpClientName: "codex-mcp-client", env: {} }
    );
    expect(first.agentName).toBe("Codex");
    expect(first.agentSource).toBe("mcp-client");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    expect(approved.approvalGrantId).toMatch(/^grant_/);

    const sameAgent = await store.createRequest(
      record.handle,
      action,
      "Agent requested local secret-backed execution.",
      { mcpClientName: "Codex", env: {} }
    );
    expect(sameAgent.state).toBe("approved");
    expect(sameAgent.approvalGrantId).toBe(approved.approvalGrantId);

    const otherAgent = await store.createRequest(
      record.handle,
      action,
      "Agent requested local secret-backed execution.",
      { mcpClientName: "Claude Code", env: {} }
    );
    expect(otherAgent.state).toBe("pending");
  });

  it("auto-approves a matching request from an approval policy rule", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "policy codex token",
      type: "api-token",
      value: "policy-codex-secret-value-123456789",
      provider: "github",
      policy: {
        injectEnv: "SGW_POLICY_CODEX_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    await store.addApprovalPolicyRule({
      name: "Codex may use this GitHub token",
      decision: "allow",
      conditions: {
        handles: [record.handle],
        agents: ["Codex"],
        providers: ["github"],
        commands: [process.execPath],
        injectEnvs: ["SGW_POLICY_CODEX_TOKEN"]
      }
    });

    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_POLICY_CODEX_TOKEN)"],
      injectEnv: "SGW_POLICY_CODEX_TOKEN"
    });
    const request = await store.createRequest(record.handle, action, "Codex policy run");
    expect(request.state).toBe("approved");
    expect(request.approvalPolicyRuleId).toMatch(/^policy_/);
    expect(request.approvalGrantId).toBeUndefined();

    const result = await executeApprovedRequest(store, request.id);
    expect(result.stdout).toContain(`<<SGW_SECRET:${record.handle}>>`);
    expect(result.stdout).not.toContain("policy-codex-secret-value");
  });

  it("lets a higher-priority ask policy override a broader allow policy", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "policy ask token",
      type: "api-token",
      value: "policy-ask-secret-value-123456789",
      policy: {
        injectEnv: "SGW_POLICY_ASK_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    await store.addApprovalPolicyRule({
      name: "Allow Codex broadly",
      decision: "allow",
      priority: 200,
      conditions: { agents: ["Codex"], commands: [process.execPath] }
    });
    await store.addApprovalPolicyRule({
      name: "Ask for this handle",
      decision: "ask",
      priority: 50,
      conditions: { handles: [record.handle] }
    });

    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_POLICY_ASK_TOKEN)"],
      injectEnv: "SGW_POLICY_ASK_TOKEN"
    });
    const request = await store.createRequest(record.handle, action, "Codex should be asked");
    expect(request.state).toBe("pending");
    expect(request.approvalPolicyRuleId).toMatch(/^policy_/);
  });

  it("denies a matching policy even when an approval grant exists", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "policy deny token",
      type: "api-token",
      value: "policy-deny-secret-value-123456789",
      severity: "critical",
      policy: {
        injectEnv: "SGW_POLICY_DENY_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_POLICY_DENY_TOKEN)"],
      injectEnv: "SGW_POLICY_DENY_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex first approval");
    await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    await store.addApprovalPolicyRule({
      name: "Block critical token",
      decision: "deny",
      priority: 10,
      conditions: {
        minSeverity: "critical",
        agents: ["Codex"]
      }
    });

    const denied = await store.createRequest(record.handle, action, "Codex after deny policy");
    expect(denied.state).toBe("denied");
    expect(denied.error).toContain("Denied by approval policy");
  });

  it("reuses a timed approval when the same agent changes command arguments", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "codex wrapper credential",
      type: "password",
      value: "codex-wrapper-secret-value-123456789",
      policy: {
        injectEnv: "SGW_WRAPPER_PASSWORD",
        allowedCommands: [process.execPath]
      }
    });
    const firstAction = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log('first', process.env.SGW_WRAPPER_PASSWORD)"],
      injectEnv: "SGW_WRAPPER_PASSWORD"
    });
    const secondAction = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log('second', process.env.SGW_WRAPPER_PASSWORD)"],
      injectEnv: "SGW_WRAPPER_PASSWORD"
    });

    const first = await store.createRequest(record.handle, firstAction, "Codex wrapper first run");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });

    const next = await store.createRequest(record.handle, secondAction, "Codex wrapper follow-up");
    expect(next.state).toBe("approved");
    expect(next.approvalGrantId).toBe(approved.approvalGrantId);
  });

  it("migrates old approval grants that were keyed to command arguments", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "legacy wrapper credential",
      type: "password",
      value: "legacy-wrapper-secret-value-123456789",
      policy: {
        injectEnv: "SGW_LEGACY_WRAPPER_PASSWORD",
        allowedCommands: [process.execPath]
      }
    });
    const firstAction = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log('legacy first', process.env.SGW_LEGACY_WRAPPER_PASSWORD)"],
      injectEnv: "SGW_LEGACY_WRAPPER_PASSWORD"
    });
    const secondAction = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log('legacy second', process.env.SGW_LEGACY_WRAPPER_PASSWORD)"],
      injectEnv: "SGW_LEGACY_WRAPPER_PASSWORD"
    });

    const first = await store.createRequest(record.handle, firstAction, "Codex legacy wrapper first run");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    const legacyKey = legacyApprovalActionKey(record.handle, firstAction);

    const raw = JSON.parse(await readFile(store.storePath, "utf8"));
    raw.approvalGrants[0].actionKey = legacyKey;
    await writeFile(store.storePath, `${JSON.stringify(raw, null, 2)}\n`);

    const next = await store.createRequest(record.handle, secondAction, "Codex legacy wrapper follow-up");
    expect(next.state).toBe("approved");
    expect(next.approvalGrantId).toBe(approved.approvalGrantId);

    const grants = await store.listApprovalGrants();
    expect(grants).toHaveLength(1);
    expect(grants[0].actionKey).not.toBe(legacyKey);
  });

  it("can reuse an approval across agents when explicitly scoped that way", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "any-agent token",
      type: "api-token",
      value: "any-agent-secret-value-123456789",
      policy: {
        injectEnv: "SGW_ANY_AGENT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_ANY_AGENT_TOKEN)"],
      injectEnv: "SGW_ANY_AGENT_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex initial approval");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000,
      agentScope: "any-agent"
    });

    const claude = await store.createRequest(record.handle, action, "Claude follow-up approval");
    expect(claude.state).toBe("approved");
    expect(claude.approvalGrantId).toBe(approved.approvalGrantId);
  });

  it("revokes reusable approval grants before the next matching request", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "revoke grant token",
      type: "api-token",
      value: "revoke-grant-secret-value-123456789",
      policy: {
        injectEnv: "SGW_REVOKE_GRANT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_REVOKE_GRANT_TOKEN)"],
      injectEnv: "SGW_REVOKE_GRANT_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex grant first");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    expect(approved.approvalGrantId).toMatch(/^grant_/);

    const grants = await store.listApprovalGrants();
    expect(grants.map((grant) => grant.id)).toEqual([approved.approvalGrantId]);

    const revoked = await store.revokeApprovalGrant(approved.approvalGrantId!);
    expect(revoked.id).toBe(approved.approvalGrantId);
    expect(await store.listApprovalGrants()).toHaveLength(0);

    const next = await store.createRequest(record.handle, action, "Codex grant after revoke");
    expect(next.state).toBe("pending");
  });

  it("clears every reusable approval grant", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "clear grants token",
      type: "api-token",
      value: "clear-grants-secret-value-123456789",
      policy: {
        injectEnv: "SGW_CLEAR_GRANTS_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_CLEAR_GRANTS_TOKEN)"],
      injectEnv: "SGW_CLEAR_GRANTS_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex clear grants");
    await store.approveRequest(first.id, { mode: "timed-session", agentScope: "same-agent" });

    const cleared = await store.clearApprovalGrants();
    expect(cleared.revokedCount).toBe(1);
    expect(await store.listApprovalGrants()).toHaveLength(0);
  });

  it("deletes a handle, revokes reusable grants, and fails unfinished requests", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "delete token",
      type: "api-token",
      value: "delete-secret-value-123456789",
      policy: {
        injectEnv: "SGW_DELETE_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_DELETE_TOKEN)"],
      injectEnv: "SGW_DELETE_TOKEN"
    });

    const approved = await store.createRequest(record.handle, action, "Codex approved before delete");
    await store.approveRequest(approved.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    const pending = await store.createRequest(record.handle, action, "Claude pending before delete");
    await store.addApprovalPolicyRule({
      name: "Delete scoped policy",
      decision: "allow",
      conditions: { handles: [record.handle], agents: ["Codex"] }
    });

    const deleted = await store.deleteSecret(record.handle);
    expect(deleted.handle).toBe(record.handle);
    expect(deleted.revokedApprovalGrants).toBe(1);
    expect(deleted.revokedApprovalPolicies).toBe(1);
    expect(deleted.failedRequests.map((request) => request.id).sort()).toEqual([approved.id, pending.id].sort());
    expect(await store.listApprovalPolicyRules()).toHaveLength(0);

    await expect(store.getSecretRecord(record.handle)).rejects.toThrow(/unknown secret handle/i);
    await expect(store.createRequest(record.handle, action, "Codex after delete")).rejects.toThrow(/unknown secret handle/i);
    await expect(executeApprovedRequest(store, approved.id)).rejects.toThrow(/failed/);

    const audit = await store.auditLog();
    expect(audit.some((event) => event.type === "secret.deleted" && event.handle === record.handle)).toBe(true);
  });

  it("can create an unlimited approval that survives login-session changes", async () => {
    process.env.SGW_LOGIN_SESSION_ID = "login-session-a";
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "unlimited token",
      type: "api-token",
      value: "unlimited-secret-value-123456789",
      policy: {
        injectEnv: "SGW_UNLIMITED_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_UNLIMITED_TOKEN)"],
      injectEnv: "SGW_UNLIMITED_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex persistent approval");
    const approved = await store.approveRequest(first.id, {
      mode: "always",
      agentScope: "same-agent"
    });

    process.env.SGW_LOGIN_SESSION_ID = "login-session-b";
    const afterLoginChange = await store.createRequest(record.handle, action, "Codex after login switch");
    expect(afterLoginChange.state).toBe("approved");
    expect(afterLoginChange.approvalGrantId).toBe(approved.approvalGrantId);
  });

  it("resolves 1Password-backed handles only during approved local execution", async () => {
    const fakeOp = await writeFakeOp("op-e2e-secret-value-1234567890");
    process.env.SGW_OP_CLI = fakeOp;

    const store = new SecretStore();
    const reference = onePasswordFixtureRef();
    const record = await store.addOnePasswordReference({
      name: "1password e2e token",
      type: "api-token",
      reference,
      policy: {
        injectEnv: "SGW_OP_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });

    const storeText = await readFile(store.storePath, "utf8");
    expect(storeText).not.toContain(reference);
    expect(storeText).not.toContain("op-e2e-secret-value");

    const handles = await store.listHandles();
    expect(handles[0].backend).toBe("onepassword");
    expect(handles[0].provider).toBe("1password");
    expect(handles[0].source).toBe("onepassword");

    const request = await store.createRequest(
      record.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "console.log(process.env.SGW_OP_TOKEN)"],
        injectEnv: "SGW_OP_TOKEN"
      }),
      "1Password unit test"
    );

    await store.approveRequest(request.id);
    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).not.toContain("op-e2e-secret-value");
    expect(summary.stdout).toContain(tokenForHandle(record.handle));
    expect(summary.sanitized).toBe(true);

    const afterExecute = JSON.parse(await readFile(store.storePath, "utf8"));
    expect(afterExecute.secrets[0].cache).toBeUndefined();
  });

  it("caches 1Password reads in the encrypted store for a reusable approval TTL", async () => {
    const counterPath = path.join(tmpHome, "op-read-count.txt");
    process.env.SGW_OP_CLI = await writeCountingFakeOp("op-cached-secret-value-1234567890", counterPath);

    const store = new SecretStore();
    const reference = onePasswordFixtureRef();
    const record = await store.addOnePasswordReference({
      name: "1password cached token",
      type: "api-token",
      reference,
      policy: {
        injectEnv: "SGW_OP_CACHED_TOKEN",
        allowedCommands: [process.execPath],
        maxOutputBytes: 4096
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_OP_CACHED_TOKEN)"],
      injectEnv: "SGW_OP_CACHED_TOKEN"
    });

    const first = await store.createRequest(record.handle, action, "Codex cached 1Password first run");
    const approved = await store.approveRequest(first.id, {
      mode: "timed-session",
      durationMs: 8 * 60 * 60 * 1000,
      agentScope: "same-agent"
    });
    const firstSummary = await executeApprovedRequest(store, first.id);
    expect(firstSummary.stdout).toContain(tokenForHandle(record.handle));

    const second = await store.createRequest(record.handle, action, "Codex cached 1Password second run");
    expect(second.state).toBe("approved");
    expect(second.approvalGrantId).toBe(approved.approvalGrantId);
    const secondSummary = await executeApprovedRequest(store, second.id);
    expect(secondSummary.stdout).toContain(tokenForHandle(record.handle));

    expect(await readCount(counterPath)).toBe(1);
    const storeText = await readFile(store.storePath, "utf8");
    expect(storeText).not.toContain(reference);
    expect(storeText).not.toContain("op-cached-secret-value");

    const raw = JSON.parse(storeText);
    expect(raw.secrets[0].cache.approvalGrantId).toBe(approved.approvalGrantId);
    expect(raw.secrets[0].cache.expiresAt).toBeTruthy();
  });

  it("drops cached 1Password values when the reusable approval is revoked", async () => {
    const counterPath = path.join(tmpHome, "op-revoke-count.txt");
    process.env.SGW_OP_CLI = await writeCountingFakeOp("op-revoked-cache-secret-1234567890", counterPath);

    const store = new SecretStore();
    const record = await store.addOnePasswordReference({
      name: "1password revoked cache token",
      type: "api-token",
      reference: onePasswordFixtureRef(),
      policy: {
        injectEnv: "SGW_OP_REVOKE_CACHE",
        allowedCommands: [process.execPath]
      }
    });
    const action = buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_OP_REVOKE_CACHE)"],
      injectEnv: "SGW_OP_REVOKE_CACHE"
    });

    const first = await store.createRequest(record.handle, action, "Codex cached revoke first run");
    const approved = await store.approveRequest(first.id, { mode: "timed-session", agentScope: "same-agent" });
    await executeApprovedRequest(store, first.id);

    let raw = JSON.parse(await readFile(store.storePath, "utf8"));
    expect(raw.secrets[0].cache.approvalGrantId).toBe(approved.approvalGrantId);

    await store.revokeApprovalGrant(approved.approvalGrantId!);
    raw = JSON.parse(await readFile(store.storePath, "utf8"));
    expect(raw.secrets[0].cache).toBeUndefined();

    const next = await store.createRequest(record.handle, action, "Codex cached revoke after revoke");
    expect(next.state).toBe("pending");
  });

  it("rejects commands outside the handle policy", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "restricted",
      type: "api-token",
      value: "another-secret-value-123456789",
      policy: {
        injectEnv: "TOKEN",
        allowedCommands: ["ssh"]
      }
    });

    await expect(
      store.createRequest(
        record.handle,
        buildEnvCommandAction({
          command: process.execPath,
          args: ["-v"],
          injectEnv: "TOKEN"
        }),
        "wrong command"
      )
    ).rejects.toThrow(/not allowed/i);
  });

  it("does not treat an absolute command as allowed by a bare basename grant", async () => {
    const store = new SecretStore();
    const record = await store.addSecret({
      name: "basename restricted",
      type: "api-token",
      value: "basename-secret-value-123456789",
      policy: {
        injectEnv: "TOKEN",
        allowedCommands: ["node"]
      }
    });

    await expect(
      store.createRequest(
        record.handle,
        buildEnvCommandAction({
          command: process.execPath,
          args: ["-v"],
          injectEnv: "TOKEN"
        }),
        "absolute request"
      )
    ).rejects.toThrow(/not allowed/i);
  });
});

async function backdateRequest(requestId: string, agoMs: number, fields = ["updatedAt"]): Promise<void> {
  const storePath = path.join(tmpHome, "store.json");
  const store = JSON.parse(await readFile(storePath, "utf8"));
  const request = store.requests.find((item: { id: string }) => item.id === requestId);
  const value = new Date(Date.now() - agoMs).toISOString();
  for (const field of fields) {
    request[field] = value;
  }
  await writeFile(storePath, `${JSON.stringify(store, null, 2)}\n`);
}

function legacyApprovalActionKey(handle: string, action: ReturnType<typeof buildEnvCommandAction>): string {
  const command = path.isAbsolute(action.command) ? path.normalize(action.command) : action.command.trim();
  const payload = {
    handle,
    kind: action.kind,
    command,
    args: action.args,
    injectEnv: action.injectEnv,
    workingDir: action.workingDir ? path.resolve(action.workingDir) : ""
  };

  return createHash("sha256").update(JSON.stringify(payload)).digest("base64url");
}

async function writeFakeOp(secret: string): Promise<string> {
  const fakeOp = path.join(tmpHome, "op");
  const reference = onePasswordFixtureRef();
  await writeFile(fakeOp, `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '2.34.0\\n'
  exit 0
fi
if [ "$1" = "read" ] && [ "$2" = "${reference}" ]; then
  printf '%s' '${secret}'
  exit 0
fi
printf 'unexpected op call: %s %s\\n' "$1" "$2" >&2
exit 2
`);
  await chmod(fakeOp, 0o755);
  return fakeOp;
}

async function writeCountingFakeOp(secret: string, counterPath: string): Promise<string> {
  const fakeOp = path.join(tmpHome, `op-counting-${path.basename(counterPath)}`);
  const reference = onePasswordFixtureRef();
  await writeFile(fakeOp, `#!/bin/sh
if [ "$1" = "--version" ]; then
  printf '2.34.0\\n'
  exit 0
fi
if [ "$1" = "read" ] && [ "$2" = "${reference}" ]; then
  count="$(cat '${counterPath}' 2>/dev/null || printf 0)"
  count="$((count + 1))"
  printf '%s' "$count" > '${counterPath}'
  printf '%s' '${secret}'
  exit 0
fi
printf 'unexpected op call: %s %s\\n' "$1" "$2" >&2
exit 2
`);
  await chmod(fakeOp, 0o755);
  return fakeOp;
}

async function writeFakeKeychainHelper(dbPath: string): Promise<string> {
  const helper = path.join(tmpHome, "s-gw-keychain-helper");
  await writeFile(helper, `#!/usr/bin/env node
const fs = require("fs");
const dbPath = ${JSON.stringify(dbPath)};

function arg(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || index + 1 >= process.argv.length) {
    return "";
  }
  return process.argv[index + 1];
}

function readDb() {
  try {
    return JSON.parse(fs.readFileSync(dbPath, "utf8"));
  } catch {
    return {};
  }
}

function writeDb(db) {
  fs.writeFileSync(dbPath, JSON.stringify(db, null, 2) + "\\n");
}

const command = process.argv[2];
const service = arg("--service");
const account = arg("--account");
const key = service + "\\u0000" + account;

if (!service || !account) {
  process.stderr.write("missing service/account\\n");
  process.exit(64);
}

if (command === "get") {
  const db = readDb();
  if (!Object.prototype.hasOwnProperty.call(db, key)) {
    process.exit(44);
  }
  process.stdout.write(db[key] + "\\n");
  process.exit(0);
}

if (command === "set") {
  let input = "";
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", chunk => input += chunk);
  process.stdin.on("end", () => {
    const db = readDb();
    db[key] = input;
    writeDb(db);
  });
  return;
}

if (command === "delete") {
  const db = readDb();
  delete db[key];
  writeDb(db);
  process.exit(0);
}

process.stderr.write("unexpected command\\n");
process.exit(2);
`);
  await chmod(helper, 0o755);
  return helper;
}

async function readCount(file: string): Promise<number> {
  const text = await readFile(file, "utf8").catch(() => "0");
  return Number.parseInt(text.trim() || "0", 10);
}
