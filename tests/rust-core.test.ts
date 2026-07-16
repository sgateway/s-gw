import { existsSync } from "node:fs";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, afterEach, beforeEach, describe, expect, it } from "vitest";
import { executeApprovedRequest } from "../src/executor.js";
import { buildEnvCommandAction } from "../src/gateway.js";
import { tokenForHandle } from "../src/scanner.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";
const oldEngine = process.env.SGW_EXECUTION_ENGINE;
const oldAwsSecret = process.env.AWS_SECRET_ACCESS_KEY;
const coreName = process.platform === "win32" ? "s-gw-core.exe" : "s-gw-core";
const packagedCore = path.resolve("dist", "native", coreName);
const coreIt = existsSync(packagedCore) ? it : it.skip;

beforeEach(async () => {
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-rust-core-test-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_MASTER_PASSPHRASE = "rust core test passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_EXECUTION_ENGINE = "rust";
});

afterEach(async () => {
  delete process.env.SGW_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  delete process.env.SGW_EXECUTION_ENGINE;
  delete process.env.AWS_SECRET_ACCESS_KEY;
  await rm(tmpHome, { recursive: true, force: true });
});

afterAll(() => {
  restoreEnv("SGW_EXECUTION_ENGINE", oldEngine);
  restoreEnv("AWS_SECRET_ACCESS_KEY", oldAwsSecret);
});

describe("Rust execution core", () => {
  coreIt("isolates parent credentials and sanitizes consecutive approved executions", async () => {
    process.env.AWS_SECRET_ACCESS_KEY = "parent-credential-must-not-reach-child";
    const store = new SecretStore();
    const first = await addCredential(store, "first", "rust-first-secret-value-123456789");
    const second = await addCredential(store, "second", "rust-second-secret-value-123456789");

    const firstSummary = await approveAndExecute(store, first.handle, "SGW_RUST_FIRST", [
      "console.log(process.env.SGW_RUST_FIRST)",
      "console.log(process.env.AWS_SECRET_ACCESS_KEY || 'parent-secret-absent')",
      "console.log(process.env.SGW_MASTER_PASSPHRASE || 'master-passphrase-absent')"
    ].join(";"));
    expect(firstSummary.stdout).toContain(tokenForHandle(first.handle));
    expect(firstSummary.stdout).toContain("parent-secret-absent");
    expect(firstSummary.stdout).toContain("master-passphrase-absent");
    expect(firstSummary.stdout).not.toContain("rust-first-secret-value");
    expect(firstSummary.stdout).not.toContain("parent-credential-must-not-reach-child");

    const secondSummary = await approveAndExecute(
      store,
      second.handle,
      "SGW_RUST_SECOND",
      "console.log(process.env.SGW_RUST_SECOND)"
    );
    expect(secondSummary.stdout).toContain(tokenForHandle(second.handle));
    expect(secondSummary.stdout).not.toContain("rust-second-secret-value");
    expect(secondSummary.stdout).not.toContain(tokenForHandle(first.handle));
  });

  it("fails closed when the Rust core is required but missing", async () => {
    const store = new SecretStore();
    const secret = "missing-core-secret-value-123456789";
    const record = await addCredential(store, "missing core", secret);
    const request = await createRequest(store, record.handle, "SGW_MISSING_CORE", "console.log('should-not-run')");
    await store.approveRequest(request.id);
    const missingCore = path.join(tmpHome, "does-not-exist", "s-gw-core");

    await expect(executeApprovedRequest(store, request.id, {
      engine: "rust",
      coreBinary: missingCore
    })).rejects.toThrow(/Rust execution core is unavailable/);
    const failed = await store.getRequest(request.id);
    expect(failed.state).toBe("failed");
    expect(failed.error).not.toContain(secret);
  });

  it("rejects a core response containing a raw credential", async () => {
    if (process.platform === "win32") return;

    const fakeCore = path.join(tmpHome, "fake-core");
    await writeFile(fakeCore, [
      "#!/usr/bin/env node",
      "let input = '';",
      "process.stdin.on('data', chunk => input += chunk);",
      "process.stdin.on('end', () => {",
      "  const request = JSON.parse(input);",
      "  console.log(JSON.stringify({",
      "    exitCode: 0, signal: null, stdout: request.secretValue, stderr: '',",
      "    proof: 'invalid', durationMs: 1, timeoutMs: request.timeoutMs,",
      "    timedOut: false, sanitized: false",
      "  }));",
      "});"
    ].join("\n"), { mode: 0o700 });
    await chmod(fakeCore, 0o700);

    const store = new SecretStore();
    const secret = "malicious-core-secret-value-123456789";
    const record = await addCredential(store, "malicious core", secret);
    const request = await createRequest(store, record.handle, "SGW_BAD_CORE", "console.log('should-not-run')");
    await store.approveRequest(request.id);

    await expect(executeApprovedRequest(store, request.id, {
      engine: "rust",
      coreBinary: fakeCore
    })).rejects.toThrow("Rust execution core returned unsanitized output.");
    const failed = await store.getRequest(request.id);
    expect(failed.state).toBe("failed");
    expect(failed.error).not.toContain(secret);
  });

  coreIt("terminates commands at the approved timeout", async () => {
    const store = new SecretStore();
    const record = await addCredential(store, "timeout", "rust-timeout-secret-value-123456789");
    const request = await createRequest(
      store,
      record.handle,
      "SGW_RUST_TIMEOUT",
      "setTimeout(() => console.log('late'), 5000)",
      30
    );
    await store.approveRequest(request.id);

    const summary = await executeApprovedRequest(store, request.id);
    expect(summary.exitCode).toBe(124);
    expect(summary.timedOut).toBe(true);
    expect(summary.durationMs).toBeLessThan(2_000);
  });

  it("preserves the explicit TypeScript compatibility path", async () => {
    const store = new SecretStore();
    const secret = "typescript-fallback-secret-value-123456789";
    const record = await addCredential(store, "fallback", secret);
    const request = await createRequest(
      store,
      record.handle,
      "SGW_TYPESCRIPT_FALLBACK",
      "console.log(process.env.SGW_TYPESCRIPT_FALLBACK)"
    );
    await store.approveRequest(request.id);

    const summary = await executeApprovedRequest(store, request.id, { engine: "typescript" });
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).toContain(tokenForHandle(record.handle));
    expect(summary.stdout).not.toContain(secret);
    expect(summary.proof).toMatch(new RegExp(`^s-gw-proof:${request.id}:`));
  });

  it("uses the compatibility path when automatic mode has no platform core", async () => {
    const store = new SecretStore();
    const secret = "automatic-fallback-secret-value-123456789";
    const record = await addCredential(store, "automatic fallback", secret);
    const request = await createRequest(
      store,
      record.handle,
      "SGW_AUTOMATIC_FALLBACK",
      "console.log(process.env.SGW_AUTOMATIC_FALLBACK)"
    );
    await store.approveRequest(request.id);

    const summary = await executeApprovedRequest(store, request.id, {
      engine: "auto",
      coreBinary: path.join(tmpHome, "missing-platform-core")
    });
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).toContain(tokenForHandle(record.handle));
    expect(summary.stdout).not.toContain(secret);
  });

  it("falls back before launch when automatic mode finds an incompatible core", async () => {
    const incompatibleCore = path.join(tmpHome, process.platform === "win32" ? "foreign-core.exe" : "foreign-core");
    await writeFile(incompatibleCore, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), { mode: 0o700 });
    await chmod(incompatibleCore, 0o700);

    const store = new SecretStore();
    const secret = "incompatible-core-secret-value-123456789";
    const record = await addCredential(store, "incompatible core", secret);
    const request = await createRequest(
      store,
      record.handle,
      "SGW_INCOMPATIBLE_CORE",
      "console.log(process.env.SGW_INCOMPATIBLE_CORE)"
    );
    await store.approveRequest(request.id);

    const summary = await executeApprovedRequest(store, request.id, {
      engine: "auto",
      coreBinary: incompatibleCore
    });
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).toContain(tokenForHandle(record.handle));
    expect(summary.stdout).not.toContain(secret);
  });

  it("fails closed when an incompatible core is explicitly required", async () => {
    const incompatibleCore = path.join(tmpHome, process.platform === "win32" ? "required-foreign.exe" : "required-foreign");
    await writeFile(incompatibleCore, Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), { mode: 0o700 });
    await chmod(incompatibleCore, 0o700);

    const store = new SecretStore();
    const record = await addCredential(store, "required incompatible core", "required-incompatible-secret-value-123456789");
    const request = await createRequest(store, record.handle, "SGW_REQUIRED_CORE", "console.log('must-not-run')");
    await store.approveRequest(request.id);

    await expect(executeApprovedRequest(store, request.id, {
      engine: "rust",
      coreBinary: incompatibleCore
    })).rejects.toThrow(/not compatible|could not be launched/i);
    expect((await store.getRequest(request.id)).state).toBe("failed");
  });

  it("falls back only when an automatic core cannot be launched", async () => {
    if (process.platform === "win32") return;
    const brokenCore = path.join(tmpHome, "missing-interpreter-core");
    await writeFile(brokenCore, "#!/definitely/missing/s-gw-interpreter\n", { mode: 0o700 });
    await chmod(brokenCore, 0o700);

    const store = new SecretStore();
    const record = await addCredential(store, "launch fallback", "launch-fallback-secret-value-123456789");
    const request = await createRequest(
      store,
      record.handle,
      "SGW_LAUNCH_FALLBACK",
      "console.log(process.env.SGW_LAUNCH_FALLBACK)"
    );
    await store.approveRequest(request.id);

    const summary = await executeApprovedRequest(store, request.id, {
      engine: "auto",
      coreBinary: brokenCore
    });
    expect(summary.stdout).toContain(tokenForHandle(record.handle));
    expect(summary.stdout).not.toContain("launch-fallback-secret-value");
  });

  it("does not retry an already launched core failure through TypeScript", async () => {
    if (process.platform === "win32") return;
    const failingCore = path.join(tmpHome, "failing-core");
    await writeFile(failingCore, "#!/bin/sh\necho 'core rejected request' >&2\nexit 23\n", { mode: 0o700 });
    await chmod(failingCore, 0o700);

    const store = new SecretStore();
    const record = await addCredential(store, "no retry", "no-retry-secret-value-123456789");
    const request = await createRequest(store, record.handle, "SGW_NO_RETRY", "console.log('must-not-run')");
    await store.approveRequest(request.id);

    await expect(executeApprovedRequest(store, request.id, {
      engine: "auto",
      coreBinary: failingCore
    })).rejects.toThrow("core rejected request");
    expect((await store.getRequest(request.id)).state).toBe("failed");
  });
});

async function addCredential(store: SecretStore, name: string, value: string) {
  return store.addSecret({
    name,
    type: "credential",
    value,
    policy: {
      allowedCommands: [process.execPath],
      maxOutputBytes: 4096
    }
  });
}

async function createRequest(
  store: SecretStore,
  handle: string,
  injectEnv: string,
  script: string,
  timeoutMs = 30_000
) {
  return store.createRequest(
    handle,
    buildEnvCommandAction({
      command: process.execPath,
      args: ["-e", script],
      injectEnv,
      timeoutMs
    }),
    "Rust core compatibility test",
    { name: "Codex", source: "configured" }
  );
}

async function approveAndExecute(
  store: SecretStore,
  handle: string,
  injectEnv: string,
  script: string
) {
  const request = await createRequest(store, handle, injectEnv, script);
  await store.approveRequest(request.id);
  return executeApprovedRequest(store, request.id);
}

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }
  process.env[name] = value;
}
