import { chmod, copyFile, mkdtemp, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { resolveCommandExecutable } from "../src/command-path.js";
import { executeApprovedRequest, executeReusablePermit } from "../src/executor.js";
import { buildEnvCommandAction } from "../src/gateway.js";
import { SecretStore } from "../src/store.js";

let testRoot = "";
let savedPath: string | undefined;
let savedPathExt: string | undefined;

beforeEach(async () => {
  testRoot = await mkdtemp(path.join(os.tmpdir(), "sgw-command-path-"));
  savedPath = process.env.PATH;
  savedPathExt = process.env.PATHEXT;
  process.env.SGW_HOME = path.join(testRoot, "home");
  process.env.SGW_RECOVERY_HOME = path.join(testRoot, "recovery");
  process.env.SGW_MASTER_PASSPHRASE = "command path test passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
});

afterEach(async () => {
  restoreEnv("PATH", savedPath);
  restoreEnv("PATHEXT", savedPathExt);
  delete process.env.SGW_HOME;
  delete process.env.SGW_RECOVERY_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  vi.restoreAllMocks();
  await rm(testRoot, { recursive: true, force: true });
});

describe("credential command path pinning", () => {
  it("keeps the requested grant string but does not reuse it for a different PATH target", async () => {
    const firstBin = path.join(testRoot, "first-bin");
    const secondBin = path.join(testRoot, "second-bin");
    await mkdir(firstBin);
    await mkdir(secondBin);
    const command = "sgw-path-swap-test";
    const firstExecutable = await writeTestExecutable(firstBin, command);
    const secondExecutable = await writeTestExecutable(secondBin, command);
    process.env.PATH = withOriginalPath(firstBin);

    const store = new SecretStore();
    const primary = await addSecret(store, "primary", "SGW_PIN_PRIMARY", command);
    const extra = await addSecret(store, "extra", "SGW_PIN_EXTRA", command);
    const action = buildEnvCommandAction({
      command,
      injectEnv: "SGW_PIN_PRIMARY",
      env: [{ handle: extra.handle, injectEnv: "SGW_PIN_EXTRA" }]
    });
    const request = await store.createRequest(primary.handle, action, "Codex pinned executable first request");
    expect(request.action.command).toBe(command);
    expect(request.action.resolvedCommand).toBe(await realpath(firstExecutable));

    const approved = await store.approveRequest(request.id, {
      mode: "timed-session",
      durationMs: 60 * 60 * 1000
    });
    expect(approved.approvalGrantId).toMatch(/^grant_/);

    await expect(store.createRequest(
      primary.handle,
      buildEnvCommandAction({ command: firstExecutable, injectEnv: "SGW_PIN_PRIMARY" }),
      "Codex absolute request against bare grant"
    )).rejects.toThrow(/not allowed/i);

    process.env.PATH = withOriginalPath(secondBin);
    const next = await store.createRequest(primary.handle, action, "Codex pinned executable after PATH swap");
    expect(next.action.resolvedCommand).toBe(await realpath(secondExecutable));
    expect(next.state).toBe("pending");
    expect(next.approvalGrantId).toBeUndefined();

    const reveal = vi.spyOn(store, "revealSecretForLocalUse");
    await expect(executeApprovedRequest(store, request.id, { engine: "typescript" }))
      .rejects.toThrow(/different executable/i);
    expect(reveal).not.toHaveBeenCalled();
    expect((await store.getRequest(request.id)).state).toBe("failed");
  });

  it("revalidates reusable permits before revealing a credential", async () => {
    const firstBin = path.join(testRoot, "permit-first");
    const secondBin = path.join(testRoot, "permit-second");
    await mkdir(firstBin);
    await mkdir(secondBin);
    const command = "sgw-permit-path-test";
    await writeTestExecutable(firstBin, command);
    await writeTestExecutable(secondBin, command);
    process.env.PATH = withOriginalPath(firstBin);

    const store = new SecretStore();
    const record = await addSecret(store, "permit", "SGW_PIN_PERMIT", command);
    const action = buildEnvCommandAction({ command, injectEnv: "SGW_PIN_PERMIT" });
    const first = await store.createRequest(record.handle, action, "Codex reusable pin approval");
    await store.approveRequest(first.id, { mode: "timed-session", durationMs: 60 * 60 * 1000 });
    const admission = await store.prepareOneShotExecution(record.handle, action, "Codex reusable pin run");
    expect(admission.kind).toBe("reusable");
    if (admission.kind !== "reusable") throw new Error("Expected a reusable permit.");

    process.env.PATH = withOriginalPath(secondBin);
    const reveal = vi.spyOn(store, "revealSecretForLocalUse");
    await expect(executeReusablePermit(store, admission.permit, { engine: "typescript" }))
      .rejects.toThrow(/different executable/i);
    expect(reveal).not.toHaveBeenCalled();
  });

  it("upgrades legacy absolute requests and rejects legacy bare requests without a pin", async () => {
    const store = new SecretStore();
    const absoluteSecret = await addSecret(store, "absolute", "SGW_LEGACY_ABSOLUTE", process.execPath);
    const absoluteRequest = await store.createRequest(
      absoluteSecret.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "process.stdout.write('legacy-absolute-ok')"],
        injectEnv: "SGW_LEGACY_ABSOLUTE"
      }),
      "Codex legacy absolute request"
    );
    await removeStoredPin(store.storePath, absoluteRequest.id);
    await store.approveRequest(absoluteRequest.id);
    const summary = await executeApprovedRequest(store, absoluteRequest.id, { engine: "typescript" });
    expect(summary.stdout).toBe("legacy-absolute-ok");
    expect((await store.getRequest(absoluteRequest.id)).action.resolvedCommand).toBe(await realpath(process.execPath));

    const legacyPolicyRequest = await store.createRequest(
      absoluteSecret.handle,
      buildEnvCommandAction({
        command: process.execPath,
        args: ["-e", "0"],
        injectEnv: "SGW_LEGACY_ABSOLUTE"
      }),
      "Codex legacy policy request"
    );
    await removeStoredPin(store.storePath, legacyPolicyRequest.id);
    await expect(store.approveRequestWithScopedPolicy(legacyPolicyRequest.id))
      .rejects.toThrow(/legacy request has no pinned executable/i);

    const binDir = path.join(testRoot, "legacy-bare-bin");
    await mkdir(binDir);
    const bare = "sgw-legacy-bare-test";
    await writeTestExecutable(binDir, bare);
    process.env.PATH = withOriginalPath(binDir);
    const bareSecret = await addSecret(store, "bare", "SGW_LEGACY_BARE", bare);
    const bareRequest = await store.createRequest(
      bareSecret.handle,
      buildEnvCommandAction({ command: bare, injectEnv: "SGW_LEGACY_BARE" }),
      "Codex legacy bare request"
    );
    await removeStoredPin(store.storePath, bareRequest.id);
    await store.approveRequest(bareRequest.id);

    const reveal = vi.spyOn(store, "revealSecretForLocalUse");
    await expect(executeApprovedRequest(store, bareRequest.id, { engine: "typescript" }))
      .rejects.toThrow(/legacy request has no pinned executable/i);
    expect(reveal).not.toHaveBeenCalled();
    expect((await store.getRequest(bareRequest.id)).state).toBe("failed");
  });

  it("rejects Windows shell script launchers", () => {
    for (const command of ["tool.cmd", "tool.bat", "tool.ps1"]) {
      expect(() => resolveCommandExecutable(command, {
        platform: "win32",
        env: { PATH: "C:\\Tools", PATHEXT: ".EXE;.COM;.CMD;.BAT" },
        cwd: "C:\\work"
      })).toThrow(/script launchers are not accepted/i);
    }
  });
});

async function addSecret(store: SecretStore, name: string, injectEnv: string, command: string) {
  return store.addSecret({
    name,
    type: "api-token",
    value: `${name}-command-path-secret-value-123456789`,
    policy: { injectEnv, allowedCommands: [command] }
  });
}

async function writeTestExecutable(directory: string, command: string): Promise<string> {
  const file = path.join(directory, process.platform === "win32" ? `${command}.exe` : command);
  if (process.platform === "win32") {
    await copyFile(process.execPath, file);
  } else {
    await writeFile(file, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  }
  await chmod(file, 0o700);
  return file;
}

async function removeStoredPin(storePath: string, requestId: string): Promise<void> {
  const raw = JSON.parse(await readFile(storePath, "utf8"));
  const request = raw.requests.find((item: { id: string }) => item.id === requestId);
  delete request.action.resolvedCommand;
  await writeFile(storePath, `${JSON.stringify(raw, null, 2)}\n`);
}

function withOriginalPath(directory: string): string {
  return [directory, savedPath].filter(Boolean).join(path.delimiter);
}

function restoreEnv(name: string, value: string | undefined): void {
  if (value === undefined) {
    delete process.env[name];
    return;
  }
  process.env[name] = value;
}
