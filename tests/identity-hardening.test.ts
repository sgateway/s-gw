import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { principalForVerifiedPeer } from "../src/agent-context.js";
import { extractNamedDestinations } from "../src/destinations.js";
import { buildEnvCommandAction } from "../src/gateway.js";
import { buildSshSessionAction, SGW_SSH_SESSION_COMMAND } from "../src/ssh.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";
const hour = 60 * 60 * 1000;
const verifiedCodex = { managedPrincipal: principalForVerifiedPeer("test:codex", "Codex", "session-1"), env: {} };

function fakeToken(label: string): string {
  return ["sk", "-proj-", label, "_1234567890abcdef"].join("");
}

beforeEach(async () => {
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-hardening-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_RECOVERY_HOME = `${tmpHome}-recovery`;
  process.env.SGW_MASTER_PASSPHRASE = "local test passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
});

afterEach(async () => {
  vi.useRealTimers();
  delete process.env.SGW_HOME;
  delete process.env.SGW_RECOVERY_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  await rm(tmpHome, { recursive: true, force: true });
  await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
});

describe("handle destination enforcement", () => {
  it("only treats URLs and host flags as named env-command destinations", () => {
    const action = buildEnvCommandAction({
      command: "/usr/bin/tool",
      args: ["deploy.sh", "notes.md", "https://api.example.test/v1", "--host", "db.example.test", "--endpoint=cache.example.test:6379"],
      injectEnv: "TOKEN"
    });
    expect(extractNamedDestinations(action)).toEqual([
      { host: "api.example.test", port: 443 },
      { host: "db.example.test" },
      { host: "cache.example.test", port: 6379 }
    ]);
  });

  it("refuses an env command that names a destination outside the handle list", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "pinned api token",
      type: "api-token",
      value: fakeToken("pinned_destination"),
      policy: { injectEnv: "TOKEN", allowedCommands: [process.execPath], allowedDestinations: ["api.example.test:443"] }
    });
    const run = (args: string[]) => store.createRequest(
      secret.handle,
      buildEnvCommandAction({ command: process.execPath, args, injectEnv: "TOKEN" }),
      "Destination enforcement"
    );

    await expect(run(["-e", "0", "https://evil.example.test/collect"])).rejects.toThrow(/evil\.example\.test:443 is not allowed/u);
    await expect(run(["-e", "0", "--url=http://api.example.test/"])).rejects.toThrow(/api\.example\.test:80 is not allowed/u);
    expect((await run(["-e", "0", "https://api.example.test/v1/items"])).state).toBe("pending");
    // No named destination: the command allowlist alone decides, as before.
    expect((await run(["-e", "0", "deploy.sh"])).state).toBe("pending");
  });

  it("leaves handles without a destination list unchanged", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "open api token",
      type: "api-token",
      value: fakeToken("open_destination"),
      policy: { injectEnv: "TOKEN", allowedCommands: [process.execPath] }
    });
    const request = await store.createRequest(
      secret.handle,
      buildEnvCommandAction({ command: process.execPath, args: ["-e", "0", "https://anywhere.example.test/"], injectEnv: "TOKEN" }),
      "No destination list"
    );
    expect(request.state).toBe("pending");
  });

  it("checks the SSH target against the handle list", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "pinned ssh password",
      type: "password",
      value: "correct horse battery staple 42",
      policy: { allowedCommands: [SGW_SSH_SESSION_COMMAND], allowedDestinations: ["build.example.test:22"] }
    });

    await expect(store.createRequest(
      secret.handle,
      buildSshSessionAction({ target: "deploy@other.example.test", args: ["uptime"] }),
      "SSH destination enforcement"
    )).rejects.toThrow(/other\.example\.test:22 is not allowed/u);
    await expect(store.createRequest(
      secret.handle,
      buildSshSessionAction({ target: "deploy@build.example.test", port: 2222, args: ["uptime"] }),
      "SSH port enforcement"
    )).rejects.toThrow(/build\.example\.test:2222 is not allowed/u);

    const allowed = await store.createRequest(
      secret.handle,
      buildSshSessionAction({ target: "deploy@build.example.test", args: ["uptime"] }),
      "SSH allowed destination"
    );
    expect(allowed.state).toBe("pending");
  });
});

describe("manual approval expiry at claim", () => {
  async function approvedNodeRequest(store: SecretStore, label: string, caller?: typeof verifiedCodex) {
    const secret = await store.addSecret({
      name: `expiry ${label}`,
      type: "api-token",
      value: fakeToken(`expiry_${label}`),
      policy: { injectEnv: "TOKEN", allowedCommands: [process.execPath] }
    });
    const action = () => buildEnvCommandAction({ command: process.execPath, args: ["-e", "0"], injectEnv: "TOKEN" });
    const request = await store.createRequest(secret.handle, action(), `Expiry ${label}`, caller);
    return { secret, request, action };
  }

  it("claims a manual approval inside the hour", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-22T10:00:00Z"));
    const store = new SecretStore();
    const { request } = await approvedNodeRequest(store, "fresh");
    await store.approveRequest(request.id);

    vi.setSystemTime(new Date(Date.parse("2026-11-22T10:00:00Z") + hour - 1000));
    expect((await store.claimApprovedRequest(request.id)).state).toBe("executing");
  });

  it("refuses a manual approval left unused for an hour and records why", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-22T10:00:00Z"));
    const store = new SecretStore();
    const { request } = await approvedNodeRequest(store, "stale");
    await store.approveRequest(request.id);

    vi.setSystemTime(new Date(Date.parse("2026-11-22T10:00:00Z") + hour));
    await expect(store.claimApprovedRequest(request.id)).rejects.toThrow(/expired before execution/u);

    const after = await store.getRequest(request.id);
    expect(after.state).toBe("failed");
    expect(after.error).toMatch(/Create a fresh request/u);
    const events = (await store.auditLog()).filter((event) => event.requestId === request.id).map((event) => event.type);
    expect(events).toContain("request.expired");
    await expect(store.claimApprovedRequest(request.id)).rejects.toThrow(/is failed/u);
  });

  it("does not expire a request approved by a live reusable grant", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-11-22T10:00:00Z"));
    const store = new SecretStore();
    const { secret, request, action } = await approvedNodeRequest(store, "grant", verifiedCodex);
    await store.approveRequest(request.id, { mode: "timed-session", durationMs: 4 * hour });

    const reused = await store.createRequest(secret.handle, action(), "Expiry grant reuse", verifiedCodex);
    expect(reused.state).toBe("approved");
    expect(reused.approvalSource).toBe("grant");

    vi.setSystemTime(new Date(Date.parse("2026-11-22T10:00:00Z") + 2 * hour));
    expect((await store.claimApprovedRequest(reused.id)).state).toBe("executing");
  });
});

describe("sealed authorization state", () => {
  const manifestPath = () => path.join(tmpHome, ".store-control.json");

  async function storeWithGrant() {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "sealed grant token",
      type: "api-token",
      value: fakeToken("sealed_grant"),
      policy: { injectEnv: "TOKEN", allowedCommands: [process.execPath] }
    });
    const action = () => buildEnvCommandAction({ command: process.execPath, args: ["-e", "0"], injectEnv: "TOKEN" });
    const first = await store.createRequest(secret.handle, action(), "Sealed grant first run", verifiedCodex);
    await store.approveRequest(first.id, { mode: "timed-session", durationMs: 4 * hour });
    return { store, secret, action, first };
  }

  async function editJson(file: string, edit: (value: any) => void): Promise<void> {
    const value = JSON.parse(await readFile(file, "utf8"));
    edit(value);
    await writeFile(file, `${JSON.stringify(value, null, 2)}\n`);
  }

  it("seals a new home and keeps the seal across ordinary changes", async () => {
    const { store, secret, action } = await storeWithGrant();
    expect(await store.authorizationSealStatus()).toBe("sealed");

    const reused = await store.createRequest(secret.handle, action(), "Sealed grant reuse", verifiedCodex);
    expect(reused.state).toBe("approved");
    expect(reused.approvalSeal).toBeTruthy();
    expect((await store.claimApprovedRequest(reused.id)).state).toBe("executing");
  });

  it("refuses a request flipped to approved outside s-gw", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "forged approval token",
      type: "api-token",
      value: fakeToken("forged_approval"),
      policy: { injectEnv: "TOKEN", allowedCommands: [process.execPath] }
    });
    const request = await store.createRequest(
      secret.handle,
      buildEnvCommandAction({ command: process.execPath, args: ["-e", "0"], injectEnv: "TOKEN" }),
      "Forged approval"
    );
    await editJson(store.storePath, (raw) => {
      const stored = raw.requests.find((item: { id: string }) => item.id === request.id);
      stored.state = "approved";
      stored.approvedAt = new Date().toISOString();
      stored.approvalSource = "manual";
    });

    await expect(store.claimApprovedRequest(request.id)).rejects.toThrow(/not sealed by this s-gw installation/u);
    expect((await store.getRequest(request.id)).state).toBe("failed");
    const events = (await store.auditLog()).filter((event) => event.requestId === request.id).map((event) => event.type);
    expect(events).toContain("request.seal_invalid");
  });

  it("refuses an approved request whose arguments changed after approval", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "swapped argv token",
      type: "api-token",
      value: fakeToken("swapped_argv"),
      policy: { injectEnv: "TOKEN", allowedCommands: [process.execPath] }
    });
    const request = await store.createRequest(
      secret.handle,
      buildEnvCommandAction({ command: process.execPath, args: ["-e", "0"], injectEnv: "TOKEN" }),
      "Swapped argv"
    );
    await store.approveRequest(request.id);
    await editJson(store.storePath, (raw) => {
      raw.requests.find((item: { id: string }) => item.id === request.id).action.args = ["-e", "process.exit(7)"];
    });

    await expect(store.claimApprovedRequest(request.id)).rejects.toThrow(/changed after approval/u);
  });

  it("stops grants from approving once the seal is removed, until an operator reseals", async () => {
    const { store, secret, action } = await storeWithGrant();
    await editJson(manifestPath(), (manifest) => { delete manifest.authorizationSeal; });
    expect(await store.authorizationSealStatus()).toBe("unsealed");

    const waiting = await store.createRequest(secret.handle, action(), "Unsealed grant reuse", verifiedCodex);
    expect(waiting.state).toBe("pending");
    const skipped = (await store.auditLog()).filter((event) => event.requestId === waiting.id).map((event) => event.type);
    expect(skipped).toContain("approval.autoapprove.skipped");

    // A one-off human approval is sealed on its own and still runs.
    await store.approveRequest(waiting.id);
    expect((await store.claimApprovedRequest(waiting.id)).state).toBe("executing");

    const sealed = await store.sealAuthorizationState();
    expect(sealed).toMatchObject({ status: "sealed", previous: "unsealed", approvalGrants: 1 });
    const reused = await store.createRequest(secret.handle, action(), "Resealed grant reuse", verifiedCodex);
    expect(reused.state).toBe("approved");
  });

  it("refuses to claim a grant-approved request after the seal is replaced", async () => {
    const { store, secret, action } = await storeWithGrant();
    const reused = await store.createRequest(secret.handle, action(), "Grant reuse before tamper", verifiedCodex);
    expect(reused.state).toBe("approved");

    await editJson(manifestPath(), (manifest) => { manifest.authorizationSeal = "not-a-real-seal"; });
    expect(await store.authorizationSealStatus()).toBe("invalid");
    await expect(store.claimApprovedRequest(reused.id)).rejects.toThrow(/not sealed by this s-gw installation/u);
    expect((await store.getRequest(reused.id)).state).toBe("denied");
  });

  it("does not accept a seal made with a different unlock key", async () => {
    const { store } = await storeWithGrant();
    process.env.SGW_MASTER_PASSPHRASE = "a different passphrase";
    expect(await store.authorizationSealStatus()).toBe("invalid");
  });
});
