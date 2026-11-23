import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { realpathSync } from "node:fs";
import { principalForVerifiedPeer } from "../src/agent-context.js";
import {
  attestLauncherChain,
  launcherChainFromAttestation,
  launcherPrincipalId,
  launcherSessionId,
  parseCodesignDetails,
  parseProcessRow
} from "../src/launcher-signature.js";
import { extractNamedDestinations } from "../src/destinations.js";
import { buildEnvCommandAction } from "../src/gateway.js";
import { buildSshSessionAction, SGW_SSH_SESSION_COMMAND } from "../src/ssh.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";
const hour = 60 * 60 * 1000;
// Without this the tests would pick up whichever agent happens to be running them.
const quietEnv = { SGW_DISABLE_PROCESS_AGENT_DETECTION: "1" };
const verifiedCodex = { managedPrincipal: principalForVerifiedPeer("test:codex", "Codex", "session-1"), env: quietEnv };

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

  it("reseals on its own when the seal goes missing and records that it did", async () => {
    const { store, secret, action } = await storeWithGrant();
    await editJson(manifestPath(), (manifest) => { delete manifest.authorizationSeal; });
    expect(await store.authorizationSealStatus()).toBe("unsealed");

    // No operator step: the next write reseals, and the grant keeps working.
    const reused = await store.createRequest(secret.handle, action(), "Reuse after lost seal", verifiedCodex);
    expect(reused.state).toBe("approved");
    expect(await store.authorizationSealStatus()).toBe("sealed");

    const events = (await store.auditLog()).map((event) => event.type);
    expect(events).toContain("store.authorization.resealed");
    expect(events).not.toContain("approval.autoapprove.skipped");
  });

  it("reseals after a replaced seal and still runs a grant-approved request", async () => {
    const { store, secret, action } = await storeWithGrant();
    const reused = await store.createRequest(secret.handle, action(), "Grant reuse before tamper", verifiedCodex);
    expect(reused.state).toBe("approved");

    await editJson(manifestPath(), (manifest) => { manifest.authorizationSeal = "not-a-real-seal"; });
    expect(await store.authorizationSealStatus()).toBe("invalid");
    expect((await store.claimApprovedRequest(reused.id)).state).toBe("executing");

    const resealed = (await store.auditLog()).find((event) => event.type === "store.authorization.resealed");
    expect(resealed?.message).toMatch(/changed outside s-gw \(seal was invalid\)/u);
  });

  it("treats an unsealed home from an older version as an upgrade and carries pending approvals", async () => {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: "upgrade token",
      type: "api-token",
      value: fakeToken("upgrade_path"),
      policy: { injectEnv: "TOKEN", allowedCommands: [process.execPath] }
    });
    const request = await store.createRequest(
      secret.handle,
      buildEnvCommandAction({ command: process.execPath, args: ["-e", "0"], injectEnv: "TOKEN" }),
      "Approved just before the upgrade"
    );
    await store.approveRequest(request.id);

    // What an older runtime leaves behind: no seal anywhere and its own writer version.
    await editJson(manifestPath(), (manifest) => {
      delete manifest.authorizationSeal;
      manifest.writerVersion = "0.1.22";
    });
    await editJson(store.storePath, (raw) => {
      delete raw.requests.find((item: { id: string }) => item.id === request.id).approvalSeal;
    });

    expect((await store.claimApprovedRequest(request.id)).state).toBe("executing");
    const sealed = (await store.auditLog()).find((event) => event.type === "store.authorization.sealed");
    expect(sealed?.message).toMatch(/after upgrading from 0\.1\.22, and carried over 1 approved requests/u);
    expect((await store.auditLog()).map((event) => event.type)).not.toContain("store.authorization.resealed");
    expect(await store.authorizationSealStatus()).toBe("sealed");
  });

  it("does not accept a seal made with a different unlock key", async () => {
    const { store } = await storeWithGrant();
    process.env.SGW_MASTER_PASSPHRASE = "a different passphrase";
    expect(await store.authorizationSealStatus()).toBe("invalid");
  });
});

describe("launcher signature parsing", () => {
  it("reads the identifier and team from codesign output", () => {
    const report = [
      "Executable=/Applications/Example.app/Contents/MacOS/example",
      "Identifier=com.example.agent",
      "Format=Mach-O thin (arm64)",
      "TeamIdentifier=ABCDE12345"
    ].join("\n");
    expect(parseCodesignDetails(report)).toEqual({ teamId: "ABCDE12345", identifier: "com.example.agent" });
  });

  it("ignores code without a team identifier", () => {
    expect(parseCodesignDetails("Identifier=com.apple.zsh\nTeamIdentifier=not set\n")).toBeUndefined();
    expect(parseCodesignDetails("")).toBeUndefined();
  });

  it("reads the parent pid and start time from a ps row", () => {
    expect(parseProcessRow("  827 Sun Nov 22 11:38:59 2026\n")).toEqual({ parentPid: 827, startedAt: "Sun Nov 22 11:38:59 2026" });
    expect(parseProcessRow("\n")).toBeUndefined();
  });

  it("refuses a malformed attestation", () => {
    expect(() => launcherChainFromAttestation([
      { teamId: "short", identifier: "com.example.agent", pid: 10, startedAt: "x" }
    ])).toThrow(/malformed/u);
  });

  it.skipIf(process.platform !== "darwin")("attests this process's ancestors without failing", () => {
    const chain = attestLauncherChain();
    expect(Array.isArray(chain?.signatures)).toBe(true);
    for (const signature of chain?.signatures || []) {
      expect(signature.teamId).toMatch(/^[A-Z0-9]{10}$/u);
      expect(signature.pid).toBeGreaterThan(1);
    }
  });
});

describe("trusted launcher signature tier", () => {
  const signature = { teamId: "ABCDE12345", identifier: "com.example.agent", pid: 4242, startedAt: "Sun Nov 22 10:00:00 2026" };
  const signedAgent = () => ({ launcherChain: launcherChainFromAttestation([signature]), env: quietEnv });
  const principalId = launcherPrincipalId(signature);
  const nodeAction = () => buildEnvCommandAction({ command: process.execPath, args: ["-e", "0"], injectEnv: "TOKEN" });

  async function tokenStore(label: string) {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: `launcher ${label}`,
      type: "api-token",
      value: fakeToken(`launcher_${label}`),
      policy: { injectEnv: "TOKEN", allowedCommands: [process.execPath] }
    });
    return { store, secret };
  }

  it("records the signature but grants nothing until an operator trusts it", async () => {
    const { store, secret } = await tokenStore("untrusted");
    const first = await store.createRequest(secret.handle, nodeAction(), "Untrusted signed agent", signedAgent());
    expect(first.agentSource).not.toBe("signed-launcher");
    expect(first.principalId).toBeUndefined();
    expect(first.launcherSignatures).toEqual([{ teamId: "ABCDE12345", identifier: "com.example.agent" }]);

    await store.approveRequest(first.id, { mode: "timed-session", durationMs: 4 * hour });
    const second = await store.createRequest(secret.handle, nodeAction(), "Untrusted signed agent again", signedAgent());
    expect(second.state).toBe("pending");
  });

  it("treats a trusted signature as a verified agent for grants and its own execution", async () => {
    const { store, secret } = await tokenStore("trusted");
    const seen = await store.createRequest(secret.handle, nodeAction(), "First contact", signedAgent());
    const trusted = await store.addTrustedLauncher({ name: "Example Agent", requestId: seen.id });
    expect(trusted.principalId).toBe(principalId);
    expect(await store.authorizationSealStatus()).toBe("sealed");

    const first = await store.createRequest(secret.handle, nodeAction(), "Trusted run", signedAgent());
    expect(first).toMatchObject({
      state: "pending",
      agentName: "Example Agent",
      agentSource: "signed-launcher",
      principalId,
      agentSessionId: launcherSessionId(signature)
    });
    await store.approveRequest(first.id, { mode: "timed-session", durationMs: 4 * hour });

    const reused = await store.createRequest(secret.handle, nodeAction(), "Trusted repeat", signedAgent());
    expect(reused).toMatchObject({ state: "approved", approvalSource: "grant" });

    const otherSession = { launcherChain: launcherChainFromAttestation([{ ...signature, pid: 9999 }]), env: quietEnv };
    await expect(store.claimApprovedRequest(reused.id, otherSession)).rejects.toThrow(/different verified agent or session/u);
    await expect(store.claimApprovedRequest(reused.id, { mcpClientName: "example", env: quietEnv }))
      .rejects.toThrow(/different verified agent or session/u);
    expect((await store.claimApprovedRequest(reused.id, signedAgent())).state).toBe("executing");
  });

  it("does not extend a grant to a different signature or a forged chain", async () => {
    const { store, secret } = await tokenStore("others");
    await store.addTrustedLauncher({ name: "Example Agent", teamId: "ABCDE12345", identifier: "com.example.agent" });
    const first = await store.createRequest(secret.handle, nodeAction(), "Trusted run", signedAgent());
    await store.approveRequest(first.id, { mode: "timed-session", durationMs: 4 * hour });

    const stranger = { launcherChain: launcherChainFromAttestation([{ ...signature, identifier: "com.example.other" }]), env: quietEnv };
    expect((await store.createRequest(secret.handle, nodeAction(), "Other app", stranger)).state).toBe("pending");

    // Shaped like an attestation but not produced by the attestation module.
    const forged = { launcherChain: { signatures: [signature] }, env: quietEnv };
    const fromForged = await store.createRequest(secret.handle, nodeAction(), "Forged chain", forged);
    expect(fromForged.state).toBe("pending");
    expect(fromForged.agentSource).not.toBe("signed-launcher");
  });

  it("revokes grants and verified standing when the signature is removed", async () => {
    const { store, secret } = await tokenStore("removed");
    const trusted = await store.addTrustedLauncher({ name: "Example Agent", teamId: "ABCDE12345", identifier: "com.example.agent" });
    const first = await store.createRequest(secret.handle, nodeAction(), "Trusted run", signedAgent());
    await store.approveRequest(first.id, { mode: "timed-session", durationMs: 4 * hour });
    const reused = await store.createRequest(secret.handle, nodeAction(), "Trusted repeat", signedAgent());
    expect(reused.state).toBe("approved");

    const removed = await store.removeTrustedLauncher(trusted.launcher.id);
    expect(removed.revokedApprovalGrants).toBe(1);
    await expect(store.claimApprovedRequest(reused.id, signedAgent())).rejects.toThrow();
    const after = await store.createRequest(secret.handle, nodeAction(), "After removal", signedAgent());
    expect(after.state).toBe("pending");
    expect(after.agentSource).not.toBe("signed-launcher");
  });

  it("keeps the trust list working after an automatic reseal", async () => {
    const { store, secret } = await tokenStore("resealed");
    await store.addTrustedLauncher({ name: "Example Agent", teamId: "ABCDE12345", identifier: "com.example.agent" });
    const manifest = path.join(tmpHome, ".store-control.json");
    const raw = JSON.parse(await readFile(manifest, "utf8"));
    delete raw.authorizationSeal;
    await writeFile(manifest, `${JSON.stringify(raw, null, 2)}\n`);

    const request = await store.createRequest(secret.handle, nodeAction(), "After a lost seal", signedAgent());
    expect(request.agentSource).toBe("signed-launcher");
    expect((await store.auditLog()).map((event) => event.type)).toContain("store.authorization.resealed");
  });

  it("refuses to trust a general-purpose runtime", async () => {
    const { store } = await tokenStore("runtime");
    await expect(store.addTrustedLauncher({ name: "Node", teamId: "HX7739G8FX", identifier: "node" }))
      .rejects.toThrow(/general-purpose runtime/u);
    expect(await store.listTrustedLaunchers()).toEqual([]);
  });

  it("can bind an existing name-based allow policy to the pinned signature", async () => {
    const { store, secret } = await tokenStore("policy");
    await store.addApprovalPolicyRule({
      name: "Allow Example Agent",
      decision: "allow",
      conditions: {
        agents: ["Example Agent"],
        handles: [secret.handle],
        commands: [process.execPath],
        resolvedCommands: [realpathSync.native(process.execPath)]
      }
    });
    // A declared name still matches a name-based policy, as it did before verified identities.
    const named = await store.createRequest(secret.handle, nodeAction(), "Example Agent by name", { agentName: "Example Agent", env: quietEnv });
    expect(named).toMatchObject({ state: "approved", approvalSource: "policy", agentSource: "configured" });

    const trusted = await store.addTrustedLauncher({
      name: "Example Agent", teamId: "ABCDE12345", identifier: "com.example.agent", bindPolicies: true
    });
    expect(trusted.boundPolicies).toBe(1);
    const signed = await store.createRequest(secret.handle, nodeAction(), "Signed policy run", signedAgent());
    expect(signed).toMatchObject({ state: "approved", approvalSource: "policy", agentSource: "signed-launcher" });
  });
});

describe("declared agent names and session-bound execution", () => {
  const declared = (nonce?: string) => ({ agentName: "Claude Desktop", env: quietEnv, sessionNonce: nonce });
  const nodeAction = () => buildEnvCommandAction({ command: process.execPath, args: ["-e", "0"], injectEnv: "TOKEN" });

  async function tokenStore(label: string) {
    const store = new SecretStore();
    const secret = await store.addSecret({
      name: `declared ${label}`,
      type: "api-token",
      value: fakeToken(`declared_${label}`),
      policy: { injectEnv: "TOKEN", allowedCommands: [process.execPath] }
    });
    return { store, secret };
  }

  it("keeps reusable grants working for an agent identified by its configured name", async () => {
    const { store, secret } = await tokenStore("grant");
    const first = await store.createRequest(secret.handle, nodeAction(), "First run", declared("session-a"));
    expect(first).toMatchObject({ state: "pending", agentName: "Claude Desktop", agentSource: "configured" });
    const approved = await store.approveRequest(first.id, { mode: "timed-session", durationMs: 4 * hour });
    expect(approved.approvalGrantId).toBeTruthy();

    const reused = await store.createRequest(secret.handle, nodeAction(), "Repeat run", declared("session-a"));
    expect(reused).toMatchObject({ state: "approved", approvalSource: "grant" });
    const other = await store.createRequest(secret.handle, nodeAction(), "Other agent", { agentName: "Codex", env: quietEnv });
    expect(other.state).toBe("pending");
  });

  it("keeps a name-based allow policy working", async () => {
    const { store, secret } = await tokenStore("policy");
    await store.addApprovalPolicyRule({
      name: "Allow Claude Desktop",
      decision: "allow",
      conditions: {
        agents: ["Claude Desktop"],
        handles: [secret.handle],
        commands: [process.execPath],
        resolvedCommands: [realpathSync.native(process.execPath)]
      }
    });
    const request = await store.createRequest(secret.handle, nodeAction(), "Policy run", declared("session-a"));
    expect(request).toMatchObject({ state: "approved", approvalSource: "policy" });
  });

  it("does not let a name taken from the request reason use a grant", async () => {
    const { store, secret } = await tokenStore("reason");
    const first = await store.createRequest(secret.handle, nodeAction(), "Codex wants to run this", { env: quietEnv });
    expect(first.agentSource).toBe("reason");
    const approved = await store.approveRequest(first.id, { mode: "timed-session", durationMs: 4 * hour });
    expect(approved.approvalGrantId).toBeUndefined();
    const second = await store.createRequest(secret.handle, nodeAction(), "Codex wants to run this again", { env: quietEnv });
    expect(second.state).toBe("pending");
  });

  it("lets only the session that created a request execute it", async () => {
    const { store, secret } = await tokenStore("session");
    const request = await store.createRequest(secret.handle, nodeAction(), "Session bound", declared("session-a"));
    expect(request.requesterSession).toMatch(/^[a-f0-9]{64}$/u);
    expect(request.requesterSession).not.toContain("session-a");
    await store.approveRequest(request.id);

    await expect(store.claimApprovedRequest(request.id, declared("session-b"))).rejects.toThrow(/own session created/u);
    await expect(store.claimApprovedRequest(request.id, declared())).rejects.toThrow(/own session created/u);
    expect((await store.getRequest(request.id)).state).toBe("approved");
    expect((await store.claimApprovedRequest(request.id, declared("session-a"))).state).toBe("executing");
  });

  it("leaves operator-created requests to the operator", async () => {
    const { store, secret } = await tokenStore("operator");
    const request = await store.createRequest(secret.handle, nodeAction(), "Operator request");
    await store.approveRequest(request.id);
    await expect(store.claimApprovedRequest(request.id, declared("session-a"))).rejects.toThrow(/own session created/u);
    expect((await store.claimApprovedRequest(request.id)).state).toBe("executing");
  });

  it("notes when a known agent name arrives from a different launcher, without blocking it", async () => {
    const { store, secret } = await tokenStore("launcher");
    const from = (launcher: string) => ({ ...declared("session-a"), observedLaunchers: [launcher, "exe:/usr/bin/zsh"] });
    const first = await store.createRequest(secret.handle, nodeAction(), "First launcher", from("exe:/opt/agent/bin/agent"));
    const same = await store.createRequest(secret.handle, nodeAction(), "Same launcher", from("exe:/opt/agent/bin/agent"));
    const moved = await store.createRequest(secret.handle, nodeAction(), "New launcher", from("exe:/tmp/other/agent"));

    expect(first.launchers).toEqual(["exe:/opt/agent/bin/agent", "exe:/usr/bin/zsh"]);
    expect(moved.state).toBe("pending");
    const changed = (await store.auditLog()).filter((event) => event.type === "agent.launcher.changed");
    expect(changed.map((event) => event.requestId)).toEqual([moved.id]);
    expect(same.id).not.toBe(moved.id);
  });

  it("refuses a request whose session binding was edited after approval", async () => {
    const { store, secret } = await tokenStore("rebind");
    const request = await store.createRequest(secret.handle, nodeAction(), "Rebound", declared("session-a"));
    await store.approveRequest(request.id);
    const raw = JSON.parse(await readFile(store.storePath, "utf8"));
    delete raw.requests.find((item: { id: string }) => item.id === request.id).requesterSession;
    await writeFile(store.storePath, `${JSON.stringify(raw, null, 2)}\n`);
    await expect(store.claimApprovedRequest(request.id)).rejects.toThrow(/changed after approval/u);
  });
});
