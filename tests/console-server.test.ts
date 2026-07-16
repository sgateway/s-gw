import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { startConsoleServer, type RunningConsoleServer } from "../src/console-server.js";
import { ReleaseChecker } from "../src/update-check.js";

let tmpHome = "";
let running: RunningConsoleServer | undefined;
let oldEnv: NodeJS.ProcessEnv;

function fakeOpenAiToken(): string {
  return ["sk", "-proj-", "abcdefghijklmnopqrstuvwxyz1234567890"].join("");
}

beforeEach(async () => {
  oldEnv = { ...process.env };
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-console-e2e-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_RECOVERY_HOME = `${tmpHome}-recovery`;
  process.env.SGW_MASTER_PASSPHRASE = "console e2e passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
});

afterEach(async () => {
  if (running) {
    await running.close();
    running = undefined;
  }

  process.env = oldEnv;
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
  }
});

describe("local console server", () => {
  it("serves the console with a session token and protects local API writes", async () => {
    running = await startConsoleServer({ port: 0 });

    const html = await fetchText("/");
    expect(html).toContain("s-gw");
    expect(html).toContain("SGW_CONSOLE_TOKEN");

    const rejected = await fetch(`${running.url}api/secrets`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "blocked", value: "nope" })
    });
    expect(rejected.status).toBe(403);
  });

  it("does not report favicon requests as server errors", async () => {
    running = await startConsoleServer({ port: 0 });

    const response = await fetch(`${running.url}favicon.ico`);
    expect(response.status).toBe(204);
  });

  it("serves actionable agent configuration details", async () => {
    running = await startConsoleServer({ port: 0 });

    const state = await fetchJson("api/state");
    const codex = state.agents.find((agent: { id: string }) => agent.id === "codex");
    const omnigent = state.agents.find((agent: { id: string }) => agent.id === "omnigent");

    expect(codex.mcp.snippet).toContain("[mcp_servers.s-gw]");
    expect(codex.mcp.configPaths).toContain("~/.codex/config.toml");
    expect(codex.snippetCommand).toBe("s-gw agent mcp-snippet codex");
    expect(codex.guardCommand).toBe("s-gw run codex");
    expect(codex.codeGuard.supported).toBe(true);
    expect(omnigent.mcp.supported).toBe(false);
    expect(omnigent.mcp.snippet).toBeNull();
  });

  it("installs and uninstalls a detected agent through the console API", async () => {
    const binDir = path.join(tmpHome, "bin");
    mkdirSync(binDir, { recursive: true });
    const commandPath = path.join(binDir, process.platform === "win32" ? "codex.cmd" : "codex");
    writeFileSync(commandPath, process.platform === "win32" ? "@exit /b 0\r\n" : "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    if (process.platform !== "win32") chmodSync(commandPath, 0o755);
    const mcpPath = path.join(binDir, process.platform === "win32" ? "s-gw-mcp.cmd" : "s-gw-mcp");
    writeFileSync(mcpPath, process.platform === "win32" ? "@exit /b 0\r\n" : "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    if (process.platform !== "win32") chmodSync(mcpPath, 0o755);

    running = await startConsoleServer({ port: 0, agentHomeDir: tmpHome, agentPathEnv: binDir });
    const before = await fetchJson("api/state");
    expect(before.metrics.activeAgents).toBe(0);
    expect(before.agents.find((agent: { id: string }) => agent.id === "codex").integration).toMatchObject({
      detected: true,
      state: "available"
    });

    const connected = await fetchJson("api/agents/codex/install", { method: "POST", body: {} });
    expect(connected.result).toMatchObject({ state: "installed", changed: true });
    const configPath = path.join(tmpHome, ".codex", "config.toml");
    expect(readFileSync(configPath, "utf8")).toContain("[mcp_servers.s-gw]");
    expect(existsSync(path.join(tmpHome, ".codex", "skills", "s-gw", "SKILL.md"))).toBe(true);

    const after = await fetchJson("api/state");
    expect(after.metrics.activeAgents).toBe(1);
    expect(after.agents.find((agent: { id: string }) => agent.id === "codex").integration.state).toBe("installed");

    const disconnected = await fetchJson("api/agents/codex/uninstall", { method: "POST", body: {} });
    expect(disconnected.result.changed).toBe(true);
    expect(readFileSync(configPath, "utf8")).not.toContain("mcp_servers.s-gw");
  });

  it("keeps the console available when agent ownership metadata is malformed", async () => {
    const manifestPath = path.join(tmpHome, ".s-gw", "agent-integrations.json");
    mkdirSync(path.dirname(manifestPath), { recursive: true });
    writeFileSync(manifestPath, "{ not valid json");

    running = await startConsoleServer({ port: 0, agentHomeDir: tmpHome });
    const state = await fetchJson("api/state");
    expect(state.ready).toBeTypeOf("boolean");
    expect(state.agents.find((agent: { id: string }) => agent.id === "codex").integration).toMatchObject({
      state: "conflict"
    });

    const result = await fetchJson("api/agents/codex/install", { method: "POST", body: {} });
    expect(result.result).toMatchObject({ state: "conflict", changed: false });
    expect(readFileSync(manifestPath, "utf8")).toBe("{ not valid json");
  });

  it("publishes an available release to console clients", async () => {
    const checker = new ReleaseChecker({
      cachePath: path.join(tmpHome, "update.json"),
      currentVersion: "0.1.0",
      enabled: true,
      fetcher: async () => new Response(JSON.stringify([{
        tag_name: "v0.1.1",
        html_url: "https://github.com/sgateway/s-gw/releases/tag/v0.1.1",
        draft: false,
        prerelease: true,
        published_at: "2026-07-04T00:00:00.000Z"
      }]), { status: 200 })
    });
    await checker.check(true);
    running = await startConsoleServer({ port: 0, updateChecker: checker });

    const state = await fetchJson("api/state");
    expect(state.update).toMatchObject({
      currentVersion: "0.1.0",
      latestVersion: "0.1.1",
      available: true,
      prerelease: true
    });
  });

  it("runs a secret-backed command through the HTTP console lifecycle", async () => {
    running = await startConsoleServer({ port: 0 });

    const created = await fetchJson("api/secrets", {
      method: "POST",
      body: {
        name: "console-e2e",
        type: "api-token",
        value: "console-e2e-secret-value-1234567890",
        injectEnv: "SGW_E2E_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    expect(created.handle).toMatch(/^s-gw:api-token:/);

    const request = await fetchJson("api/requests", {
      method: "POST",
      body: {
        handle: created.handle,
        command: process.execPath,
        args: ["-e", "console.log(process.env.SGW_E2E_TOKEN)"],
        injectEnv: "SGW_E2E_TOKEN",
        reason: "Codex console e2e"
      }
    });
    expect(request.state).toBe("pending");

    const early = await fetch(`${running.url}api/requests/${request.id}/execute`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}"
    });
    expect(early.status).toBe(409);

    const stateBefore = await fetchJson("api/state");
    expect(stateBefore.metrics.localSecrets).toBe(1);
    expect(stateBefore.metrics.pendingApprovals).toBe(1);
    expect(stateBefore.pendingRequests[0].id).toBe(request.id);

    const approved = await fetchJson(`api/requests/${request.id}/approve`, {
      method: "POST",
      body: {}
    });
    expect(approved.state).toBe("approved");

    const executed = await fetchJson(`api/requests/${request.id}/execute`, {
      method: "POST",
      body: {}
    });
    expect(executed.exitCode).toBe(0);
    expect(executed.stdout).not.toContain("console-e2e-secret-value");
    expect(executed.stdout).toContain(`<<SGW_SECRET:${created.handle}>>`);
    expect(executed.proof).toMatch(/^s-gw-proof:/);

    const second = await fetchJson("api/requests", {
      method: "POST",
      body: {
        handle: created.handle,
        command: process.execPath,
        args: ["-e", "console.log('should-not-run')"],
        injectEnv: "SGW_E2E_TOKEN",
        reason: "Codex second request"
      }
    });
    const denied = await fetchJson(`api/requests/${second.id}/deny`, {
      method: "POST",
      body: {}
    });
    expect(denied.state).toBe("denied");

    const deniedExecute = await fetch(`${running.url}api/requests/${second.id}/execute`, {
      method: "POST",
      headers: authHeaders(),
      body: "{}"
    });
    expect(deniedExecute.status).toBe(409);

    const csv = await fetchText("api/audit.csv");
    expect(csv).toContain("request.executed");
    expect(csv).toContain("request.denied");
    expect(csv).not.toContain("console-e2e-secret-value");
  });

  it("deletes a credential through the HTTP console API", async () => {
    running = await startConsoleServer({ port: 0 });

    const created = await fetchJson("api/secrets", {
      method: "POST",
      body: {
        name: "delete-console",
        type: "api-token",
        value: "console-delete-secret-value-1234567890",
        injectEnv: "SGW_DELETE_TOKEN",
        allowedCommands: [process.execPath]
      }
    });

    const request = await fetchJson("api/requests", {
      method: "POST",
      body: {
        handle: created.handle,
        command: process.execPath,
        args: ["-e", "console.log(process.env.SGW_DELETE_TOKEN)"],
        injectEnv: "SGW_DELETE_TOKEN",
        reason: "Codex pending before delete"
      }
    });
    expect(request.state).toBe("pending");

    const deleted = await fetchJson(`api/secrets/${encodeURIComponent(created.handle)}`, {
      method: "DELETE"
    });
    expect(deleted.handle).toBe(created.handle);
    expect(deleted.failedRequests.map((item: { id: string }) => item.id)).toEqual([request.id]);

    const state = await fetchJson("api/state");
    expect(state.metrics.localSecrets).toBe(0);
    expect(state.metrics.pendingApprovals).toBe(0);
    expect(state.handles).toHaveLength(0);
    expect(state.requests.find((item: { id: string }) => item.id === request.id).state).toBe("failed");
  });

  it("accepts scoped timed approval choices from the console API", async () => {
    running = await startConsoleServer({ port: 0 });

    const created = await fetchJson("api/secrets", {
      method: "POST",
      body: {
        name: "console-grant",
        type: "api-token",
        value: "console-grant-secret-value-1234567890",
        injectEnv: "SGW_GRANT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const commandBody = {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_GRANT_TOKEN)"],
      injectEnv: "SGW_GRANT_TOKEN"
    };

    const first = await fetchJson("api/requests", {
      method: "POST",
      body: { ...commandBody, reason: "Console grant", agentName: "Codex" }
    });
    const approved = await fetchJson(`api/requests/${first.id}/approve`, {
      method: "POST",
      body: {
        mode: "timed-session",
        durationMs: 8 * 60 * 60 * 1000,
        agentScope: "same-agent"
      }
    });
    expect(approved.approvalGrantId).toMatch(/^grant_/);

    const sameAgent = await fetchJson("api/requests", {
      method: "POST",
      body: { ...commandBody, reason: "Console retry", agentName: "Codex" }
    });
    expect(sameAgent.state).toBe("approved");
    expect(sameAgent.approvalGrantId).toBe(approved.approvalGrantId);

    const otherAgent = await fetchJson("api/requests", {
      method: "POST",
      body: { ...commandBody, reason: "Console retry", agentName: "Claude" }
    });
    expect(otherAgent.state).toBe("pending");
  });

  it("lists and revokes approval grants through the console API", async () => {
    running = await startConsoleServer({ port: 0 });

    const created = await fetchJson("api/secrets", {
      method: "POST",
      body: {
        name: "console-revoke-grant",
        type: "api-token",
        value: "console-revoke-grant-secret-value-1234567890",
        injectEnv: "SGW_REVOKE_GRANT_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const commandBody = {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_REVOKE_GRANT_TOKEN)"],
      injectEnv: "SGW_REVOKE_GRANT_TOKEN"
    };

    const first = await fetchJson("api/requests", {
      method: "POST",
      body: { ...commandBody, reason: "Codex console revoke grant" }
    });
    const approved = await fetchJson(`api/requests/${first.id}/approve`, {
      method: "POST",
      body: {
        mode: "timed-session",
        durationMs: 60 * 60 * 1000,
        agentScope: "same-agent"
      }
    });
    expect(approved.approvalGrantId).toMatch(/^grant_/);

    const grants = await fetchJson("api/approval/grants");
    expect(grants.map((grant: { id: string }) => grant.id)).toEqual([approved.approvalGrantId]);

    const stateBefore = await fetchJson("api/state");
    expect(stateBefore.approvalGrants).toHaveLength(1);

    const revoked = await fetchJson(`api/approval/grants/${approved.approvalGrantId}`, {
      method: "DELETE"
    });
    expect(revoked.id).toBe(approved.approvalGrantId);

    const afterRevoke = await fetchJson("api/requests", {
      method: "POST",
      body: { ...commandBody, reason: "Codex console after revoke" }
    });
    expect(afterRevoke.state).toBe("pending");
  });

  it("updates and auto-arranges approval policy rules through the console API", async () => {
    running = await startConsoleServer({ port: 0 });

    const created = await fetchJson("api/approval/policies", {
      method: "POST",
      body: {
        name: "Console Codex allow",
        decision: "allow",
        priority: 200,
        expiresAt: "2030-01-01T00:00:00.000Z",
        agents: ["Codex"],
        envBindings: [{ handle: "s-gw:api-token:console", injectEnv: "SGW_CONSOLE_POLICY_TOKEN" }],
        actionKinds: ["env_command"],
        commands: [process.execPath],
        injectEnvs: ["SGW_CONSOLE_POLICY_TOKEN"],
        sshPorts: [2222]
      }
    });
    expect(created.id).toMatch(/^policy_/);
    expect(created.conditions.agents).toEqual(["codex"]);
    expect(created.conditions.envBindings).toEqual([
      { handle: "s-gw:api-token:console", injectEnv: "SGW_CONSOLE_POLICY_TOKEN" }
    ]);
    expect(created.conditions.sshPorts).toEqual([2222]);
    const createdAt = created.createdAt;

    const state = await fetchJson("api/state");
    expect(state.approvalPolicyRules.map((rule: { id: string }) => rule.id)).toContain(created.id);

    const disabled = await fetchJson(`api/approval/policies/${created.id}`, {
      method: "PATCH",
      body: { enabled: false }
    });
    expect(disabled.enabled).toBe(false);

    const updated = await fetchJson(`api/approval/policies/${created.id}`, {
      method: "PUT",
      body: {
        name: "Console Claude deny aws",
        enabled: true,
        decision: "deny",
        agents: ["Claude"],
        sshPorts: [2200, 2222]
      }
    });
    expect(updated).toMatchObject({
      id: created.id,
      createdAt,
      name: "Console Claude deny aws",
      enabled: true,
      decision: "deny"
    });
    expect(updated.conditions).toMatchObject({
      agents: ["claude"],
      envBindings: [{ handle: "s-gw:api-token:console", injectEnv: "SGW_CONSOLE_POLICY_TOKEN" }],
      commands: [process.execPath],
      injectEnvs: ["SGW_CONSOLE_POLICY_TOKEN"],
      sshPorts: [2200, 2222]
    });
    expect(updated.expiresAt).toBe("2030-01-01T00:00:00.000Z");

    const noExpiry = await fetchJson(`api/approval/policies/${created.id}`, {
      method: "PUT",
      body: { expiresAt: null }
    });
    expect(noExpiry.expiresAt).toBeUndefined();
    expect(noExpiry.conditions.agents).toEqual(["claude"]);

    const broad = await fetchJson("api/approval/policies", {
      method: "POST",
      body: {
        name: "Console Claude broad ask",
        decision: "ask",
        priority: 10,
        agents: ["Claude"]
      }
    });
    const arranged = await fetchJson("api/approval/policies/arrange", { method: "POST", body: {} });
    expect(arranged.reordered).toBeGreaterThan(0);
    expect(arranged.rules.map((rule: { id: string }) => rule.id)).toEqual([created.id, broad.id]);

    const ordered = await fetchJson("api/approval/policies");
    expect(ordered.map((rule: { id: string }) => rule.id)).toEqual([created.id, broad.id]);

    await fetchJson(`api/approval/policies/${broad.id}`, { method: "DELETE" });
    const deleted = await fetchJson(`api/approval/policies/${created.id}`, {
      method: "DELETE"
    });
    expect(deleted.id).toBe(created.id);

    const policies = await fetchJson("api/approval/policies");
    expect(policies).toHaveLength(0);
  });

  it("rejects malformed policy constraints without widening an existing rule", async () => {
    running = await startConsoleServer({ port: 0 });
    const created = await fetchJson("api/approval/policies", {
      method: "POST",
      body: {
        name: "Narrow console policy",
        decision: "allow",
        commands: [process.execPath],
        sshPorts: [22]
      }
    });
    const scoped = await fetchJson("api/approval/policies", {
      method: "POST",
      body: {
        name: "Exact binding policy",
        decision: "allow",
        envBindings: [{ handle: "s-gw:api-token:exact", injectEnv: "SGW_EXACT_TOKEN" }]
      }
    });
    const before = await fetchJson("api/approval/policies");

    const emptyUpdate = await fetch(consoleUrl(`api/approval/policies/${created.id}`), {
      method: "PUT",
      headers: authHeaders(),
      body: "{}"
    });
    expect(emptyUpdate.status).toBe(400);
    expect((await emptyUpdate.json()).error).toMatch(/at least one change/i);

    const badExpiry = await fetch(consoleUrl(`api/approval/policies/${created.id}`), {
      method: "PUT",
      headers: authHeaders(),
      body: JSON.stringify({ expiresAt: "" })
    });
    expect(badExpiry.status).toBe(400);
    expect((await badExpiry.json()).error).toMatch(/expiresAt/i);

    const badPort = await fetch(consoleUrl("api/approval/policies"), {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        name: "Invalid port policy",
        decision: "allow",
        sshPorts: [0]
      })
    });
    expect(badPort.status).toBe(400);
    expect((await badPort.json()).error).toMatch(/sshPorts/i);

    const blankCommand = await fetch(consoleUrl("api/approval/policies"), {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        name: "Blank command policy",
        decision: "allow",
        commands: [""]
      })
    });
    expect(blankCommand.status).toBe(400);
    expect((await blankCommand.json()).error).toMatch(/commands.*non-empty/i);

    const typoedConstraint = await fetch(consoleUrl("api/approval/policies"), {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({
        name: "Typoed command policy",
        decision: "allow",
        command: process.execPath
      })
    });
    expect(typoedConstraint.status).toBe(400);
    expect((await typoedConstraint.json()).error).toMatch(/unsupported approval policy field.*command/i);

    const changedBindings = await fetch(consoleUrl(`api/approval/policies/${scoped.id}`), {
      method: "PUT",
      headers: authHeaders(),
      body: JSON.stringify({ envBindings: [] })
    });
    expect(changedBindings.status).toBe(409);
    expect((await changedBindings.json()).error).toMatch(/exact credential bindings/i);

    const clearedByNull = await fetch(consoleUrl(`api/approval/policies/${created.id}`), {
      method: "PUT",
      headers: authHeaders(),
      body: JSON.stringify({ commands: null })
    });
    expect(clearedByNull.status).toBe(400);
    expect((await clearedByNull.json()).error).toMatch(/commands.*array/i);
    expect(await fetchJson("api/approval/policies")).toEqual(before);
  });

  it("builds an agent to credential to action usage flow without exposing secret values", async () => {
    running = await startConsoleServer({ port: 0 });

    const created = await fetchJson("api/secrets", {
      method: "POST",
      body: {
        name: "usage-flow-token",
        type: "api-token",
        value: "usage-flow-secret-value-1234567890",
        injectEnv: "SGW_USAGE_FLOW_TOKEN",
        allowedCommands: [process.execPath]
      }
    });
    const commandBody = {
      handle: created.handle,
      command: process.execPath,
      args: ["-e", "console.log(process.env.SGW_USAGE_FLOW_TOKEN)"],
      injectEnv: "SGW_USAGE_FLOW_TOKEN"
    };

    const codex = await fetchJson("api/requests", {
      method: "POST",
      body: { ...commandBody, reason: "Usage flow", agentName: "Codex" }
    });
    const claude = await fetchJson("api/requests", {
      method: "POST",
      body: { ...commandBody, reason: "Usage flow", agentName: "Claude" }
    });
    await fetchJson(`api/requests/${codex.id}/approve`, { method: "POST", body: {} });
    await fetchJson(`api/requests/${codex.id}/execute`, { method: "POST", body: {} });
    await fetchJson(`api/requests/${claude.id}/deny`, { method: "POST", body: {} });

    const state = await fetchJson("api/state");
    expect(state.usageFlow.totalRequests).toBe(2);
    expect(state.usageFlow.nodes).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ id: "agent:Codex", kind: "agent", count: 1 }),
        expect.objectContaining({ id: "agent:Claude", kind: "agent", count: 1 }),
        expect.objectContaining({ kind: "auth", label: "API token", count: 2 }),
        expect.objectContaining({ kind: "target", label: "Local command", count: 2 })
      ])
    );
    expect(state.usageFlow.links).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ source: "agent:Codex", value: 1 }),
        expect.objectContaining({ source: "agent:Claude", value: 1 }),
        expect.objectContaining({ source: "auth:api-token", target: "target:local-command", value: 2 })
      ])
    );
    expect(state.usageFlow.rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ agent: "Codex", handle: created.handle, count: 1, authType: "API token", targetType: "Local command" }),
        expect.objectContaining({ agent: "Claude", handle: created.handle, count: 1, authType: "API token", targetType: "Local command" })
      ])
    );
    expect(state.usageFlow.entries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ requestId: codex.id, agent: "Codex", state: "executed" }),
        expect.objectContaining({ requestId: claude.id, agent: "Claude", state: "denied" })
      ])
    );
    expect(state.usageFlow.entries.every((entry: Record<string, unknown>) => !("count" in entry))).toBe(true);
    expect(JSON.stringify(state.usageFlow)).not.toContain("usage-flow-secret-value");
  });

  it("shows real SSH destinations without treating shell text as a host", async () => {
    running = await startConsoleServer({ port: 0 });
    const created = await fetchJson("api/secrets", {
      method: "POST",
      body: {
        name: "usage-flow-ssh-key",
        type: "private-key",
        provider: "ssh",
        value: "usage-flow-ssh-secret-value-1234567890",
        injectEnv: "SGW_USAGE_FLOW_SSH_KEY",
        allowedCommands: ["/usr/bin/ssh", "/private/tmp/openclaw-sgw-ssh"]
      }
    });

    await fetchJson("api/requests", {
      method: "POST",
      body: {
        handle: created.handle,
        command: "/usr/bin/ssh",
        args: ["-p", "2222", "ubuntu@ec2-01.internal", "hostname"],
        injectEnv: "SGW_USAGE_FLOW_SSH_KEY",
        reason: "Codex SSH destination"
      }
    });
    await fetchJson("api/requests", {
      method: "POST",
      body: {
        handle: created.handle,
        command: "/private/tmp/openclaw-sgw-ssh",
        args: ["node -e 'console.log(pkg.name + \"@\" + pkg.version)'"],
        injectEnv: "SGW_USAGE_FLOW_SSH_KEY",
        reason: "Codex local wrapper"
      }
    });

    const state = await fetchJson("api/state");
    expect(state.usageFlow.entries).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ targetType: "SSH server", target: "ubuntu@ec2-01.internal" }),
        expect.objectContaining({ targetType: "Local command", target: "node -e 'console.log(pkg.name + \"@\" + pkg.version)'" })
      ])
    );
  });

  it("reports a ready readiness verdict when an unlock source is configured", async () => {
    running = await startConsoleServer({ port: 0 });

    const state = await fetchJson("api/state");
    expect(state.ready).toBe(true);
    expect(state.readiness.ok).toBe(true);
    expect(state.readiness.blockers).toEqual([]);
  });

  it("reports a not-ready verdict with an actionable blocker when no unlock source exists", async () => {
    delete process.env.SGW_MASTER_PASSPHRASE;
    running = await startConsoleServer({ port: 0 });

    const state = await fetchJson("api/state");
    expect(state.ready).toBe(false);
    expect(state.readiness.ok).toBe(false);
    expect(state.readiness.blockers.length).toBeGreaterThan(0);
    expect(state.readiness.blockers.join(" ")).toMatch(/s-gw setup/);
    // The verdict relays the env var *name* as guidance, but must never carry a value.
    expect(JSON.stringify(state.readiness)).not.toContain(["SGW_MASTER_PASSPHRASE", "="].join(""));
  });

  it("can scan and persist tokenized text through the console API", async () => {
    running = await startConsoleServer({ port: 0 });
    const raw = fakeOpenAiToken();

    const result = await fetchJson("api/scan", {
      method: "POST",
      body: {
        text: `OPENAI_API_KEY=${raw}`,
        persist: true,
        source: "console-text"
      }
    });

    expect(result.tokenizedText).toContain("<<SGW_SECRET:");
    expect(result.tokenizedText).not.toContain(raw);
    expect(result.findings[0].provider).toBe("openai");

    const state = await fetchJson("api/state");
    expect(state.credentials.some((item: { provider: string }) => item.provider === "openai")).toBe(true);
  });
});

async function fetchJson(pathName: string, options: { method?: string; body?: unknown } = {}) {
  const response = await fetch(consoleUrl(pathName), {
    method: options.method || "GET",
    headers: authHeaders(),
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });

  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || `HTTP ${response.status}`);
  }

  return payload;
}

async function fetchText(pathName: string): Promise<string> {
  const response = await fetch(consoleUrl(pathName), {
    headers: pathName.startsWith("api/") ? authHeaders() : undefined
  });
  expect(response.ok).toBe(true);
  return response.text();
}

function consoleUrl(pathName: string): string {
  return new URL(pathName.replace(/^\/+/, ""), running!.url).toString();
}

function authHeaders(): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "X-SGW-Console-Token": running!.token
  };
}
