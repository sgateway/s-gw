import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, realpathSync, symlinkSync, writeFileSync } from "node:fs";
import { createHash, generateKeyPairSync } from "node:crypto";
import { request as httpRequest } from "node:http";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { principalForVerifiedPeer } from "../src/agent-context.js";
import { consoleMcpSnippet, startConsoleServer, type RunningConsoleServer } from "../src/console-server.js";
import { buildEnvCommandAction } from "../src/gateway.js";
import { getSgwInstanceKey } from "../src/paths.js";
import { buildSshSessionAction } from "../src/ssh.js";
import { SecretStore } from "../src/store.js";
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
  process.env.SGW_SECRET_BACKEND = "local";
});

afterEach(async () => {
  if (running) {
    await running.close();
    running = undefined;
  }

  process.env = oldEnv;
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true, maxRetries: 4, retryDelay: 250 });
  }
});

describe("local console server", () => {
  it("identifies the credential home on the unauthenticated health endpoint", async () => {
    running = await startConsoleServer({ port: 0 });

    const health = await fetchJson("api/health");
    expect(health).toMatchObject({
      ok: true,
      name: "s-gw",
      instanceKey: getSgwInstanceKey(tmpHome)
    });
  });

  it("rejects attempts to disable verified-only automatic approval through the console API", async () => {
    running = await startConsoleServer({ port: 0 });
    const before = await fetchJson("api/approval");
    expect(before.requireVerifiedAgentForAutoApproval).toBe(true);

    const rejected = await fetch(consoleUrl("api/approval"), {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ mode: "timed-session", durationMs: 60_000, requireVerifiedAgentForAutoApproval: false })
    });
    expect(rejected.status).toBe(400);
    expect((await rejected.json()).error).toMatch(/requires a verified agent/i);
    expect(await fetchJson("api/approval")).toEqual(before);

    const updated = await fetchJson("api/approval", {
      method: "POST",
      body: { mode: "timed-session", durationMs: 60_000, requireVerifiedAgentForAutoApproval: true }
    });
    expect(updated).toMatchObject({ mode: "timed-session", durationMs: 60_000, requireVerifiedAgentForAutoApproval: true });
  });

  it("serves the console with a session token and protects local API writes", async () => {
    running = await startConsoleServer({ port: 0 });

    const consoleResponse = await fetch(running.url);
    const html = await consoleResponse.text();
    expect(html).toContain("s-gw");
    expect(html).toContain("SGW_CONSOLE_TOKEN");
    const policy = consoleResponse.headers.get("content-security-policy") || "";
    const nonce = /script-src 'nonce-([^']+)'/u.exec(policy)?.[1];
    expect(nonce).toBeTruthy();
    expect(html).toContain(`nonce="${nonce}"`);
    expect(policy).toContain("connect-src 'self'");
    expect(policy).toContain("form-action 'none'");

    const rejected = await fetch(`${running.url}api/secrets`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: "blocked", value: "nope" })
    });
    expect(rejected.status).toBe(403);
  });

  it("keeps the protected console private until one-time operator enrollment", async () => {
    let code = "";
    running = await startConsoleServer({
      port: 0,
      operatorAuth: { displayCode: (value) => { code = value; } }
    });
    expect(running.token).toBe("");
    expect(code).toMatch(/^[A-Za-z0-9_-]{32}$/u);

    const before = await fetch(running.url);
    const signInPage = await before.text();
    expect(before.status).toBe(200);
    expect(signInPage).toContain("operator sign-in");
    expect(signInPage).not.toContain(code);
    expect(before.headers.get("cache-control")).toBe("no-store");
    expect(before.headers.get("x-frame-options")).toBe("DENY");
    expect((await fetch(`${running.url}api/health`)).status).toBe(401);
    expect((await fetch(`${running.url}api/state`, {
      headers: { "X-SGW-Console-Token": "guessed" }
    })).status).toBe(401);
    expect((await fetch(`${running.url}assets/whatever.js`)).status).toBe(401);

    const enroll = (attempt: string, headers: Record<string, string> = {}) => fetch(`${running!.url}auth/enroll`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Origin: new URL(running!.url).origin, ...headers },
      body: JSON.stringify({ code: attempt })
    });
    expect((await enroll(code, { Origin: "http://malicious.example" })).status).toBe(403);
    const wrongHost = await new Promise<number>((resolve, reject) => {
      const req = httpRequest(`${running!.url}auth/enroll`, {
        method: "POST",
        headers: { Host: "malicious.example", Origin: new URL(running!.url).origin, "Content-Type": "application/json" }
      }, (response) => {
        response.resume();
        response.on("end", () => resolve(response.statusCode || 0));
      });
      req.on("error", reject);
      req.end(JSON.stringify({ code }));
    });
    expect(wrongHost).toBe(403);
    expect((await enroll("x".repeat(32))).status).toBe(401);

    const signedIn = await enroll(code);
    expect(signedIn.status).toBe(200);
    const proof = (await signedIn.json() as { proof: string }).proof;
    expect(proof).toMatch(/^[A-Za-z0-9_-]{32}$/u);
    const cookie = signedIn.headers.get("set-cookie") || "";
    expect(cookie).toMatch(/^sgw_operator=[A-Za-z0-9_-]{43};/u);
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).toContain("Max-Age=900");
    expect(cookie).not.toContain(code);
    expect((await enroll(code)).status).toBe(401);

    const sessionCookie = cookie.split(";")[0];
    const signedInPage = await fetch(`${running.url}auth/app`, { headers: { Cookie: sessionCookie } });
    const html = await signedInPage.text();
    expect(html).toContain('window.SGW_CONSOLE_TOKEN||""');
    expect(html).not.toContain(code);
    expect(html).not.toContain(proof);
    expect(html).not.toContain(sessionCookie);
    expect((await fetch(running.url, { headers: { Cookie: sessionCookie } })).status).toBe(200);
    expect((await fetch(`${running.url}api/health`, { headers: { Cookie: sessionCookie } })).status).toBe(403);
    expect((await fetch(`${running.url}api/health`, { headers: { Cookie: sessionCookie, "X-SGW-Console-Token": "é".repeat(32) } })).status).toBe(403);
    expect((await fetch(`${running.url}api/health`, { headers: { Cookie: sessionCookie, "X-SGW-Console-Token": proof } })).status).toBe(200);

    const action = (headers: Record<string, string>) => fetch(`${running!.url}api/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...headers },
      body: JSON.stringify({ text: "no secret", persist: false })
    });
    expect((await action({ Cookie: sessionCookie, Origin: new URL(running.url).origin })).status).toBe(403);
    expect((await action({ Cookie: sessionCookie, "X-SGW-Console-Token": proof })).status).toBe(403);
    expect((await action({ Cookie: sessionCookie, Origin: "http://malicious.example", "X-SGW-Console-Token": proof })).status).toBe(403);
    expect((await action({ Origin: new URL(running.url).origin, "X-SGW-Console-Token": proof })).status).toBe(401);
    expect((await action({ Cookie: sessionCookie, Origin: new URL(running.url).origin, "X-SGW-Console-Token": proof })).status).toBe(200);
  });

  it("limits operator code guesses and requires loopback binding", async () => {
    await expect(startConsoleServer({
      host: "0.0.0.0",
      port: 0,
      operatorAuth: { displayCode: () => {} }
    })).rejects.toThrow("requires 127.0.0.1");

    let code = "";
    running = await startConsoleServer({ port: 0, operatorAuth: { displayCode: (value) => { code = value; } } });
    const origin = new URL(running.url).origin;
    for (let index = 0; index < 5; index += 1) {
      const response = await fetch(`${running.url}auth/enroll`, {
        method: "POST",
        headers: { Origin: origin, "Content-Type": "application/json" },
        body: JSON.stringify({ code: "x".repeat(32) })
      });
      expect(response.status).toBe(401);
    }
    const blockedGuess = await fetch(`${running.url}auth/enroll`, {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({ code: "y".repeat(32) })
    });
    expect(blockedGuess.status).toBe(429);
    const validCode = await fetch(`${running.url}auth/enroll`, {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });
    expect(validCode.status).toBe(200);
  });

  it.skipIf(process.platform === "win32")("rejects symlinks outside the protected UI directory", async () => {
    const uiDir = path.join(tmpHome, "operator-ui");
    mkdirSync(uiDir);
    writeFileSync(path.join(uiDir, "index.html"), "<html><head></head><body>trusted UI</body></html>");
    const outside = path.join(tmpHome, "outside.js");
    writeFileSync(outside, "untrusted script");
    symlinkSync(outside, path.join(uiDir, "outside.js"));

    let code = "";
    running = await startConsoleServer({ port: 0, uiDir, operatorAuth: { displayCode: (value) => { code = value; } } });
    const origin = new URL(running.url).origin;
    const signedIn = await fetch(`${running.url}auth/enroll`, {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });
    expect(signedIn.status).toBe(200);
    const cookie = (signedIn.headers.get("set-cookie") || "").split(";")[0];
    const escaped = await fetch(`${running.url}outside.js`, { headers: { Cookie: cookie } });
    expect(escaped.status).toBe(403);
    expect(await escaped.text()).not.toContain("untrusted script");
  });

  it("shows why every listener for one store needs the protected mode", async () => {
    const store = new SecretStore();
    let code = "";
    running = await startConsoleServer({ port: 0, store, operatorAuth: { displayCode: (value) => { code = value; } } });
    const ordinary = await startConsoleServer({ port: 0, store });
    try {
      const ordinaryPage = await (await fetch(ordinary.url)).text();
      expect(ordinaryPage).toContain(ordinary.token);
      const ordinaryApi = await fetch(`${ordinary.url}api/state`, {
        headers: { "X-SGW-Console-Token": ordinary.token }
      });
      expect(ordinaryApi.status).toBe(200);
      const protectedApi = await fetch(`${running.url}api/state`, {
        headers: { "X-SGW-Console-Token": ordinary.token }
      });
      expect(protectedApi.status).toBe(401);
      expect(ordinaryPage).not.toContain(code);
    } finally {
      await ordinary.close();
    }
  });

  it("expires the one-time code and operator session", async () => {
    let code = "";
    running = await startConsoleServer({ port: 0, operatorAuth: { displayCode: (value) => { code = value; } } });
    const origin = new URL(running.url).origin;
    const startedAt = Date.now();
    const clock = vi.spyOn(Date, "now");
    try {
      clock.mockReturnValue(startedAt + 5 * 60_000 + 1);
      const expiredCode = await fetch(`${running.url}auth/enroll`, {
        method: "POST",
        headers: { Origin: origin, "Content-Type": "application/json" },
        body: JSON.stringify({ code })
      });
      expect(expiredCode.status).toBe(401);
    } finally {
      clock.mockRestore();
    }

    await running.close();
    running = await startConsoleServer({ port: 0, operatorAuth: { displayCode: (value) => { code = value; } } });
    const newOrigin = new URL(running.url).origin;
    const signedIn = await fetch(`${running.url}auth/enroll`, {
      method: "POST",
      headers: { Origin: newOrigin, "Content-Type": "application/json" },
      body: JSON.stringify({ code })
    });
    expect(signedIn.status).toBe(200);
    const cookie = (signedIn.headers.get("set-cookie") || "").split(";")[0];
    const sessionStartedAt = Date.now();
    const sessionClock = vi.spyOn(Date, "now");
    try {
      sessionClock.mockReturnValue(sessionStartedAt + 15 * 60_000 + 1);
      const expiredSession = await fetch(`${running.url}api/state`, { headers: { Cookie: cookie } });
      expect(expiredSession.status).toBe(401);
    } finally {
      sessionClock.mockRestore();
    }
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

  it("renders self-contained MCP snippets with only the validated authority environment", () => {
    const runtime = "/Applications/s-gw.app/Contents/Resources/s-gw-runtime";
    const primaryHome = path.join(tmpHome, "primary-ledger");
    const recoveryHome = path.join(tmpHome, "recovery-ledger");
    const mcp = consoleMcpSnippet({
      homeDir: tmpHome,
      sgwHome: primaryHome,
      platform: "darwin",
      env: {
        HOME: tmpHome,
        SGW_RECOVERY_HOME: "recovery-ledger",
        SGW_KEYCHAIN_SERVICE: "com.example.s-gw.master",
        SGW_KEYCHAIN_ACCOUNT: "ordinary-user",
        SGW_SECRET_KEYCHAIN_SERVICE: "com.example.s-gw.secret",
        SGW_SECRET_BACKEND: " LOCAL ",
        SGW_EXECUTION_ENGINE: " RUST ",
        SGW_MASTER_PASSPHRASE: "must-not-be-written",
        AWS_SECRET_ACCESS_KEY: "must-not-be-written"
      }
    }, {
      packageRoot: path.posix.join(runtime, "package"),
      nodePath: path.posix.join(runtime, "node", "bin", "node"),
      mcpPath: path.posix.join(runtime, "package", "dist", "mcp-server.js"),
      isSelfContainedMacApp: true
    });

    expect(mcp.options).toEqual({
      command: path.posix.join(runtime, "node", "bin", "node"),
      args: [path.posix.join(runtime, "package", "dist", "mcp-server.js")],
      env: {
        SGW_HOME: primaryHome,
        SGW_RECOVERY_HOME: recoveryHome,
        SGW_KEYCHAIN_SERVICE: "com.example.s-gw.master",
        SGW_KEYCHAIN_ACCOUNT: "ordinary-user",
        SGW_SECRET_KEYCHAIN_SERVICE: "com.example.s-gw.secret",
        SGW_SECRET_BACKEND: "local",
        SGW_EXECUTION_ENGINE: "rust"
      }
    });
    expect(mcp.cliCommand).toBe(path.posix.join(runtime, "bin", "s-gw"));
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
    const installer = process.platform === "darwin"
      ? "s-gw-0.1.1-macos.dmg"
      : process.platform === "win32" ? "s-gw-0.1.1-windows.zip" : "s-gw-0.1.1.tgz";
    const checker = new ReleaseChecker({
      cachePath: path.join(tmpHome, "update.json"),
      currentVersion: "0.1.0",
      enabled: true,
      fetcher: async () => new Response(JSON.stringify([{
        tag_name: "v0.1.1",
        html_url: "https://github.com/sgateway/s-gw/releases/tag/v0.1.1",
        draft: false,
        prerelease: false,
        published_at: "2026-07-04T00:00:00.000Z",
        assets: [
          { name: installer, state: "uploaded" },
          { name: `${installer}.sha256`, state: "uploaded" }
        ]
      }]), { status: 200 })
    });
    await checker.check(true);
    running = await startConsoleServer({ port: 0, updateChecker: checker });

    const state = await fetchJson("api/state");
    expect(state.update).toMatchObject({
      currentVersion: "0.1.0",
      latestVersion: "0.1.1",
      available: true,
      installerReady: true,
      prerelease: false
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

  it("keeps name-only console timed approvals one-shot", async () => {
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
    expect(first.action.resolvedCommand).toBe(realpathSync.native(process.execPath));
    const approved = await fetchJson(`api/requests/${first.id}/approve`, {
      method: "POST",
      body: {
        mode: "timed-session",
        durationMs: 8 * 60 * 60 * 1000,
        agentScope: "same-agent"
      }
    });
    expect(approved).toMatchObject({ id: first.id, state: "approved", approvalSource: "manual" });
    expect(approved.approvalGrantId).toBeUndefined();

    const sameAgent = await fetchJson("api/requests", {
      method: "POST",
      body: { ...commandBody, reason: "Console retry", agentName: "Codex" }
    });
    expect(sameAgent.state).toBe("pending");
    expect(sameAgent.approvalGrantId).toBeUndefined();

    const otherAgent = await fetchJson("api/requests", {
      method: "POST",
      body: { ...commandBody, reason: "Console retry", agentName: "Claude" }
    });
    expect(otherAgent.state).toBe("pending");
  });

  it("lists and revokes approval grants through the console API", async () => {
    const store = new SecretStore();
    running = await startConsoleServer({ port: 0, store });

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

    const agent = { managedPrincipal: principalForVerifiedPeer("test:console-grant", "Codex", "session-1"), env: {} };
    const action = buildEnvCommandAction(commandBody);
    const first = await store.createRequest(created.handle, action, "Codex console revoke grant", agent);
    const approved = await fetchJson(`api/requests/${first.id}/approve`, {
      method: "POST",
      body: {
        mode: "timed-session",
        durationMs: 60 * 60 * 1000,
        agentScope: "same-agent"
      }
    });
    expect(approved.approvalGrantId).toMatch(/^grant_/);

    const reused = await store.createRequest(created.handle, action, "Codex console grant reuse", agent);
    expect(reused).toMatchObject({ state: "approved", approvalSource: "grant", approvalGrantId: approved.approvalGrantId });

    const grants = await fetchJson("api/approval/grants");
    expect(grants.map((grant: { id: string }) => grant.id)).toEqual([approved.approvalGrantId]);

    const stateBefore = await fetchJson("api/state");
    expect(stateBefore.approvalGrants).toHaveLength(1);

    const revoked = await fetchJson(`api/approval/grants/${approved.approvalGrantId}`, {
      method: "DELETE"
    });
    expect(revoked.id).toBe(approved.approvalGrantId);

    const afterRevoke = await store.createRequest(created.handle, action, "Codex console after revoke", agent);
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
        resolvedCommands: [realpathSync.native(process.execPath)],
        injectEnvs: ["SGW_CONSOLE_POLICY_TOKEN"],
        sshPorts: [2222]
      }
    });
    expect(created.id).toMatch(/^policy_/);
    expect(created.conditions.agents).toEqual(["codex"]);
    expect(created.conditions.envBindings).toEqual([
      { handle: "s-gw:api-token:console", injectEnv: "SGW_CONSOLE_POLICY_TOKEN" }
    ]);
    expect(created.conditions.resolvedCommands).toEqual([realpathSync.native(process.execPath)]);
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
      resolvedCommands: [realpathSync.native(process.execPath)],
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

  it("preserves omitted command scope and accepts an explicit Any command scope", async () => {
    running = await startConsoleServer({ port: 0 });

    const incomplete = await fetchJson("api/approval/policies", {
      method: "POST",
      body: {
        name: "Legacy-style incomplete allow",
        decision: "allow",
        agents: ["Codex"],
        actionKinds: ["env_command"]
      }
    });
    expect(incomplete.conditions).not.toHaveProperty("commands");
    expect(incomplete.conditions).not.toHaveProperty("resolvedCommands");

    const anyCommand = await fetchJson("api/approval/policies", {
      method: "POST",
      body: {
        name: "Codex Any command",
        decision: "allow",
        agents: ["Codex"],
        actionKinds: ["env_command"],
        commands: [],
        resolvedCommands: []
      }
    });
    expect(anyCommand.conditions.commands).toEqual([]);
    expect(anyCommand.conditions.resolvedCommands).toEqual([]);
  });

  it("accepts a scoped model relay deny rule and rejects automatic model relay allow", async () => {
    running = await startConsoleServer({ port: 0 });
    const deny = await fetchJson("api/approval/policies", {
      method: "POST",
      body: { name: "Deny model relay", decision: "deny", actionKinds: ["model_relay"],
        handles: ["s-gw:api-token:console"] }
    });
    expect(deny.conditions.actionKinds).toEqual(["model_relay"]);

    const allow = await fetch(consoleUrl("api/approval/policies"), {
      method: "POST", headers: authHeaders(),
      body: JSON.stringify({ name: "Unsafe model autoallow", decision: "allow", actionKinds: ["model_relay"] })
    });
    expect(allow.status).toBe(409);
    expect((await allow.json()).error).toMatch(/one-time verified-session approval/);
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
    const toolDir = path.join(tmpHome, "usage-flow-tools");
    mkdirSync(toolDir, { recursive: true });
    const sshCommand = writeFixtureExecutable(path.join(toolDir, "ssh"));
    const wrapperCommand = writeFixtureExecutable(path.join(toolDir, "openclaw-sgw-wrapper"));
    const created = await fetchJson("api/secrets", {
      method: "POST",
      body: {
        name: "usage-flow-ssh-key",
        type: "private-key",
        provider: "ssh",
        value: "usage-flow-ssh-secret-value-1234567890",
        injectEnv: "SGW_USAGE_FLOW_SSH_KEY",
        allowedCommands: [sshCommand, wrapperCommand]
      }
    });

    await fetchJson("api/requests", {
      method: "POST",
      body: {
        handle: created.handle,
        command: sshCommand,
        args: ["-p", "2222", "ubuntu@ec2-01.internal", "hostname"],
        injectEnv: "SGW_USAGE_FLOW_SSH_KEY",
        reason: "Codex SSH destination"
      }
    });
    await fetchJson("api/requests", {
      method: "POST",
      body: {
        handle: created.handle,
        command: wrapperCommand,
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
  }, 15_000);

  it("shows the resolved managed SSH destination and pinned host-key fingerprint", async () => {
    const rawKey = generateKeyPairSync("ed25519").publicKey.export({ format: "der", type: "spki" }).subarray(-32);
    const type = Buffer.from("ssh-ed25519");
    const length = (value: Buffer) => { const prefix = Buffer.alloc(4); prefix.writeUInt32BE(value.length); return Buffer.concat([prefix, value]); };
    const wireKey = Buffer.concat([length(type), length(rawKey)]);
    const hostPublicKey = `ssh-ed25519 ${wireKey.toString("base64")}`;
    const expectedFingerprint = `SHA256:${createHash("sha256").update(wireKey).digest("base64").replace(/=+$/, "")}`;
    const store = new SecretStore();
    const route = await store.addManagedSshRoute({ name: "innocent-alias", host: "127.0.0.1", user: "deploy", port: 2222, hostPublicKey });
    const secret = await store.addSecret({ name: "managed SSH key", type: "private-key", value: "synthetic-key-material", policy: { allowedCommands: ["s-gw:ssh-session"] } });
    const action = buildSshSessionAction({ target: route.name, port: 2222, args: ["hostname"] });
    action.ssh!.managedRouteId = route.id;
    const request = await store.createRequest(secret.handle, action, "managed SSH approval fixture");
    running = await startConsoleServer({ port: 0, store });

    const state = await fetchJson("api/state");
    expect(state.pendingRequests[0]).toMatchObject({ id: request.id, managedSsh: {
      destination: "deploy@127.0.0.1:2222", hostKeyFingerprint: expectedFingerprint, routeName: "innocent-alias", routeCurrent: true
    } });
    expect(state.pendingRequests[0].action.ssh.target).toBe(route.id);
    expect(state.usageFlow.entries).toEqual(expect.arrayContaining([
      expect.objectContaining({ requestId: request.id, target: "deploy@127.0.0.1:2222", action: "ssh -> deploy@127.0.0.1:2222" })
    ]));
    expect(JSON.stringify(state)).not.toContain("synthetic-key-material");

    await store.updateManagedSshRoute(route.id, { host: "127.0.0.2" });
    const stale = await fetchJson("api/state");
    expect(stale.pendingRequests[0].managedSsh).toMatchObject({
      destination: "deploy@127.0.0.1:2222", hostKeyFingerprint: expectedFingerprint, routeCurrent: false
    });
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

function writeFixtureExecutable(requestedPath: string): string {
  const executablePath = process.platform === "win32" ? `${requestedPath}.exe` : requestedPath;
  if (process.platform === "win32") {
    copyFileSync(process.execPath, executablePath);
  } else {
    writeFileSync(executablePath, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  }
  chmodSync(executablePath, 0o700);
  return requestedPath;
}

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
