import { createHash, randomUUID } from "node:crypto";
import { mkdtemp, mkdir, writeFile, readFile, rm, symlink, realpath } from "node:fs/promises";
import { createServer, connect } from "node:net";
import { createServer as createHttpsServer } from "node:https";
import { execFileSync, spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import { anthropicSandboxConfig, runAnthropicSandbox, sandboxAgentArguments } from "../src/anthropic-sandbox.js";
import { prepareGuardedRun, runGuardedAgent } from "../src/guard.js";
import { buildEnvCommandAction } from "../src/gateway.js";
import { SecretStore } from "../src/store.js";
import { startSandboxBroker, runSandboxMcpBridge } from "../src/sandbox-broker.js";
import { anthropicSandboxReadiness, agentAuthenticationPaths, restrictMacCredentialIpc, macAgentKeychainReadPath, allowMacAgentKeychainRead } from "../src/anthropic-sandbox.js";
import { httpsFixture } from "./helpers/https-fixture.js";

let root = "";
const originalEnv = { ...process.env };
afterEach(async () => {
  vi.restoreAllMocks();
  process.env = { ...originalEnv };
  if (root) {
    const hash = createHash("sha256").update(path.join(root, "store")).digest("hex").slice(0, 12);
    await rm(path.join(process.platform === "darwin" ? "/private/tmp" : "/tmp", `sgw-ssh-${process.getuid?.() ?? "user"}-${hash}`), { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  }
});
async function fixtureStore() {
  process.env.SGW_ALLOW_NO_CGROUP = "1";
  root = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-anthropic-test-")));
  await Promise.all(["workspace", "outside"].map(name => mkdir(path.join(root, name))));
  process.env.SGW_HOME = path.join(root, "store");
  process.env.SGW_MASTER_PASSPHRASE = randomUUID();
  process.env.SGW_DISABLE_KEYCHAIN = "1";
  process.env.SGW_DISABLE_ONEPASSWORD_BACKUP = "1";
  process.env.SGW_DISABLE_PROCESS_AGENT_DETECTION = "1";
  const store = new SecretStore();
  await store.init();
  return store;
}

describe("Anthropic sandbox", () => {
  it("provides launch-only MCP overrides for Codex and Claude while preserving other arguments", () => {
    const entry = { command: "/node", args: ["/mcp.js"] };
    const env = { SGW_SANDBOX_BROKER_PORT: "1234" };
    expect(sandboxAgentArguments("claude", ["fixture prompt"], "/session/mcp.json", entry, env)).toEqual(["fixture prompt", "--mcp-config", "/session/mcp.json"]);
    expect(sandboxAgentArguments("claude", ["--mcp-config", "/existing.json", "--help"], "/session/mcp.json", entry, env)).toEqual(["--mcp-config", "/existing.json", "/session/mcp.json", "--help"]);
    const args = sandboxAgentArguments("codex", ["exec", "fixture"], "/session/mcp.json", entry, env);
    expect(args).toContain('mcp_servers.s-gw.env.SGW_SANDBOX_BROKER_PORT="1234"');
    expect(args[0]).toBe("exec"); expect(args.at(-1)).toBe("fixture");
    const interactive = sandboxAgentArguments("codex", ["--help"], "/session/mcp.json", entry, env);
    expect(interactive[0]).toBe("--config"); expect(interactive.at(-1)).toBe("--help");
    expect(sandboxAgentArguments("custom-agent", ["fixture"], "/session/mcp.json", entry, env)).toEqual(["fixture"]);
  });
  it("uses only confinement policy with no TLS, credential substitution or request filters", () => {
    const workspace = path.resolve("sandbox-workspace");
    const home = path.resolve("sandbox-store");
    const config = anthropicSandboxConfig(workspace, home, { allowHosts: ["example.test"], denyRead: ["private"], allowWrite: ["build"] });
    expect(config.filesystem.denyRead).toContain(home);
    expect(config.filesystem.denyRead).toContain(path.join(workspace, "private"));
    expect(config.filesystem.allowWrite).toEqual([workspace, path.join(workspace, "build")]);
    expect(config.network.allowedDomains).toContain("example.test");
    expect(config).not.toHaveProperty("credentials");
    expect(config.network).not.toHaveProperty("tlsTerminate");
    expect(config.network).not.toHaveProperty("filterRequest");
    expect(config.network).not.toHaveProperty("mitmProxy");
    expect(() => anthropicSandboxConfig(workspace, home, { allowHosts: ["*"] })).toThrow();
  });

  it("keeps builtin as the default and rejects invalid or unscrubbed opt-in plans", async () => {
    const store = await fixtureStore();
    const base = { agent: "codex", command: process.execPath, cwd: path.join(root, "workspace"), env: { PATH: process.env.PATH } };
    expect((await prepareGuardedRun(store, base)).plan.sandbox.provider).toBe("builtin");
    await expect(prepareGuardedRun(store, { ...base, sandbox: "invalid" as "anthropic" })).rejects.toThrow("Unknown sandbox");
    await expect(prepareGuardedRun(store, { ...base, sandbox: "anthropic", scrubEnv: false })).rejects.toThrow("requires credential");
    await expect(prepareGuardedRun(store, { ...base, sandboxOptions: { allowHosts: ["example.test"] } })).rejects.toThrow("require --sandbox");
    const preview = await prepareGuardedRun(store, { ...base, sandbox: "anthropic" });
    expect(preview.plan.sandbox).toMatchObject({ provider: "anthropic", tlsInterception: false, policy: { credentialOperations: ["ssh", "https"] } });
    expect(preview.plan.instructions).toContain("external trusted executor");
    expect(await store.listHandles()).toEqual([]);
    const loader = new URL("../node_modules/tsx/dist/esm/index.mjs", import.meta.url).href;
    const cli = execFileSync(process.execPath, ["--import", loader, "src/cli.ts", "run", "codex", "--sandbox", "anthropic", "--dry-run", "--command", process.execPath, "--allow-host", "example.test", "--", "-v"], { encoding: "utf8", env: process.env });
    expect(JSON.parse(cli).sandbox.provider).toBe("anthropic");
    const keychainPlan = execFileSync(process.execPath, ["--import", loader, "src/cli.ts", "run", "claude-code", "--sandbox", "anthropic", "--dry-run", "--command", process.execPath, "--allow-agent-keychain", "--", "-v"], { encoding: "utf8", env: process.env });
    expect(JSON.parse(keychainPlan).sandbox.policy.allowRead).toEqual(process.platform === "darwin" ? [path.join(os.homedir(), "Library", "Keychains", "login.keychain-db")] : []);
  });

  it("adds stricter egress and authentication-file protection only when selected", () => {
    const cwd = path.resolve("fixture-workspace");
    const store = path.resolve("fixture-store");
    const env = { HOME: path.resolve("fixture-home"), CODEX_HOME: path.resolve("custom-codex"), CLAUDE_CONFIG_DIR: path.resolve("custom-claude") };
    const base = anthropicSandboxConfig(cwd, store, {}, env);
    const strict = anthropicSandboxConfig(cwd, store, { strictEgress: true, denyAgentAuth: true, allowHosts: ["api.example.test"] }, env);
    expect(strict.network.allowedDomains).toEqual(["api.example.test"]);
    expect(base.network.allowedDomains.length).toBeGreaterThan(1);
    for (const file of agentAuthenticationPaths(env)) { expect(strict.filesystem.denyRead).toContain(file); expect(base.filesystem.denyRead).not.toContain(file); }
    expect(anthropicSandboxReadiness("win32")).toMatchObject({ supported: false, ready: false, tlsInterception: false });
  });

  it("adds the Keychain IPC denial to the existing trusted macOS profile", () => {
    const wrapped = "env NO_PROXY=localhost,*.local /usr/bin/sandbox-exec -p '(version 1)(allow default)' /bin/bash -c 'fixed command'";
    const restricted = restrictMacCredentialIpc(wrapped);
    expect(restricted).toContain('com.apple.securityd.xpc');
    expect(restricted).toContain('/bin/bash');
    for (const command of ["echo unsafe", wrapped + "; echo unsafe", wrapped.replace("(version 1)", "unexpected")]) {
      expect(() => restrictMacCredentialIpc(command)).toThrow("wrapper");
      expect(() => allowMacAgentKeychainRead(command, "/fixture/login.keychain-db")).toThrow("wrapper");
    }
    const allowed = allowMacAgentKeychainRead(wrapped, '/fixture/quote" and space/login.keychain-db');
    expect(allowed).toContain('(allow file-read* (literal');
    expect(allowed).not.toContain('allow file-write');
    expect(allowed).not.toContain('trustd');
  });

  it("makes login Keychain access opt-in, macOS-only, and subordinate to explicit denies", async () => {
    await fixtureStore();
    const cwd = path.join(root, "workspace");
    const keychains = path.join(root, "outside", "Library", "Keychains");
    await mkdir(keychains, { recursive: true });
    const loginFile = path.join(keychains, "login.keychain-db");
    await writeFile(loginFile, "synthetic encrypted database");
    const alias = path.join(root, "workspace", "keychains-link");
    await symlink(keychains, alias);
    vi.spyOn(os, "homedir").mockReturnValue(path.join(root, "outside"));
    expect(macAgentKeychainReadPath(cwd, {}, "darwin")).toBeUndefined();
    const allowed = { allowAgentKeychain: true };
    expect(macAgentKeychainReadPath(cwd, allowed, "darwin")).toBe(loginFile);
    for (const platform of ["linux", "win32"]) expect(macAgentKeychainReadPath(cwd, allowed, platform)).toBeUndefined();
    expect(macAgentKeychainReadPath(cwd, { ...allowed, denyAgentAuth: true }, "darwin")).toBeUndefined();
    for (const deny of [loginFile, keychains, path.dirname(keychains), "/", path.join(keychains, "*.keychain-db"), path.join(keychains, "**"), alias, path.join(alias, "*.keychain-db"), path.relative(cwd, keychains)]) {
      expect(macAgentKeychainReadPath(cwd, { ...allowed, denyRead: [deny] }, "darwin"), deny).toBeUndefined();
    }
    expect(macAgentKeychainReadPath(cwd, { ...allowed, denyRead: [path.join(keychains, "other-db")] }, "darwin")).toBe(loginFile);
  });

  it.skipIf(process.platform !== "darwin")("allows only the selected synthetic login database and keeps writes, siblings, and explicit denies blocked", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const userHome = path.join(root, "outside");
    const keychains = path.join(userHome, "Library", "Keychains");
    await mkdir(keychains, { recursive: true });
    const loginFile = path.join(keychains, "login.keychain-db");
    const sibling = path.join(keychains, "other.keychain-db");
    await writeFile(loginFile, "synthetic database"); await writeFile(sibling, "synthetic unrelated database");
    vi.spyOn(os, "homedir").mockReturnValue(userHome);
    const probe = path.join(workspace, "keychain-probe.mjs");
    await writeFile(probe, `import assert from 'node:assert/strict'; import {readFileSync,writeFileSync} from 'node:fs'; const file=${JSON.stringify(loginFile)}; if(process.env.SGW_EXPECT_KEYCHAIN_READ==='1') assert.equal(readFileSync(file,'utf8'),'synthetic database'); else assert.throws(()=>readFileSync(file)); assert.throws(()=>readFileSync(${JSON.stringify(sibling)})); assert.throws(()=>writeFileSync(file,'changed')); assert.throws(()=>writeFileSync(${JSON.stringify(path.join(keychains, 'created'))},'changed'));`);
    for (const sandboxOptions of [{}, { allowAgentKeychain: true }, { allowAgentKeychain: true, denyAgentAuth: true }, { allowAgentKeychain: true, denyRead: [loginFile] }, { allowAgentKeychain: true, denyRead: [keychains] }]) {
      const visible = Boolean(macAgentKeychainReadPath(workspace, sandboxOptions));
      const prepared = await prepareGuardedRun(store, { agent: "claude-code", command: process.execPath, args: [probe], cwd: workspace, env: { PATH: process.env.PATH, SGW_EXPECT_KEYCHAIN_READ: visible ? "1" : "0" }, sandbox: "anthropic", sandboxOptions });
      expect(prepared.plan.sandbox.policy?.allowRead).toEqual(visible ? [loginFile] : []);
      expect(await runAnthropicSandbox(prepared, store.home, sandboxOptions)).toBe(0);
    }
    expect(await readFile(loginFile, "utf8")).toBe("synthetic database");
  });

  it("fails before credential enrollment when platform or dependency checks fail", async () => {
    const store = await fixtureStore();
    const opts = { agent: "codex", command: process.execPath, cwd: path.join(root, "workspace"), env: { TEST_PASSWORD: randomUUID() }, sandbox: "anthropic" as const, persist: true };
    const platform = process.platform;
    try {
      Object.defineProperty(process, "platform", { value: "win32" });
      await expect(prepareGuardedRun(store, opts)).rejects.toThrow("Windows");
    } finally { Object.defineProperty(process, "platform", { value: platform }); }
    if (platform !== "win32") {
      vi.spyOn(SandboxManager, "checkDependencies").mockReturnValue({ errors: ["missing fixture dependency"], warnings: [] });
      await expect(prepareGuardedRun(store, opts)).rejects.toThrow("missing fixture dependency");
    }
    expect(await store.listHandles()).toEqual([]);
    expect(SandboxManager.getProxyPort()).toBeUndefined();
  });

  it.skipIf(!["darwin", "linux"].includes(process.platform))("preserves saved authentication by default and denies selected authentication files while workspace actions still work", async () => {
    const store = await fixtureStore();
    const auth = path.join(root, "outside", "codex"); await mkdir(auth);
    await writeFile(path.join(auth, "auth.json"), JSON.stringify({ synthetic: randomUUID() }));
    const workspace = path.join(root, "workspace");
    const probe = path.join(workspace, "auth-probe.mjs");
    await writeFile(probe, "import assert from 'node:assert/strict'; import {readFileSync,writeFileSync} from 'node:fs'; const file=process.env.CODEX_HOME+'/auth.json'; if(process.env.SGW_EXPECT_AUTH_VISIBLE==='1') assert(JSON.parse(readFileSync(file)).synthetic); else { try { assert.equal(readFileSync(file).length,0); } catch(error) { assert.match(error.code || '',/^(EPERM|EACCES|ENOENT)$/); } } writeFileSync('strict-ready','ok');\n");
    const defaults = await prepareGuardedRun(store, { agent: "codex", command: process.execPath, args: [probe], cwd: workspace, env: { PATH: process.env.PATH, CODEX_HOME: auth, SGW_EXPECT_AUTH_VISIBLE: "1" }, sandbox: "anthropic" });
    expect(await runAnthropicSandbox(defaults, store.home)).toBe(0);
    const prepared = await prepareGuardedRun(store, { agent: "codex", command: process.execPath, args: [probe], cwd: workspace, env: { PATH: process.env.PATH, CODEX_HOME: auth }, sandbox: "anthropic", sandboxOptions: { strictEgress: true, denyAgentAuth: true } });
    expect(await runAnthropicSandbox(prepared, store.home, { strictEgress: true, denyAgentAuth: true })).toBe(0);
    expect(await readFile(path.join(workspace, "strict-ready"), "utf8")).toBe("ok");
  });

  it("rejects invalid broker capabilities and closes unauthenticated connections", async () => {
    const store = await fixtureStore();
    await expect(runSandboxMcpBridge({ SGW_SANDBOX_BROKER_PORT: "0" })).rejects.toThrow("Invalid sandbox");
    const broker = await startSandboxBroker(path.join(root, "workspace"), store.home);
    try {
      await new Promise<void>((resolve, reject) => {
        const socket = connect(broker.port, "127.0.0.1", () => socket.write("invalid fixture capability\n"));
        socket.once("error", reject);
        socket.once("close", () => resolve());
      });
      expect(await store.listHandles()).toEqual([]);
    } finally { await broker.close(); }
  });

  it.skipIf(!["darwin", "linux"].includes(process.platform))("resets after initialization or wrapping failure and can launch again", async () => {
    const store = await fixtureStore();
    const prepared = await prepareGuardedRun(store, { agent: "codex", command: process.execPath, args: ["-v"], cwd: path.join(root, "workspace"), env: { PATH: process.env.PATH }, sandbox: "anthropic" });
    const init = vi.spyOn(SandboxManager, "initialize").mockRejectedValueOnce(new Error("dependency fixture failure"));
    await expect(runAnthropicSandbox(prepared, store.home)).rejects.toThrow("dependency fixture failure");
    expect(SandboxManager.getProxyPort()).toBeUndefined();
    init.mockRestore();
    const wrap = vi.spyOn(SandboxManager, "wrapWithSandbox").mockRejectedValueOnce(new Error("wrapping fixture failure"));
    await expect(runAnthropicSandbox(prepared, store.home)).rejects.toThrow("wrapping fixture failure");
    expect(SandboxManager.getProxyPort()).toBeUndefined();
    wrap.mockRestore();
    expect(await runAnthropicSandbox(prepared, store.home)).toBe(0);
    expect(SandboxManager.getProxyPort()).toBeUndefined();
    prepared.plan.command = "/missing/sandbox-fixture-command";
    expect(await runAnthropicSandbox(prepared, store.home)).toBe(1);
  });

  it.skipIf(!["darwin", "linux"].includes(process.platform))("passes shell metacharacters as inert arguments through a protected manifest", async () => {
    const store = await fixtureStore();
    const probe = path.join(root, "workspace", "args.mjs");
    await writeFile(probe, "import {mkdtempSync,writeFileSync} from 'node:fs'; import path from 'node:path'; writeFileSync(path.join(mkdtempSync(path.join(process.env.TMPDIR,'probe-')),'data'),'temporary'); writeFileSync('tmp.json',JSON.stringify(process.env.TMPDIR)); writeFileSync('args.json', JSON.stringify(process.argv.slice(2)));\n");
    const args = ["semi; colon", "$(touch injected)", "`touch injected`", "quote' and spaces", "line\nbreak"];
    const prepared = await prepareGuardedRun(store, { agent: "codex", command: process.execPath, args: [probe, ...args], cwd: path.join(root, "workspace"), env: { PATH: process.env.PATH }, sandbox: "anthropic" });
    expect(await runAnthropicSandbox(prepared, store.home)).toBe(0);
    expect(JSON.parse(await readFile(path.join(root, "workspace", "args.json"), "utf8"))).toEqual(args);
    const tmpdir = JSON.parse(await readFile(path.join(root, "workspace", "tmp.json"), "utf8"));
    expect(path.dirname(tmpdir)).toBe(path.join(root, "workspace"));
    await expect(readFile(tmpdir)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(path.join(root, "workspace", "injected"))).rejects.toThrow();
  });

  it.skipIf(!["darwin", "linux"].includes(process.platform))("closes broker and proxy and removes session configuration after SIGTERM", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const probe = path.join(workspace, "wait.mjs");
    await writeFile(probe, "import {readFileSync,writeFileSync} from 'node:fs'; writeFileSync('ready.json', JSON.stringify({config:process.env.SGW_SANDBOX_MCP_CONFIG, data:JSON.parse(readFileSync(process.env.SGW_SANDBOX_MCP_CONFIG,'utf8'))})); setInterval(()=>{},1000);\n");
    const loader = new URL("../node_modules/tsx/dist/esm/index.mjs", import.meta.url).href;
    const child = spawn(process.execPath, ["--import", loader, "src/cli.ts", "run", "codex", "--sandbox", "anthropic", "--cwd", workspace, "--command", process.execPath, "--", probe], {
      env: process.env, stdio: ["ignore", "ignore", "pipe"]
    });
    const completion = new Promise<number | null>((resolve, reject) => { child.once("error", reject); child.once("close", resolve); });
    try {
      let ready: { config: string; data: { mcpServers: { "s-gw": { env: Record<string, string> } } } } | undefined;
      const deadline = Date.now() + 10000;
      while (!ready && Date.now() < deadline) {
        try { ready = JSON.parse(await readFile(path.join(workspace, "ready.json"), "utf8")); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        if (!ready) await new Promise(resolve => setTimeout(resolve, 30));
      }
      expect(ready).toBeTruthy();
      child.kill("SIGTERM");
      expect(await completion).toBe(143);
      await expect(readFile(ready!.config)).rejects.toThrow();
      const env = ready!.data.mcpServers["s-gw"].env;
      const ports = [Number(env.SGW_SANDBOX_BROKER_PORT), ...(process.platform === "darwin" ? [Number(new URL(env.SGW_SANDBOX_PROXY_URL).port)] : [])];
      for (const port of ports) {
        await new Promise<void>((resolve, reject) => {
          const socket = connect(port, "127.0.0.1");
          socket.once("connect", () => { socket.destroy(); reject(new Error("Sandbox listener survived termination")); });
          socket.once("error", error => { expect((error as NodeJS.ErrnoException).code).toBe("ECONNREFUSED"); resolve(); });
        });
      }
    } finally { if (child.exitCode === null) child.kill("SIGKILL"); await completion; }
  });

  it.skipIf(!["darwin", "linux"].includes(process.platform))("confines a real process tree while MCP approval and execution run outside it", async () => {
    const store = await fixtureStore();
    const password = `synthetic SSH fixture ${randomUUID()}`;
    await store.addSecret({ name: "sandbox SSH fixture", type: "password", value: password, policy: { allowedCommands: ["s-gw:ssh-session"] } });
    const other = await store.addSecret({ name: "generic fixture", type: "password", value: randomUUID(), policy: { injectEnv: "FIXTURE", allowedCommands: [process.execPath] } });
    const generic = await store.createRequest(other.handle, buildEnvCommandAction({ command: process.execPath, args: ["-v"], injectEnv: "FIXTURE" }), "Generic fixture");
    await store.approveRequest(generic.id);
    const helper = path.join(store.home, "ssh-fixture.cjs");
    await writeFile(helper, `#!${process.execPath}\nif (!process.argv.includes('-M') && !process.argv.includes('-O')) console.log('owned SSH fixture complete');\n`, { mode: 0o700 });
    process.env.SGW_SSH_CLI = helper;
    await symlink(store.storePath, path.join(root, "workspace", "store-link"));
    let directConnections = 0;
    const server = createServer(socket => { directConnections += 1; socket.end(); });
    await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("Fixture port missing");
    const agent = path.resolve("tests/fixtures/anthropic-agent.mjs");
    const tls = await httpsFixture(path.join(root, "outside"));
    const httpPassword = `synthetic HTTPS fixture ${randomUUID()}`;
    const issued = randomUUID();
    const https = createHttpsServer(tls, (req, res) => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify({ result: "owned HTTPS fixture complete", echo: req.headers.authorization, access_token: issued })); });
    await new Promise<void>(resolve => https.listen(0, "127.0.0.1", resolve));
    const httpsAddress = https.address();
    if (!httpsAddress || typeof httpsAddress === "string") throw new Error("HTTPS fixture port missing");
    await store.addSecret({ name: "sandbox HTTPS fixture", type: "api-token", value: httpPassword, policy: { allowedCommands: ["s-gw:https-request"], allowedDestinations: [`127.0.0.1:${httpsAddress.port}`] } });
    process.env.NODE_EXTRA_CA_CERTS = tls.certFile;
    let launch: Promise<number> | undefined;
    try {
      launch = runGuardedAgent(store, {
        agent: "codex", command: process.execPath, args: [agent], cwd: path.join(root, "workspace"), sandbox: "anthropic",
        env: { PATH: process.env.PATH, SGW_TEST_ROOT: root, SGW_TEST_PORT: String(address.port), SGW_TEST_HTTP_URL: `https://127.0.0.1:${httpsAddress.port}/operation`, SGW_TEST_ENV_REQUEST_ID: generic.id,
          SGW_MASTER_PASSPHRASE: process.env.SGW_MASTER_PASSPHRASE, SSH_AUTH_SOCK: "/synthetic/socket", BASH_ENV: "/missing/bash-env", NODE_OPTIONS: "--trace-warnings" }
      });
      const deadline = Date.now() + 15000;
      let requestId: string | undefined, httpRequestId: string | undefined;
      while (!requestId && Date.now() < deadline) {
        try { ({ requestId, httpRequestId } = JSON.parse(await readFile(path.join(root, "workspace", "request.json"), "utf8"))); }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        if (!requestId) await new Promise(resolve => setTimeout(resolve, 30));
      }
      expect(requestId).toBeTruthy();
      await store.approveRequest(requestId!);
      expect(httpRequestId).toBeTruthy(); await store.approveRequest(httpRequestId!);
      await writeFile(path.join(root, "workspace", "approval-ready"), "approved fixture");
      expect(await launch).toBe(0);
      expect(directConnections).toBe(0);
      const results = await readFile(path.join(root, "workspace", "results.json"), "utf8");
      expect(JSON.parse(results)).toHaveLength(6);
      expect(results).not.toContain(password);
      expect(results).not.toContain(httpPassword); expect(results).not.toContain(issued);
      expect((await store.getRequest(httpRequestId!)).state).toBe("executed");
      expect((await store.getRequest(requestId!)).state).toBe("executed");
      expect((await store.getRequest(generic.id)).state).toBe("approved");
      expect(SandboxManager.getProxyPort()).toBeUndefined();
    } finally {
      await new Promise<void>(resolve => server.close(() => resolve()));
      https.closeAllConnections(); await new Promise<void>(resolve => https.close(() => resolve()));
      if (launch) await launch;
    }
  }, 30_000);
});
