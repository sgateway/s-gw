import { createHash, randomUUID } from "node:crypto";
import { copyFile, mkdtemp, mkdir, writeFile, readFile, rm, symlink, realpath } from "node:fs/promises";
import { createServer, connect } from "node:net";
import { createServer as createHttpsServer } from "node:https";
import { execFileSync, spawn } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { SandboxManager } from "@anthropic-ai/sandbox-runtime";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { anthropicSandboxConfig, isolatedAgentEnvironment, runAnthropicSandbox, sandboxAgentArguments, sandboxSessionRoot } from "../src/anthropic-sandbox.js";
import { prepareGuardedRun, runGuardedAgent } from "../src/guard.js";
import { buildEnvCommandAction } from "../src/gateway.js";
import { executeApprovedRequest } from "../src/executor.js";
import { SecretStore } from "../src/store.js";
import { startSandboxBroker, runSandboxMcpBridge, ownedModuleCommand, brokerChildEnvironment } from "../src/sandbox-broker.js";
import { anthropicSandboxReadiness, agentAuthenticationPaths, restrictMacCredentialIpc, macAgentKeychainReadPath, allowMacAgentKeychainRead } from "../src/anthropic-sandbox.js";
import { httpsFixture } from "./helpers/https-fixture.js";

let root = "";
const originalEnv = { ...process.env };

it.skipIf(process.platform === "win32")("keeps marked Keychain repair lock mode in the strict outside broker", () => {
  const env = brokerChildEnvironment(process.cwd(), path.join(os.tmpdir(), "sgw-test-store"), "Codex", [], {
    strictEnv: true,
    inheritedEnv: { PATH: process.env.PATH, SGW_REQUIRE_MARKED_KEYCHAIN_REPAIR_LOCK: "1" },
    agentWritablePaths: [process.cwd()]
  });
  expect(env.SGW_REQUIRE_MARKED_KEYCHAIN_REPAIR_LOCK).toBe("1");
});

it.skipIf(process.platform === "win32")("passes a validated Keychain subprocess timeout to the strict outside broker", () => {
  const inheritedEnv = { PATH: process.env.PATH, SGW_MAC_KEYCHAIN_SUBPROCESS_TIMEOUT_MS: "2000" };
  const options = { strictEnv: true, inheritedEnv, agentWritablePaths: [process.cwd()] };
  const env = brokerChildEnvironment(process.cwd(), path.join(os.tmpdir(), "sgw-test-store"), "Codex", [], options);
  expect(env.SGW_MAC_KEYCHAIN_SUBPROCESS_TIMEOUT_MS).toBe("2000");

  inheritedEnv.SGW_MAC_KEYCHAIN_SUBPROCESS_TIMEOUT_MS = "200000";
  expect(() => brokerChildEnvironment(process.cwd(), path.join(os.tmpdir(), "sgw-test-store"), "Codex", [], options))
    .toThrow(/Invalid trusted broker setting: SGW_MAC_KEYCHAIN_SUBPROCESS_TIMEOUT_MS/);
});
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
  process.env.SGW_RECOVERY_HOME = path.join(root, "recovery");
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
    const deniedKeychainPlan = execFileSync(process.execPath, ["--import", loader, "src/cli.ts", "run", "claude-code", "--sandbox", "anthropic", "--dry-run", "--command", process.execPath, "--allow-agent-keychain", "--deny-keychain", "--", "-v"], { encoding: "utf8", env: process.env });
    expect(JSON.parse(deniedKeychainPlan).sandbox.policy.allowRead).toEqual([]);
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

  it("starts isolated authentication with a fresh agent home and a small environment", () => {
    const workspace = path.resolve("fixture-workspace");
    const store = path.resolve("fixture-store");
    const outside = path.resolve("fixture-outside");
    const config = anthropicSandboxConfig(workspace, store, { isolatedAuth: true, allowHosts: ["model.example.test"] },
      { HOME: outside, PATH: process.env.PATH }, process.execPath);
    expect(config.filesystem.denyRead).toContain(outside);
    expect(config.filesystem.allowRead).toContain(workspace);
    expect(config.network.allowedDomains).toEqual(["model.example.test"]);
    expect(() => anthropicSandboxConfig(workspace, store, { isolatedAuth: true, allowAgentKeychain: true })).toThrow();
    expect(() => anthropicSandboxConfig(workspace, store, { isolatedAuth: true, denyRead: ["private"] })).toThrow();
    expect(() => anthropicSandboxConfig(store, store, { isolatedAuth: true })).toThrow();
    const env = isolatedAgentEnvironment({ PATH: "/usr/bin", LANG: "en_US.UTF-8", API_KEY: "private",
      SGW_MASTER_PASSPHRASE: "private", NODE_OPTIONS: "--require /private", SSH_AUTH_SOCK: "/private/socket" },
    { SGW_SANDBOX_BROKER_PORT: "1234" }, "/fixture/agent-tmp", "/fixture/mcp.json");
    expect(env).toMatchObject({ HOME: "/fixture/agent-tmp", PATH: "/usr/bin", LANG: "en_US.UTF-8",
      SGW_SANDBOX_BROKER_PORT: "1234", SGW_SANDBOX_MCP_CONFIG: "/fixture/mcp.json" });
    for (const name of ["API_KEY", "SGW_MASTER_PASSPHRASE", "NODE_OPTIONS", "SSH_AUTH_SOCK"]) expect(env[name]).toBeUndefined();
  });

  it("checks native account paths and workspace overlap in strict isolated mode", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const outside = path.join(root, "outside");
    const nativeHome = path.join(root, "native-home");
    await mkdir(nativeHome);
    const account = os.userInfo();
    vi.spyOn(os, "userInfo").mockReturnValue({ ...account, homedir: nativeHome });
    process.env.HOME = outside;
    const opts = { isolatedAuth: true, strictIsolatedAuth: true };
    const config = anthropicSandboxConfig(workspace, store.home, opts, { HOME: outside, PATH: process.env.PATH }, process.execPath);
    expect(config.filesystem.denyRead).toContain(nativeHome);
    expect(config.filesystem.allowRead).toContain(workspace);
    await mkdir(path.join(workspace, "nested-store"));
    expect(() => anthropicSandboxConfig(workspace, path.join(workspace, "nested-store"), opts)).toThrow("overlap the s-gw store");
    const storeAlias = path.join(root, "store-alias");
    await symlink(store.home, storeAlias);
    const aliasConfig = anthropicSandboxConfig(workspace, storeAlias, opts);
    expect(aliasConfig.filesystem.denyRead).toContain(store.home);
    expect(aliasConfig.filesystem.denyWrite).toContain(store.home);
    const recovery = path.join(root, "recovery");
    await mkdir(recovery, { recursive: true });
    const recoveryConfig = anthropicSandboxConfig(workspace, store.home, opts);
    expect(recoveryConfig.filesystem.denyRead).toContain(recovery);
    expect(recoveryConfig.filesystem.denyWrite).toContain(recovery);
    expect(() => anthropicSandboxConfig(recovery, store.home, opts)).toThrow("recovery vault and workspace");
    expect(() => anthropicSandboxConfig(workspace, store.home, { ...opts, allowWrite: [outside] })).toThrow("only inside the workspace");
    await symlink(outside, path.join(workspace, "writable-alias"));
    expect(() => anthropicSandboxConfig(workspace, store.home, { ...opts, allowWrite: ["writable-alias"] })).toThrow("only inside the workspace");
    const authFile = path.join(outside, ".codex", "auth.json");
    await mkdir(path.dirname(authFile));
    await writeFile(authFile, randomUUID());
    expect(() => anthropicSandboxConfig(workspace, store.home, opts,
      { HOME: outside, NODE_EXTRA_CA_CERTS: authFile }, process.execPath)).toThrow("runtime dependency");
    expect(() => anthropicSandboxConfig(workspace, store.home, opts,
      { HOME: outside, SSL_CERT_FILE: path.join(store.home, "store.json") }, process.execPath)).toThrow("runtime dependency");
    expect(() => anthropicSandboxConfig(workspace, store.home, { strictIsolatedAuth: true })).toThrow("requires isolated authentication");
  });

  it("does not re-allow an arbitrary native-home file as a CA dependency", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const nativeHome = path.join(root, "native-home");
    await mkdir(nativeHome);
    const account = os.userInfo();
    vi.spyOn(os, "userInfo").mockReturnValue({ ...account, homedir: nativeHome });
    const canary = path.join(nativeHome, "runtime.pem");
    await writeFile(canary, randomUUID());
    const opts = { isolatedAuth: true, strictIsolatedAuth: true };
    const env = { HOME: nativeHome, PATH: process.env.PATH };
    for (const name of ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"] as const) {
      expect(() => anthropicSandboxConfig(workspace, store.home, opts,
        { ...env, [name]: canary }, process.execPath)).toThrow("runtime dependency");
    }
    const outsideCa = path.join(root, "outside", "runtime.pem");
    await writeFile(outsideCa, randomUUID());
    const config = anthropicSandboxConfig(workspace, store.home, opts,
      { ...env, NODE_EXTRA_CA_CERTS: outsideCa }, process.execPath);
    expect(config.filesystem.allowRead).toContain(outsideCa);
  });

  it("rejects package and command read allowances under protected homes", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const outside = path.join(root, "outside");
    const packageRoot = await realpath(fileURLToPath(new URL("../", import.meta.url)));
    const account = os.userInfo();
    const userInfo = vi.spyOn(os, "userInfo").mockReturnValue({ ...account, homedir: path.dirname(packageRoot) });
    const opts = { isolatedAuth: true, strictIsolatedAuth: true };
    expect(() => anthropicSandboxConfig(workspace, store.home, opts,
      { HOME: outside, PATH: process.env.PATH }, process.execPath)).toThrow("runtime dependency");

    const nativeHome = path.join(root, "native-home");
    await mkdir(nativeHome);
    userInfo.mockReturnValue({ ...account, homedir: nativeHome });
    const nativeCommand = path.join(nativeHome, "agent");
    await writeFile(nativeCommand, randomUUID());
    expect(() => anthropicSandboxConfig(workspace, store.home, opts,
      { HOME: outside, PATH: process.env.PATH }, nativeCommand)).toThrow("runtime dependency");
    const workspaceCommand = path.join(workspace, "agent");
    await writeFile(workspaceCommand, "fixture");
    expect(anthropicSandboxConfig(workspace, store.home, opts,
      { HOME: outside, PATH: process.env.PATH }, workspaceCommand).filesystem.allowRead).toContain(workspaceCommand);
    const workspaceNode = path.join(workspace, "runtime-node");
    await writeFile(workspaceNode, "fixture");
    const originalNode = process.execPath;
    try {
      process.execPath = workspaceNode;
      expect(() => anthropicSandboxConfig(workspace, store.home, opts,
        { HOME: outside, PATH: process.env.PATH }, workspaceCommand)).toThrow("broker's Node runtime");
    } finally { process.execPath = originalNode; }
    expect(() => anthropicSandboxConfig(packageRoot, store.home, opts,
      { HOME: outside, PATH: process.env.PATH }, process.execPath)).toThrow("runtime package and workspace");
  });

  it.skipIf(!["darwin", "linux"].includes(process.platform))("denies a native-home canary when the parent HOME is overridden", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const outside = path.join(root, "outside");
    const nativeProbe = await mkdtemp(path.join(os.userInfo().homedir, ".sgw-native-home-probe-"));
    try {
      const canary = path.join(nativeProbe, "canary.txt");
      const authFile = path.join(outside, ".codex", "auth.json");
      const logDir = path.join(outside, ".npm", "_logs");
      const logFile = path.join(logDir, "canary.txt");
      const recoveryFile = path.join(root, "recovery", "canary.txt");
      await mkdir(path.dirname(authFile));
      await mkdir(logDir, { recursive: true });
      await writeFile(authFile, randomUUID());
      await writeFile(logFile, randomUUID());
      await mkdir(path.dirname(recoveryFile), { recursive: true });
      await writeFile(recoveryFile, randomUUID());
      const homeAlias = path.join(root, "home-alias");
      await symlink(outside, homeAlias);
      const script = path.join(workspace, "native-home-probe.mjs");
      await writeFile(canary, randomUUID());
      await writeFile(script, `import { readFileSync, writeFileSync } from 'node:fs';
const read = file => { try { readFileSync(file); return true; } catch { return false; } };
let logWritable = false;
try { writeFileSync(${JSON.stringify(logFile)}, 'unexpected'); logWritable = true; } catch {}
writeFileSync('native-home-result.json', JSON.stringify({ native: read(${JSON.stringify(canary)}),
  aliasHome: read(${JSON.stringify(authFile)}), defaultLog: read(${JSON.stringify(logFile)}),
  recovery: read(${JSON.stringify(recoveryFile)}), logWritable }));
`);
      process.env.HOME = homeAlias;
      const opts = { isolatedAuth: true, strictIsolatedAuth: true };
      const run = { agent: "codex", command: process.execPath,
        args: [script], cwd: workspace, env: { PATH: process.env.PATH, HOME: homeAlias },
        sandbox: "anthropic" as const, sandboxOptions: opts };
      const packageRoot = await realpath(fileURLToPath(new URL("../", import.meta.url)));
      const nativeHome = await realpath(os.userInfo().homedir);
      const runtimeInNativeHome = [packageRoot, await realpath(process.execPath)].some(file =>
        file === nativeHome || file.startsWith(nativeHome + path.sep));
      if (runtimeInNativeHome) {
        await expect(prepareGuardedRun(store, run)).rejects.toThrow("runtime dependency");
        return;
      }
      const prepared = await prepareGuardedRun(store, run);
      expect(await runAnthropicSandbox(prepared, store.home, opts)).toBe(0);
      expect(JSON.parse(await readFile(path.join(workspace, "native-home-result.json"), "utf8"))).toEqual({
        native: false, aliasHome: false, defaultLog: false, recovery: false, logWritable: false
      });
    } finally { await rm(nativeProbe, { recursive: true, force: true }); }
  });

  it("refuses isolated Linux mode when Unix socket blocking is unavailable", async () => {
    const store = await fixtureStore();
    const opts = { isolatedAuth: true };
    const prepared = await prepareGuardedRun(store, { agent: "codex", command: process.execPath,
      cwd: path.join(root, "workspace"), env: { PATH: process.env.PATH }, sandbox: "anthropic", sandboxOptions: opts });
    const platform = process.platform;
    try {
      Object.defineProperty(process, "platform", { value: "linux" });
      vi.spyOn(SandboxManager, "checkDependencies").mockReturnValue({ errors: [],
        warnings: ["seccomp not available - unix socket access not restricted"] });
      await expect(runAnthropicSandbox(prepared, store.home, opts)).rejects.toThrow("Unix-socket seccomp filter");
    } finally { Object.defineProperty(process, "platform", { value: platform }); }
  });

  it.skipIf(!["darwin", "linux"].includes(process.platform))("blocks outside authentication files and symlink aliases in isolated mode", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const outside = path.join(root, "outside");
    const auth = path.join(outside, "auth.json");
    await writeFile(auth, randomUUID());
    await symlink(auth, path.join(workspace, "auth-link"));
    const probe = path.join(workspace, "isolated-auth-probe.mjs");
    await writeFile(probe, `import { readFileSync, writeFileSync } from 'node:fs';
const read = file => { try { readFileSync(file); return true; } catch { return false; } };
writeFileSync('isolated-result.json', JSON.stringify({
  direct: read(${JSON.stringify(auth)}),
  symlink: read('auth-link'),
  inheritedSecret: Boolean(process.env.SGW_TEST_SECRET),
  inheritedStore: Boolean(process.env.SGW_MASTER_PASSPHRASE),
  freshHome: process.env.HOME.includes('.sgw-tmp-')
}));
`);
    const opts = { isolatedAuth: true };
    const prepared = await prepareGuardedRun(store, { agent: "codex", command: process.execPath,
      args: [probe], cwd: workspace, env: { PATH: process.env.PATH, HOME: outside,
        SGW_TEST_SECRET: randomUUID(), SGW_MASTER_PASSPHRASE: randomUUID() }, sandbox: "anthropic", sandboxOptions: opts });
    expect(await runAnthropicSandbox(prepared, store.home, opts)).toBe(0);
    expect(JSON.parse(await readFile(path.join(workspace, "isolated-result.json"), "utf8"))).toEqual({
      direct: false, symlink: false, inheritedSecret: false, inheritedStore: false, freshHome: true
    });
  });

  it.skipIf(!["darwin", "linux"].includes(process.platform))("runs restricted MCP through the strict outside broker environment", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const probe = path.join(workspace, "strict-broker-probe.mjs");
    const sdkRoot = path.resolve("node_modules/@modelcontextprotocol/sdk/dist/esm");
    await writeFile(probe, `import { readFileSync, writeFileSync } from 'node:fs';
import { Client } from ${JSON.stringify(new URL(`file://${path.join(sdkRoot, "client/index.js")}`).href)};
import { StdioClientTransport } from ${JSON.stringify(new URL(`file://${path.join(sdkRoot, "client/stdio.js")}`).href)};
const entry = JSON.parse(readFileSync(process.env.SGW_SANDBOX_MCP_CONFIG, 'utf8')).mcpServers['s-gw'];
const client = new Client({ name: 'untrusted display name', version: '1' });
try {
  await client.connect(new StdioClientTransport({ ...entry, stderr: 'pipe' }));
  const names = (await client.listTools()).tools.map(tool => tool.name);
  writeFileSync('strict-broker-result.json', JSON.stringify({ http: names.includes('sgw_request_http'), scan: names.includes('sgw_scan_file') }));
} finally { await client.close(); }
`);
    const opts = { strictBrokerEnv: true };
    const prepared = await prepareGuardedRun(store, { agent: "codex", command: process.execPath,
      args: [probe], cwd: workspace, env: { PATH: process.env.PATH }, sandbox: "anthropic", sandboxOptions: opts });
    expect(await runAnthropicSandbox(prepared, store.home, opts)).toBe(0);
    expect(JSON.parse(await readFile(path.join(workspace, "strict-broker-result.json"), "utf8"))).toEqual({ http: true, scan: false });
  });

  it.skipIf(!["darwin", "linux"].includes(process.platform))("hides another live session capability while keeping own MCP and allowed localhost access", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const siblingWorkspace = path.join(root, "sibling-workspace");
    await mkdir(siblingWorkspace);
    const sessionRoot = sandboxSessionRoot();
    await mkdir(sessionRoot, { recursive: true, mode: 0o700 });
    const siblingDir = await mkdtemp(path.join(sessionRoot, "session-"));
    const siblingBroker = await startSandboxBroker(siblingWorkspace, store.home, "Claude Code", [],
      { strictEnv: true, agentWritablePaths: [siblingWorkspace] });
    const local = createServer(socket => socket.end("synthetic localhost fixture"));
    await new Promise<void>(resolve => local.listen(0, "127.0.0.1", resolve));
    try {
      const siblingConfig = path.join(siblingDir, "mcp.json");
      await writeFile(siblingConfig, JSON.stringify({ mcpServers: { "s-gw": { env: {
        SGW_SANDBOX_BROKER_PORT: String(siblingBroker.port), SGW_SANDBOX_BROKER_TOKEN: siblingBroker.token
      } } } }), { mode: 0o600 });
      await writeFile(path.join(workspace, "fixture.json"), JSON.stringify({ siblingConfig,
        localPort: (local.address() as { port: number }).port }));
      const sdkRoot = path.resolve("node_modules/@modelcontextprotocol/sdk/dist/esm");
      const probe = path.join(workspace, "session-isolation-probe.mjs");
      await writeFile(probe, `import { readFileSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { request } from 'node:http';
import { Client } from ${JSON.stringify(new URL(`file://${path.join(sdkRoot, "client/index.js")}`).href)};
import { StdioClientTransport } from ${JSON.stringify(new URL(`file://${path.join(sdkRoot, "client/stdio.js")}`).href)};
const fixture = JSON.parse(readFileSync('fixture.json', 'utf8'));
let siblingRead = false;
try { readFileSync(fixture.siblingConfig); siblingRead = true; } catch {}
const own = JSON.parse(readFileSync(process.env.SGW_SANDBOX_MCP_CONFIG, 'utf8')).mcpServers['s-gw'];
const client = new Client({ name: 'synthetic agent', version: '1' });
let ownMcp = false;
try {
  await client.connect(new StdioClientTransport({ ...own, stderr: 'pipe' }));
  ownMcp = (await client.listTools()).tools.some(tool => tool.name === 'sgw_request_http');
} finally { await client.close(); }
const direct = await new Promise(resolve => {
  const socket = connect(fixture.localPort, '127.0.0.1');
  socket.once('connect', () => { socket.destroy(); resolve(true); });
  socket.once('error', () => resolve(false));
  socket.setTimeout(2000, () => { socket.destroy(); resolve(false); });
});
const proxy = new URL(process.env.SGW_SANDBOX_PROXY_URL);
const viaProxy = await new Promise(resolve => {
  const req = request({ hostname: proxy.hostname, port: Number(proxy.port), method: 'CONNECT',
    path: '127.0.0.1:' + fixture.localPort });
  req.once('connect', (response, socket) => {
    if (response.statusCode !== 200) { socket.destroy(); resolve(false); return; }
    socket.once('data', chunk => { socket.destroy(); resolve(chunk.toString() === 'synthetic localhost fixture'); });
    socket.once('error', () => resolve(false));
    socket.setTimeout(2000, () => { socket.destroy(); resolve(false); });
  });
  req.once('error', () => resolve(false));
  req.end();
});
writeFileSync('session-isolation-result.json', JSON.stringify({ siblingRead, ownMcp, direct, viaProxy }));
`);
      const opts = { isolatedAuth: true, allowHosts: ["127.0.0.1"] };
      const prepared = await prepareGuardedRun(store, { agent: "codex", command: process.execPath,
        args: [probe], cwd: workspace, env: { PATH: process.env.PATH }, sandbox: "anthropic", sandboxOptions: opts });
      expect(await runAnthropicSandbox(prepared, store.home, opts)).toBe(0);
      expect(JSON.parse(await readFile(path.join(workspace, "session-isolation-result.json"), "utf8"))).toEqual({
        siblingRead: false, ownMcp: true, direct: false, viaProxy: true
      });
    } finally {
      await siblingBroker.close();
      await new Promise<void>(resolve => local.close(() => resolve()));
      await rm(siblingDir, { recursive: true, force: true });
    }
  });

  it("adds the Keychain IPC denial to the existing trusted macOS profile", () => {
    const wrapped = "env NO_PROXY=localhost,*.local /usr/bin/sandbox-exec -p '(version 1)(allow default)' /bin/bash -c 'fixed command'";
    const restricted = restrictMacCredentialIpc(wrapped);
    expect(restricted).toContain('com.apple.securityd.xpc');
    expect(restricted).not.toContain('com.apple.SecurityServer');
    expect(restrictMacCredentialIpc(wrapped, true)).toContain('com.apple.SecurityServer');
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
    expect(macAgentKeychainReadPath(cwd, { ...allowed, denyKeychain: true }, "darwin")).toBeUndefined();
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
    await copyFile(path.join(process.cwd(), "tests/fixtures/keychain-policy-agent.mjs"), probe);
    for (const sandboxOptions of [{}, { allowAgentKeychain: true }, { allowAgentKeychain: true, denyAgentAuth: true }, { allowAgentKeychain: true, denyRead: [loginFile] }, { allowAgentKeychain: true, denyRead: [keychains] }]) {
      const visible = Boolean(macAgentKeychainReadPath(workspace, sandboxOptions));
      const prepared = await prepareGuardedRun(store, { agent: "claude-code", command: process.execPath, args: [probe], cwd: workspace, env: { PATH: process.env.PATH, SGW_EXPECT_KEYCHAIN_READ: visible ? "1" : "0", SGW_TEST_LOGIN_FILE: loginFile, SGW_TEST_SIBLING_FILE: sibling, SGW_TEST_CREATED_FILE: path.join(keychains, "created") }, sandbox: "anthropic", sandboxOptions });
      expect(prepared.plan.sandbox.policy?.allowRead).toEqual(visible ? [loginFile] : []);
      expect(await runAnthropicSandbox(prepared, store.home, sandboxOptions)).toBe(0);
    }
    expect(await readFile(loginFile, "utf8")).toBe("synthetic database");
  });

  it.skipIf(process.platform !== "darwin")("denies native retrieval of a disposable Keychain item", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const keychain = path.join(root, "outside", "fixture.keychain-db");
    const password = randomUUID();
    const item = randomUUID();
    const service = "sgw-keychain-fixture";
    const account = "fixture-agent";
    const security = (args: string[]) => execFileSync("/usr/bin/security", args, { encoding: "utf8", timeout: 10_000 });
    security(["create-keychain", "-p", password, keychain]);
    try {
      security(["unlock-keychain", "-p", password, keychain]);
      security(["add-generic-password", "-a", account, "-s", service, "-w", item, "-A", keychain]);
      expect(security(["find-generic-password", "-w", "-a", account, "-s", service, keychain]).trim()).toBe(item);

      const probe = path.join(workspace, "native-keychain-probe.mjs");
      await writeFile(probe, `import { spawnSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
const result = spawnSync('/usr/bin/security', ['find-generic-password', '-w', '-a', process.env.SGW_TEST_ACCOUNT, '-s', process.env.SGW_TEST_SERVICE, process.env.SGW_TEST_KEYCHAIN], { encoding: 'utf8', timeout: 10000 });
writeFileSync('keychain-result.json', JSON.stringify({ read: result.status === 0, timedOut: result.error?.code === 'ETIMEDOUT' }));
`);
      const launch = async (sandboxOptions: { denyAgentAuth?: boolean; denyKeychain?: boolean; denyRead?: string[] }) => {
        const prepared = await prepareGuardedRun(store, {
          agent: "claude-code", command: process.execPath, args: [probe], cwd: workspace,
          env: { PATH: process.env.PATH, SGW_TEST_ACCOUNT: account, SGW_TEST_SERVICE: service, SGW_TEST_KEYCHAIN: keychain },
          sandbox: "anthropic", sandboxOptions
        });
        expect(await runAnthropicSandbox(prepared, store.home, sandboxOptions)).toBe(0);
        return JSON.parse(await readFile(path.join(workspace, "keychain-result.json"), "utf8"));
      };
      expect(await launch({})).toEqual({ read: true, timedOut: false });
      expect(await launch({ denyAgentAuth: true })).toEqual({ read: true, timedOut: false });
      expect(await launch({ denyKeychain: true })).toEqual({ read: false, timedOut: false });
      const sandboxOptions = { denyAgentAuth: true, denyRead: [keychain] };
      expect(await launch(sandboxOptions)).toEqual({ read: false, timedOut: false });
    } finally {
      security(["delete-keychain", keychain]);
    }
  }, 30_000);

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
    const broker = await startSandboxBroker(path.join(root, "workspace"), store.home, "Codex");
    try {
      await new Promise<void>((resolve, reject) => {
        const socket = connect(broker.port, "127.0.0.1", () => socket.write("invalid fixture capability\n"));
        socket.once("error", reject);
        socket.once("close", () => resolve());
      });
      expect(await store.listHandles()).toEqual([]);
    } finally { await broker.close(); }
  });

  it("pins restricted MCP identity and discards inherited Node startup options", async () => {
    const store = await fixtureStore();
    const workspace = path.join(root, "workspace");
    const secret = await store.addSecret({ name: "identity fixture", type: "api-token", value: randomUUID(),
      policy: { allowedCommands: ["s-gw:https-request"], allowedDestinations: ["api.example.test:443"] } });
    process.env.NODE_OPTIONS = `--require=${path.join(root, "missing-startup-option.cjs")}`;
    const broker = await startSandboxBroker(workspace, store.home, "Claude Code");
    const entry = ownedModuleCommand("mcp-server");
    const bridgeEnv = { ...process.env, SGW_SANDBOX_BROKER_PORT: String(broker.port), SGW_SANDBOX_BROKER_TOKEN: broker.token };
    delete bridgeEnv.NODE_OPTIONS;
    const client = new Client({ name: "Fixture client", version: "1" });
    try {
      await client.connect(new StdioClientTransport({ ...entry, env: bridgeEnv, stderr: "pipe" }));
      const response = await client.callTool({ name: "sgw_request_http", arguments: {
        handle: secret.handle, url: "https://api.example.test/fixture", auth: { kind: "bearer" }, reason: "fixture request"
      } });
      expect(response.isError).not.toBe(true);
      const request = JSON.parse((response.content[0] as { text: string }).text).request;
      expect(request).toMatchObject({ state: "pending", agentName: "Claude", agentSource: "configured" });
    } finally { await client.close(); await broker.close(); }
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
  }, 20_000);

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
    let ownedHttpHits = 0;
    const https = createHttpsServer(tls, (req, res) => {
      ownedHttpHits += 1;
      expect(req.headers.authorization).toBe(`Bearer ${httpPassword}`);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify({ result: "owned HTTPS fixture complete", echo: req.headers.authorization, access_token: issued }));
    });
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
      let sshClaimDenied = false;
      while (!sshClaimDenied && Date.now() < deadline) {
        try { await readFile(path.join(root, "workspace", "ssh-claim-denied")); sshClaimDenied = true; }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        if (!sshClaimDenied) await new Promise(resolve => setTimeout(resolve, 30));
      }
      expect(sshClaimDenied).toBe(true);
      expect((await store.getRequest(requestId!)).state).toBe("approved");
      const sshSummary = await executeApprovedRequest(store, requestId!);
      expect(sshSummary.exitCode).toBe(0);
      await writeFile(path.join(root, "workspace", "ssh-operator-result.json"), JSON.stringify(sshSummary));
      await writeFile(path.join(root, "workspace", "ssh-operator-executed"), "trusted operator executed");
      let claimDenied = false;
      while (!claimDenied && Date.now() < deadline) {
        try { await readFile(path.join(root, "workspace", "http-claim-denied")); claimDenied = true; }
        catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
        if (!claimDenied) await new Promise(resolve => setTimeout(resolve, 30));
      }
      expect(claimDenied).toBe(true);
      expect(ownedHttpHits).toBe(0);
      expect((await store.getRequest(httpRequestId!)).state).toBe("approved");
      const httpSummary = await executeApprovedRequest(store, httpRequestId!, { http: { ca: tls.cert } });
      expect(httpSummary.exitCode).toBe(0);
      expect(ownedHttpHits).toBe(1);
      await writeFile(path.join(root, "workspace", "operator-result.json"), JSON.stringify(httpSummary));
      await writeFile(path.join(root, "workspace", "operator-executed"), "trusted operator executed");
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
