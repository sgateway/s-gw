import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { realpathSync, statSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseShell, quote as quoteShell } from "shell-quote";
import { SandboxManager, SandboxRuntimeConfigSchema, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import { containsGlobChars, globToRegex, normalizePathForSandbox } from "@anthropic-ai/sandbox-runtime/dist/sandbox/sandbox-utils.js";
import { sensitiveChildPaths, DEFAULT_GUARD_ALLOWLIST } from "./sandbox-paths.js";
import type { GuardRunPreparation } from "./guard.js";
import { linuxCgroupRequired, writableCgroupRoot } from "./linux-cgroup.js";
import { spawnIsolated, killProcessTree } from "./process-tree.js";
import { ownedModuleCommand, startSandboxBroker } from "./sandbox-broker.js";

export interface AnthropicSandboxOptions {
  allowHosts?: string[];
  allowWrite?: string[];
  denyRead?: string[];
  strictEgress?: boolean;
  denyAgentAuth?: boolean;
  allowAgentKeychain?: boolean;
  isolatedAuth?: boolean;
  strictBrokerEnv?: boolean;
}

export function macAgentKeychainReadPath(cwd: string, options: AnthropicSandboxOptions = {}, platform = process.platform): string | undefined {
  if (platform !== "darwin" || !options.allowAgentKeychain || options.denyAgentAuth || options.isolatedAuth) return;
  const loginFile = normalizePathForSandbox(path.join(os.homedir(), "Library", "Keychains", "login.keychain-db"));
  for (const file of options.denyRead || []) {
    let denied = normalizePathForSandbox(path.resolve(cwd, file));
    const prefix = denied.split(/[*?[\]]/)[0];
    const base = containsGlobChars(denied) ? (prefix.endsWith(path.sep) ? prefix.slice(0, -1) || path.sep : path.dirname(prefix)) : denied;
    try { denied = realpathSync(base) + denied.slice(base.length); }
    catch (error) {
      if (!["ENOENT", "ENOTDIR"].includes((error as NodeJS.ErrnoException).code || "")) return;
    }
    if (containsGlobChars(denied)) {
      if (new RegExp(globToRegex(denied)).test(loginFile)) return;
    } else if (loginFile === denied || loginFile.startsWith(denied.endsWith(path.sep) ? denied : denied + path.sep)) return;
  }
  return loginFile;
}

export function agentAuthenticationPaths(env: NodeJS.ProcessEnv = process.env): string[] {
  const userHome = env.HOME || os.homedir();
  return [path.join(env.CODEX_HOME || path.join(userHome, ".codex"), "auth.json"),
    path.join(env.CLAUDE_CONFIG_DIR || path.join(userHome, ".claude"), ".credentials.json"),
    path.join(userHome, ".config", "gh", "hosts.yml"), path.join(userHome, ".git-credentials"),
    path.join(userHome, ".netrc"), path.join(userHome, ".npmrc"), path.join(userHome, ".docker", "config.json"),
    path.join(userHome, ".kube", "config")];
}

export function anthropicSandboxReadiness(platform = process.platform) {
  const supported = ["darwin", "linux"].includes(platform);
  const dependencies = supported ? SandboxManager.checkDependencies() : { errors: ["Pinned Anthropic runtime has no native Windows backend."], warnings: [] };
  if (platform === "linux" && process.platform === "linux" && linuxCgroupRequired() && !writableCgroupRoot()) {
    dependencies.errors.push("Linux isolation requires a writable delegated cgroup v2.");
  }
  return { provider: "anthropic", version: "0.0.50", platform, supported,
    ready: supported && dependencies.errors.length === 0, dependencies, tlsInterception: false,
    credentialOperations: ["ssh", "https"], nativeWindows: "pending; no account or VM is provisioned automatically" };
}

export function anthropicSandboxConfig(cwd: string, home: string, options: AnthropicSandboxOptions = {}, env: NodeJS.ProcessEnv = process.env, command?: string): SandboxRuntimeConfig {
  if (options.isolatedAuth && options.allowAgentKeychain) throw new Error("Isolated authentication cannot allow the agent login Keychain.");
  const workspace = path.resolve(cwd);
  const userHome = path.resolve(os.homedir());
  if (options.isolatedAuth && (userHome === workspace || userHome.startsWith(workspace + path.sep))) {
    throw new Error("Isolated authentication requires a workspace narrower than the user home.");
  }
  if (options.isolatedAuth && (workspace === path.resolve(home) || workspace.startsWith(path.resolve(home) + path.sep))) {
    throw new Error("Isolated authentication cannot use the s-gw store as the workspace.");
  }
  if (options.isolatedAuth && (options.denyRead || []).some(file => {
    const denied = path.resolve(cwd, file);
    return denied === workspace || denied.startsWith(workspace + path.sep);
  })) {
    throw new Error("Isolated authentication cannot enforce a read denial inside the allowed workspace.");
  }
  const allowRead = options.isolatedAuth ? [workspace, ...trustedRuntimeReadPaths(env, command)] : [];
  return SandboxRuntimeConfigSchema.parse({
    filesystem: {
      denyRead: [...new Set([...sensitiveChildPaths(home), home,
        path.join(os.homedir(), ".config", "op"),
        path.join(os.homedir(), "Library", "Application Support", "1Password"),
        ...(options.isolatedAuth ? [userHome, ...(env.HOME ? [path.resolve(env.HOME)] : [])] : []),
        ...(options.denyAgentAuth || options.isolatedAuth ? agentAuthenticationPaths(env).map(file => path.resolve(cwd, file)) : []),
        ...(options.denyRead || []).map(file => path.resolve(cwd, file))])],
      ...(allowRead.length ? { allowRead } : {}),
      allowWrite: [path.resolve(cwd), ...(options.allowWrite || []).map(file => path.resolve(cwd, file))],
      denyWrite: [home, fileURLToPath(new URL("../", import.meta.url)), process.execPath,
        ...(options.allowAgentKeychain && process.platform === "darwin" ? [path.join(os.homedir(), "Library", "Keychains")] : [])]
    },
    network: { allowedDomains: [...(options.strictEgress || options.isolatedAuth ? [] : DEFAULT_GUARD_ALLOWLIST), ...(options.allowHosts || [])], deniedDomains: [] }
  });
}

function trustedRuntimeReadPaths(env: NodeJS.ProcessEnv, command?: string): string[] {
  const packageRoot = fileURLToPath(new URL("../", import.meta.url));
  const paths = [packageRoot, process.execPath];
  if (command) {
    const resolved = path.isAbsolute(command) ? command : env.PATH?.split(path.delimiter).map(dir => path.join(dir, command)).find(file => {
      try { return statSync(file).isFile(); } catch { return false; }
    });
    if (resolved) {
      const real = realpathSync(resolved);
      const modules = real.indexOf(`${path.sep}node_modules${path.sep}`);
      if (modules >= 0) {
        const parts = real.slice(modules + `${path.sep}node_modules${path.sep}`.length).split(path.sep);
        const count = parts[0]?.startsWith("@") ? 2 : 1;
        paths.push(real.slice(0, modules + `${path.sep}node_modules${path.sep}`.length) + parts.slice(0, count).join(path.sep));
      } else paths.push(real);
    }
  }
  for (const name of ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE"] as const) {
    const file = env[name];
    if (!file) continue;
    if (!path.isAbsolute(file)) throw new Error(`${name} must use an absolute path in isolated authentication mode.`);
    const real = realpathSync(file);
    if (!statSync(real).isFile()) throw new Error(`${name} must be a regular file in isolated authentication mode.`);
    paths.push(real);
  }
  return [...new Set(paths.map(file => path.resolve(file)))];
}

export function isolatedAgentEnvironment(parentEnv: NodeJS.ProcessEnv, capabilityEnv: Record<string, string>, agentTmp: string, mcpConfig: string): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    HOME: agentTmp,
    TMPDIR: agentTmp,
    XDG_CONFIG_HOME: path.join(agentTmp, "config"),
    XDG_CACHE_HOME: path.join(agentTmp, "cache"),
    XDG_DATA_HOME: path.join(agentTmp, "data"),
    CODEX_HOME: path.join(agentTmp, "codex"),
    CLAUDE_CONFIG_DIR: path.join(agentTmp, "claude"),
    USER: os.userInfo().username,
    LOGNAME: os.userInfo().username,
    SGW_SANDBOX_MCP_CONFIG: mcpConfig,
    ...capabilityEnv
  };
  for (const name of ["PATH", "LANG", "LC_ALL", "LC_CTYPE", "TERM", "COLORTERM", "NO_COLOR", "CLICOLOR",
    "NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "SGW_GUARD_MODE", "SGW_GUARD_AGENT",
    "SGW_GUARD_INSTRUCTIONS", "SGW_GUARD_TOKENIZED_ENV"] as const) {
    if (parentEnv[name] !== undefined) env[name] = parentEnv[name];
  }
  return env;
}

let running = false;

function macSandboxProfileArgs(wrapped: string): { args: string[]; at: number } {
  const parsed = parseShell(wrapped);
  const args = parsed.map(token => {
    if (typeof token === "string") return token;
    if ("op" in token && token.op === "glob" && /^(?:NO_PROXY|no_proxy)=/.test(token.pattern)) return token.pattern;
    throw new Error("Unexpected Anthropic macOS wrapper format.");
  });
  const at = args.indexOf("/usr/bin/sandbox-exec");
  if (args[0] !== "env" || at < 1 || args[at + 1] !== "-p" || !args[at + 2]?.startsWith("(version 1)")) throw new Error("Anthropic macOS wrapper does not contain the expected sandbox profile.");
  return { args, at };
}

export function restrictMacCredentialIpc(wrapped: string, strict = false): string {
  const { args, at } = macSandboxProfileArgs(wrapped);
  args[at + 2] += '\n(deny mach-lookup (global-name "com.apple.securityd.xpc"))\n';
  if (strict) args[at + 2] += '(deny mach-lookup (global-name "com.apple.SecurityServer"))\n';
  return quoteShell(args);
}

export function allowMacAgentKeychainRead(wrapped: string, loginFile: string): string {
  const { args, at } = macSandboxProfileArgs(wrapped);
  args[at + 2] += `\n(allow file-read* (literal ${JSON.stringify(loginFile)}))\n`;
  return quoteShell(args);
}

export function sandboxAgentArguments(command: string, args: string[], configPath: string, entry: { command: string; args: string[] }, capabilityEnv: Record<string, string>): string[] {
  const name = path.basename(command);
  if (name === "claude") {
    const result = [...args];
    const existing = result.indexOf("--mcp-config");
    if (existing < 0) return [...result, "--mcp-config", configPath];
    let end = existing + 1;
    while (end < result.length && !result[end].startsWith("-")) end += 1;
    result.splice(end, 0, configPath);
    return result;
  }
  if (name !== "codex") return args;
  const settings = [
    `mcp_servers.s-gw.command=${JSON.stringify(entry.command)}`,
    `mcp_servers.s-gw.args=${JSON.stringify(entry.args)}`,
    ...Object.entries(capabilityEnv).map(([key, value]) => `mcp_servers.s-gw.env.${key}=${JSON.stringify(value)}`)
  ];
  const overrides = settings.flatMap(value => ["--config", value]);
  // Codex exec reads MCP overrides from its subcommand options.
  if (args[0] === "exec") return ["exec", ...overrides, ...args.slice(1)];
  return [...overrides, ...args];
}

export async function runAnthropicSandbox(prepared: GuardRunPreparation, home: string, options: AnthropicSandboxOptions = {}): Promise<number> {
  if (!["darwin", "linux"].includes(process.platform)) {
    throw new Error("The Anthropic s-gw launcher currently supports macOS and Linux. Native Windows integration is pending alpha-runtime validation.");
  }
  if (options.isolatedAuth && process.platform === "linux" &&
    SandboxManager.checkDependencies().warnings.some(warning => warning.includes("unix socket access not restricted"))) {
    throw new Error("Isolated authentication on Linux requires Anthropic's Unix-socket seccomp filter.");
  }
  if (running) throw new Error("An Anthropic sandbox is already running in this process.");
  const config = anthropicSandboxConfig(prepared.plan.cwd, home, options, prepared.env, prepared.plan.command);
  running = true;
  let sessionDir: string | undefined;
  let agentTmp: string | undefined;
  let broker: Awaited<ReturnType<typeof startSandboxBroker>> | undefined;
  try {
    sessionDir = await mkdtemp(path.join(os.tmpdir(), "sgw-sandbox-"));
    agentTmp = await mkdtemp(path.join(prepared.plan.cwd, ".sgw-tmp-"));
    const manifestPath = path.join(sessionDir, "launch.json");
    config.filesystem.denyWrite.push(sessionDir);
    broker = await startSandboxBroker(prepared.plan.cwd, home, prepared.plan.agent.displayName, config.filesystem.denyRead,
      { strictEnv: options.strictBrokerEnv || options.isolatedAuth, agentWritablePaths: config.filesystem.allowWrite,
        ...(options.isolatedAuth ? { uploadWorkspace: prepared.plan.cwd } : {}) });
    const brokerPort = broker.port;
    await SandboxManager.initialize(config, async ({ host, port }) => host === "127.0.0.1" && port === brokerPort);
    const proxyPort = process.platform === "linux" ? 3128 : SandboxManager.getProxyPort();
    if (!proxyPort) throw new Error("Anthropic sandbox HTTP proxy did not initialize.");
    const capabilityEnv = {
      SGW_SANDBOX_BROKER_PORT: String(broker.port), SGW_SANDBOX_BROKER_TOKEN: broker.token,
      SGW_SANDBOX_PROXY_URL: `http://localhost:${proxyPort}`,
      TMPDIR: agentTmp,
      TSX_DISABLE_CACHE: "1"
    };
    const mcpEntry = ownedModuleCommand("mcp-server");
    const mcpConfig = path.join(sessionDir, "mcp.json");
    await writeFile(mcpConfig, JSON.stringify({ mcpServers: { "s-gw": { ...mcpEntry, env: capabilityEnv } } }), { mode: 0o600 });
    const agentArgs = sandboxAgentArguments(prepared.plan.command, prepared.plan.args, mcpConfig, mcpEntry, capabilityEnv);
    await writeFile(manifestPath, JSON.stringify({ command: prepared.plan.command, args: agentArgs, tmpdir: agentTmp }), { mode: 0o600 });
    const entry = ownedModuleCommand("sandbox-child");
    const quote = (value: string) => "'" + value.replaceAll("'", "'\\''") + "'";
    const fixedCommand = [entry.command, ...entry.args, manifestPath].map(quote).join(" ");
    let wrapped = await SandboxManager.wrapWithSandbox(fixedCommand, "/bin/bash");
    const loginFile = macAgentKeychainReadPath(prepared.plan.cwd, options);
    if (loginFile) wrapped = allowMacAgentKeychainRead(wrapped, loginFile);
    if ((options.denyAgentAuth || options.isolatedAuth) && process.platform === "darwin") wrapped = restrictMacCredentialIpc(wrapped, options.isolatedAuth);
    const env: NodeJS.ProcessEnv = options.isolatedAuth
      ? isolatedAgentEnvironment(prepared.env, capabilityEnv, agentTmp, mcpConfig)
      : { ...prepared.env, ...capabilityEnv, SGW_SANDBOX_MCP_CONFIG: mcpConfig };
    delete env.SGW_HOME;
    delete env.SGW_SANDBOX_OPERATIONS_ONLY;
    delete env.SSH_AUTH_SOCK;
    delete env.NODE_OPTIONS;
    for (const name of Object.keys(env)) {
      if (["BASH_ENV", "ENV", "ZDOTDIR", "SHELLOPTS", "BASHOPTS", "CDPATH", "GIT_CONFIG", "GIT_CONFIG_GLOBAL"].includes(name) ||
          name.startsWith("BASH_FUNC_") || name.startsWith("DYLD_") || name.startsWith("LD_")) delete env[name];
    }
    const child = spawnIsolated("/bin/bash", ["-c", wrapped], { cwd: prepared.plan.cwd, env, stdio: "inherit" });
    const signals = ["SIGINT", "SIGTERM", "SIGHUP"] as const;
    const handlers = signals.map(signal => () => killProcessTree(child, signal));
    signals.forEach((signal, index) => process.on(signal, handlers[index]));
    try {
      return await new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("close", (code, signal) => resolve(code ?? (signal === "SIGINT" ? 130 : signal === "SIGHUP" ? 129 : 143)));
      });
    } finally {
      signals.forEach((signal, index) => process.off(signal, handlers[index]));
      killProcessTree(child, "SIGKILL");
    }
  } finally {
    try { await broker?.close(); }
    finally {
      try { await SandboxManager.reset(); }
      finally {
        running = false;
        try { if (sessionDir) await rm(sessionDir, { recursive: true, force: true }); }
        finally { if (agentTmp) await rm(agentTmp, { recursive: true, force: true }); }
      }
    }
  }
}
