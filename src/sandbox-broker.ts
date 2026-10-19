import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync, realpathSync, statSync } from "node:fs";
import { createServer, connect, type Socket } from "node:net";
import { request } from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { ChildProcess } from "node:child_process";
import { spawnIsolated, killProcessTree } from "./process-tree.js";

export function ownedModuleCommand(name: "mcp-server" | "sandbox-child") {
  const compiled = fileURLToPath(new URL(`./${name}.js`, import.meta.url));
  if (existsSync(compiled)) return { command: process.execPath, args: [compiled] };
  const source = fileURLToPath(new URL(`./${name}.ts`, import.meta.url));
  const loader = new URL("../node_modules/tsx/dist/esm/index.mjs", import.meta.url).href;
  if (!existsSync(source)) throw new Error(`s-gw module is missing: ${name}`);
  return { command: process.execPath, args: ["--import", loader, source] };
}

export interface BrokerEnvironmentOptions {
  strictEnv?: boolean;
  inheritedEnv?: NodeJS.ProcessEnv;
  agentWritablePaths?: string[];
}

export async function startSandboxBroker(
  cwd: string, home: string, agentName: string, denyRead: string[] = [], options: BrokerEnvironmentOptions = {}
) {
  const trustedAgent = agentName.trim();
  if (!trustedAgent) throw new Error("A launched agent identity is required for the sandbox broker.");
  const strictChildEnv = options.strictEnv
    ? brokerChildEnvironment(cwd, home, trustedAgent, denyRead, options)
    : undefined;
  const strictEntry = options.strictEnv ? ownedModuleCommand("mcp-server") : undefined;
  if (strictEntry) validateBrokerEntry(strictEntry, brokerWritablePaths(cwd, options.agentWritablePaths || [], options.inheritedEnv || process.env));
  const token = randomBytes(32).toString("hex");
  const sockets = new Set<Socket>();
  const children = new Set<ChildProcess>();
  const server = createServer(socket => {
    if (sockets.size >= 8) { socket.destroy(); return; }
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
    socket.on("error", () => socket.destroy());
    socket.setTimeout(5000, () => socket.destroy());
    let handshake = Buffer.alloc(0);
    const authenticate = (chunk: Buffer) => {
      handshake = Buffer.concat([handshake, chunk]);
      const end = handshake.indexOf(10);
      if (end < 0) {
        if (handshake.length > 1024) socket.destroy();
        return;
      }
      const supplied = handshake.subarray(0, end);
      if (supplied.length !== token.length || !timingSafeEqual(supplied, Buffer.from(token))) {
        socket.destroy(); return;
      }
      socket.removeListener("data", authenticate);
      socket.setTimeout(0);
      const env = strictChildEnv || brokerChildEnvironment(cwd, home, trustedAgent, denyRead, options);
      const entry = strictEntry || ownedModuleCommand("mcp-server");
      let child: ReturnType<typeof spawnIsolated>;
      try { child = spawnIsolated(entry.command, entry.args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] }); }
      catch { socket.destroy(); return; }
      children.add(child);
      child.once("error", () => socket.destroy());
      child.stdin?.on("error", () => socket.destroy());
      child.stdout?.on("error", () => socket.destroy());
      child.stderr?.on("error", () => socket.destroy());
      child.once("close", () => { children.delete(child); socket.destroy(); });
      socket.once("close", () => { if (child.exitCode === null && child.signalCode === null) killProcessTree(child); });
      child.stderr?.on("data", chunk => process.stderr.write(chunk));
      socket.pipe(child.stdin!);
      child.stdout!.pipe(socket);
      if (handshake.length > end + 1) child.stdin!.write(handshake.subarray(end + 1));
      handshake = Buffer.alloc(0);
    };
    socket.on("data", authenticate);
  });
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
  } catch (error) { server.close(); throw error; }
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("Sandbox broker could not bind loopback.");
  return {
    port: address.port, token,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      for (const child of children) killProcessTree(child, "SIGKILL");
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  };
}

export function brokerChildEnvironment(
  cwd: string, home: string, agentName: string, denyRead: string[] = [], options: BrokerEnvironmentOptions = {}
): NodeJS.ProcessEnv {
  const inherited = options.inheritedEnv || process.env;
  const env: NodeJS.ProcessEnv = options.strictEnv
    ? strictBrokerEnvironment(inherited, cwd, home, options.agentWritablePaths || [])
    : { ...inherited };

  env.SGW_HOME = home;
  env.SGW_SANDBOX_OPERATIONS_ONLY = "1";
  env.SGW_SANDBOX_DENY_READ = JSON.stringify(denyRead);
  env.SGW_SANDBOX_AGENT_NAME = agentName;
  env.TSX_DISABLE_CACHE = "1";
  if (options.strictEnv) return env;

  for (const name of ["SGW_SANDBOX_BROKER_PORT", "SGW_SANDBOX_BROKER_TOKEN", "SGW_SANDBOX_PROXY_URL",
    "SGW_SANDBOX_MCP_CONFIG", "SGW_AGENT_NAME", "SGW_REQUEST_AGENT_NAME", "SGW_CLIENT_IDENTITY", "NODE_OPTIONS", "NODE_PATH"]) {
    delete env[name];
  }
  for (const name of Object.keys(env)) {
    if (name.startsWith("LD_") || name.startsWith("DYLD_")) delete env[name];
  }
  return env;
}

function strictBrokerEnvironment(inherited: NodeJS.ProcessEnv, cwd: string, home: string, extraWritable: string[]): NodeJS.ProcessEnv {
  const nativeHome = os.userInfo().homedir;
  const writable = brokerWritablePaths(cwd, extraWritable, inherited);
  if (isWritable(writable, nativeHome) || isWritable(writable, home)) {
    throw new Error("The trusted broker home or store is writable by the agent.");
  }
  const env: NodeJS.ProcessEnv = {
    HOME: nativeHome,
    USER: os.userInfo().username,
    LOGNAME: os.userInfo().username,
    PATH: trustedPath(inherited.PATH, writable)
  };

  for (const name of ["LANG", "LC_ALL", "LC_CTYPE", "NO_COLOR", "TERM", "TZ",
    "SGW_MASTER_PASSPHRASE", "SGW_KEYCHAIN_SERVICE", "SGW_KEYCHAIN_ACCOUNT",
    "SGW_SECRET_KEYCHAIN_SERVICE", "OP_SERVICE_ACCOUNT_TOKEN", "OP_CONNECT_TOKEN",
    "OP_ACCOUNT", "OP_VAULT", "OP_FORMAT"] as const) {
    const value = inherited[name];
    if (value !== undefined) env[name] = boundedBrokerValue(name, value);
  }

  for (const name of ["SGW_DISABLE_KEYCHAIN", "SGW_DISABLE_ONEPASSWORD_BACKUP", "SGW_ALLOW_SECURITY_CLI"] as const) {
    const value = inherited[name];
    if (value === undefined) continue;
    if (value !== "0" && value !== "1") throw new Error(`Invalid trusted broker setting: ${name}.`);
    env[name] = value;
  }

  copyEnum(env, inherited, "SGW_SECRET_BACKEND", ["local", "keychain"]);
  copyEnum(env, inherited, "SGW_EXECUTION_ENGINE", ["auto", "rust", "typescript"]);
  copyEnum(env, inherited, "OP_BIOMETRIC_UNLOCK_ENABLED", ["true", "false"]);

  const timeout = inherited.SGW_ONEPASSWORD_TIMEOUT_MS;
  if (timeout !== undefined) {
    if (!/^\d{1,6}$/.test(timeout) || Number(timeout) < 1 || Number(timeout) > 300_000) {
      throw new Error("Invalid trusted broker setting: SGW_ONEPASSWORD_TIMEOUT_MS.");
    }
    env.SGW_ONEPASSWORD_TIMEOUT_MS = timeout;
  }

  const connectHost = inherited.OP_CONNECT_HOST;
  if (connectHost) {
    const url = new URL(connectHost);
    if ((url.protocol !== "https:" && !(url.protocol === "http:" && ["localhost", "127.0.0.1"].includes(url.hostname)))
      || url.username || url.password) {
      throw new Error("Invalid trusted broker setting: OP_CONNECT_HOST.");
    }
    env.OP_CONNECT_HOST = url.href;
  }

  const sessionBus = inherited.DBUS_SESSION_BUS_ADDRESS;
  if (sessionBus) {
    validateSessionBusAddress(sessionBus, writable);
    env.DBUS_SESSION_BUS_ADDRESS = sessionBus;
  }

  for (const [name, value] of Object.entries(inherited)) {
    if (/^OP_SESSION_[A-Za-z0-9_.-]+$/.test(name) && value !== undefined) {
      env[name] = boundedBrokerValue(name, value);
    }
  }

  for (const name of ["NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "CURL_CA_BUNDLE", "SGW_OP_CLI"] as const) {
    const value = inherited[name];
    if (value) env[name] = trustedFile(name, value, writable);
  }
  for (const name of ["XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR", "TMPDIR"] as const) {
    const value = inherited[name];
    if (value) env[name] = trustedDirectory(name, value, writable);
  }

  const recovery = inherited.SGW_RECOVERY_HOME;
  if (recovery) {
    const expanded = recovery === "~" ? nativeHome
      : recovery.startsWith("~/") ? path.join(nativeHome, recovery.slice(2))
        : recovery;
    const resolved = trustedDirectory("SGW_RECOVERY_HOME", expanded, writable);
    if (inside(home, resolved) || inside(resolved, home)) throw new Error("Trusted broker recovery home overlaps the primary store.");
    env.SGW_RECOVERY_HOME = resolved;
  }

  return env;
}

function validateSessionBusAddress(value: string, writable: string[]): void {
  for (const address of value.split(";")) {
    const parts = address.split(",");
    if (!parts[0]?.startsWith("unix:path=") || parts.length > 2 ||
      (parts[1] !== undefined && !/^guid=[a-fA-F0-9]{32}$/.test(parts[1]))) {
      throw new Error("Invalid trusted broker session bus address.");
    }
    let socketPath: string;
    try { socketPath = decodeURIComponent(parts[0].slice("unix:path=".length)); }
    catch { throw new Error("Invalid trusted broker session bus address."); }
    if (!path.isAbsolute(socketPath) || isWritable(writable, socketPath)) {
      throw new Error("Untrusted broker session bus address.");
    }
    const info = statSync(realpathSync(socketPath));
    if (!info.isSocket() || (process.getuid && info.uid !== process.getuid())) {
      throw new Error("Untrusted broker session bus address.");
    }
  }
}

function brokerWritablePaths(cwd: string, extra: string[], inherited: NodeJS.ProcessEnv): string[] {
  // The pinned sandbox runtime grants these writes even when they are absent from allowWrite.
  const writable = [cwd, ...extra, "/tmp/claude", "/private/tmp/claude"];
  for (const runtimeHome of new Set([os.userInfo().homedir, os.homedir(), inherited.HOME])) {
    if (!runtimeHome || !path.isAbsolute(runtimeHome)) continue;
    writable.push(path.join(runtimeHome, ".npm", "_logs"));
    writable.push(path.join(runtimeHome, ".claude", "debug"));
  }
  return writable;
}

function validateBrokerEntry(entry: { command: string; args: string[] }, writable: string[]): void {
  trustedFile("trusted broker executable", entry.command, writable);
  for (const arg of entry.args) {
    const file = arg.startsWith("file:") ? fileURLToPath(arg) : arg;
    if (path.isAbsolute(file)) trustedFile("trusted broker module", file, writable);
  }
}

function boundedBrokerValue(name: string, value: string): string {
  if (value.length > 16_384 || value.includes("\0")) throw new Error(`Invalid trusted broker setting: ${name}.`);
  return value;
}

function copyEnum(env: NodeJS.ProcessEnv, inherited: NodeJS.ProcessEnv, name: string, choices: string[]): void {
  const value = inherited[name];
  if (value === undefined || value === "") return;
  const normalized = value.trim().toLowerCase();
  if (!choices.includes(normalized)) throw new Error(`Invalid trusted broker setting: ${name}.`);
  env[name] = normalized;
}

function trustedFile(name: string, value: string, writable: string[]): string {
  if (!path.isAbsolute(value) || isWritable(writable, value)) throw new Error(`Invalid trusted broker path: ${name}.`);
  const real = realpathSync(value);
  const info = statSync(real);
  if (isWritable(writable, real) || !info.isFile() || info.nlink !== 1 || (info.mode & 0o022) !== 0) {
    throw new Error(`Untrusted broker path: ${name}.`);
  }
  return real;
}

function trustedDirectory(name: string, value: string, writable: string[]): string {
  if (!path.isAbsolute(value) || isWritable(writable, value)) throw new Error(`Invalid trusted broker path: ${name}.`);
  const resolved = existsSync(value) ? realpathSync(value) : path.resolve(value);
  if (isWritable(writable, resolved)) throw new Error(`Untrusted broker path: ${name}.`);
  return resolved;
}

function trustedPath(value: string | undefined, writable: string[]): string {
  const defaults = process.platform === "darwin" ? "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin" : "/usr/local/bin:/usr/bin:/bin";
  const candidates = (value || defaults).split(path.delimiter);
  const safe: string[] = [];
  for (const entry of candidates) {
    if (!entry || !path.isAbsolute(entry) || isWritable(writable, entry)) continue;
    try {
      const real = realpathSync(entry);
      const info = statSync(real);
      if (isWritable(writable, real) || !info.isDirectory() || (info.mode & 0o002) !== 0) continue;
      if (!safe.includes(real)) safe.push(real);
    } catch {
      continue;
    }
  }
  if (safe.length) return safe.join(path.delimiter);
  if (value) return trustedPath(undefined, writable);
  throw new Error("No trusted executable directory is available for the broker.");
}

function isWritable(writable: string[], candidate: string): boolean {
  return writable.some((entry) => inside(entry, candidate));
}

function inside(parent: string, child: string): boolean {
  const relative = path.relative(canonicalPath(parent), canonicalPath(child));
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

function canonicalPath(value: string): string {
  let current = path.resolve(value);
  const missing: string[] = [];
  while (!existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) break;
    missing.unshift(path.basename(current));
    current = parent;
  }
  return path.join(realpathSync(current), ...missing);
}

export async function runSandboxMcpBridge(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const port = Number(env.SGW_SANDBOX_BROKER_PORT);
  const token = env.SGW_SANDBOX_BROKER_TOKEN;
  if (!Number.isInteger(port) || port < 1 || port > 65535 || !token || !/^[a-f0-9]{64}$/.test(token)) {
    throw new Error("Invalid sandbox MCP broker capability.");
  }
  const socket = await connectBroker(port, env);
  socket.write(`${token}\n`);
  await new Promise<void>((resolve, reject) => {
    socket.once("error", reject);
    socket.once("close", () => { process.stdin.unpipe(socket); process.stdin.pause(); resolve(); });
    process.stdin.pipe(socket);
    socket.pipe(process.stdout, { end: false });
  });
}

function connectBroker(port: number, env: NodeJS.ProcessEnv): Promise<Socket> {
  const proxyUrl = env.SGW_SANDBOX_PROXY_URL || env.HTTP_PROXY || env.http_proxy;
  if (!proxyUrl) {
    return new Promise((resolve, reject) => {
      const socket = connect(port, "127.0.0.1", () => { socket.setTimeout(0); resolve(socket); });
      socket.once("error", reject);
      socket.setTimeout(5000, () => socket.destroy(new Error("Sandbox broker connection timed out.")));
    });
  }
  const proxy = new URL(proxyUrl);
  if (proxy.protocol !== "http:" || !["localhost", "127.0.0.1"].includes(proxy.hostname)) {
    throw new Error("Sandbox MCP requires the runtime's local HTTP proxy.");
  }
  return new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};
    if (proxy.username || proxy.password) {
      const auth = `${decodeURIComponent(proxy.username)}:${decodeURIComponent(proxy.password)}`;
      headers["Proxy-Authorization"] = `Basic ${Buffer.from(auth).toString("base64")}`;
    }
    const req = request({ hostname: proxy.hostname, port: Number(proxy.port), method: "CONNECT", path: `127.0.0.1:${port}`, headers });
    req.once("error", reject);
    req.setTimeout(5000, () => req.destroy(new Error("Sandbox broker proxy connection timed out.")));
    req.once("connect", (response, socket, head) => {
      if (response.statusCode !== 200) { socket.destroy(); reject(new Error("Sandbox broker connection was denied.")); return; }
      socket.setTimeout(0);
      if (head.length) socket.unshift(head);
      resolve(socket);
    });
    req.end();
  });
}
