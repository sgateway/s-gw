import { randomBytes, timingSafeEqual } from "node:crypto";
import { existsSync } from "node:fs";
import { createServer, connect, type Socket } from "node:net";
import { request } from "node:http";
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

export async function startSandboxBroker(cwd: string, home: string, denyRead: string[] = []) {
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
      const env: NodeJS.ProcessEnv = { ...process.env, SGW_HOME: home, SGW_SANDBOX_OPERATIONS_ONLY: "1", SGW_SANDBOX_DENY_READ: JSON.stringify(denyRead), TSX_DISABLE_CACHE: "1" };
      delete env.SGW_SANDBOX_BROKER_PORT;
      delete env.SGW_SANDBOX_BROKER_TOKEN;
      delete env.SGW_SANDBOX_PROXY_URL;
      delete env.SGW_SANDBOX_MCP_CONFIG;
      const entry = ownedModuleCommand("mcp-server");
      const child = spawnIsolated(entry.command, entry.args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
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
