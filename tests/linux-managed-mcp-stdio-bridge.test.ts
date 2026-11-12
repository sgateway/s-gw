import { spawn, spawnSync, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const native = process.platform === "linux" || process.platform === "darwin";
const compiler = spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;
const project = fileURLToPath(new URL("..", import.meta.url));
const bridgeSource = path.join(project, "native/linux-managed-mcp-stdio/bridge.c");
const port = 43871;
let tmp = "";
let bridge = "";
let filter = "";
let server: Server | undefined;
const openSockets = new Set<Socket>();

function compile(output: string, source: string) {
  const result = spawnSync("cc", ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
    "-o", output, source], { encoding: "utf8" });
  if (result.error || result.status !== 0) throw new Error(result.stderr || result.error?.message);
}

async function listen(handler: (socket: Socket) => void) {
  server = createServer(socket => {
    openSockets.add(socket);
    socket.once("close", () => openSockets.delete(socket));
    socket.on("error", () => {});
    handler(socket);
  });
  await new Promise<void>((resolve, reject) => {
    server!.once("error", reject);
    server!.listen(port, "127.0.0.1", () => {
      server!.off("error", reject);
      resolve();
    });
  });
}

function launch(): ChildProcessWithoutNullStreams {
  const child = spawn(bridge, [], { env: {
    ...process.env, SGW_MCP_PORT: "1", SGW_MCP_SOCKET: "/tmp/untrusted.sock"
  } });
  child.stdin.on("error", () => {});
  return child;
}

async function finished(child: ChildProcessWithoutNullStreams) {
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", chunk => { stdout += chunk.toString(); });
  child.stderr.on("data", chunk => { stderr += chunk.toString(); });
  const code = await new Promise<number | null>((resolve, reject) => {
    const timeout = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Managed MCP bridge did not close."));
    }, 5000);
    child.once("error", error => { clearTimeout(timeout); reject(error); });
    child.once("exit", value => { clearTimeout(timeout); resolve(value); });
  });
  return { code, stdout, stderr };
}

async function sdkExchange(filtered = false) {
  await listen(socket => {
    let pending = "";
    socket.on("data", chunk => {
      pending += chunk.toString();
      for (;;) {
        const end = pending.indexOf("\n");
        if (end < 0) break;
        const message = JSON.parse(pending.slice(0, end));
        pending = pending.slice(end + 1);
        if (message.method === "initialize") {
          socket.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: {
            protocolVersion: message.params.protocolVersion, capabilities: { tools: {} },
            serverInfo: { name: "synthetic-forwarder", version: "1" }
          } }) + "\n");
        } else if (message.method === "tools/list") {
          socket.write(JSON.stringify({ jsonrpc: "2.0", id: message.id, result: { tools: [] } }) + "\n");
        }
      }
    });
  });
  const transport = new StdioClientTransport({ command: filtered ? filter : bridge,
    args: filtered ? [bridge] : [], env: {
      SGW_MCP_PORT: "1", SGW_MCP_SOCKET: "/tmp/untrusted.sock"
    }, stderr: "pipe" });
  const client = new Client({ name: "managed-bridge-fixture", version: "1" });
  try {
    await client.connect(transport);
    expect((await client.listTools()).tools).toEqual([]);
  } finally {
    await client.close();
  }
}

beforeAll(async () => {
  if (!native || !compiler) return;
  tmp = await mkdtemp(path.join(os.tmpdir(), "sgw-managed-mcp-bridge-"));
  bridge = path.join(tmp, "bridge");
  compile(bridge, bridgeSource);
  if (process.platform === "linux") {
    filter = path.join(tmp, "filter-only-exec");
    compile(filter, path.join(project, "vendor/anthropic-seccomp/filter-only-exec.c"));
  }
});

afterEach(async () => {
  for (const socket of openSockets) socket.destroy();
  if (server) await new Promise<void>(resolve => server!.close(() => resolve()));
  server = undefined;
});

afterAll(async () => {
  if (tmp) await rm(tmp, { recursive: true, force: true });
});

describe.skipIf(!native || !compiler).sequential("managed MCP stdio bridge", () => {
  it("serves a real SDK MCP initialization and tool listing on the fixed port", async () => {
    await sdkExchange();
  });

  it("rejects arguments before connecting", async () => {
    const result = spawnSync(bridge, ["/tmp/untrusted.sock"], { encoding: "utf8", timeout: 5000 });
    expect(result.status).toBe(2);
    expect(result.stderr).toContain("takes no arguments");
  });

  it("fails closed when the fixed forwarder port is absent", async () => {
    const result = spawnSync(bridge, [], { encoding: "utf8", timeout: 5000 });
    expect(result.status).toBe(1);
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("could not reach its forwarder");
  });

  it("copies opaque bytes and half-closes after stdin EOF", async () => {
    const payload = "Content-Length: 1048580\r\n\r\n" + "x".repeat(1024 * 1024 + 1);
    let received = "";
    await listen(socket => {
      socket.on("data", chunk => {
        received += chunk.toString();
        socket.write(chunk);
      });
      socket.on("end", () => socket.end());
    });
    const child = launch();
    const result = finished(child);
    child.stdin.end(payload);
    expect(await result).toMatchObject({ code: 0, stdout: payload, stderr: "" });
    expect(received).toBe(payload);
  });

  it("closes after the bounded stream byte limit", async () => {
    let received = 0;
    await listen(socket => socket.on("data", chunk => { received += chunk.length; }));
    const child = launch();
    const result = finished(child);
    child.stdin.end(Buffer.alloc(64 * 1024 * 1024 + 1, 120));
    expect((await result).code).toBe(1);
    expect(received).toBeLessThanOrEqual(64 * 1024 * 1024);
  });

  it("closes promptly when the forwarder closes", async () => {
    await listen(socket => socket.end());
    const child = launch();
    expect((await finished(child)).code).toBe(0);
  });

  it.skipIf(process.platform !== "linux")("relays with the pinned AF_UNIX-denying filter", async () => {
    await sdkExchange(true);
  });
});
