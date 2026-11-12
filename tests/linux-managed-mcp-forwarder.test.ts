import { once } from "node:events";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, symlink } from "node:fs/promises";
import { createServer, connect, type Socket } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { checkManagedMcpForwarderBoundary, startManagedMcpForwarder } from "../src/linux-managed-mcp-forwarder.js";

const live: Array<() => Promise<void>> = [];
afterEach(async () => {
  await Promise.allSettled(live.splice(0).reverse().map(stop => stop()));
});

function status(uid: number, gid: number) {
  return `Uid:\t${uid}\t${uid}\t${uid}\t${uid}\nGid:\t${gid}\t${gid}\t${gid}\t${gid}\nGroups:\t${gid}\n` +
    "CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\n" +
    "CapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n";
}

describe.skipIf(process.platform === "win32")("managed MCP TCP forwarder", () => {
  it("checks the dedicated forwarder identity and private network namespace", () => {
    const proof = {
      version: 1 as const, sessionId: "session-a", uid: 32001, gid: 32001,
      agentUid: 31001, brokerUid: 30001,
      cgroup: "/system.slice/s-gw-forwarder-session-a.service",
      networkNamespace: "net:[1234]", hostNetworkNamespace: "net:[99]",
      pidNamespace: "pid:[1234]", agentPidNamespace: "pid:[99]",
      ipcNamespace: "ipc:[1234]", agentIpcNamespace: "ipc:[99]",
      mountNamespace: "mnt:[1234]", agentMountNamespace: "mnt:[99]",
      brokerSocketDevice: "10", brokerSocketInode: "20"
    };
    const actual = {
      uid: 32001, gid: 32001, status: status(32001, 32001),
      cgroup: "0::/system.slice/s-gw-forwarder-session-a.service\n",
      networkNamespace: "net:[1234]", brokerSocketDevice: "10", brokerSocketInode: "20",
      pidNamespace: "pid:[1234]", ipcNamespace: "ipc:[1234]", mountNamespace: "mnt:[1234]",
      brokerSocketUid: 0, brokerSocketGid: 32001, brokerSocketMode: 0o660
    };
    expect(checkManagedMcpForwarderBoundary(proof, actual)).toEqual(proof);
    expect(() => checkManagedMcpForwarderBoundary(proof, { ...actual, networkNamespace: "net:[99]" })).toThrow();
    expect(() => checkManagedMcpForwarderBoundary(proof, { ...actual, brokerSocketInode: "21" })).toThrow();
    expect(() => checkManagedMcpForwarderBoundary(proof, { ...actual, status: status(31001, 32001) })).toThrow();
    expect(() => checkManagedMcpForwarderBoundary(proof, { ...actual, pidNamespace: "pid:[99]" })).toThrow();
    expect(() => checkManagedMcpForwarderBoundary(proof, { ...actual, ipcNamespace: "ipc:[99]" })).toThrow();
    expect(() => checkManagedMcpForwarderBoundary(proof, { ...actual, mountNamespace: "mnt:[99]" })).toThrow();
    expect(() => checkManagedMcpForwarderBoundary({ ...proof, agentPidNamespace: "pid:[1234]" }, actual)).toThrow();
  });

  it("copies opaque MCP bytes only to the fixed Unix listener and closes with the session", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sgw-mcp-forwarder-"));
    const socketPath = path.join(dir, "broker.sock");
    const seen: Buffer[] = [];
    const broker = createServer(socket => {
      socket.on("data", bytes => { seen.push(bytes); socket.write(bytes); });
    });
    broker.listen(socketPath);
    await once(broker, "listening");
    live.push(async () => { await new Promise<void>(resolve => broker.close(() => resolve())); await rm(dir, { recursive: true, force: true }); });

    const forwarder = await startManagedMcpForwarder({ socketPath, port: 0, assertBoundary: async () => {} });
    live.push(() => forwarder.close());
    const client = connect(forwarder.port, "127.0.0.1");
    live.push(async () => { client.destroy(); });
    await once(client, "connect");
    const payload = Buffer.from('{"jsonrpc":"2.0","method":"tools/list","params":{"socketPath":"/tmp/other.sock"}}\n');
    const reply = once(client, "data");
    client.write(payload);
    expect((await reply)[0]).toEqual(payload);
    expect(Buffer.concat(seen)).toEqual(payload);
    await forwarder.close();
    await once(client, "close");
  });

  it("rejects a connection when live attestation fails", async () => {
    let checks = 0;
    const forwarder = await startManagedMcpForwarder({
      socketPath: "/tmp/unreachable-managed-mcp.sock", port: 0,
      assertBoundary: async () => { if (++checks > 1) throw new Error("revoked"); }
    });
    live.push(() => forwarder.close());
    const client = connect(forwarder.port, "127.0.0.1");
    live.push(async () => { client.destroy(); });
    await once(client, "connect");
    await once(client, "close");
    expect(client.destroyed).toBe(true);
  });

  it("keeps a response available after the client finishes writing", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sgw-mcp-forwarder-"));
    const socketPath = path.join(dir, "broker.sock");
    let sawData = false, sawEof = false;
    const broker = createServer({ allowHalfOpen: true }, socket => {
      socket.on("data", () => { sawData = true; });
      socket.on("end", () => { sawEof = true; socket.end("reply\n"); });
    });
    broker.listen(socketPath);
    await once(broker, "listening");
    live.push(async () => { await new Promise<void>(resolve => broker.close(() => resolve())); await rm(dir, { recursive: true, force: true }); });
    const forwarder = await startManagedMcpForwarder({ socketPath, port: 0, assertBoundary: async () => {} });
    live.push(() => forwarder.close());
    const client = connect(forwarder.port, "127.0.0.1");
    live.push(async () => { client.destroy(); });
    await once(client, "connect");
    const response = once(client, "data");
    client.end("request\n");
    await vi.waitFor(() => expect(sawData).toBe(true), { timeout: 1000 });
    await vi.waitFor(() => expect(sawEof).toBe(true), { timeout: 1000 });
    expect(String((await response)[0])).toBe("reply\n");
  });

  it("admits no more than eight live TCP clients", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sgw-mcp-forwarder-"));
    const socketPath = path.join(dir, "broker.sock");
    let accepted = 0;
    const brokerClients = new Set<Socket>();
    const broker = createServer(socket => {
      accepted++;
      brokerClients.add(socket);
      socket.once("close", () => brokerClients.delete(socket));
    });
    broker.listen(socketPath);
    await once(broker, "listening");
    live.push(async () => {
      for (const socket of brokerClients) socket.destroy();
      await new Promise<void>(resolve => broker.close(() => resolve()));
      await rm(dir, { recursive: true, force: true });
    });
    const forwarder = await startManagedMcpForwarder({ socketPath, port: 0, assertBoundary: async () => {} });
    live.push(() => forwarder.close());
    const clients = Array.from({ length: 8 }, () => connect(forwarder.port, "127.0.0.1"));
    live.push(async () => { for (const socket of clients) socket.destroy(); });
    await Promise.all(clients.map(socket => once(socket, "connect")));
    await vi.waitFor(() => expect(accepted).toBe(8));
    const ninth = connect(forwarder.port, "127.0.0.1");
    live.push(async () => { ninth.destroy(); });
    await once(ninth, "close");
    expect(accepted).toBe(8);
  });

  it("enters the installed preflight when invoked through a package symlink", async () => {
    const dir = await mkdtemp(path.join(tmpdir(), "sgw-mcp-forwarder-bin-"));
    live.push(() => rm(dir, { recursive: true, force: true }));
    const source = fileURLToPath(new URL("../src/linux-managed-mcp-forwarder.ts", import.meta.url));
    const loader = fileURLToPath(new URL("../node_modules/tsx/dist/esm/index.mjs", import.meta.url));
    const link = path.join(dir, "mcp-forwarder.ts");
    await symlink(source, link);
    const child = spawnSync(process.execPath, ["--import", loader, link], {
      encoding: "utf8", timeout: 5_000, env: { PATH: process.env.PATH || "" }
    });
    expect(child.status).toBe(1);
    expect(child.stderr).toContain("Managed MCP forwarder refused launch");
  });
});
