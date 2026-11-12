import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { writeFile, lstat, readFile, readlink } from "node:fs/promises";
import { createConnection } from "node:net";
import path from "node:path";
import { pathToFileURL } from "node:url";

const [project, work, bridge, expectedUid] = process.argv.slice(2);
if (!project || !work || !bridge || !/^[0-9]+$/.test(expectedUid) ||
    process.getuid() !== Number(expectedUid)) {
  throw new Error("The managed bridge agent has the wrong fixture identity.");
}

const sdkRoot = path.join(work, "node_modules/@modelcontextprotocol/sdk/dist/esm/client");
const { Client } = await import(pathToFileURL(path.join(sdkRoot, "index.js")).href);
const { StdioClientTransport } = await import(pathToFileURL(path.join(sdkRoot, "stdio.js")).href);
const output = path.join(work, "agent-output");
const brokerPath = "/run/s-gw/broker.sock";
process.once("SIGTERM", () => process.exit(0));

async function assertBridgeScope(pid) {
  assert.ok(Number.isSafeInteger(pid) && pid > 0, "SDK transport has no bridge PID.");
  const [status, cgroup, selfCgroup] = await Promise.all([
    readFile(`/proc/${pid}/status`, "utf8"), readFile(`/proc/${pid}/cgroup`, "utf8"),
    readFile("/proc/self/cgroup", "utf8")
  ]);
  for (const field of ["Uid", "Gid"]) {
    const values = new RegExp(`^${field}:\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)$`, "m")
      .exec(status)?.slice(1).map(Number);
    assert.deepEqual(values, Array(4).fill(Number(expectedUid)), `Bridge ${field} differs from agent.`);
  }
  assert.equal(cgroup, selfCgroup, "Bridge escaped the agent cgroup.");
  assert.match(status, /^NoNewPrivs:\s+1$/m);
  assert.match(status, /^Seccomp:\s+2$/m);
  for (const field of ["CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"]) {
    assert.match(status, new RegExp(`^${field}:\\s+0+$`, "m"));
  }
  for (const kind of ["net", "pid", "ipc", "mnt"]) {
    assert.equal(await readlink(`/proc/${pid}/ns/${kind}`), await readlink(`/proc/self/ns/${kind}`),
      `Bridge escaped the agent ${kind} namespace.`);
  }
}

async function waitFor(name) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      await lstat(path.join(work, name));
      return;
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for ${name}.`);
}

async function exchange() {
  const transport = new StdioClientTransport({ command: bridge, args: [],
    env: { PATH: "/usr/bin:/bin" }, stderr: "pipe" });
  const client = new Client({ name: "managed-bridge-native-fixture", version: "1" });
  let timer;
  let connected = false;
  let tools;
  let failure;
  try {
    const timeout = new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("MCP bridge handshake timed out.")), 8000);
    });
    await Promise.race([client.connect(transport), timeout]);
    connected = true;
    await assertBridgeScope(transport.pid);
    tools = await Promise.race([client.listTools(), timeout]);
  } catch (error) {
    failure = error;
  }
  try {
    clearTimeout(timer);
    await client.close();
  } catch (error) {
    if (!failure) throw error;
  }
  return { connected, tools, failure };
}

async function directBrokerDenied() {
  const code = await new Promise(resolve => {
    const socket = createConnection(brokerPath);
    socket.setTimeout(3000, () => { socket.destroy(); resolve("timeout"); });
    socket.once("connect", () => { socket.destroy(); resolve("connected"); });
    socket.once("error", error => resolve(error.code));
  });
  assert.equal(code, "EACCES", `Agent reached broker Unix socket: ${code}`);
}

await writeFile(path.join(output, "ready"), `${process.getuid()}\n`, { flag: "wx" });
await waitFor("go");
await directBrokerDenied();
const initial = await exchange();
assert.equal(initial.failure, undefined);
assert.equal(initial.connected, true);
assert.deepEqual(initial.tools.tools, []);
await writeFile(path.join(output, "bridge-scope"), "ok\n", { flag: "wx" });
await writeFile(path.join(output, "handshake"), "ok\n", { flag: "wx" });

await waitFor("rebound");
const rebound = await exchange();
assert.equal(rebound.connected, false, "A rebound broker socket completed the MCP handshake.");
assert.ok(rebound.failure, "A rebound broker socket served MCP through stale proof.");
await writeFile(path.join(output, "rebind-denied"), "ok\n", { flag: "wx" });

await waitFor("forwarder-stopped");
const afterStop = spawnSync(bridge, [], { input: "", encoding: "utf8", timeout: 7000 });
assert.equal(afterStop.status, 1, `Bridge still reached a stopped forwarder: ${afterStop.stderr}`);
assert.match(afterStop.stderr, /could not reach its forwarder/);
await writeFile(path.join(output, "teardown-denied"), "ok\n", { flag: "wx" });
setInterval(() => {}, 1000);
