import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { LinuxPeerPidfdUnavailableError, validLinuxCgroupPath, verifyLinuxPeerProcess } from "../src/linux-peer-identity.js";

const linux = process.platform === "linux";
const compiler = linux && spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;
const cgroup = linux ? readFileSync("/proc/self/cgroup", "utf8").split("\n")
  .find(line => line.startsWith("0::/"))?.slice(3) : undefined;
const scopedCgroup = Boolean(cgroup && cgroup !== "/");
const build = fileURLToPath(new URL("../scripts/build-linux-peer-identity.mjs", import.meta.url));
let tmpDir = "";
let server: Server | undefined;
let client: Socket | undefined;
let acceptedSocket: Socket | undefined;

beforeAll(() => {
  if (!compiler) return;
  const result = spawnSync(process.execPath, [build], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
});

afterEach(async () => {
  client?.destroy();
  client = undefined;
  acceptedSocket?.destroy();
  acceptedSocket = undefined;
  if (server) await new Promise<void>((resolve, reject) => server!.close(error => error ? reject(error) : resolve()));
  server = undefined;
  if (tmpDir) await rm(tmpDir, { recursive: true, force: true });
  tmpDir = "";
});

async function connect(): Promise<Socket> {
  tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-linux-peer-"));
  const location = path.join(tmpDir, "peer.sock");
  let accepted!: (socket: Socket) => void;
  const peer = new Promise<Socket>(resolve => { accepted = resolve; });
  server = createServer(socket => { acceptedSocket = socket; socket.pause(); accepted(socket); });
  await new Promise<void>((resolve, reject) => {
    server!.once("error", reject);
    server!.listen(location, resolve);
  });
  client = createConnection(location);
  await new Promise<void>((resolve, reject) => { client!.once("connect", resolve); client!.once("error", reject); });
  return peer;
}

describe("Linux peer-process boundary", () => {
  it("requires a specific canonical cgroup", () => {
    expect(validLinuxCgroupPath("/system.slice/agent.scope")).toBe(true);
    for (const value of ["/", "relative", "/agent/../other", "/agent//child", "/agent/", "/agent\0other"]) {
      expect(validLinuxCgroupPath(value)).toBe(false);
    }
  });

  it.skipIf(linux)("does not offer a synthetic verifier on another OS", async () => {
    await expect(verifyLinuxPeerProcess({ destroyed: false } as Socket, "/agent.scope"))
      .rejects.toThrow("unavailable on this platform");
  });

  it.skipIf(!linux || !compiler || !scopedCgroup)("requires the kernel pidfd option and a live peer in the registered cgroup", async () => {
    const socket = await connect();
    let verified;
    try {
      verified = await verifyLinuxPeerProcess(socket, cgroup!);
    } catch (error) {
      if (error instanceof LinuxPeerPidfdUnavailableError) return;
      throw error;
    }
    expect(verified).toEqual({ uid: process.getuid!(), gid: process.getgid!(), pid: process.pid });
    await expect(verifyLinuxPeerProcess(socket, "/some-other-agent.scope"))
      .rejects.toThrow("Could not verify live Linux peer in its cgroup");
  });

  it.skipIf(!linux || !compiler)("rejects a request without a connected Unix socket", async () => {
    const helper = fileURLToPath(new URL(`../dist/native/linux-${process.arch}/s-gw-linux-peer-identity`, import.meta.url));
    const result = spawnSync(helper, ["/agent.scope"], { encoding: "utf8" });
    expect(result.status).not.toBe(0);
    expect(result.stdout).toBe("");
  });
});
