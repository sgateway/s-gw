import { spawnSync } from "node:child_process";
import { mkdtemp, realpath, rm, symlink, unlink, writeFile } from "node:fs/promises";
import { createServer, type Server } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { linuxListenerRecordMatches, systemdAgentSocketFd } from "../src/linux-activated-socket.js";

const socket = "/run/s-gw/agents/session-123/broker.sock";
const table = [
  "Num       RefCount Protocol Flags    Type St Inode Path",
  `00000000: 00000002 00000000 00010000 0001 01 12345 ${socket}`,
  "00000000: 00000002 00000000 00010000 0001 01 67890 /run/other.sock"
].join("\n");

describe("Linux activated agent sockets", () => {
  it("selects one session descriptor from a systemd service with multiple listeners", () => {
    const env = {
      LISTEN_PID: String(process.pid), LISTEN_FDS: "3",
      LISTEN_FDNAMES: "s-gw-agent-other:s-gw-agent-session-123:s-gw-agent-last"
    };
    expect(systemdAgentSocketFd("session-123", env)).toBe(4);
  });

  it("rejects spoofed, unnamed, duplicate, and oversized descriptor manifests", () => {
    const good = { LISTEN_PID: String(process.pid), LISTEN_FDS: "1",
      LISTEN_FDNAMES: "s-gw-agent-session-123" };
    for (const env of [
      { ...good, LISTEN_PID: String(process.pid + 1) },
      { ...good, LISTEN_FDS: "2" },
      { ...good, LISTEN_FDS: "0" },
      { ...good, LISTEN_FDS: "65" },
      { ...good, LISTEN_FDNAMES: "other" },
      { ...good, LISTEN_FDS: "2", LISTEN_FDNAMES: `${good.LISTEN_FDNAMES}:${good.LISTEN_FDNAMES}` }
    ]) expect(() => systemdAgentSocketFd("session-123", env)).toThrow();
    expect(() => systemdAgentSocketFd("../session", good)).toThrow();
  });

  it("matches only a listening stream FD bound to the exact agent path", () => {
    expect(linuxListenerRecordMatches(table, "12345", socket)).toBe(true);
    expect(linuxListenerRecordMatches(table, "67890", socket)).toBe(false);
    expect(linuxListenerRecordMatches(table, "12345", "/run/s-gw/agents/other/broker.sock")).toBe(false);
    expect(linuxListenerRecordMatches(table.replace("00010000 0001", "00000000 0001"), "12345", socket)).toBe(false);
    expect(linuxListenerRecordMatches(table.replace("00010000 0001", "00010000 0002"), "12345", socket)).toBe(false);
    expect(linuxListenerRecordMatches(table.replace("00010000 0001 01", "00010000 0001 03"), "12345", socket)).toBe(false);
  });
});

const native = process.platform === "linux" && spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;
const build = fileURLToPath(new URL("../scripts/build-linux-activated-socket.mjs", import.meta.url));
const helper = fileURLToPath(new URL(`../dist/native/linux-${process.arch}/s-gw-linux-activated-socket`, import.meta.url));
let directory = "";
const servers: Server[] = [];

beforeAll(() => {
  if (!native) return;
  const result = spawnSync(process.execPath, [build], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
});

afterEach(async () => {
  for (const server of servers.splice(0)) await new Promise<void>(resolve => server.close(() => resolve()));
  if (directory) await rm(directory, { recursive: true, force: true });
  directory = "";
});

async function bind(location: string): Promise<number> {
  const server = createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(location, () => { server.off("error", reject); resolve(); });
  });
  servers.push(server);
  const fd = (server as Server & { _handle?: { fd?: number } })._handle?.fd;
  if (fd === undefined) throw new Error("The Linux test listener has no descriptor.");
  return fd;
}

function probe(fd: number, location: string, env: NodeJS.ProcessEnv = {}): number {
  const result = spawnSync(helper, [location], { stdio: ["ignore", "pipe", "pipe", fd], env });
  if (result.error || result.status === null) throw result.error || new Error("Socket verifier did not exit.");
  return result.status;
}

describe.skipIf(!native)("native Linux activated-socket binding", () => {
  it("matches the listener's current pathname inode as an unprivileged broker user", async () => {
    expect(process.geteuid!()).not.toBe(0);
    directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-socket-binding-")));
    const location = path.join(directory, "broker.sock");
    const original = await bind(location);
    expect(probe(original, location)).toBe(0);

    await unlink(location);
    expect(probe(original, location)).not.toBe(0);
    const replacement = await bind(location);
    expect(probe(original, location)).not.toBe(0);
    expect(probe(replacement, location)).toBe(0);

    const alias = path.join(directory, "alias.sock");
    await symlink(location, alias);
    expect(probe(replacement, alias)).not.toBe(0);

    await unlink(location);
    await writeFile(location, "not a socket");
    expect(probe(replacement, location)).not.toBe(0);
  });

  it("fails closed when the kernel socket diagnostic API is denied", async () => {
    directory = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-socket-diag-")));
    const location = path.join(directory, "broker.sock");
    const fd = await bind(location);
    const source = path.join(directory, "deny-netlink.c");
    const preload = path.join(directory, "deny-netlink.so");
    await writeFile(source, [
      "#define _GNU_SOURCE",
      "#include <errno.h>",
      "#include <sys/socket.h>",
      "int socket(int family, int type, int protocol) {",
      "  (void)family; (void)type; (void)protocol;",
      "  errno = EACCES; return -1;",
      "}"
    ].join("\n"));
    const compiled = spawnSync("cc", ["-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", source, "-o", preload], {
      encoding: "utf8"
    });
    expect(compiled.status, compiled.stderr).toBe(0);
    expect(probe(fd, location, { LD_PRELOAD: preload })).not.toBe(0);
  });
});
