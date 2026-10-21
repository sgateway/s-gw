import { spawnSync } from "node:child_process";
import { chmod, mkdtemp, realpath, rm } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { acknowledgeMacAgentLaunch } from "../src/macos-agent-probe.js";
import { startVerifiedPeerServer, type PeerSession, type VerifiedPeerServer } from "../src/peer-identity.js";

const canRun = process.platform === "darwin" &&
  spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;
let tmpDir = "";
let server: VerifiedPeerServer | undefined;

beforeAll(() => {
  if (!canRun) return;
  const build = spawnSync(process.execPath, [fileURLToPath(new URL("../scripts/build-peer-credentials.mjs", import.meta.url))], {
    encoding: "utf8"
  });
  expect(build.status, build.stderr || build.stdout).toBe(0);
});

afterEach(async () => {
  await server?.close();
  server = undefined;
  if (tmpDir) await rm(tmpDir, { recursive: true, force: true });
  tmpDir = "";
});

async function startProbe(register = true): Promise<string> {
  tmpDir = await realpath(await mkdtemp(path.join(os.tmpdir(), "sgw-mac-probe-")));
  await chmod(tmpDir, 0o700);
  const location = path.join(tmpDir, "broker.sock");
  server = await startVerifiedPeerServer({
    socketPath: location,
    onConnection: acknowledgeMacAgentLaunch
  });
  if (!register) return location;
  const session: PeerSession = {
    uid: process.getuid!(), gid: process.getgid!(), sessionId: "test-session", name: "Agent"
  };
  const actualUid = process.getuid!();
  const otherUid = actualUid === 0 ? 1 : 0;
  const getuid = vi.spyOn(process, "getuid").mockReturnValue(otherUid);
  const geteuid = vi.spyOn(process, "geteuid").mockReturnValue(otherUid);
  try { server.registerSession(session); }
  finally { getuid.mockRestore(); geteuid.mockRestore(); }
  return location;
}

function probe(location: string, message: string, splitAt?: number, closeWrite = true): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket: Socket = createConnection(location);
    let response = "";
    socket.on("data", chunk => { response += String(chunk); });
    socket.once("error", error => {
      if ((error as NodeJS.ErrnoException).code === "ECONNRESET") return;
      reject(error);
    });
    socket.once("close", () => resolve(response));
    socket.once("connect", () => {
      if (splitAt !== undefined) {
        socket.write(message.slice(0, splitAt));
        setTimeout(() => {
          if (closeWrite) socket.end(message.slice(splitAt));
          else socket.write(message.slice(splitAt));
        }, 20);
      } else if (closeWrite) socket.end(message);
      else socket.write(message);
    });
  });
}

describe.skipIf(!canRun)("macOS agent launch probe", () => {
  it("acknowledges a fragmented probe only after native peer verification", async () => {
    const location = await startProbe();
    const uid = process.getuid!();
    expect(await probe(location, `HELLO-V1 ${uid} test-session\n`, 5))
      .toBe(`READY-V1 ${uid} test-session\n`);
  });

  it("rejects claimed UID, session, extra bytes, and an incomplete probe", async () => {
    const location = await startProbe();
    const uid = process.getuid!();
    expect(await probe(location, `HELLO-V1 ${uid + 1} test-session\n`)).toBe("");
    expect(await probe(location, `HELLO-V1 ${uid} other-session\n`)).toBe("");
    expect(await probe(location, `HELLO-V1 ${uid} test-session\nNEXT\n`)).toBe("");
    expect(await probe(location, "HELLO-V1 ")).toBe("");
  });

  it("rejects extra bytes that arrive after a complete frame", async () => {
    const location = await startProbe();
    const frame = `HELLO-V1 ${process.getuid!()} test-session\n`;
    expect(await probe(location, `${frame}LATE\n`, frame.length)).toBe("");
  });

  it("does not acknowledge a complete frame without write-side EOF", async () => {
    const location = await startProbe();
    const started = Date.now();
    expect(await probe(location, `HELLO-V1 ${process.getuid!()} test-session\n`, undefined, false)).toBe("");
    expect(Date.now() - started).toBeGreaterThanOrEqual(1000);
  });

  it("does not acknowledge a peer without a trusted session registration", async () => {
    const location = await startProbe(false);
    expect(await probe(location, `HELLO-V1 ${process.getuid!()} test-session\n`)).toBe("");
  });
});
