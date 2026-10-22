import { chmod, lstat, realpath, rm } from "node:fs/promises";
import { createConnection, createServer, type Server, type Socket } from "node:net";
import path from "node:path";
import { assertNoMacAclAllow } from "./macos-path-acl.js";
import { checkedSocketPath, checkUnixPeerHelper, readUnixPeer } from "./peer-identity.js";

const codePattern = /^[A-Za-z0-9_-]{32}\n$/u;

export function consoleControlPath(storePath: string, port: number): string {
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("A background operator console needs a bound TCP port.");
  }
  return path.join(path.dirname(storePath), `console-${port}.sock`);
}

export async function startConsoleControl(
  socketPath: string,
  issueCode: () => string
): Promise<{ close: () => Promise<void> }> {
  assertMacControlSupport();
  await checkUnixPeerHelper();
  await assertPrivateHome(path.dirname(socketPath));
  await removeStaleSocket(socketPath);
  await checkedSocketPath(socketPath);

  const clients = new Set<Socket>();
  const server = createServer({ pauseOnConnect: true }, socket => {
    clients.add(socket);
    socket.on("error", () => socket.destroy());
    socket.once("close", () => clients.delete(socket));
    socket.setTimeout(1500, () => socket.destroy());
    void readUnixPeer(socket).then(peer => {
      if (socket.destroyed || peer.uid !== process.getuid!()) {
        socket.destroy();
        return;
      }
      socket.end(`${issueCode()}\n`);
    }).catch(() => socket.destroy());
  });

  let bound: { dev: number; ino: number } | undefined;
  try {
    await listen(server, socketPath);
    const firstInfo = await lstat(socketPath);
    if (!firstInfo.isSocket() || firstInfo.uid !== process.getuid!()) {
      throw new Error("Operator control socket binding changed during startup.");
    }
    bound = { dev: firstInfo.dev, ino: firstInfo.ino };
    await chmod(socketPath, 0o600);
    const socketInfo = await lstat(socketPath);
    if (!socketInfo.isSocket() || socketInfo.uid !== process.getuid!() || (socketInfo.mode & 0o077) !== 0) {
      throw new Error("Operator control socket is not private.");
    }
    await assertNoMacAclAllow(socketPath);
    return {
      close: async () => {
        await closeServer(server, clients);
        await removeOwnSocket(socketPath, socketInfo.dev, socketInfo.ino);
      }
    };
  } catch (error) {
    try {
      await closeServer(server, clients);
    } finally {
      if (bound) await removeOwnSocket(socketPath, bound.dev, bound.ino);
    }
    throw error;
  }
}

export async function requestConsoleCode(socketPath: string): Promise<string> {
  assertMacControlSupport();
  await assertPrivateHome(path.dirname(socketPath));
  const info = await lstat(socketPath);
  if (!info.isSocket() || info.uid !== process.getuid!() || (info.mode & 0o077) !== 0) {
    throw new Error("Operator control socket is not private.");
  }
  await assertNoMacAclAllow(socketPath);

  const socket = createConnection(socketPath);
  socket.pause();
  socket.setTimeout(1500, () => socket.destroy(new Error("Operator control request timed out.")));
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
    });
    const peer = await readUnixPeer(socket);
    if (peer.uid !== process.getuid!()) throw new Error("Operator control server identity does not match.");
    const code = await readCode(socket);
    return code;
  } finally {
    socket.destroy();
  }
}

function assertMacControlSupport(): void {
  if (process.platform !== "darwin" || typeof process.getuid !== "function") {
    throw new Error("Background operator enrollment currently requires macOS peer verification.");
  }
}

async function assertPrivateHome(dir: string): Promise<void> {
  const info = await lstat(dir);
  if (!info.isDirectory() || info.uid !== process.getuid!() || (info.mode & 0o077) !== 0 ||
      await realpath(dir) !== dir) {
    throw new Error("Operator control directory must be private to the broker user.");
  }
  await assertNoMacAclAllow(dir);
}

function listen(server: Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

function closeServer(server: Server, clients: Set<Socket>): Promise<void> {
  for (const socket of clients) socket.destroy();
  return new Promise((resolve, reject) => {
    if (!server.listening) {
      resolve();
      return;
    }
    server.close(error => error ? reject(error) : resolve());
  });
}

async function removeOwnSocket(socketPath: string, dev: number, ino: number): Promise<void> {
  let info;
  try {
    info = await lstat(socketPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (info.isSocket() && info.dev === dev && info.ino === ino) {
    await rm(socketPath);
  }
}

async function removeStaleSocket(socketPath: string): Promise<void> {
  let info;
  try {
    info = await lstat(socketPath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (!info.isSocket() || info.uid !== process.getuid!() || (info.mode & 0o077) !== 0) {
    throw new Error("Existing operator control path is not a private socket.");
  }
  await assertNoMacAclAllow(socketPath);

  const stale = await new Promise<boolean>((resolve, reject) => {
    const probe = createConnection(socketPath);
    probe.setTimeout(500, () => probe.destroy(new Error("Operator control socket did not respond.")));
    probe.once("connect", () => { probe.destroy(); resolve(false); });
    probe.once("error", error => {
      if ((error as NodeJS.ErrnoException).code === "ECONNREFUSED") resolve(true);
      else reject(error);
    });
  });
  if (!stale) throw new Error("An operator control server is already running.");
  await removeOwnSocket(socketPath, info.dev, info.ino);
}

function readCode(socket: Socket): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    socket.on("data", chunk => {
      data += String(chunk);
      if (data.length > 33) socket.destroy(new Error("Invalid operator control response."));
    });
    socket.once("error", reject);
    socket.once("end", () => {
      if (!codePattern.test(data)) {
        reject(new Error("Invalid operator control response."));
        return;
      }
      resolve(data.slice(0, -1));
    });
    socket.resume();
  });
}
