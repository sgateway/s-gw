import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import type { PeerSession } from "./peer-identity.js";

export class MacAgentSessionLeases {
  constructor(private readonly leaseDir: string) {}

  async register(session: PeerSession, registerPeer: (session: PeerSession) => () => void): Promise<() => void> {
    if (process.platform !== "darwin") throw new Error("macOS agent leases require macOS.");
    const brokerUid = process.getuid?.();
    const brokerEuid = process.geteuid?.();
    const brokerGid = process.getgid?.();
    if (brokerUid === undefined || brokerEuid === undefined || brokerGid === undefined ||
        !Number.isSafeInteger(session.uid) || session.uid < 1 || session.uid === brokerUid ||
        session.uid === brokerEuid || !Number.isSafeInteger(session.gid) || session.gid! < 1 ||
        session.gid === brokerGid || !session.sessionId?.trim()) {
      throw new Error("A macOS agent lease needs a dedicated UID, GID, and session ID.");
    }

    await checkedLeaseDirectory(this.leaseDir);
    const leasePath = path.join(this.leaseDir, String(session.uid));
    let file;
    try {
      file = await open(leasePath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        throw new Error("This macOS agent UID was already used; provision a fresh identity.");
      }
      throw error;
    }

    try {
      await file.writeFile(JSON.stringify({ uid: session.uid, sessionId: session.sessionId, createdAt: new Date().toISOString() }) + "\n");
      await file.sync();
    } finally {
      await file.close();
    }
    const dir = await open(this.leaseDir, constants.O_RDONLY);
    try { await dir.sync(); }
    finally { await dir.close(); }

    // A failed registration still burns the UID: an old process may already exist.
    const stopPeer = registerPeer(session);
    let stopped = false;
    return () => {
      if (stopped) return;
      stopped = true;
      stopPeer();
    };
  }
}

async function checkedLeaseDirectory(value: string): Promise<void> {
  const brokerUid = process.getuid?.();
  if (brokerUid === undefined) throw new Error("Agent UID leases require a native broker UID.");
  if (!path.isAbsolute(value) || path.resolve(value) !== value) {
    throw new Error("Agent UID lease directory must be an absolute canonical path.");
  }
  const dir = await lstat(value);
  if (!dir.isDirectory() || dir.uid !== brokerUid || (dir.mode & 0o077) !== 0 ||
      await realpath(value) !== value) {
    throw new Error("Agent UID lease directory must be private to the broker.");
  }
  let current = path.dirname(value);
  while (true) {
    const info = await lstat(current);
    const stickyRoot = info.uid === 0 && (info.mode & 0o1000) !== 0;
    if (!info.isDirectory() || (info.uid !== 0 && info.uid !== brokerUid) ||
        ((info.mode & 0o022) !== 0 && !stickyRoot)) {
      throw new Error("Agent UID lease directory has an untrusted parent.");
    }
    const next = path.dirname(current);
    if (next === current) return;
    current = next;
  }
}
