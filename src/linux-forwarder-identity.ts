import { lstat, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import type { LinuxManagedPlanRecord } from "./linux-agent-control.js";

export const linuxForwarderIdentityDir = "/var/lib/s-gw/forwarder-identities";

export function linuxForwarderIdentityRecord(record: LinuxManagedPlanRecord): string {
  const forwarder = record.mcpForwarder;
  if (!forwarder || !record.plan.identityGeneration) {
    throw new Error("Linux forwarder needs a durable agent generation.");
  }
  return `${JSON.stringify({ sessionId: record.plan.sessionId,
    identityGeneration: record.plan.identityGeneration,
    uid: forwarder.uid, gid: forwarder.gid })}\n`;
}

export async function attestDurableLinuxForwarderIdentity(record: LinuxManagedPlanRecord): Promise<void> {
  const forwarder = record.mcpForwarder;
  if (!forwarder) return;
  if (process.platform !== "linux" || process.getuid?.() !== 0 || process.geteuid?.() !== 0) {
    throw new Error("Only Linux root control can attest a forwarder identity.");
  }
  const directory = await lstat(linuxForwarderIdentityDir);
  if (!directory.isDirectory() || directory.uid !== 0 || directory.gid !== 0 ||
      (directory.mode & 0o777) !== 0o700 ||
      await realpath(linuxForwarderIdentityDir) !== linuxForwarderIdentityDir) {
    throw new Error("Linux forwarder identity registry is not root-private.");
  }
  let current = path.dirname(linuxForwarderIdentityDir);
  while (true) {
    const parent = await lstat(current);
    if (!parent.isDirectory() || parent.uid !== 0 || (parent.mode & 0o022) !== 0 ||
        await realpath(current) !== current) {
      throw new Error("Linux forwarder identity registry has an untrusted parent.");
    }
    const next = path.dirname(current);
    if (next === current) break;
    current = next;
  }
  const expected = linuxForwarderIdentityRecord(record);
  for (const filename of [`uid-${forwarder.uid}.json`, `gid-${forwarder.gid}.json`,
    `session-${record.plan.sessionId}.json`]) {
    const fullPath = path.join(linuxForwarderIdentityDir, filename);
    const item = await lstat(fullPath);
    if (!item.isFile() || item.uid !== 0 || item.gid !== 0 ||
        (item.mode & 0o777) !== 0o600 || item.nlink !== 1 ||
        item.size !== Buffer.byteLength(expected) || await realpath(fullPath) !== fullPath ||
        await readFile(fullPath, "utf8") !== expected) {
      throw new Error("Linux forwarder identity receipt differs from the root plan.");
    }
  }
}
