import { lstat, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { validateLinuxAgentPlan, type LinuxAgentUnitPlan } from "./linux-agent-unit.js";

export const linuxAgentIdentityDir = "/var/lib/s-gw/agent-identities";

export async function attestDurableLinuxAgentIdentity(plan: LinuxAgentUnitPlan): Promise<void> {
  validateLinuxAgentPlan(plan);
  if (!plan.identityGeneration) return;
  if (process.platform !== "linux" || process.geteuid?.() !== 0) {
    throw new Error("Only Linux root control can attest a durable agent identity.");
  }

  const directory = await lstat(linuxAgentIdentityDir);
  if (!directory.isDirectory() || directory.uid !== 0 ||
      (directory.mode & 0o777) !== 0o700 ||
      await realpath(linuxAgentIdentityDir) !== linuxAgentIdentityDir) {
    throw new Error("Linux agent identity registry is not root-private.");
  }
  await checkedRootParents(path.dirname(linuxAgentIdentityDir));

  const active = path.join(linuxAgentIdentityDir, `uid-${plan.uid}.json`);
  const used = path.join(linuxAgentIdentityDir, `generation-${plan.identityGeneration}.json`);
  for (const filename of [active, used]) {
    const file = await lstat(filename);
    if (!file.isFile() || file.uid !== 0 || (file.mode & 0o777) !== 0o600 ||
        file.nlink !== 1 || file.size > 512 || await realpath(filename) !== filename) {
      throw new Error("Linux agent identity record is not root-private.");
    }
    const record = JSON.parse(await readFile(filename, "utf8")) as Record<string, unknown>;
    if (!record || typeof record !== "object" ||
        Object.keys(record).sort().join(",") !== "gid,identityGeneration,logicalAgentId,uid" ||
        record.logicalAgentId !== plan.logicalAgentId ||
        record.identityGeneration !== plan.identityGeneration ||
        record.uid !== plan.uid || record.gid !== plan.gid) {
      throw new Error("Linux agent identity record differs from the root plan.");
    }
  }
}

async function checkedRootParents(start: string): Promise<void> {
  let current = start;
  while (true) {
    const info = await lstat(current);
    if (!info.isDirectory() || info.uid !== 0 || (info.mode & 0o022) !== 0 ||
        await realpath(current) !== current) {
      throw new Error("Linux agent identity registry has an untrusted parent.");
    }
    const next = path.dirname(current);
    if (next === current) return;
    current = next;
  }
}
