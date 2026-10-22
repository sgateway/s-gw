import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import path from "node:path";
import { validLinuxCgroupPath } from "./linux-peer-identity.js";
import { linuxAgentUnitName, validateLinuxAgentPlan, type LinuxAgentUnitManager, type LinuxAgentUnitPlan } from "./linux-agent-unit.js";
import type { PeerSession } from "./peer-identity.js";

export class LinuxAgentSessionLeases {
  constructor(private readonly leaseDir: string, private readonly units: LinuxAgentUnitManager) {}

  async launch(plan: LinuxAgentUnitPlan, name: string,
    registerPeer: (session: PeerSession) => (() => void) | Promise<() => void>,
    assertSocketBinding?: () => Promise<void>): Promise<() => Promise<void>> {
    validateLinuxAgentPlan(plan);
    if (plan.activatedSocket && !assertSocketBinding) {
      throw new Error("An activated Linux agent socket needs a live broker FD binding check.");
    }
    const brokerUid = process.getuid?.();
    const brokerGid = process.getgid?.();
    if (brokerUid === undefined || brokerGid === undefined || plan.uid === brokerUid ||
        plan.gid === brokerGid || plan.brokerUid !== brokerUid || !name.trim()) {
      throw new Error("Linux agent session needs a separate UID and GID from its broker.");
    }
    await checkedLeaseDirectory(this.leaseDir, brokerUid);
    await reserve(this.leaseDir, `session-${plan.sessionId}`, plan);
    await reserve(this.leaseDir, `uid-${plan.uid}`, plan);
    await reserve(this.leaseDir, `gid-${plan.gid}`, plan);
    const dir = await open(this.leaseDir, constants.O_RDONLY);
    try { await dir.sync(); }
    finally { await dir.close(); }

    let started = false;
    let stopPeer: (() => void) | undefined;
    try {
      await this.units.start(plan);
      started = true;
      const state = await this.units.inspect(plan);
      if (state.unit !== linuxAgentUnitName(plan.sessionId) || state.uid !== plan.uid ||
          state.gid !== plan.gid || !validLinuxCgroupPath(state.cgroup) ||
          state.cgroup !== `/system.slice/${state.unit}` || !Number.isSafeInteger(state.mainPid) ||
          state.mainPid < 1 || !/^[a-f0-9]{32}$/.test(state.invocationId)) {
        throw new Error("Linux agent unit identity changed before peer registration.");
      }
      if (plan.activatedSocket) await assertSocketBinding!();
      stopPeer = await registerPeer({ uid: plan.uid, gid: plan.gid, sessionId: plan.sessionId,
        name, linuxCgroup: state.cgroup,
        ...(plan.identityGeneration ? { linuxIdentityGeneration: plan.identityGeneration } : {}) });
      if (plan.launchGate) {
        if (!this.units.release) throw new Error("Linux agent launch gate cannot be released by this unit manager.");
        if (plan.activatedSocket) await assertSocketBinding!();
        await this.units.release(plan, state);
      }
      let revoked = false;
      let stopping: Promise<void> | undefined;
      return async () => {
        if (!revoked) { revoked = true; stopPeer!(); }
        if (!stopping) {
          stopping = this.units.stop(plan).catch(error => { stopping = undefined; throw error; });
        }
        await stopping;
      };
    } catch (error) {
      stopPeer?.();
      if (started) {
        try { await this.units.stop(plan); }
        catch (stopError) { throw new AggregateError([error, stopError], "Linux agent launch and teardown failed."); }
      }
      throw error;
    }
  }
}

async function reserve(dir: string, name: string, plan: LinuxAgentUnitPlan): Promise<void> {
  let file;
  try {
    file = await open(path.join(dir, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") {
      throw new Error("This Linux agent session or identity was already used; provision a fresh session, UID, and GID.");
    }
    throw error;
  }
  try {
    await file.writeFile(JSON.stringify({ sessionId: plan.sessionId, uid: plan.uid, gid: plan.gid,
      createdAt: new Date().toISOString() }) + "\n");
    await file.sync();
  } finally { await file.close(); }
}

async function checkedLeaseDirectory(value: string, brokerUid: number): Promise<void> {
  if (!path.isAbsolute(value) || path.resolve(value) !== value) {
    throw new Error("Linux agent lease directory must be an absolute canonical path.");
  }
  const dir = await lstat(value);
  if (!dir.isDirectory() || dir.uid !== brokerUid || (dir.mode & 0o077) !== 0 ||
      await realpath(value) !== value) {
    throw new Error("Linux agent lease directory must be private to the broker.");
  }
  let current = path.dirname(value);
  while (true) {
    const info = await lstat(current);
    const rootSticky = info.uid === 0 && (info.mode & 0o1000) !== 0;
    if (!info.isDirectory() || (info.uid !== 0 && info.uid !== brokerUid) ||
        ((info.mode & 0o022) !== 0 && !rootSticky)) {
      throw new Error("Linux agent lease directory has an untrusted parent.");
    }
    const next = path.dirname(current);
    if (next === current) return;
    current = next;
  }
}
