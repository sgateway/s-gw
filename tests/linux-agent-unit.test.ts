import { describe, expect, it, vi } from "vitest";
import { spawnSync } from "node:child_process";
import { mkdtemp, mkdir, realpath, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { linuxAgentUnitName, linuxPrivateSharedMemoryMount, linuxProcessGroupsAreDedicated, linuxUnitIsAbsent,
  linuxUnitOwnedByStartAttempt,
  parseSystemdAgentState, reserveLinuxUnitLifecycleDirectory, startPreparedLinuxAgentUnit,
  stopOwnedLinuxAgentUnit, systemdRunArgs, validateLinuxAgentPlan, withLinuxUnitOperationLock,
  type LinuxAgentUnitPlan } from "../src/linux-agent-unit.js";

function plan(): LinuxAgentUnitPlan {
  return {
    sessionId: "session-123", uid: 231001, gid: 231001, brokerUid: 1000,
    rootDirectory: "/var/lib/s-gw/agent-roots/session-123",
    brokerSocket: "/run/s-gw/agents/session-123/broker.sock",
    executable: "/usr/bin/node", args: ["/app/agent.js", "--prompt", "a b"]
  };
}

function attestation(p: LinuxAgentUnitPlan): string {
  const binds = `${p.brokerSocket}:/run/s-gw/broker.sock` +
    (p.launchGate ? ` /run/s-gw/launch-gates/${p.sessionId}:/run/s-gw/launch-gate` : "");
  return [
    `Id=${linuxAgentUnitName(p.sessionId)}`, "ActiveState=active", "Type=exec",
    `User=${p.uid}`, `Group=${p.gid}`, "SupplementaryGroups=",
    `RootDirectory=${p.rootDirectory}`, "WorkingDirectory=/workspace",
    `ReadWritePaths=${p.rootDirectory}/workspace`,
    `BindReadOnlyPaths=${binds}`, "BindPaths=",
    `TemporaryFileSystem=${p.isolatedSharedMemory ? "/dev/shm:rw,nosuid,nodev,noexec,mode=1777" : ""}`,
    `StandardInput=${p.sealedStdio ? "null" : "tty"}`,
    `StandardOutput=${p.sealedStdio ? "null" : "journal"}`,
    `StandardError=${p.sealedStdio ? "null" : "inherit"}`,
    "Environment=SGW_BROKER_SOCKET=/run/s-gw/broker.sock",
    "Restart=no", "KillMode=control-group", "SendSIGKILL=yes", "Delegate=no",
    "DynamicUser=no", "PrivateUsers=no",
    "PrivateNetwork=yes", "PrivateIPC=yes", "PrivateTmp=yes", "ProtectSystem=strict",
    "ProtectHome=yes", "PrivateDevices=yes", "NoNewPrivileges=yes",
    "CapabilityBoundingSet=", "AmbientCapabilities=", "ProtectKernelTunables=yes",
    "ProtectKernelModules=yes", "ProtectControlGroups=yes", "RestrictNamespaces=yes",
    "RestrictSUIDSGID=yes", "NetworkNamespacePath=", "IPCNamespacePath=", "JoinsNamespaceOf=",
    `ControlGroup=/system.slice/${linuxAgentUnitName(p.sessionId)}`,
    "MainPID=1234", "InvocationID=0123456789abcdef0123456789abcdef"
  ].join("\n") + "\n";
}

describe("Linux systemd agent unit plan", () => {
  it("pins a unique static UID, root view, network and IPC isolation, and whole-cgroup teardown", () => {
    const args = systemdRunArgs(plan());
    expect(args).toContain("--system");
    expect(args).toContain("--property=User=231001");
    expect(args).toContain("--property=Group=231001");
    expect(args).toContain("--property=PrivateNetwork=yes");
    expect(args).toContain("--property=PrivateIPC=yes");
    expect(args).toContain("--property=PrivateTmp=yes");
    expect(args).toContain("--property=RootDirectory=/var/lib/s-gw/agent-roots/session-123");
    expect(args).toContain("--property=ReadWritePaths=/var/lib/s-gw/agent-roots/session-123/workspace");
    expect(args).toContain("--property=BindReadOnlyPaths=/run/s-gw/agents/session-123/broker.sock:/run/s-gw/broker.sock");
    expect(args).toContain("--property=KillMode=control-group");
    expect(args).toContain("--property=Restart=no");
    expect(args).toContain("--property=RestrictNamespaces=yes");
    expect(args).toContain("--property=CapabilityBoundingSet=");
    expect(args).not.toContain("--property=DynamicUser=yes");
    expect(args.slice(-4)).toEqual(["/usr/bin/node", "/app/agent.js", "--prompt", "a b"]);
  });

  it("runs the opt-in launch gate with a read-only root-owned release mount", () => {
    const p = { ...plan(), launchGate: true };
    const args = systemdRunArgs(p);
    expect(args).toContain("--property=BindReadOnlyPaths=/run/s-gw/agents/session-123/broker.sock:/run/s-gw/broker.sock /run/s-gw/launch-gates/session-123:/run/s-gw/launch-gate");
    expect(args.slice(-6)).toEqual(["/usr/libexec/s-gw/agent-launch-gate", "--", "/usr/bin/node", "/app/agent.js", "--prompt", "a b"]);
    expect(parseSystemdAgentState(p, attestation(p)).mainPid).toBe(1234);
    expect(parseSystemdAgentState(p, attestation(p).replace(
      "BindReadOnlyPaths=/run/s-gw/agents/session-123/broker.sock:/run/s-gw/broker.sock /run/s-gw/launch-gates/session-123:/run/s-gw/launch-gate",
      "BindReadOnlyPaths=/run/s-gw/agents/session-123/broker.sock:/run/s-gw/broker.sock:rbind /run/s-gw/launch-gates/session-123:/run/s-gw/launch-gate:rbind"))
      .mainPid).toBe(1234);
    expect(() => parseSystemdAgentState(p, attestation(p).replace(
      " /run/s-gw/launch-gates/session-123:/run/s-gw/launch-gate", ""))).toThrow("did not attest");
    expect(args.some(arg => arg.startsWith("--property=Standard"))).toBe(false);
  });

  it("keeps POSIX shared memory usable but private in the isolated profile", () => {
    const ordinary = plan();
    const isolated = { ...ordinary, launchGate: true, isolatedSharedMemory: true };
    expect(systemdRunArgs(ordinary).some(arg => arg.startsWith("--property=TemporaryFileSystem="))).toBe(false);
    expect(systemdRunArgs(isolated)).toContain(
      "--property=TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777");
    expect(parseSystemdAgentState(isolated, attestation(isolated)).mainPid).toBe(1234);
    expect(() => parseSystemdAgentState(isolated, attestation(isolated).replace(
      "TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777",
      "TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,mode=1777"))).toThrow("did not attest");
    expect(() => parseSystemdAgentState(isolated, attestation(isolated).replace(
      "TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777",
      "TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777 /dev/shm-host")))
      .toThrow("did not attest");
    expect(() => validateLinuxAgentPlan({ ...ordinary, isolatedSharedMemory: "yes" as never }))
      .toThrow("arguments");
    expect(() => validateLinuxAgentPlan({ ...ordinary, isolatedSharedMemory: true }))
      .toThrow("arguments");
  });

  it("requires a gated unit for the opt-in serialized lifecycle", () => {
    const ordinary = plan();
    expect(systemdRunArgs(ordinary).some(arg => arg.startsWith("--property=Standard"))).toBe(false);
    expect(() => validateLinuxAgentPlan({ ...ordinary, serializedLifecycle: true })).toThrow("arguments");
    expect(() => validateLinuxAgentPlan({ ...ordinary, launchGate: true,
      serializedLifecycle: "yes" as never })).toThrow("arguments");
    expect(() => validateLinuxAgentPlan({ ...ordinary, sealedStdio: true })).toThrow("arguments");
    expect(() => validateLinuxAgentPlan({ ...ordinary, launchGate: true,
      sealedStdio: "yes" as never })).toThrow("arguments");
    const sealed = { ...ordinary, launchGate: true, serializedLifecycle: true, sealedStdio: true };
    const args = systemdRunArgs(sealed);
    for (const property of ["StandardInput", "StandardOutput", "StandardError"]) {
      expect(args).toContain(`--property=${property}=null`);
      expect(() => parseSystemdAgentState(sealed, attestation(sealed).replace(
        `${property}=null`, `${property}=journal`))).toThrow("did not attest");
    }
    expect(parseSystemdAgentState(sealed, attestation(sealed)).mainPid).toBe(1234);
  });

  it("rejects a host shared-memory bind despite matching tmpfs mount flags", () => {
    const mount = "51 30 0:44 / /dev/shm rw,nosuid,nodev,noexec - tmpfs tmpfs rw,mode=1777\n";
    expect(linuxPrivateSharedMemoryMount(mount, 44, 43)).toBe(true);
    expect(linuxPrivateSharedMemoryMount(mount, 43, 43)).toBe(false);
    expect(linuxPrivateSharedMemoryMount(mount + mount, 44, 43)).toBe(false);
    expect(linuxPrivateSharedMemoryMount(mount.replace("noexec", "exec"), 44, 43)).toBe(false);
    expect(linuxPrivateSharedMemoryMount(mount.replace("tmpfs tmpfs", "ext4 /dev/sda"), 44, 43))
      .toBe(false);
  });

  it("marks each start attempt and refuses ownership of a preexisting unit", () => {
    const p = plan();
    const attempt = "0123456789abcdef0123456789abcdef";
    const output = [
      `Id=${linuxAgentUnitName(p.sessionId)}`,
      `Description=s-gw-agent-start:${attempt}`,
      `User=${p.uid}`, `Group=${p.gid}`, `RootDirectory=${p.rootDirectory}`
    ].join("\n") + "\n";
    expect(systemdRunArgs(p, attempt)).toContain(`--description=s-gw-agent-start:${attempt}`);
    expect(() => systemdRunArgs(p, "wrong")).toThrow("launch attempt ID");
    expect(linuxUnitOwnedByStartAttempt(p, attempt, output)).toBe(true);
    for (const changed of [
      output.replace(attempt, "fedcba9876543210fedcba9876543210"),
      output.replace(`Id=${linuxAgentUnitName(p.sessionId)}`, "Id=other.service"),
      output.replace(`User=${p.uid}`, "User=1000"),
      output.replace(`Group=${p.gid}`, "Group=1000"),
      output.replace(`RootDirectory=${p.rootDirectory}`, "RootDirectory=/"),
      output + `Description=s-gw-agent-start:${attempt}\n`,
      output.replace(`Description=s-gw-agent-start:${attempt}\n`, "")
    ]) {
      expect(linuxUnitOwnedByStartAttempt(p, attempt, changed)).toBe(false);
    }
  });

  it("stops only the unit from an ambiguous start attempt", async () => {
    const p = plan();
    const attempt = "0123456789abcdef0123456789abcdef";
    const owned = [`Id=${linuxAgentUnitName(p.sessionId)}`, `Description=s-gw-agent-start:${attempt}`,
      `User=${p.uid}`, `Group=${p.gid}`, `RootDirectory=${p.rootDirectory}`].join("\n") + "\n";
    const events: string[] = [];
    const launch = vi.fn(async () => { events.push("launch"); throw new Error("systemd-run timed out"); });
    const inspectOwnership = vi.fn(async () => { events.push("inspect"); return owned; });
    const verify = vi.fn(async () => { events.push("verify"); });
    const stopOwned = vi.fn(async () => { events.push("stop"); });
    const operations = { launch, inspectOwnership, verify, stopOwned };

    await expect(startPreparedLinuxAgentUnit(p, attempt, operations)).rejects.toThrow("systemd-run timed out");
    expect(events).toEqual(["launch", "inspect", "stop"]);
    expect(verify).not.toHaveBeenCalled();

    events.length = 0;
    inspectOwnership.mockImplementationOnce(async () => {
      events.push("inspect");
      return owned.replace(attempt, "fedcba9876543210fedcba9876543210");
    });
    await expect(startPreparedLinuxAgentUnit(p, attempt, operations)).rejects.toThrow("systemd-run timed out");
    expect(events).toEqual(["launch", "inspect"]);

    events.length = 0;
    launch.mockImplementationOnce(async () => { events.push("launch"); });
    verify.mockImplementationOnce(async () => { events.push("verify"); throw new Error("socket changed"); });
    await expect(startPreparedLinuxAgentUnit(p, attempt, operations)).rejects.toThrow("socket changed");
    expect(events).toEqual(["launch", "verify", "inspect", "stop"]);

    events.length = 0;
    launch.mockImplementationOnce(async () => { events.push("launch"); });
    verify.mockImplementationOnce(async () => { events.push("verify"); throw new Error("socket changed"); });
    inspectOwnership.mockImplementationOnce(async () => {
      events.push("inspect");
      return owned.replace(attempt, "fedcba9876543210fedcba9876543210");
    });
    await expect(startPreparedLinuxAgentUnit(p, attempt, operations))
      .rejects.toThrow("Linux agent start and teardown failed");
    expect(events).toEqual(["launch", "verify", "inspect"]);
  });

  it("retains the failed start for recovery when owned-unit stop fails", async () => {
    const p = plan();
    const attempt = "0123456789abcdef0123456789abcdef";
    const owned = [`Id=${linuxAgentUnitName(p.sessionId)}`, `Description=s-gw-agent-start:${attempt}`,
      `User=${p.uid}`, `Group=${p.gid}`, `RootDirectory=${p.rootDirectory}`].join("\n") + "\n";
    let gateCleaned = false;
    const stopUnit = vi.fn(async () => { throw new Error("systemctl stop failed"); });
    const result = startPreparedLinuxAgentUnit(p, attempt, {
      launch: async () => { throw new Error("systemd-run timed out"); },
      inspectOwnership: async () => owned,
      verify: async () => { throw new Error("should not verify"); },
      stopOwned: async () => { await stopUnit(); gateCleaned = true; }
    });
    await expect(result).rejects.toThrow("Linux agent start and teardown failed");
    expect(stopUnit).toHaveBeenCalledOnce();
    expect(gateCleaned).toBe(false);
  });

  it("refuses a leased stop when the attempt or invocation changed", async () => {
    const p = { ...plan(), launchGate: true, serializedLifecycle: true };
    const attempt = "0123456789abcdef0123456789abcdef";
    const invocation = "fedcba9876543210fedcba9876543210";
    const owned = [`Id=${linuxAgentUnitName(p.sessionId)}`, `Description=s-gw-agent-start:${attempt}`,
      `User=${p.uid}`, `Group=${p.gid}`, `RootDirectory=${p.rootDirectory}`,
      `InvocationID=${invocation}`].join("\n") + "\n";
    const stopOwned = vi.fn(async () => {});
    await stopOwnedLinuxAgentUnit(p, attempt, invocation, {
      inspectOwnership: async () => owned, stopOwned
    });
    expect(stopOwned).toHaveBeenCalledOnce();
    stopOwned.mockClear();
    for (const output of [
      owned.replace(attempt, "00000000000000000000000000000000"),
      owned.replace(invocation, "00000000000000000000000000000000"),
      owned.replace(`RootDirectory=${p.rootDirectory}`, "RootDirectory=/"),
      owned + `InvocationID=${invocation}\n`
    ]) {
      await expect(stopOwnedLinuxAgentUnit(p, attempt, invocation, {
        inspectOwnership: async () => output, stopOwned
      })).rejects.toThrow("changed before its owned stop");
    }
    expect(stopOwned).not.toHaveBeenCalled();
  });

  it("reserves only one per-unit lifecycle directory and leaves stale locks closed", async () => {
    const ownerUid = process.getuid?.();
    if (ownerUid === undefined) return;
    const root = await realpath(await mkdtemp(path.join(tmpdir(), "s-gw-unit-lock-")));
    try {
      const directory = path.join(root, linuxAgentUnitName("session-123"));
      const results = await Promise.allSettled([
        reserveLinuxUnitLifecycleDirectory(directory, ownerUid),
        reserveLinuxUnitLifecycleDirectory(directory, ownerUid)
      ]);
      expect(results.filter(result => result.status === "fulfilled")).toHaveLength(1);
      expect(results.filter(result => result.status === "rejected")).toHaveLength(1);
      await expect(reserveLinuxUnitLifecycleDirectory(directory, ownerUid))
        .rejects.toThrow("active or unreconciled lifecycle lease");
      const stale = path.join(root, linuxAgentUnitName("old-session"));
      await mkdir(stale, { mode: 0o700 });
      await expect(reserveLinuxUnitLifecycleDirectory(stale, ownerUid))
        .rejects.toThrow("active or unreconciled lifecycle lease");
      const link = path.join(root, linuxAgentUnitName("linked-session"));
      await symlink(stale, link);
      await expect(reserveLinuxUnitLifecycleDirectory(link, ownerUid))
        .rejects.toThrow("active or unreconciled lifecycle lease");
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("requires an absent unit before a serialized start", () => {
    const p = { ...plan(), launchGate: true, serializedLifecycle: true };
    const unit = linuxAgentUnitName(p.sessionId);
    const absent = `Id=${unit}\nLoadState=not-found\nActiveState=inactive\n`;
    expect(linuxUnitIsAbsent(p, absent)).toBe(true);
    for (const output of [
      absent.replace("LoadState=not-found", "LoadState=loaded"),
      absent.replace("ActiveState=inactive", "ActiveState=active"),
      absent.replace(`Id=${unit}`, "Id=other.service"),
      absent.replace("Id=", "Other="),
      absent + "LoadState=not-found\n",
      absent + "Description=other\n",
      ""
    ]) expect(linuxUnitIsAbsent(p, output)).toBe(false);
  });

  it.skipIf(process.platform !== "linux")("holds the per-unit operation lock across processes until close", async () => {
    const ownerUid = process.getuid?.();
    if (ownerUid === undefined) throw new Error("Linux UID is unavailable.");
    const root = await realpath(await mkdtemp(path.join(tmpdir(), "s-gw-unit-operation-")));
    const filename = path.join(root, `${linuxAgentUnitName("session-123")}.lock`);
    let entered!: () => void;
    let leave!: () => void;
    const ready = new Promise<void>(resolve => { entered = resolve; });
    const hold = new Promise<void>(resolve => { leave = resolve; });
    try {
      const running = withLinuxUnitOperationLock(filename, ownerUid, async () => {
        entered();
        await hold;
      });
      try {
        await Promise.race([ready, running]);
        const contender = () => spawnSync("/usr/bin/flock", ["--nonblock", filename, "/usr/bin/true"],
          { timeout: 3000 });
        const refused = contender();
        expect(refused.error).toBeUndefined();
        expect(refused.status).toBe(1);
        await expect(withLinuxUnitOperationLock(filename, ownerUid, async () => {}))
          .rejects.toThrow("unavailable or busy");
        leave();
        await running;
        const accepted = contender();
        expect(accepted.error).toBeUndefined();
        expect(accepted.status).toBe(0);
        await withLinuxUnitOperationLock(filename, ownerUid, async () => {});
      } finally {
        leave();
        await running.catch(() => {});
      }
    } finally { await rm(root, { recursive: true, force: true }); }
  });

  it("accepts an opt-in root-owned socket activation plan without changing the agent unit", () => {
    const base = plan();
    const activated = { ...base, activatedSocket: true };
    expect(systemdRunArgs(activated)).toEqual(systemdRunArgs(base));
    expect(parseSystemdAgentState(activated, attestation(activated)).mainPid).toBe(1234);
    expect(() => validateLinuxAgentPlan({ ...base, activatedSocket: "yes" as never })).toThrow("arguments");
  });

  it("rejects identity reuse, path traversal, shell interpolation, and unmanaged roots", () => {
    const base = plan();
    expect(() => validateLinuxAgentPlan({ ...base, uid: base.brokerUid })).toThrow("dedicated UID");
    expect(() => validateLinuxAgentPlan({ ...base, rootDirectory: "/home/operator/repo" })).toThrow("managed paths");
    expect(() => validateLinuxAgentPlan({ ...base, brokerSocket: "/run/s-gw/agents/a/../b/broker.sock" })).toThrow("managed paths");
    expect(() => validateLinuxAgentPlan({ ...base, executable: "/bin/sh" })).toThrow("executable");
    expect(() => validateLinuxAgentPlan({ ...base, args: ["ok\0bad"] })).toThrow("arguments");
    expect(() => linuxAgentUnitName("../../operator.service")).toThrow("session ID");
  });

  it("accepts only the intended running unit and critical isolation properties", () => {
    const p = plan();
    const good = attestation(p);
    expect(parseSystemdAgentState(p, good)).toMatchObject({
      uid: p.uid, gid: p.gid, cgroup: "/system.slice/s-gw-agent-session-123.service",
      invocationId: "0123456789abcdef0123456789abcdef"
    });
    for (const [before, after] of [
      ["PrivateNetwork=yes", "PrivateNetwork=no"],
      ["PrivateIPC=yes", "PrivateIPC=no"],
      ["User=231001", "User=1000"],
      ["SupplementaryGroups=\n", "SupplementaryGroups=docker\n"],
      ["RootDirectory=/var/lib/s-gw/agent-roots/session-123", "RootDirectory=/"],
      [`ReadWritePaths=${p.rootDirectory}/workspace`, "ReadWritePaths=/"],
      ["ControlGroup=/system.slice/s-gw-agent-session-123.service", "ControlGroup=/system.slice/other.service"],
      ["Restart=no", "Restart=always"],
      ["ActiveState=active", "ActiveState=failed"],
      ["NoNewPrivileges=yes", "NoNewPrivileges=no"],
      ["RestrictNamespaces=yes", "RestrictNamespaces=no"],
      ["CapabilityBoundingSet=\n", "CapabilityBoundingSet=cap_net_admin\n"],
      [`BindReadOnlyPaths=${p.brokerSocket}:/run/s-gw/broker.sock`, "BindReadOnlyPaths="]
    ]) {
      expect(() => parseSystemdAgentState(p, good.replace(before, after))).toThrow("did not attest");
    }
    expect(() => parseSystemdAgentState(p, good + "User=231001\n")).toThrow("Duplicate");
  });

  it("rejects an agent process with an unintended supplementary group", () => {
    expect(linuxProcessGroupsAreDedicated("Groups:\t231001\n", 231001)).toBe(true);
    expect(linuxProcessGroupsAreDedicated("Groups:\t\n", 231001)).toBe(true);
    expect(linuxProcessGroupsAreDedicated("Groups:\t231001 998\n", 231001)).toBe(false);
    expect(linuxProcessGroupsAreDedicated("Uid:\t231001\n", 231001)).toBe(false);
  });
});
