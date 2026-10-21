import { describe, expect, it } from "vitest";
import { linuxAgentUnitName, linuxProcessGroupsAreDedicated, parseSystemdAgentState, systemdRunArgs, validateLinuxAgentPlan,
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
    `BindReadOnlyPaths=${binds}`, "BindPaths=",
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
