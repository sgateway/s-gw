import { describe, expect, it } from "vitest";
import { linuxAgentUnitName, parseSystemdAgentState, systemdRunArgs, validateLinuxAgentPlan,
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
  return [
    `Id=${linuxAgentUnitName(p.sessionId)}`, "ActiveState=active", "Type=exec",
    `User=${p.uid}`, `Group=${p.gid}`,
    `RootDirectory=${p.rootDirectory}`, "WorkingDirectory=/workspace",
    `BindReadOnlyPaths=${p.brokerSocket}:/run/s-gw/broker.sock`, "BindPaths=",
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
});
