import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { unsafeStartupEnv, validateLinuxManagedPlanRecord,
  type LinuxManagedPlanRecord } from "./linux-agent-control.js";
import type { LinuxManagedMcpConfig } from "./linux-managed-mcp.js";
import { linuxForwarderEntry, linuxForwarderNode } from "./linux-forwarder-runtime.js";
import { normalizeModelRelayGrant } from "./model-relay-action.js";

export interface LinuxManagedUnitBundle {
  brokerConfig: string;
  planRecord: string;
  brokerUnit: string;
  mcpSocketUnit: string;
  modelSocketUnit?: string;
  forwarderUnit?: string;
}

export interface LinuxControlUnitRuntime {
  unitFile: string;
  runtimeRoot: string;
  preflight: string;
  node: string;
  entry: string;
  brokerUid: number;
  brokerGid: number;
}

export function renderLinuxAgentControlUnit(runtime: LinuxControlUnitRuntime): string {
  if (!runtime || !Number.isSafeInteger(runtime.brokerUid) || runtime.brokerUid < 1 ||
      !Number.isSafeInteger(runtime.brokerGid) || runtime.brokerGid < 1 ||
      [runtime.unitFile, runtime.runtimeRoot, runtime.preflight, runtime.node, runtime.entry]
        .some(value => typeof value !== "string" || !path.isAbsolute(value) ||
          path.resolve(value) !== value) ||
      !["/run/systemd/system", "/etc/systemd/system", "/usr/lib/systemd/system"]
        .includes(path.dirname(runtime.unitFile)) ||
      path.basename(runtime.unitFile) !== "s-gw-agent-control.service" ||
      path.basename(runtime.entry) !== "linux-agent-control.js" ||
      !runtime.node.startsWith(`${runtime.runtimeRoot}/`) ||
      !runtime.entry.startsWith(`${runtime.runtimeRoot}/`) ||
      !runtime.preflight.startsWith(`${runtime.runtimeRoot}/`)) {
    throw new Error("Linux root control unit needs a trusted runtime and broker identity.");
  }
  for (const value of [runtime.unitFile, runtime.runtimeRoot, runtime.preflight,
    runtime.node, runtime.entry]) safeUnitLiteral(value);
  const verifyArgs = `${runtime.runtimeRoot} ${runtime.node} ${runtime.entry} ${runtime.unitFile} - -`;
  return `[Unit]\nDescription=s-gw root agent control\n` +
    `[Service]\nType=exec\nUser=root\nGroup=root\n` +
    `ExecStartPre=${runtime.preflight} verify ${verifyArgs}\n` +
    `UnsetEnvironment=${unsafeStartupEnv.join(" ")} NODE_EXTRA_CA_CERTS\n` +
    `ExecStart=${runtime.preflight} verify-exec ${verifyArgs} -- --serve ` +
    `${runtime.brokerUid} ${runtime.brokerGid}\nRestart=no\n`;
}

const grantKeys = new Set(["handle", "provider", "routes", "ttlMs", "payloadProfile", "toolBoundary",
  "maxRequests", "maxInputBytes", "maxOutputTokens", "allowedModels", "workspaceId",
  "organizationId", "projectId", "anthropicVersion", "allowedBetaValues"]);

function safeUnitLiteral(value: string): string {
  if (typeof value !== "string" || !/^[\/A-Za-z0-9_.@+-]+$/.test(value)) {
    throw new Error("Linux provisioner found an unsafe systemd unit value.");
  }
  return value;
}

function managedSocketUnit(socketPath: string, group: number, descriptor: string,
  brokerUnit: string): string {
  return `[Unit]\nDescription=s-gw managed agent socket\n` +
    `BindsTo=s-gw-agent-control.service\nAfter=s-gw-agent-control.service\n` +
    `[Socket]\nListenStream=${socketPath}\nSocketUser=root\nSocketGroup=${group}\n` +
    `SocketMode=0660\nDirectoryMode=0711\nPassCredentials=yes\n` +
    `FileDescriptorName=${descriptor}\nAccept=no\nRemoveOnStop=no\n` +
    `Service=${brokerUnit}\n`;
}

function managedForwarderUnit(record: LinuxManagedPlanRecord): string {
  const forwarder = record.mcpForwarder!;
  const sessionId = record.plan.sessionId;
  const proof = `/run/s-gw/forwarder-proofs/${sessionId}.json`;
  for (const value of [forwarder.rootDirectory, forwarder.networkNamespacePath,
    record.plan.brokerSocket, proof, linuxForwarderNode, linuxForwarderEntry]) safeUnitLiteral(value);
  return `[Unit]\nDescription=s-gw managed MCP forwarder\n` +
    `BindsTo=s-gw-agent-control.service s-gw-agent-${sessionId}.service\n` +
    `After=s-gw-agent-control.service s-gw-agent-${sessionId}.service\n` +
    `[Service]\nType=exec\nUser=${forwarder.uid}\nGroup=${forwarder.gid}\n` +
    `SupplementaryGroups=\nRootDirectory=${forwarder.rootDirectory}\nWorkingDirectory=/\n` +
    `MountAPIVFS=yes\n` +
    `NetworkNamespacePath=${forwarder.networkNamespacePath}\nPrivateNetwork=yes\n` +
    `PrivateIPC=yes\nPrivateTmp=yes\nMountFlags=private\nBindLogSockets=no\n` +
    `TemporaryFileSystem=/dev/shm:rw,nosuid,nodev,noexec,mode=1777\n` +
    `ProtectHome=yes\nProtectSystem=strict\nPrivateDevices=yes\n` +
    `NoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\n` +
    `RestrictNamespaces=yes\nRestrictSUIDSGID=yes\n` +
    `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nSystemCallArchitectures=native\n` +
    `KillMode=control-group\n` +
    `BindReadOnlyPaths=${record.plan.brokerSocket}:/run/s-gw/broker.sock ` +
    `${proof}:/run/s-gw/forwarder-attestation.json\n` +
    `UnsetEnvironment=${unsafeStartupEnv.join(" ")}\n` +
    `ExecStart=${linuxForwarderNode} ${linuxForwarderEntry}\nRestart=no\n`;
}

export function renderLinuxManagedUnitBundle(config: LinuxManagedMcpConfig,
  record: LinuxManagedPlanRecord, brokerGid: number,
  phase: "prepare" | "runtime"): LinuxManagedUnitBundle {
  if (phase !== "prepare" && phase !== "runtime") {
    throw new Error("Invalid Linux managed provisioning phase.");
  }
  if (!record?.plan) throw new Error("Linux managed provisioning needs a root plan.");
  if (record.mcpForwarder && record.plan.modelRelaySocket) {
    throw new Error("Linux MCP-only forwarder staging has no model relay transport.");
  }
  validateLinuxManagedPlanRecord(record, record.plan.sessionId, record.plan.brokerUid, brokerGid);
  if (!record.plan.identityGeneration || !record.plan.logicalAgentId) {
    throw new Error("Linux managed provisioning needs a durable identity.");
  }
  if (record.plan.restrictedSocketFamilies !== true || record.plan.requirePtracePolicy !== true) {
    throw new Error("Linux managed provisioning needs strict isolation options.");
  }
  if (!config || typeof config !== "object" ||
      Object.keys(config).some(key => !["name", "leaseDir", "plan", "relay", "mcpForwarder"].includes(key)) ||
      typeof config.name !== "string" || !config.name.trim() || config.name.length > 120 ||
      typeof config.leaseDir !== "string" || !path.isAbsolute(config.leaseDir) ||
      path.resolve(config.leaseDir) !== config.leaseDir ||
      !isDeepStrictEqual(config.plan, record.plan)) {
    throw new Error("Linux broker configuration differs from its managed root plan.");
  }
  if (Boolean(config.mcpForwarder) !== Boolean(record.mcpForwarder) ||
      (record.mcpForwarder && (config.mcpForwarder?.uid !== record.mcpForwarder.uid ||
        config.mcpForwarder?.gid !== record.mcpForwarder.gid))) {
    throw new Error("Linux MCP forwarder differs from its root-managed plan.");
  }
  if (!config.leaseDir.startsWith("/run/s-gw/") ||
      !record.brokerConfig.startsWith("/run/s-gw/")) {
    throw new Error("Linux provisioner needs root-managed runtime paths.");
  }

  if (record.plan.modelRelaySocket) {
    const relay = config.relay;
    if (!relay || Object.keys(relay).some(key => key !== "grant" && key !== "requestId") ||
        !relay.grant || Object.keys(relay.grant).some(key => !grantKeys.has(key)) ||
        normalizeModelRelayGrant(relay.grant).payloadProfile !== "strict") {
      throw new Error("Linux managed model relay needs a strict grant.");
    }
    if (phase === "prepare" && relay.requestId !== undefined) {
      throw new Error("Linux model relay preparation must have no sealed request ID.");
    }
    if (phase === "runtime" && (typeof relay.requestId !== "string" ||
        !/^[A-Za-z0-9_-]{1,256}$/.test(relay.requestId))) {
      throw new Error("Linux model relay runtime needs a sealed request ID.");
    }
  } else if (config.relay || (phase === "prepare" && !record.mcpForwarder)) {
    throw new Error("Linux preparation requires a managed model relay.");
  }

  for (const value of [record.brokerUnit, record.brokerUnitFile,
    record.mcpSocketUnitFile, record.modelRelaySocketUnitFile,
    record.brokerEntry, record.brokerConfig, record.brokerNode,
    record.brokerRuntimeRoot, record.brokerPreflight,
    record.brokerEnvironmentFile, record.brokerCa,
    record.plan.brokerSocket, record.plan.modelRelaySocket,
    config.leaseDir]) {
    if (value !== undefined && value !== null) safeUnitLiteral(value);
  }
  const unit = record.brokerUnit;
  const sessionId = record.plan.sessionId;
  const ca = record.brokerCa ?? "-";
  const verifyArgs = `${record.brokerRuntimeRoot} ${record.brokerNode} ${record.brokerEntry} ` +
    `${record.brokerConfig} ${ca} ${record.brokerEnvironmentFile}`;
  const brokerUnit = `[Unit]\nDescription=s-gw managed agent broker\n` +
    `BindsTo=s-gw-agent-control.service\nAfter=s-gw-agent-control.service\n` +
    `[Service]\nType=exec\nUser=${record.plan.brokerUid}\nGroup=${brokerGid}\n` +
    `EnvironmentFile=${record.brokerEnvironmentFile}\n` +
    `UnsetEnvironment=${unsafeStartupEnv.join(" ")}\n` +
    `ExecStartPre=${record.brokerPreflight} verify ${verifyArgs}\n` +
    `ExecStart=${record.brokerPreflight} verify-exec ${verifyArgs} -- ${record.brokerConfig}\n` +
    `Restart=no\n`;
  return {
    brokerConfig: `${JSON.stringify(config)}\n`,
    planRecord: `${JSON.stringify(record)}\n`,
    brokerUnit,
    mcpSocketUnit: managedSocketUnit(record.plan.brokerSocket,
      record.mcpForwarder?.gid ?? record.plan.gid,
      `s-gw-agent-${sessionId}`, unit),
    ...(record.mcpForwarder ? { forwarderUnit: managedForwarderUnit(record) } : {}),
    ...(record.plan.modelRelaySocket ? { modelSocketUnit: managedSocketUnit(
      record.plan.modelRelaySocket, record.mcpForwarder?.gid ?? record.plan.gid,
      `s-gw-model-${sessionId}`, unit) } : {})
  };
}
