import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { unsafeStartupEnv, validateLinuxManagedPlanRecord,
  type LinuxManagedPlanRecord } from "./linux-agent-control.js";
import type { LinuxManagedMcpConfig } from "./linux-managed-mcp.js";
import { normalizeModelRelayGrant } from "./model-relay-action.js";

export interface LinuxManagedUnitBundle {
  brokerConfig: string;
  planRecord: string;
  brokerUnit: string;
  mcpSocketUnit: string;
  modelSocketUnit?: string;
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

const grantKeys = new Set(["handle", "provider", "routes", "ttlMs", "payloadProfile",
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

export function renderLinuxManagedUnitBundle(config: LinuxManagedMcpConfig,
  record: LinuxManagedPlanRecord, brokerGid: number,
  phase: "prepare" | "runtime"): LinuxManagedUnitBundle {
  if (phase !== "prepare" && phase !== "runtime") {
    throw new Error("Invalid Linux managed provisioning phase.");
  }
  if (!record?.plan) throw new Error("Linux managed provisioning needs a root plan.");
  validateLinuxManagedPlanRecord(record, record.plan.sessionId, record.plan.brokerUid, brokerGid);
  if (!record.plan.identityGeneration || !record.plan.logicalAgentId) {
    throw new Error("Linux managed provisioning needs a durable identity.");
  }
  if (record.plan.restrictedSocketFamilies !== true || record.plan.requirePtracePolicy !== true) {
    throw new Error("Linux managed provisioning needs strict isolation options.");
  }
  if (!config || typeof config !== "object" ||
      Object.keys(config).some(key => !["name", "leaseDir", "plan", "relay"].includes(key)) ||
      typeof config.name !== "string" || !config.name.trim() || config.name.length > 120 ||
      typeof config.leaseDir !== "string" || !path.isAbsolute(config.leaseDir) ||
      path.resolve(config.leaseDir) !== config.leaseDir ||
      !isDeepStrictEqual(config.plan, record.plan)) {
    throw new Error("Linux broker configuration differs from its managed root plan.");
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
  } else if (config.relay || phase === "prepare") {
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
    mcpSocketUnit: managedSocketUnit(record.plan.brokerSocket, record.plan.gid,
      `s-gw-agent-${sessionId}`, unit),
    ...(record.plan.modelRelaySocket ? { modelSocketUnit: managedSocketUnit(
      record.plan.modelRelaySocket, record.plan.gid, `s-gw-model-${sessionId}`, unit) } : {})
  };
}
