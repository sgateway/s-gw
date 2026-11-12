#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertApprovedLinuxManagedRelay } from "./linux-agent-installer.js";
import { readLinuxManagedMcpConfig } from "./linux-managed-mcp.js";
import { SecretStore } from "./store.js";
import type { RequestRecord } from "./types.js";

export async function readLinuxManagedApproval(configPath: string,
  requestId: string, store?: Pick<SecretStore, "getRequestWithoutRecovery">): Promise<RequestRecord> {
  if (process.platform !== "linux" || process.geteuid?.() === 0 ||
      !/^[A-Za-z0-9_-]{1,256}$/.test(requestId) ||
      !process.env.SGW_HOME || !path.isAbsolute(process.env.SGW_HOME) ||
      path.resolve(process.env.SGW_HOME) !== process.env.SGW_HOME ||
      !process.env.SGW_RECOVERY_HOME || !path.isAbsolute(process.env.SGW_RECOVERY_HOME) ||
      path.resolve(process.env.SGW_RECOVERY_HOME) !== process.env.SGW_RECOVERY_HOME) {
    throw new Error("Linux approval reader needs a dedicated broker and explicit store paths.");
  }
  const config = await readLinuxManagedMcpConfig(configPath);
  if (process.getuid?.() !== config.plan.brokerUid ||
      process.geteuid?.() !== config.plan.brokerUid ||
      process.getgid?.() !== process.getegid?.() ||
      (config.relay?.requestId && config.relay.requestId !== requestId)) {
    throw new Error("Linux approval reader differs from its broker session.");
  }
  const request = await (store ?? new SecretStore(process.env.SGW_HOME))
    .getRequestWithoutRecovery(requestId);
  assertApprovedLinuxManagedRelay({ ...config,
    relay: { ...config.relay!, requestId } }, request);
  return { id: request.id, handle: request.handle, reason: "",
    agentName: request.agentName, agentSource: request.agentSource,
    principalId: request.principalId, agentSessionId: request.agentSessionId,
    action: request.action, state: request.state, approvalSource: request.approvalSource,
    approvedAt: request.approvedAt, createdAt: request.createdAt,
    updatedAt: request.updatedAt };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4) {
    throw new Error("Usage: linux-managed-approval-reader <broker-config> <request-id>");
  }
  const request = await readLinuxManagedApproval(process.argv[2], process.argv[3]);
  process.stdout.write(`${JSON.stringify(request)}\n`);
}
