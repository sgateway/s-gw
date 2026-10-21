#!/usr/bin/env node
import { lstat, readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { systemdAgentSocketFd } from "./linux-activated-socket.js";
import { connectLinuxAgentControl, validateLinuxManagedPlan,
  type LinuxAgentControlClient } from "./linux-agent-control.js";
import { LinuxAgentSessionLeases } from "./linux-agent-session.js";
import type { LinuxAgentUnitPlan } from "./linux-agent-unit.js";
import { SecretStore } from "./store.js";
import { startVerifiedMcpServer, type VerifiedMcpServer } from "./verified-mcp-server.js";

export interface LinuxManagedMcpConfig {
  name: string;
  leaseDir: string;
  plan: LinuxAgentUnitPlan;
}

export function validateLinuxManagedMcpConfig(value: LinuxManagedMcpConfig): void {
  if (!value || typeof value !== "object" || typeof value.name !== "string" ||
      !value.name.trim() || value.name.length > 120 ||
      typeof value.leaseDir !== "string" || !path.isAbsolute(value.leaseDir) ||
      path.resolve(value.leaseDir) !== value.leaseDir) {
    throw new Error("Invalid Linux managed MCP configuration.");
  }
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("Linux managed MCP needs a broker UID and GID.");
  validateLinuxManagedPlan(value.plan, uid, gid);
}

export async function readLinuxManagedMcpConfig(filename: string): Promise<LinuxManagedMcpConfig> {
  const gid = process.getgid?.();
  if (process.platform !== "linux" || !Number.isSafeInteger(gid) || gid! < 1 ||
      !path.isAbsolute(filename) || path.resolve(filename) !== filename) {
    throw new Error("Managed Linux MCP needs an absolute root-provisioned config path.");
  }
  const info = await lstat(filename);
  if (!info.isFile() || info.uid !== 0 || info.gid !== gid ||
      (info.mode & 0o777) !== 0o640 || info.nlink !== 1 ||
      await realpath(filename) !== filename) {
    throw new Error("Managed Linux MCP config must be root-owned and broker-group readable.");
  }
  let parent = path.dirname(filename);
  while (true) {
    const item = await lstat(parent);
    if (!item.isDirectory() || item.uid !== 0 || (item.mode & 0o022) !== 0 ||
        await realpath(parent) !== parent) {
      throw new Error("Managed Linux MCP config has an untrusted parent.");
    }
    const next = path.dirname(parent);
    if (next === parent) break;
    parent = next;
  }
  const data = JSON.parse(await readFile(filename, "utf8")) as LinuxManagedMcpConfig;
  validateLinuxManagedMcpConfig(data);
  return data;
}

export interface LinuxManagedMcpSession {
  controlLost: AbortSignal;
  close(): Promise<void>;
}

export async function startLinuxManagedMcpSession(config: LinuxManagedMcpConfig,
  store: SecretStore): Promise<LinuxManagedMcpSession> {
  if (process.platform !== "linux" || process.geteuid?.() === 0) {
    throw new Error("Managed Linux MCP must run under the unprivileged broker account.");
  }
  validateLinuxManagedMcpConfig(config);
  const fd = systemdAgentSocketFd(config.plan.sessionId);
  let control: LinuxAgentControlClient | undefined;
  let mcp: VerifiedMcpServer | undefined;
  let stopAgent: (() => Promise<void>) | undefined;
  try {
    control = await connectLinuxAgentControl(config.plan);
    mcp = await startVerifiedMcpServer({ store, socketPath: config.plan.brokerSocket,
      socketGid: config.plan.gid, activatedFd: fd, requireLinuxMessageGate: true });
    const leases = new LinuxAgentSessionLeases(config.leaseDir, control);
    stopAgent = await leases.launch(config.plan, config.name,
      session => mcp!.registerSession(session), () => mcp!.assertSocketBinding());
    if (control.signal.aborted) throw new Error("Linux root control service ended during launch.");
  } catch (error) {
    const failures = [error];
    if (mcp) { try { await mcp.close(); } catch (cleanup) { failures.push(cleanup); } }
    if (control) { try { await control.close(); } catch (cleanup) { failures.push(cleanup); } }
    if (failures.length > 1) throw new AggregateError(failures, "Linux managed MCP launch cleanup failed.");
    throw error;
  }
  let closing: Promise<void> | undefined;
  const liveControl = control;
  const liveMcp = mcp;
  const liveStop = stopAgent;
  const close = () => {
    if (closing) return closing;
    closing = (async () => {
      const failures: unknown[] = [];
      try { await liveMcp.close(); } catch (error) { failures.push(error); }
      try { await liveStop(); } catch (error) { failures.push(error); }
      try { await liveControl.close(); } catch (error) { failures.push(error); }
      if (failures.length) throw new AggregateError(failures, "Linux managed MCP teardown failed.");
    })();
    return closing;
  };
  liveControl.signal.addEventListener("abort", () => { void close().catch(() => {}); }, { once: true });
  return { controlLost: liveControl.signal, close };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || !path.isAbsolute(process.argv[2])) {
    throw new Error("Usage: linux-managed-mcp <absolute root-provisioned config.json>");
  }
  const config = await readLinuxManagedMcpConfig(process.argv[2]);
  const store = new SecretStore();
  await store.init();
  const session = await startLinuxManagedMcpSession(config, store);
  session.controlLost.addEventListener("abort", () => { process.exitCode = 1; }, { once: true });
  for (const signal of ["SIGINT", "SIGTERM"] as const) {
    process.once(signal, () => {
      void session.close().then(() => { process.exitCode = 0; }, error => {
        process.stderr.write(`${String(error)}\n`);
        process.exitCode = 1;
      });
    });
  }
}
