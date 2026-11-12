#!/usr/bin/env node
import path from "node:path";
import { fileURLToPath } from "node:url";
import { requestLinuxRelayPreparation } from "./linux-agent-control.js";
import { nativeLinuxManagedUnitInstaller, readApprovedLinuxManagedRelayFromBroker,
  readRootLinuxManagedInstallPlan } from "./linux-agent-installer.js";

export async function runLinuxManagedInstall(args: string[]): Promise<string | undefined> {
  const [mode, filename, requestId] = args;
  if (!["stage", "prepare", "activate"].includes(mode) || !filename ||
      (mode === "activate" ? args.length !== 3 : args.length !== 2)) {
    throw new Error("Usage: linux-managed-install <stage|prepare|activate> <root-plan.json> [request-id]");
  }
  const input = await readRootLinuxManagedInstallPlan(filename);
  if (mode === "stage") {
    await nativeLinuxManagedUnitInstaller.stage(input);
    return;
  }
  if (mode === "prepare") {
    return requestLinuxRelayPreparation(input.record.plan.sessionId);
  }
  await nativeLinuxManagedUnitInstaller.activate(input, requestId!, id =>
    readApprovedLinuxManagedRelayFromBroker(input, id));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const requestId = await runLinuxManagedInstall(process.argv.slice(2));
  if (requestId) process.stdout.write(`${requestId}\n`);
}
