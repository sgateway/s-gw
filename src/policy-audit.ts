import { SGW_HTTP_COMMAND } from "./http-action.js";
import type { ApprovalPolicyRule } from "./types.js";

export function potentialBroadHttpAllows(rules: ApprovalPolicyRule[], now = new Date().toISOString()): ApprovalPolicyRule[] {
  const broad: ApprovalPolicyRule[] = [];
  for (const rule of rules) {
    if (!rule.enabled || rule.decision !== "allow") continue;
    if (rule.expiresAt && rule.expiresAt <= now) continue;
    const scope = rule.conditions;
    if (scope.actionKeys?.length) continue;
    if (scope.actionKinds?.length && !scope.actionKinds.includes("http_request")) continue;
    if (scope.commands?.length && !scope.commands.includes(SGW_HTTP_COMMAND)) continue;
    if (scope.resolvedCommands?.length || scope.sshTargets?.length || scope.sshPorts?.length || scope.workingDirs?.length) continue;
    if (scope.agents?.length && !scope.principalIds?.length) continue;
    broad.push(rule);
  }
  return broad;
}
