import { describe, expect, it } from "vitest";
import { potentialBroadHttpAllows } from "../src/policy-audit.js";
import type { ApprovalPolicyConditions, ApprovalPolicyRule } from "../src/types.js";

function allow(name: string, conditions: ApprovalPolicyConditions = {}): ApprovalPolicyRule {
  return {
    id: name, name, enabled: true, priority: 0, decision: "allow", conditions,
    createdAt: "2026-01-01T00:00:00.000Z", updatedAt: "2026-01-01T00:00:00.000Z"
  };
}

describe("approval policy audit", () => {
  it("identifies active HTTPS allow rules that can vary the approved action", () => {
    const broad = allow("principal-scoped host rule", {
      principalIds: ["linux:managed:fixture"], actionKinds: ["http_request"], handles: ["s-gw:api-token:fixture"]
    });
    const unrestricted = allow("unrestricted rule");
    const exact = allow("exact HTTPS action", { actionKinds: ["http_request"], actionKeys: ["sha256:fixture"] });
    const envOnly = allow("environment only", { actionKinds: ["env_command"] });
    const oldNameRule = allow("legacy name rule", { agents: ["codex"] });
    const expired = { ...allow("expired rule"), expiresAt: "2026-01-02T00:00:00.000Z" };
    const disabled = { ...allow("disabled rule"), enabled: false };
    const ask = { ...allow("ask first"), decision: "ask" as const };
    const result = potentialBroadHttpAllows(
      [broad, unrestricted, exact, envOnly, oldNameRule, expired, disabled, ask],
      "2026-10-21T00:00:00.000Z"
    );
    expect(result.map((rule) => rule.id)).toEqual([broad.id, unrestricted.id]);
  });
});
