import { describe, expect, it } from "vitest";
import {
  approvalPolicyRuleCovers,
  arrangeApprovalPolicyRules,
  compareApprovalPolicyRules,
  findShadowingPolicyRule
} from "../src/policy-order.js";
import type { ApprovalPolicyRule } from "../src/types.js";

function rule(
  id: string,
  priority: number,
  conditions: ApprovalPolicyRule["conditions"],
  decision: ApprovalPolicyRule["decision"] = "allow"
): ApprovalPolicyRule {
  return {
    id,
    name: id,
    priority,
    decision,
    conditions,
    enabled: true,
    createdAt: `2026-07-16T00:00:0${id.length}Z`,
    updatedAt: "2026-07-16T00:00:00Z"
  };
}

describe("approval policy ordering", () => {
  it("recognizes semantic containment without treating case-sensitive commands as equivalent", () => {
    const broad = rule("broad", 10, { agents: ["codex"], minSeverity: "low" });
    const narrow = rule("narrow", 20, { agents: ["codex"], commands: ["/usr/bin/aws"], minSeverity: "high" });
    const differentCommand = rule("different-command", 20, { agents: ["codex"], commands: ["/usr/bin/AWS"], minSeverity: "high" });

    expect(approvalPolicyRuleCovers(broad, narrow)).toBe(true);
    expect(approvalPolicyRuleCovers(narrow, broad)).toBe(false);
    expect(approvalPolicyRuleCovers(narrow, differentCommand)).toBe(false);
  });

  it("requires an exact credential-binding set when a rule has one", () => {
    const broad = rule("broad", 10, {});
    const paired = rule("paired", 20, {
      envBindings: [
        { handle: "s-gw:api-token:one", injectEnv: "ONE_TOKEN" },
        { handle: "s-gw:api-token:two", injectEnv: "TWO_TOKEN" }
      ]
    });
    const subset = rule("subset", 30, {
      envBindings: [{ handle: "s-gw:api-token:one", injectEnv: "ONE_TOKEN" }]
    });
    const samePair = rule("same-pair", 40, {
      envBindings: [
        { handle: "s-gw:api-token:two", injectEnv: "TWO_TOKEN" },
        { handle: "s-gw:api-token:one", injectEnv: "ONE_TOKEN" }
      ]
    });

    expect(approvalPolicyRuleCovers(broad, paired)).toBe(true);
    expect(approvalPolicyRuleCovers(paired, subset)).toBe(false);
    expect(approvalPolicyRuleCovers(paired, samePair)).toBe(true);
  });

  it("preserves the established last-updated-first order for equal priorities", () => {
    const older = { ...rule("older", 100, {}), updatedAt: "2026-07-16T00:00:00Z" };
    const newer = { ...rule("newer", 100, {}), updatedAt: "2026-07-16T00:01:00Z" };

    expect([older, newer].sort(compareApprovalPolicyRules).map((item) => item.id)).toEqual(["newer", "older"]);
  });

  it("moves a narrower rule ahead of its broader parent while keeping unrelated order stable", () => {
    const broad = rule("broad", 10, { agents: ["codex"] }, "ask");
    const unrelated = rule("unrelated", 20, { agents: ["claude"] });
    const narrow = rule("narrow", 30, { agents: ["codex"], commands: ["/usr/bin/aws"] }, "allow");

    const arranged = arrangeApprovalPolicyRules([broad, unrelated, narrow], "2026-07-16T01:00:00Z");

    expect(arranged.rules.map((item) => item.id)).toEqual(["unrelated", "narrow", "broad"]);
    expect(arranged.rules.map((item) => item.priority)).toEqual([10, 20, 30]);
    expect(arranged.reordered).toBe(3);
  });

  it("keeps deny guardrails ahead of narrower allow rules", () => {
    const deny = rule("deny", 10, { agents: ["codex"] }, "deny");
    const allow = rule("allow", 20, { agents: ["codex"], commands: ["/usr/bin/aws"] }, "allow");

    expect(arrangeApprovalPolicyRules([deny, allow]).rules.map((item) => item.id)).toEqual(["deny", "allow"]);
  });

  it("keeps unrelated rules untouched and prefers deny then ask for equivalent scope", () => {
    const first = rule("first", 10, { agents: ["codex"] });
    const second = rule("second", 20, { agents: ["claude"] });
    expect(arrangeApprovalPolicyRules([first, second]).reordered).toBe(0);

    const allow = rule("allow", 10, { agents: ["codex"] }, "allow");
    const ask = rule("ask", 20, { agents: ["codex"] }, "ask");
    const deny = rule("deny", 30, { agents: ["codex"] }, "deny");
    expect(arrangeApprovalPolicyRules([allow, ask, deny]).rules.map((item) => item.id)).toEqual(["deny", "ask", "allow"]);
  });

  it("reports only an earlier live covering rule as shadowing", () => {
    const broad = rule("broad", 10, { agents: ["codex"] });
    const narrow = rule("narrow", 20, { agents: ["codex"], commands: ["/usr/bin/aws"] });
    const expired = { ...broad, id: "expired", priority: 5, expiresAt: "2026-07-15T00:00:00Z" };

    expect(findShadowingPolicyRule([expired, narrow], narrow, "2026-07-16T00:00:00Z")).toBeUndefined();
    expect(findShadowingPolicyRule([broad, narrow], narrow, "2026-07-16T00:00:00Z")?.id).toBe("broad");
  });
});
