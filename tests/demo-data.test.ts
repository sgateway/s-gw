import { describe, expect, it } from "vitest";

import { addDemoData } from "../src/console-ui/src/lib/demo-data.js";
import { sampleState } from "../src/console-ui/src/lib/sample-data.js";

function emptyState() {
  return {
    ...structuredClone(sampleState),
    metrics: { localSecrets: 0, pendingApprovals: 0, activeAgents: 0, highRiskFindings: 0 },
    handles: [],
    approvalPolicyRules: [],
    usageFlow: { generatedAt: "", totalRequests: 0, nodes: [], links: [], rows: [], entries: [] },
    credentials: [],
    requests: [],
    pendingRequests: [],
    audit: []
  };
}

describe("console demo data", () => {
  it("matches the public website demo and remains display-only", () => {
    const state = addDemoData(emptyState(), new Date("2026-07-16T18:00:00.000Z"));

    expect(state.usageFlow.totalRequests).toBe(630);
    expect(state.usageFlow.nodes.find((item) => item.id === "agent:Codex")?.count).toBe(204);
    expect(state.usageFlow.rows[0]).toMatchObject({
      agent: "Codex",
      credential: "AWS prod deploy pair",
      target: "cloudfront",
      count: 82,
      demo: true
    });
    expect(state.handles).toHaveLength(49);
    expect(state.approvalPolicyRules).toHaveLength(17);
    expect(state.approvalPolicyRules.filter((item) => item.decision === "allow")).toHaveLength(9);
    expect(state.approvalPolicyRules.filter((item) => item.decision === "ask")).toHaveLength(5);
    expect(state.approvalPolicyRules.filter((item) => item.decision === "deny")).toHaveLength(3);
    expect(state.audit).toHaveLength(42);
    expect(state.requests.every((item) => item.demo)).toBe(true);
    expect(state.pendingRequests).toEqual([]);
    expect(state.metrics.pendingApprovals).toBe(0);
  });

  it("keeps real records separate from removable demo records", () => {
    const live = emptyState();
    const realHandle = structuredClone(sampleState.handles[0]);
    realHandle.handle = "s-gw:api-token:real-record";
    realHandle.name = "Real record";
    live.handles = [realHandle];
    live.metrics.localSecrets = 1;

    const displayed = addDemoData(live);

    expect(displayed.handles[0]).toEqual(realHandle);
    expect(displayed.handles.filter((item) => item.demo)).toHaveLength(49);
    expect(live.handles).toEqual([realHandle]);
    expect(live.audit).toEqual([]);
  });
});
