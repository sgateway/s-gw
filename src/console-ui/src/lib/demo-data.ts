import { sampleState } from "./sample-data";
import type {
  AuditEvent,
  ConsoleState,
  ProviderSummary,
  UsageFlow,
  UsageFlowLink,
  UsageFlowNode
} from "./types";

export const DEMO_DATA_STORAGE_KEY = "sgw.demo-data";

export function addDemoData(state: ConsoleState, referenceTime = new Date()): ConsoleState {
  const demo = buildDemoState(referenceTime);
  const handles = appendUnique(state.handles, demo.handles, (item) => item.handle);
  const requests = appendUnique(state.requests, demo.requests, (item) => item.id)
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  const rules = appendUnique(state.approvalPolicyRules, demo.approvalPolicyRules, (item) => item.id);

  return {
    ...state,
    metrics: {
      ...state.metrics,
      localSecrets: handles.length,
      activeAgents: Math.max(state.metrics.activeAgents, 6),
      highRiskFindings: handles.filter((item) => item.severity === "high" || item.severity === "critical").length
    },
    handles,
    approvalPolicyRules: rules,
    usageFlow: mergeUsageFlows(state.usageFlow, demo.usageFlow),
    credentials: [...state.credentials, ...demo.credentials],
    requests,
    pendingRequests: state.pendingRequests,
    audit: [...demo.audit, ...state.audit]
  };
}

function buildDemoState(referenceTime: Date): ConsoleState {
  const shiftedRequests = sampleState.requests.map((request, index) => {
    const updatedAt = minutesAgo(referenceTime, index * 7 + 2);
    return {
      ...request,
      demo: true,
      createdAt: minutesAgo(referenceTime, index * 7 + 4),
      updatedAt,
      approvedAt: request.approvedAt ? updatedAt : undefined,
      deniedAt: request.deniedAt ? updatedAt : undefined,
      executedAt: request.executedAt ? updatedAt : undefined
    };
  });
  const requestById = new Map(shiftedRequests.map((request) => [request.id, request]));

  return {
    ...sampleState,
    handles: sampleState.handles.map((item) => ({ ...item, demo: true })),
    approvalPolicyRules: sampleState.approvalPolicyRules.map((item) => ({ ...item, demo: true })),
    usageFlow: markDemoFlow(sampleState.usageFlow, referenceTime),
    credentials: sampleState.credentials.map((item): ProviderSummary => ({
      ...item,
      provider: `demo:${item.provider}`,
      demo: true
    })),
    requests: shiftedRequests,
    pendingRequests: [],
    audit: buildBusyAudit(sampleState.audit, requestById, referenceTime)
  };
}

function markDemoFlow(flow: UsageFlow, referenceTime: Date): UsageFlow {
  const generatedAt = referenceTime.toISOString();
  return {
    ...flow,
    demo: true,
    generatedAt,
    nodes: flow.nodes.map((item) => ({ ...item, demo: true })),
    links: flow.links.map((item) => ({ ...item, demo: true })),
    rows: flow.rows.map((item, index) => ({ ...item, demo: true, lastSeen: minutesAgo(referenceTime, index * 3 + 1) })),
    entries: flow.entries.map((item, index) => ({ ...item, demo: true, lastSeen: minutesAgo(referenceTime, index * 3 + 1) }))
  };
}

function buildBusyAudit(
  seeds: AuditEvent[],
  requests: Map<string, ConsoleState["requests"][number]>,
  referenceTime: Date
): AuditEvent[] {
  const rows: AuditEvent[] = [];
  for (let index = 0; index < 42; index += 1) {
    const seed = seeds[index % seeds.length];
    const request = seed.requestId ? requests.get(seed.requestId) : undefined;
    rows.push({
      ...seed,
      demo: true,
      id: `evt_demo_${String(index + 1).padStart(3, "0")}`,
      ts: minutesAgo(referenceTime, index * 4 + 1),
      handle: request?.handle || seed.handle,
      requestId: request?.id || seed.requestId
    });
  }
  return rows;
}

function mergeUsageFlows(live: UsageFlow, demo: UsageFlow): UsageFlow {
  return {
    demo: true,
    generatedAt: demo.generatedAt,
    totalRequests: live.totalRequests + demo.totalRequests,
    nodes: mergeNodes(live.nodes, demo.nodes),
    links: mergeLinks(live.links, demo.links),
    rows: [...demo.rows, ...live.rows],
    entries: [...demo.entries, ...live.entries]
  };
}

function mergeNodes(live: UsageFlowNode[], demo: UsageFlowNode[]): UsageFlowNode[] {
  const result = new Map(live.map((item) => [item.id, { ...item }]));
  for (const item of demo) {
    const existing = result.get(item.id);
    if (!existing) {
      result.set(item.id, { ...item });
      continue;
    }
    existing.count += item.count;
    existing.demo = true;
  }
  return [...result.values()];
}

function mergeLinks(live: UsageFlowLink[], demo: UsageFlowLink[]): UsageFlowLink[] {
  const key = (item: UsageFlowLink) => `${item.source}\u0000${item.target}`;
  const result = new Map(live.map((item) => [key(item), { ...item }]));
  for (const item of demo) {
    const existing = result.get(key(item));
    if (!existing) {
      result.set(key(item), { ...item });
      continue;
    }
    existing.value += item.value;
    existing.demo = true;
  }
  return [...result.values()];
}

function appendUnique<T>(live: T[], demo: T[], getId: (item: T) => string): T[] {
  const existing = new Set(live.map(getId));
  return [...live, ...demo.filter((item) => !existing.has(getId(item)))];
}

function minutesAgo(referenceTime: Date, minutes: number): string {
  return new Date(referenceTime.getTime() - minutes * 60_000).toISOString();
}
