import { sampleState } from "@/lib/sample-data";
import type {
  ApprovalAgentScope,
  ApprovalMode,
  ApprovalPolicyDecision,
  AgentIntegrationMutation,
  ConsoleState,
  RequestRecord,
  SecretSeverity
} from "@/lib/types";

interface ApiOptions {
  method?: string;
  body?: unknown;
}

function consoleToken(): string {
  return window.SGW_CONSOLE_TOKEN || "";
}

export function isLiveConsole(): boolean {
  return window.SGW_CONSOLE_LIVE === true || Boolean(consoleToken());
}

export async function apiJson<T>(pathName: string, options: ApiOptions = {}): Promise<T> {
  const headers: Record<string, string> = {
    "X-SGW-Console-Token": consoleToken()
  };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }

  const response = await fetch(pathName, {
    method: options.method || "GET",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body)
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || `HTTP ${response.status}`);
  }
  return payload as T;
}

export async function fetchConsoleState(): Promise<ConsoleState> {
  if (!isLiveConsole()) {
    return sampleState;
  }
  return apiJson<ConsoleState>("/api/state");
}

export function approveRequest(
  request: RequestRecord,
  choice: { mode?: ApprovalMode; durationMs?: number; agentScope?: ApprovalAgentScope }
) {
  return apiJson<RequestRecord>(`/api/requests/${encodeURIComponent(request.id)}/approve`, {
    method: "POST",
    body: choice
  });
}

export function approveRequestWithScopedPolicy(request: RequestRecord) {
  return apiJson<{ request: RequestRecord; created: boolean }>(`/api/requests/${encodeURIComponent(request.id)}/approve-policy`, {
    method: "POST",
    body: {}
  });
}

export function denyRequest(request: RequestRecord) {
  return apiJson<RequestRecord>(`/api/requests/${encodeURIComponent(request.id)}/deny`, {
    method: "POST",
    body: {}
  });
}

export function deleteSecret(handle: string) {
  return apiJson(`/api/secrets/${encodeURIComponent(handle)}`, { method: "DELETE" });
}

export function createSecret(body: {
  name: string;
  type: string;
  value: string;
  provider?: string;
  injectEnv?: string;
  allowedCommands?: string[];
  backend?: "keychain" | "local";
}) {
  return apiJson("/api/secrets", { method: "POST", body });
}

export function saveApprovalSettings(body: { mode: ApprovalMode; durationMs: number }) {
  return apiJson("/api/approval", { method: "POST", body });
}

export interface PolicyInput {
  name: string;
  enabled: boolean;
  priority?: number;
  decision: ApprovalPolicyDecision;
  agents?: string[];
  handles?: string[];
  envBindings?: Array<{ handle: string; injectEnv: string }>;
  providers?: string[];
  secretTypes?: string[];
  minSeverity?: SecretSeverity | null;
  actionKinds?: string[];
  commands?: string[];
  injectEnvs?: string[];
  workingDirs?: string[];
  sshTargets?: string[];
  sshPorts?: number[];
  durationMs?: number;
  expiresAt?: string | null;
}

export function addPolicy(body: PolicyInput) {
  return apiJson("/api/approval/policies", { method: "POST", body });
}

export function updatePolicy(id: string, body: Partial<PolicyInput>) {
  return apiJson(`/api/approval/policies/${encodeURIComponent(id)}`, { method: "PUT", body });
}

export function arrangePolicies() {
  return apiJson<{ reordered: number }>("/api/approval/policies/arrange", { method: "POST", body: {} });
}

export function setPolicyEnabled(id: string, enabled: boolean) {
  return apiJson(`/api/approval/policies/${encodeURIComponent(id)}`, {
    method: "PATCH",
    body: { enabled }
  });
}

export function deletePolicy(id: string) {
  return apiJson(`/api/approval/policies/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function revokeGrant(id: string) {
  return apiJson(`/api/approval/grants/${encodeURIComponent(id)}`, { method: "DELETE" });
}

export function clearGrants() {
  return apiJson("/api/approval/grants", { method: "DELETE" });
}

export function installAgentIntegration(agentId: string) {
  return apiJson<AgentIntegrationMutation>(`/api/agents/${encodeURIComponent(agentId)}/install`, {
    method: "POST",
    body: {}
  });
}

export function uninstallAgentIntegration(agentId: string) {
  return apiJson<AgentIntegrationMutation>(`/api/agents/${encodeURIComponent(agentId)}/uninstall`, {
    method: "POST",
    body: {}
  });
}

export function auditCsvUrl(): string {
  return "/api/audit.csv";
}
