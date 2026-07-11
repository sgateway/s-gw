import { sampleState } from "@/lib/sample-data";
import type {
  ApprovalAgentScope,
  ApprovalMode,
  ApprovalPolicyDecision,
  AgentIntegrationMutation,
  ConsoleState,
  RequestRecord
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

export function addPolicy(body: {
  name: string;
  enabled: boolean;
  priority: number;
  decision: ApprovalPolicyDecision;
  agents?: string[];
  handles?: string[];
  providers?: string[];
  secretTypes?: string[];
  actionKinds?: string[];
  commands?: string[];
  injectEnvs?: string[];
  sshTargets?: string[];
  durationMs?: number;
}) {
  return apiJson("/api/approval/policies", { method: "POST", body });
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
