export type SecretSeverity = "low" | "medium" | "high" | "critical";
export type RequestState = "pending" | "approved" | "executing" | "denied" | "executed" | "failed";
export type ApprovalMode = "per-transaction" | "timed-session" | "login-session" | "always";
export type ApprovalAgentScope = "same-agent" | "any-agent";
export type ApprovalPolicyDecision = "ask" | "allow" | "deny";

export interface Readiness {
  ok: boolean;
  summary: string;
  blockers: string[];
}

export interface UnlockStatus {
  activeSource: string;
  envConfigured?: boolean;
  keychain?: {
    supported: boolean;
    service: string;
    account: string;
    provider: string;
    helperPath: string;
    configured: boolean;
  };
}

export interface ConsoleState {
  version: string;
  update: UpdateCheckResult | null;
  ready: boolean;
  readiness: Readiness;
  status: {
    daemonRunning: boolean;
    storePath: string;
    unlock: UnlockStatus;
  };
  metrics: {
    localSecrets: number;
    pendingApprovals: number;
    activeAgents: number;
    highRiskFindings: number;
  };
  handles: HandleSummary[];
  approvalSettings: ApprovalSettings;
  approvalGrants: ApprovalGrantRecord[];
  approvalPolicyRules: ApprovalPolicyRuleRecord[];
  usageFlow: UsageFlow;
  credentials: ProviderSummary[];
  requests: RequestRecord[];
  pendingRequests: RequestRecord[];
  audit: AuditEvent[];
  agents: AgentSummary[];
}

export interface UpdateCheckResult {
  checked: boolean;
  currentVersion: string;
  latestVersion: string | null;
  available: boolean;
  releaseUrl: string | null;
  prerelease: boolean;
  publishedAt: string | null;
  checkedAt: string | null;
  error?: string;
}

export interface SecretPolicy {
  injectEnv?: string;
  allowedCommands: string[];
  maxOutputBytes: number;
}

export interface HandleSummary {
  handle: string;
  name: string;
  type: string;
  backend?: string;
  provider?: string;
  ruleId?: string;
  severity?: SecretSeverity;
  confidence?: number;
  createdAt: string;
  updatedAt: string;
  source?: string;
  fingerprint: string;
  policy: SecretPolicy;
}

export interface ProviderSummary {
  provider: string;
  label: string;
  prefix: string;
  secrets: number;
  severity: SecretSeverity;
  lastUsed?: string;
}

export interface RequestRecord {
  id: string;
  handle: string;
  reason: string;
  agentName?: string;
  action: {
    kind: "env_command" | "ssh_session" | string;
    command: string;
    args: string[];
    injectEnv: string;
    workingDir?: string;
    timeoutMs: number;
    ssh?: {
      target: string;
      port?: number;
    };
  };
  state: RequestState;
  createdAt: string;
  updatedAt: string;
  approvedAt?: string;
  deniedAt?: string;
  executedAt?: string;
  error?: string;
}

export interface AuditEvent {
  id?: string;
  ts: string;
  type: string;
  handle?: string;
  requestId?: string;
  message: string;
}

export interface AgentSummary {
  id: string;
  name: string;
  status: string;
  aliases: string[];
  mcp: {
    supported: boolean;
    format: string;
    writeMode: string;
    configPaths: string[];
    notes: string[];
    snippet: string | null;
  };
  skills: AgentSurfaceSummary;
  plugins: AgentSurfaceSummary;
  hooks: AgentSurfaceSummary & {
    kind: string;
    events: string[];
  };
  limitations: string[];
  codeGuard: {
    supported: boolean;
    route: string;
    sourceRepo: string;
    releaseArtifact?: string;
    installPaths: string[];
    commands: string[];
    notes: string[];
  };
  snippetCommand: string;
  guardCommand: string;
}

export interface AgentSurfaceSummary {
  supported: boolean;
  configPaths: string[];
  notes: string[];
}

export interface ApprovalSettings {
  mode: ApprovalMode;
  durationMs: number;
}

export interface ApprovalGrantRecord {
  id: string;
  handle: string;
  actionKey: string;
  mode: ApprovalMode;
  agentScope?: ApprovalAgentScope;
  agentName?: string;
  loginSessionId: string;
  createdAt: string;
  updatedAt: string;
  expiresAt?: string;
  lastRequestId?: string;
}

export interface ApprovalPolicyRuleRecord {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  decision: ApprovalPolicyDecision;
  conditions: {
    handles?: string[];
    secretTypes?: string[];
    providers?: string[];
    minSeverity?: SecretSeverity;
    agents?: string[];
    actionKinds?: string[];
    commands?: string[];
    injectEnvs?: string[];
    workingDirs?: string[];
    sshTargets?: string[];
    sshPorts?: number[];
  };
  durationMs?: number;
  expiresAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface UsageFlowNode {
  id: string;
  kind: "agent" | "auth" | "target";
  label: string;
  detail?: string;
  count: number;
}

export interface UsageFlowLink {
  source: string;
  target: string;
  value: number;
}

export interface UsageFlowRow {
  agentId: string;
  agent: string;
  authTypeId: string;
  authType: string;
  targetTypeId: string;
  targetType: string;
  handle: string;
  credential: string;
  action: string;
  command: string;
  target: string;
  handles: string[];
  credentials: string[];
  actions: string[];
  targets: string[];
  count: number;
  lastSeen: string;
  states: Record<RequestState, number>;
}

export interface UsageFlowEntry {
  requestId: string;
  agentId: string;
  agent: string;
  authTypeId: string;
  authType: string;
  targetTypeId: string;
  targetType: string;
  credential: string;
  action: string;
  command: string;
  target: string;
  state: RequestState;
  lastSeen: string;
}

export interface UsageFlow {
  generatedAt: string;
  totalRequests: number;
  nodes: UsageFlowNode[];
  links: UsageFlowLink[];
  rows: UsageFlowRow[];
  entries: UsageFlowEntry[];
}

declare global {
  interface Window {
    SGW_CONSOLE_TOKEN?: string;
    SGW_CONSOLE_LIVE?: boolean;
  }
}
