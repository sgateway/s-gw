import type { ManagedSshRoute } from "./managed-ssh.js";

export type SecretType =
  | "api-token"
  | "ssh-key"
  | "private-key"
  | "password"
  | "credential"
  | "access-key"
  | "unknown";

export type SecretSeverity = "low" | "medium" | "high" | "critical";

export type RequestState = "pending" | "approved" | "executing" | "denied" | "executed" | "failed";
export type RequestApprovalSource = "manual" | "grant" | "policy";

export type ApprovalMode = "per-transaction" | "timed-session" | "login-session" | "always";
export type ApprovalAgentScope = "same-agent" | "any-agent";
export type ApprovalPolicyDecision = "ask" | "allow" | "deny";
export type ApprovalPolicyActionKind = "env_command" | "ssh_session" | "http_request" | "model_relay";
export type AgentIdentitySource = "managed-peer" | "configured" | "mcp-client" | "runtime" | "process" | "reason" | "manual" | "unknown";

export interface ApprovalSettings {
  mode: ApprovalMode;
  durationMs: number;
  requireVerifiedAgentForAutoApproval?: boolean;
}

export interface ApprovalGrant {
  id: string;
  handle: string;
  actionKey: string;
  mode: Exclude<ApprovalMode, "per-transaction">;
  agentScope?: ApprovalAgentScope;
  agentName?: string;
  principalId?: string;
  agentSessionId?: string;
  loginSessionId: string;
  createdAt: string;
  updatedAt: string;
  expiresAt?: string;
  lastRequestId?: string;
}

export interface ApprovalPolicyConditions {
  handles?: string[];
  envBindings?: CommandEnvBinding[];
  secretTypes?: SecretType[];
  providers?: string[];
  minSeverity?: SecretSeverity;
  agents?: string[];
  principalIds?: string[];
  actionKinds?: ApprovalPolicyActionKind[];
  commands?: string[];
  resolvedCommands?: string[];
  injectEnvs?: string[];
  workingDirs?: string[];
  sshTargets?: string[];
  sshPorts?: number[];
  actionKeys?: string[];
}

export interface ApprovalPolicyRule {
  id: string;
  name: string;
  enabled: boolean;
  priority: number;
  decision: ApprovalPolicyDecision;
  conditions: ApprovalPolicyConditions;
  expiresAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface EncryptedBox {
  alg: "aes-256-gcm";
  kdf: "scrypt";
  salt: string;
  iv: string;
  authTag: string;
  ciphertext: string;
}

export interface SecretPolicy {
  injectEnv?: string;
  allowedCommands: string[];
  allowedDestinations?: string[];
  maxOutputBytes: number;
}

export type SecretBackend = "local" | "onepassword" | "keychain";

export interface SecretValueCache {
  backend: "onepassword";
  encrypted: EncryptedBox;
  fingerprint: string;
  approvalGrantId?: string;
  approvalPolicyRuleId?: string;
  createdAt: string;
  updatedAt: string;
  expiresAt?: string;
  loginSessionId?: string;
}

export interface SecretRecord {
  handle: string;
  name: string;
  type: SecretType;
  backend?: SecretBackend;
  provider?: string;
  ruleId?: string;
  severity?: SecretSeverity;
  confidence?: number;
  createdAt: string;
  updatedAt: string;
  source?: string;
  fingerprint: string;
  encrypted: EncryptedBox;
  cache?: SecretValueCache;
  policy: SecretPolicy;
}

export interface CredentialOperation {
  id: string;
  kind: "keychain-add";
  phase: "prepared";
  record: SecretRecord;
  createdAt: string;
}

export interface HandleSummary {
  handle: string;
  name: string;
  type: SecretType;
  backend?: SecretBackend;
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

export interface SshSessionSpec {
  target: string;
  port: number;
  transfer?: SshTransferSpec;
  managedRouteId?: string;
  managed?: ManagedSshRoute;
}

export interface ManagedSshRouteRecord {
  id: string;
  name: string;
  route: ManagedSshRoute;
  createdAt: string;
  updatedAt: string;
}

export interface SshTransferSpec {
  direction: "upload";
  sourcePath: string;
  destinationPath: string;
  sha256?: string;
  approvalScope?: "content-sha256" | "path-stream" | "spooled-content-sha256";
  spoolId?: string;
  spoolExpiresAt?: string;
}

export interface CommandEnvBinding {
  handle: string;
  injectEnv: string;
}

export interface CommandAction {
  kind: ApprovalPolicyActionKind;
  command: string;
  resolvedCommand?: string;
  args: string[];
  injectEnv: string;
  env?: CommandEnvBinding[];
  workingDir?: string;
  timeoutMs: number;
  ssh?: SshSessionSpec;
  http?: HttpRequestSpec;
  model?: ModelRelaySpec;
  owned?: boolean;
}

export interface ModelRelaySpec {
  provider: "anthropic" | "openai";
  routes: string[];
  ttlMs: number;
  payloadProfile?: "strict";
  maxRequests?: number;
  maxInputBytes?: number;
  maxOutputTokens?: number;
  allowedModels?: readonly string[];
  workspaceId?: string;
  organizationId?: string;
  projectId?: string;
  anthropicVersion?: string;
  allowedBetaValues?: string[];
}

export interface HttpRequestSpec {
  url: string;
  method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE";
  headers: Record<string, string>;
  body?: string;
  auth: { kind: "bearer" } | { kind: "header"; name: string } | { kind: "basic"; username: string };
}

export interface ExecutionSummary {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  proof: string;
  durationMs: number;
  timeoutMs: number;
  timedOut: boolean;
  sanitized: boolean;
}

export interface RequestRecord {
  id: string;
  handle: string;
  reason: string;
  agentName?: string;
  agentSource?: AgentIdentitySource;
  principalId?: string;
  agentSessionId?: string;
  loginSessionId?: string;
  action: CommandAction;
  state: RequestState;
  createdAt: string;
  updatedAt: string;
  approvedAt?: string;
  approvalSource?: RequestApprovalSource;
  approvalGrantId?: string;
  approvalPolicyRuleId?: string;
  deniedAt?: string;
  executedAt?: string;
  resultSummary?: ExecutionSummary;
  error?: string;
}

export interface AuditEvent {
  id: string;
  ts: string;
  type: string;
  handle?: string;
  requestId?: string;
  uploadApprovalScope?: "content-sha256" | "path-stream" | "spooled-content-sha256";
  message: string;
}

export interface StoreFile {
  version: 1;
  secrets: SecretRecord[];
  requests: RequestRecord[];
  audit: AuditEvent[];
  approvalSettings: ApprovalSettings;
  approvalGrants: ApprovalGrant[];
  approvalPolicyRules: ApprovalPolicyRule[];
  managedSshRoutes?: ManagedSshRouteRecord[];
  credentialOps?: CredentialOperation[];
}

export interface ScanCandidate {
  type: SecretType;
  label: string;
  provider?: string;
  ruleId?: string;
  severity?: SecretSeverity;
  confidence?: number;
  value: string;
  start: number;
  end: number;
}

export interface ScanFinding {
  type: SecretType;
  label: string;
  provider?: string;
  ruleId?: string;
  severity?: SecretSeverity;
  confidence?: number;
  handle: string;
  token: string;
  start: number;
  end: number;
}

export interface ScanResult {
  tokenizedText: string;
  findings: ScanFinding[];
}
