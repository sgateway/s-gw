import type {
  AgentSummary,
  ConsoleState,
  HandleSummary,
  ProviderSummary,
  RequestRecord,
  RequestState,
  SecretSeverity,
  UsageFlow,
  UsageFlowEntry,
  UsageFlowLink,
  UsageFlowNode,
  UsageFlowRow
} from "./types";

const now = "2026-07-02T05:30:00.000Z";

const providerSummaries: ProviderSummary[] = [
  { provider: "ssh", label: "SSH", prefix: "s-gw:private-key", secrets: 10, severity: "high", lastUsed: now },
  { provider: "aws", label: "AWS", prefix: "s-gw:credential", secrets: 9, severity: "medium", lastUsed: now },
  { provider: "github", label: "GitHub", prefix: "s-gw:api-token", secrets: 8, severity: "low", lastUsed: now },
  { provider: "openai", label: "Model API", prefix: "s-gw:api-token", secrets: 7, severity: "medium", lastUsed: now },
  { provider: "database", label: "Database", prefix: "s-gw:password", secrets: 6, severity: "high", lastUsed: now },
  { provider: "mcp", label: "MCP session", prefix: "s-gw:api-token", secrets: 4, severity: "medium", lastUsed: now },
  { provider: "service-account", label: "Service account", prefix: "s-gw:credential", secrets: 3, severity: "medium", lastUsed: now },
  { provider: "docker", label: "Docker registry", prefix: "s-gw:api-token", secrets: 2, severity: "medium", lastUsed: now }
];

const usageRows = [
  usageFlowRow("Codex", "AWS access key", "AWS API", 82, "s-gw:credential:aws-prod-deploy", "AWS prod deploy pair", "aws cloudfront create-invalidation", "cloudfront"),
  usageFlowRow("Codex", "SSH private key", "SSH server", 27, "s-gw:private-key:agentsec-web", "AgentSec deploy key", "ssh agentsec-web", "agentsec-web"),
  usageFlowRow("Codex", "SSH private key", "NAS / appliance", 15, "s-gw:private-key:nas-admin", "NAS maintenance key", "ssh nas-admin", "nas-admin"),
  usageFlowRow("Codex", "AI API key", "Model API", 34, "s-gw:api-token:model-eval", "Model eval token", "npm run eval", "eval runner"),
  usageFlowRow("Codex", "GitHub token", "GitHub repository", 24, "s-gw:api-token:release-bot", "Release bot token", "gh release create", "sgateway/s-gw"),
  usageFlowRow("Codex", "MCP session token", "Local command", 22, "s-gw:api-token:mcp-tools", "MCP tool token", "codex mcp list", "local console"),
  usageFlowRow("Claude Code", "AWS access key", "AWS API", 38, "s-gw:credential:aws-dev", "AWS dev pair", "aws sts get-caller-identity", "sts"),
  usageFlowRow("Claude Code", "SSH private key", "SSH server", 58, "s-gw:private-key:nas-admin", "NAS maintenance key", "ssh nas-admin", "nas-admin"),
  usageFlowRow("Claude Code", "Database password", "Database", 30, "s-gw:password:staging-pg", "Staging Postgres admin", "psql migration smoke", "staging-postgres"),
  usageFlowRow("Claude Code", "Service account key", "Local command", 12, "s-gw:credential:launchd-helper", "LaunchAgent helper", "launchctl kickstart", "local profile"),
  usageFlowRow("Claude Code", "Service account key", "NAS / appliance", 8, "s-gw:credential:qnap-admin", "QNAP maintenance identity", "qnap deploy", "qnap"),
  usageFlowRow("Cursor", "GitHub token", "GitHub repository", 54, "s-gw:api-token:repo-read", "Repo read token", "gh repo view", "private repos"),
  usageFlowRow("Cursor", "AI API key", "Model API", 32, "s-gw:api-token:openai-eval", "OpenAI eval key", "node eval-runner", "model endpoint"),
  usageFlowRow("Cursor", "SSH private key", "SSH server", 16, "s-gw:private-key:xdr-asset", "XDR asset key", "ssh frontend", "frontend host"),
  usageFlowRow("Cursor", "MCP session token", "Web API", 10, "s-gw:api-token:browser-mcp", "Browser MCP session", "node smoke", "browser endpoint"),
  usageFlowRow("OpenCode", "AWS access key", "AWS API", 30, "s-gw:credential:aws-ci", "AWS CI pair", "aws s3 sync", "s3"),
  usageFlowRow("OpenCode", "Database password", "Database", 25, "s-gw:password:local-admin", "Local admin password", "psql local check", "local-postgres"),
  usageFlowRow("OpenCode", "Docker registry token", "Container runtime", 17, "s-gw:api-token:registry-publish", "Registry publish token", "docker push", "registry"),
  usageFlowRow("OpenCode", "GitHub token", "GitHub repository", 12, "s-gw:api-token:repo-write", "Repo write token", "gh pr checks", "sgateway/s-gw"),
  usageFlowRow("Gemini CLI", "AI API key", "Model API", 16, "s-gw:api-token:gemini-eval", "Model comparison token", "npm run bench", "model endpoint"),
  usageFlowRow("Gemini CLI", "Service account key", "Local command", 8, "s-gw:credential:lab-runner", "Lab runner identity", "python3 scripts/check_repo.py", "local repo"),
  usageFlowRow("Gemini CLI", "Service account key", "Container runtime", 5, "s-gw:credential:lab-runner", "Lab runner identity", "docker compose ps", "compose"),
  usageFlowRow("Gemini CLI", "Database password", "Database", 7, "s-gw:password:analytics-readonly", "Analytics read-only password", "psql usage rollup", "analytics"),
  usageFlowRow("Gemini CLI", "MCP session token", "Web API", 5, "s-gw:api-token:browser-mcp", "Browser MCP session", "browser fetch", "local endpoint"),
  usageFlowRow("Gemini CLI", "MCP session token", "Local command", 2, "s-gw:api-token:mcp-tools", "MCP tool token", "agent inspect", "local console"),
  usageFlowRow("Gemini CLI", "GitHub token", "GitHub repository", 5, "s-gw:api-token:repo-read", "Repo read token", "gh issue list", "private repos"),
  usageFlowRow("Windsurf", "SSH private key", "SSH server", 11, "s-gw:private-key:preview-box", "Preview box key", "ssh preview", "preview host"),
  usageFlowRow("Windsurf", "SSH private key", "NAS / appliance", 7, "s-gw:private-key:nas-admin", "NAS maintenance key", "ssh nas-admin", "nas-admin"),
  usageFlowRow("Windsurf", "Docker registry token", "Container runtime", 5, "s-gw:api-token:registry-publish", "Registry publish token", "docker pull", "registry"),
  usageFlowRow("Windsurf", "Docker registry token", "Local command", 5, "s-gw:api-token:registry-read", "Registry read token", "docker login", "local shell"),
  usageFlowRow("Windsurf", "GitHub token", "GitHub repository", 8, "s-gw:api-token:repo-read", "Repo read token", "gh repo clone", "private repos")
];

const demoUsageFlow = buildUsageFlow(usageRows);
const demoHandles = buildDemoHandles();
const demoRequests = buildDemoRequests();
const demoAgents = [
  sampleAgent("codex", "Codex", "toml", "~/.codex/config.toml"),
  sampleAgent("claudecode", "Claude Code", "json", "./.mcp.json"),
  sampleAgent("cursor", "Cursor", "json", "./.cursor/mcp.json"),
  sampleAgent("opencode", "OpenCode", "json", "./opencode.json"),
  sampleAgent("geminicli", "Gemini CLI", "json", "~/.gemini/settings.json"),
  sampleAgent("windsurf", "Windsurf", "json", "~/.codeium/windsurf/mcp_config.json"),
  sampleAgent("github-copilot", "GitHub Copilot CLI", "json", "~/.config/github-copilot/mcp.json"),
  sampleAgent("vscode", "VS Code / Copilot Agent Mode", "json", ".vscode/mcp.json"),
  sampleAgent("openclaw", "OpenClaw", "json", "~/.openclaw/openclaw.json"),
  sampleAgent("zeptoclaw", "ZeptoClaw", "json", "~/.zeptoclaw/config.json"),
  sampleAgent("hermes", "Hermes Agent", "json", "~/.hermes/config.json"),
  sampleAgent("openhands", "OpenHands", "json", "~/.openhands/mcp.json"),
  sampleAgent("antigravity", "Antigravity", "json", "~/.antigravity/mcp.json"),
  sampleAgent("omnigent", "OmniGent", "manual", "~/.omnigent/policy.json", "manual")
];

export const sampleState: ConsoleState = {
  version: "0.1.0",
  update: {
    checked: true,
    currentVersion: "0.1.0",
    latestVersion: "0.1.0",
    available: false,
    installerReady: true,
    releaseUrl: "https://github.com/sgateway/s-gw/releases/tag/v0.1.0",
    prerelease: true,
    publishedAt: null,
    checkedAt: null
  },
  ready: true,
  readiness: { ok: true, summary: "Ready", blockers: [] },
  status: {
    daemonRunning: true,
    storePath: "~/.s-gw/store.json",
    unlock: {
      activeSource: "keychain",
      keychain: {
        supported: true,
        service: "com.s-gw.sgw.secret",
        account: "local",
        provider: "macOS Keychain",
        helperPath: "dist/native/darwin-arm64/s-gw-keychain-helper",
        configured: true
      }
    }
  },
  metrics: {
    localSecrets: providerSummaries.reduce((total, item) => total + item.secrets, 0),
    pendingApprovals: demoRequests.filter((request) => request.state === "pending").length,
    activeAgents: demoAgents.length,
    highRiskFindings: demoHandles.filter((handle) => handle.severity === "high" || handle.severity === "critical").length
  },
  handles: demoHandles,
  approvalSettings: { mode: "timed-session", durationMs: 60 * 60 * 1000 },
  approvalGrants: [],
  approvalPolicyRules: [
    policyRule("policy_prod_aws_readonly", "Production AWS read only", "ask", ["codex", "claude code"], ["aws"], ["env_command"], 10),
    policyRule("policy_known_ssh_hosts", "Known SSH hosts", "ask", ["codex", "cursor", "windsurf"], ["ssh"], ["ssh_session"], 20),
    policyRule("policy_release_checks", "Release checks", "allow", ["codex"], ["github"], ["env_command"], 30, 60 * 60 * 1000),
    policyRule("policy_database_admin", "Database admin commands", "ask", ["claude code", "opencode"], ["database"], ["env_command"], 40),
    policyRule("policy_no_unknown_registry", "Unknown registry publish", "deny", ["opencode", "windsurf"], ["docker"], ["env_command"], 50),
    policyRule("policy_model_evaluations", "Model evaluation jobs", "allow", ["codex", "cursor"], ["openai"], ["env_command"], 60),
    policyRule("policy_repo_read", "Repository read access", "allow", ["cursor", "gemini cli"], ["github"], ["env_command"], 70),
    policyRule("policy_local_lab", "Local lab runner", "allow", ["gemini cli"], ["service-account"], ["env_command"], 80),
    policyRule("policy_mcp_tools", "Local MCP tools", "allow", ["codex"], ["mcp"], ["env_command"], 90),
    policyRule("policy_ci_sync", "CI artifact sync", "allow", ["opencode"], ["aws"], ["env_command"], 100),
    policyRule("policy_registry_read", "Registry read access", "allow", ["windsurf"], ["docker"], ["env_command"], 110),
    policyRule("policy_analytics_read", "Analytics read only", "allow", ["gemini cli"], ["database"], ["env_command"], 120),
    policyRule("policy_preview_ssh", "Preview host SSH", "ask", ["windsurf", "cursor"], ["ssh"], ["ssh_session"], 130),
    policyRule("policy_mcp_web", "Browser MCP sessions", "ask", ["cursor", "gemini cli"], ["mcp"], ["env_command"], 140),
    policyRule("policy_block_prod_db", "Production database changes", "deny", ["claude code", "opencode"], ["database"], ["env_command"], 150),
    policyRule("policy_block_unknown_ssh", "Unknown SSH targets", "deny", ["codex", "cursor", "windsurf"], ["ssh"], ["ssh_session"], 160),
    policyRule("policy_release_publish", "Release publishing", "allow", ["codex"], ["github"], ["env_command"], 170)
  ],
  usageFlow: demoUsageFlow,
  credentials: providerSummaries,
  requests: demoRequests,
  pendingRequests: demoRequests.filter((request) => request.state === "pending"),
  audit: buildDemoAudit(demoRequests),
  agents: demoAgents
};

function usageFlowRow(
  agent: string,
  authType: string,
  targetType: string,
  count: number,
  handle: string,
  credential: string,
  action: string,
  target: string
): UsageFlowRow {
  const command = action.split(" ")[0] || "command";

  return {
    agentId: `agent:${agent}`,
    agent,
    authTypeId: `auth:${authType}`,
    authType,
    targetTypeId: `target:${targetType}`,
    targetType,
    handle,
    credential,
    action,
    command,
    target,
    handles: [handle],
    credentials: [credential],
    actions: [action],
    targets: [target],
    count,
    lastSeen: now,
    states: {
      pending: Math.max(0, Math.round(count * 0.04)),
      approved: Math.max(0, Math.round(count * 0.08)),
      executing: 0,
      denied: Math.max(0, Math.round(count * 0.02)),
      executed: Math.max(1, Math.round(count * 0.86)),
      failed: 0
    }
  };
}

function buildUsageFlow(rows: UsageFlowRow[]): UsageFlow {
  const nodes = new Map<string, UsageFlowNode>();
  const links = new Map<string, UsageFlowLink>();
  const entries: UsageFlowEntry[] = [];

  rows.forEach((row, index) => {
    bumpNode(nodes, row.agentId, "agent", row.agent, "Requesting agent", row.count);
    bumpNode(nodes, row.authTypeId, "auth", row.authType, detailForAuth(row.authType), row.count);
    bumpNode(nodes, row.targetTypeId, "target", row.targetType, detailForTarget(row.targetType), row.count);
    bumpLink(links, row.agentId, row.authTypeId, row.count);
    bumpLink(links, row.authTypeId, row.targetTypeId, row.count);

    entries.push({
      requestId: `req_demo_flow_${String(index + 1).padStart(2, "0")}`,
      agentId: row.agentId,
      agent: row.agent,
      authTypeId: row.authTypeId,
      authType: row.authType,
      targetTypeId: row.targetTypeId,
      targetType: row.targetType,
      credential: row.credential,
      action: row.action,
      command: row.command,
      target: row.target,
      state: row.states.pending > 0 ? "pending" : row.states.denied > 0 ? "denied" : "executed",
      lastSeen: now
    });
  });

  return {
    generatedAt: now,
    totalRequests: rows.reduce((total, row) => total + row.count, 0),
    nodes: [...nodes.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label)),
    links: [...links.values()].sort((a, b) => b.value - a.value || a.source.localeCompare(b.source)),
    rows: [...rows].sort((a, b) => b.count - a.count || a.agent.localeCompare(b.agent)),
    entries
  };
}

function bumpNode(
  nodes: Map<string, UsageFlowNode>,
  id: string,
  kind: UsageFlowNode["kind"],
  label: string,
  detail: string,
  count: number
) {
  const existing = nodes.get(id);
  if (existing) {
    existing.count += count;
    return;
  }
  nodes.set(id, { id, kind, label, detail, count });
}

function bumpLink(links: Map<string, UsageFlowLink>, source: string, target: string, value: number) {
  const id = `${source}->${target}`;
  const existing = links.get(id);
  if (existing) {
    existing.value += value;
    return;
  }
  links.set(id, { source, target, value });
}

function detailForAuth(authType: string): string {
  const details: Record<string, string> = {
    "AWS access key": "Keychain-backed access pair",
    "SSH private key": "ControlMaster session key",
    "GitHub token": "repo and release access",
    "AI API key": "model and eval jobs",
    "Database password": "staging admin handle",
    "MCP session token": "short-lived tool session",
    "Service account key": "automation identity",
    "Docker registry token": "image publish token"
  };
  return details[authType] || "Credential handle";
}

function detailForTarget(targetType: string): string {
  const details: Record<string, string> = {
    "AWS API": "sts, ecs, s3, cloudfront",
    "SSH server": "deploy and admin hosts",
    "GitHub repository": "private repo automation",
    "Model API": "test and eval runs",
    "Database": "migrations and smoke checks",
    "Local command": "bounded shell actions",
    "NAS / appliance": "local infrastructure admin",
    "Container runtime": "build and publish jobs",
    "Web API": "remote tool endpoints"
  };
  return details[targetType] || "Execution target";
}

function buildDemoHandles(): HandleSummary[] {
  const seeds: HandleSummary[] = [
    handle("s-gw:credential:aws-prod-deploy", "AWS prod deploy pair", "access-key", "aws", "medium", "AWS_ACCESS_KEY_ID", ["aws"]),
    handle("s-gw:private-key:agentsec-web", "AgentSec deploy key", "private-key", "ssh", "high", "SGW_SSH_KEY", ["s-gw:ssh-session"]),
    handle("s-gw:private-key:nas-admin", "NAS maintenance key", "private-key", "ssh", "high", "SGW_SSH_KEY", ["s-gw:ssh-session"]),
    handle("s-gw:api-token:model-eval", "Model eval token", "api-token", "openai", "medium", "MODEL_API_KEY", ["npm"]),
    handle("s-gw:api-token:release-bot", "Release bot token", "api-token", "github", "low", "GITHUB_TOKEN", ["gh"]),
    handle("s-gw:api-token:mcp-tools", "MCP tool token", "api-token", "mcp", "medium", "MCP_SESSION_TOKEN", ["codex"]),
    handle("s-gw:credential:aws-dev", "AWS dev pair", "access-key", "aws", "medium", "AWS_ACCESS_KEY_ID", ["aws"]),
    handle("s-gw:password:staging-pg", "Staging database admin", "password", "database", "high", "PGPASSWORD", ["psql"]),
    handle("s-gw:credential:launchd-helper", "LaunchAgent helper", "credential", "service-account", "medium", "LAUNCHD_IDENTITY", ["launchctl"]),
    handle("s-gw:credential:qnap-admin", "QNAP maintenance identity", "credential", "service-account", "medium", "QNAP_TOKEN", ["qnap"]),
    handle("s-gw:api-token:repo-read", "Repo read token", "api-token", "github", "low", "GITHUB_TOKEN", ["gh"]),
    handle("s-gw:api-token:openai-eval", "OpenAI eval key", "api-token", "openai", "medium", "OPENAI_API_KEY", ["node"]),
    handle("s-gw:private-key:xdr-asset", "XDR asset key", "private-key", "ssh", "high", "SGW_SSH_KEY", ["s-gw:ssh-session"]),
    handle("s-gw:api-token:browser-mcp", "Browser MCP session", "api-token", "mcp", "medium", "BROWSER_MCP_TOKEN", ["node"]),
    handle("s-gw:credential:aws-ci", "AWS CI pair", "access-key", "aws", "medium", "AWS_ACCESS_KEY_ID", ["aws"]),
    handle("s-gw:password:local-admin", "Local admin password", "password", "database", "high", "PGPASSWORD", ["psql"]),
    handle("s-gw:api-token:registry-publish", "Registry publish token", "api-token", "docker", "medium", "DOCKER_TOKEN", ["docker"]),
    handle("s-gw:api-token:repo-write", "Repo write token", "api-token", "github", "medium", "GITHUB_TOKEN", ["gh"]),
    handle("s-gw:api-token:gemini-eval", "Model comparison token", "api-token", "openai", "medium", "MODEL_API_KEY", ["npm"]),
    handle("s-gw:credential:lab-runner", "Lab runner identity", "credential", "service-account", "medium", "LAB_RUNNER_ID", ["python3"]),
    handle("s-gw:password:analytics-readonly", "Analytics read-only password", "password", "database", "medium", "PGPASSWORD", ["psql"]),
    handle("s-gw:private-key:preview-box", "Preview box key", "private-key", "ssh", "high", "SGW_SSH_KEY", ["s-gw:ssh-session"]),
    handle("s-gw:api-token:registry-read", "Registry read token", "api-token", "docker", "medium", "DOCKER_TOKEN", ["docker"])
  ];

  const handles = [...seeds];
  for (const provider of providerSummaries) {
    const current = handles.filter((item) => item.provider === provider.provider).length;
    for (let i = current; i < provider.secrets; i++) {
      handles.push(handle(
        `${provider.prefix}:${provider.provider}-demo-${i + 1}`,
        `${provider.label} demo handle ${i + 1}`,
        typeForProvider(provider.provider),
        provider.provider,
        provider.severity,
        envForProvider(provider.provider),
        commandsForProvider(provider.provider)
      ));
    }
  }

  return handles.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt) || a.name.localeCompare(b.name));
}

function handle(
  id: string,
  name: string,
  type: string,
  provider: string,
  severity: SecretSeverity,
  injectEnv: string,
  allowedCommands: string[]
): HandleSummary {
  return {
    handle: id,
    name,
    type,
    backend: "keychain",
    provider,
    severity,
    confidence: 0.94,
    createdAt: now,
    updatedAt: now,
    source: "demo-data",
    fingerprint: id.split(":").slice(-1)[0],
    policy: { injectEnv, allowedCommands, maxOutputBytes: 16384 }
  };
}

function typeForProvider(provider: string): string {
  if (provider === "ssh") return "private-key";
  if (provider === "database") return "password";
  if (provider === "aws" || provider === "service-account") return "credential";
  return "api-token";
}

function envForProvider(provider: string): string {
  const envs: Record<string, string> = {
    aws: "AWS_ACCESS_KEY_ID",
    ssh: "SGW_SSH_KEY",
    github: "GITHUB_TOKEN",
    openai: "MODEL_API_KEY",
    database: "PGPASSWORD",
    mcp: "MCP_SESSION_TOKEN",
    "service-account": "SERVICE_ACCOUNT_TOKEN",
    docker: "DOCKER_TOKEN"
  };
  return envs[provider] || "SECRET_VALUE";
}

function commandsForProvider(provider: string): string[] {
  const commands: Record<string, string[]> = {
    aws: ["aws"],
    ssh: ["s-gw:ssh-session"],
    github: ["gh"],
    openai: ["npm", "node"],
    database: ["psql"],
    mcp: ["codex", "node"],
    "service-account": ["python3", "launchctl"],
    docker: ["docker"]
  };
  return commands[provider] || ["node"];
}

function buildDemoRequests(): RequestRecord[] {
  return [
    request("req_demo_codex_aws", "s-gw:credential:aws-prod-deploy", "Codex requests production AWS validation", "Codex", "env_command", "aws", ["sts", "get-caller-identity"], "AWS_ACCESS_KEY_ID", "approved", "AWS API"),
    request("req_demo_codex_ssh", "s-gw:private-key:agentsec-web", "Codex requests deploy host SSH", "Codex", "ssh_session", "ssh", [], "SGW_SSH_KEY", "pending", "agentsec-web", { target: "agentsec-web", port: 22 }),
    request("req_demo_claude_db", "s-gw:password:staging-pg", "Claude Code requests migration smoke test", "Claude Code", "env_command", "psql", ["--command", "select version()"], "PGPASSWORD", "executed", "staging-postgres"),
    request("req_demo_cursor_repo", "s-gw:api-token:repo-read", "Cursor requests repository metadata", "Cursor", "env_command", "gh", ["repo", "view", "s-gw"], "GITHUB_TOKEN", "executed", "GitHub repository"),
    request("req_demo_opencode_registry", "s-gw:api-token:registry-publish", "OpenCode requests registry publish", "OpenCode", "env_command", "docker", ["push", "registry.example/s-gw:preview"], "DOCKER_TOKEN", "denied", "Container runtime"),
    request("req_demo_gemini_model", "s-gw:api-token:gemini-eval", "Gemini CLI requests model comparison run", "Gemini CLI", "env_command", "npm", ["run", "bench"], "MODEL_API_KEY", "pending", "Model API"),
    request("req_demo_windsurf_preview", "s-gw:private-key:preview-box", "Windsurf requests preview host SSH", "Windsurf", "ssh_session", "ssh", [], "SGW_SSH_KEY", "pending", "preview host", { target: "preview-host", port: 22 })
  ];
}

function request(
  id: string,
  handleId: string,
  reason: string,
  agentName: string,
  kind: string,
  command: string,
  args: string[],
  injectEnv: string,
  state: RequestState,
  target: string,
  ssh?: { target: string; port: number }
): RequestRecord {
  return {
    id,
    handle: handleId,
    reason,
    agentName,
    action: {
      kind,
      command,
      args,
      injectEnv,
      workingDir: "/workspace/s-gw",
      timeoutMs: 30000,
      ssh
    },
    state,
    createdAt: now,
    updatedAt: now,
    approvedAt: state === "approved" || state === "executed" ? now : undefined,
    deniedAt: state === "denied" ? now : undefined,
    executedAt: state === "executed" ? now : undefined,
    error: state === "denied" ? `${target} blocked by policy` : undefined
  };
}

function buildDemoAudit(requests: RequestRecord[]) {
  return [
    { ts: now, type: "request.pending", handle: "s-gw:private-key:agentsec-web", requestId: "req_demo_codex_ssh", message: "Approval requested by Codex" },
    { ts: now, type: "request.executed", handle: "s-gw:password:staging-pg", requestId: "req_demo_claude_db", message: "Database smoke test executed locally" },
    { ts: now, type: "request.denied", handle: "s-gw:api-token:registry-publish", requestId: "req_demo_opencode_registry", message: "Registry publish blocked by policy" },
    { ts: now, type: "request.approved", handle: "s-gw:credential:aws-prod-deploy", requestId: "req_demo_codex_aws", message: "AWS read-only request approved" },
    { ts: now, type: "request.executed", handle: "s-gw:api-token:repo-read", requestId: "req_demo_cursor_repo", message: "Repository metadata command executed" },
    { ts: now, type: "request.pending", handle: "s-gw:api-token:gemini-eval", requestId: "req_demo_gemini_model", message: "Model comparison request is waiting for approval" },
    { ts: now, type: "request.pending", handle: "s-gw:private-key:preview-box", requestId: "req_demo_windsurf_preview", message: "Preview host SSH request is waiting for approval" }
  ];
}

function policyRule(
  id: string,
  name: string,
  decision: "allow" | "ask" | "deny",
  agents: string[],
  providers: string[],
  actionKinds: string[],
  priority: number,
  durationMs?: number
) {
  return {
    id,
    name,
    enabled: true,
    priority,
    decision,
    conditions: { agents, providers, actionKinds },
    durationMs,
    createdAt: now,
    updatedAt: now
  };
}

function sampleAgent(id: string, name: string, format: string, configPath: string, status = "supported"): AgentSummary {
  return {
    id,
    name,
    status,
    aliases: [],
    integration: {
      agentId: id,
      displayName: name,
      detected: true,
      eligible: status !== "manual",
      state: status === "manual" ? "manual" : "installed",
      mcp: { state: status === "manual" ? "unsupported" : "installed", owned: status !== "manual", path: configPath },
      skill: { state: status === "manual" ? "unsupported" : "installed", owned: status !== "manual" },
      plannedChanges: []
    },
    mcp: {
      supported: status !== "manual",
      format,
      writeMode: status === "manual" ? "manual" : "safe",
      configPaths: [configPath],
      notes: [],
      snippet: status === "manual" ? null : `{\n  "mcpServers": {\n    "s-gw": { "command": "s-gw-mcp" }\n  }\n}`
    },
    skills: { supported: true, configPaths: [], notes: [] },
    plugins: { supported: false, configPaths: [], notes: [] },
    hooks: { supported: true, kind: "hook", configPaths: [], events: ["PreToolUse"], notes: [] },
    limitations: [],
    codeGuard: {
      supported: true,
      route: "agent-skill",
      sourceRepo: "https://github.com/cosai-oasis/project-codeguard",
      installPaths: ["./.agents/skills/codeguard"],
      commands: [],
      notes: []
    },
    snippetCommand: `s-gw agent mcp-snippet ${id}`,
    guardCommand: `s-gw run ${id}`
  };
}
