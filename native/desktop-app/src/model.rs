use serde::Deserialize;

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StatusSnapshot {
    pub version: Option<String>,
    pub instance_key: Option<String>,
    pub ready: Option<bool>,
    pub readiness: Readiness,
    pub unlock: UnlockStatus,
    pub console_url: Option<String>,
    pub launch_agents: LaunchAgents,
    pub systemd_service: Option<SystemdService>,
}

impl StatusSnapshot {
    pub fn unlock_active(&self) -> bool {
        !matches!(self.unlock.active_source.as_str(), "" | "none" | "unknown")
    }

    pub fn is_ready(&self) -> bool {
        self.ready.unwrap_or_else(|| self.unlock_active())
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Readiness {
    pub summary: String,
    pub blockers: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UnlockStatus {
    pub active_source: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct LaunchAgents {
    pub console: LaunchAgentStatus,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct LaunchAgentStatus {
    pub loaded: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SystemdService {
    pub active: bool,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct HandleSummary {
    pub handle: String,
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub backend: Option<String>,
    pub provider: Option<String>,
    pub severity: Option<String>,
    pub updated_at: String,
    pub policy: SecretPolicy,
}

impl HandleSummary {
    pub fn provider_label(&self) -> String {
        self.provider
            .as_deref()
            .filter(|value| !value.is_empty())
            .unwrap_or(&self.kind)
            .to_ascii_uppercase()
    }

    pub fn severity_label(&self) -> &str {
        self.severity.as_deref().unwrap_or("low")
    }

    pub fn high_risk(&self) -> bool {
        matches!(self.severity_label(), "high" | "critical")
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SecretPolicy {
    pub inject_env: Option<String>,
    pub allowed_commands: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RequestRecord {
    pub id: String,
    pub handle: String,
    pub reason: String,
    pub agent_name: Option<String>,
    pub action: CommandAction,
    pub state: String,
    pub created_at: String,
    pub updated_at: String,
    pub error: Option<String>,
}

impl RequestRecord {
    pub fn agent_label(&self) -> &str {
        if let Some(name) = self.agent_name.as_deref().filter(|value| !value.is_empty()) {
            return name;
        }
        let lower = self.reason.to_ascii_lowercase();
        if lower.contains("codex") {
            "Codex"
        } else if lower.contains("claude") {
            "Claude"
        } else if lower.contains("cursor") {
            "Cursor"
        } else if lower.contains("console") {
            "Console"
        } else {
            "Agent"
        }
    }

    pub fn action_label(&self) -> String {
        if self.action.kind == "ssh_session" {
            let host = self
                .action
                .ssh
                .as_ref()
                .map(|value| value.target.as_str())
                .unwrap_or("SSH target");
            return format!("ssh -> {host}");
        }

        let command = self
            .action
            .command
            .replace('\\', "/")
            .rsplit('/')
            .next()
            .unwrap_or("command")
            .to_string();
        let target = self.action.working_dir.as_deref().or_else(|| {
            self.action
                .args
                .iter()
                .find(|value| !value.starts_with('-'))
                .map(String::as_str)
        });
        target
            .filter(|value| !value.is_empty())
            .map(|value| format!("{command} -> {value}"))
            .unwrap_or(command)
    }

    pub fn sort_key(&self) -> &str {
        if self.updated_at.is_empty() {
            &self.created_at
        } else {
            &self.updated_at
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CommandAction {
    pub kind: String,
    pub command: String,
    pub args: Vec<String>,
    pub inject_env: String,
    pub working_dir: Option<String>,
    pub ssh: Option<SshSession>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct SshSession {
    pub target: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PolicyRule {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub priority: i64,
    pub decision: String,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct AgentProfile {
    pub id: String,
    pub display_name: String,
    pub mcp_status: Option<String>,
    pub integration: Option<AgentIntegration>,
}

impl AgentProfile {
    pub fn status_label(&self) -> &str {
        self.integration
            .as_ref()
            .map(|value| value.state.as_str())
            .or(self.mcp_status.as_deref())
            .unwrap_or("manual")
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct AgentIntegration {
    pub state: String,
}

#[derive(Clone, Debug, Default)]
pub struct DesktopSnapshot {
    pub status: StatusSnapshot,
    pub handles: Vec<HandleSummary>,
    pub requests: Vec<RequestRecord>,
    pub policies: Vec<PolicyRule>,
    pub agents: Vec<AgentProfile>,
    pub daemon_running: bool,
}

impl DesktopSnapshot {
    pub fn pending_requests(&self) -> impl Iterator<Item = &RequestRecord> {
        self.requests
            .iter()
            .filter(|request| request.state == "pending")
    }

    pub fn pending_count(&self) -> usize {
        self.pending_requests().count()
    }

    pub fn high_risk_count(&self) -> usize {
        self.handles
            .iter()
            .filter(|handle| handle.high_risk())
            .count()
    }
}
