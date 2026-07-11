import Foundation
import SwiftUI

enum PanelID: String, CaseIterable, Identifiable {
  case overview
  case usageFlow
  case approvals
  case credentials
  case audit
  case activity
  case policies
  case agents
  case setup

  var id: String { rawValue }

  var title: String {
    switch self {
    case .overview: "Overview"
    case .usageFlow: "Usage Flow"
    case .approvals: "Approvals"
    case .credentials: "Credentials"
    case .audit: "Audit"
    case .activity: "Activity"
    case .policies: "Policies"
    case .agents: "Agents"
    case .setup: "Setup"
    }
  }

  var systemImage: String {
    switch self {
    case .overview: "gauge.with.dots.needle.50percent"
    case .usageFlow: "arrow.triangle.branch"
    case .approvals: "checkmark.shield"
    case .credentials: "key"
    case .audit: "list.bullet.clipboard"
    case .activity: "terminal"
    case .policies: "slider.horizontal.3"
    case .agents: "person.2.wave.2"
    case .setup: "gearshape.2"
    }
  }
}

enum SecretSeverity: String, CaseIterable, Comparable, Decodable, Identifiable {
  case low
  case medium
  case high
  case critical

  var id: String { rawValue }

  private var rank: Int {
    switch self {
    case .low: 0
    case .medium: 1
    case .high: 2
    case .critical: 3
    }
  }

  static func < (lhs: SecretSeverity, rhs: SecretSeverity) -> Bool {
    lhs.rank < rhs.rank
  }

  static func parse(_ value: String?) -> SecretSeverity {
    guard let value else { return .low }
    return SecretSeverity(rawValue: value.lowercased()) ?? .low
  }

  var label: String { rawValue.capitalized }
}

enum RequestState: String, Decodable {
  case pending
  case approved
  case executing
  case denied
  case executed
  case failed
}

enum ApprovalMode: String, CaseIterable, Decodable, Identifiable {
  case perTransaction = "per-transaction"
  case timedSession = "timed-session"
  case loginSession = "login-session"
  case always

  var id: String { rawValue }

  var label: String {
    switch self {
    case .perTransaction: "Per transaction"
    case .timedSession: "Same action for time"
    case .loginSession: "Same action for login"
    case .always: "Same action always"
    }
  }

  var helpText: String {
    switch self {
    case .perTransaction:
      "Ask before every secret-backed action."
    case .timedSession:
      "After approval, reuse the same handle and action until the timer expires."
    case .loginSession:
      "After approval, reuse the same handle and action during this Mac login session."
    case .always:
      "After approval, reuse the same handle and action until you change approval settings or clear the store."
    }
  }
}

enum ApprovalAgentScope: String, CaseIterable, Decodable, Identifiable {
  case sameAgent = "same-agent"
  case anyAgent = "any-agent"

  var id: String { rawValue }

  var label: String {
    switch self {
    case .sameAgent: "This agent"
    case .anyAgent: "All agents"
    }
  }
}

enum ApprovalPolicyDecision: String, CaseIterable, Decodable, Identifiable {
  case ask
  case allow
  case deny

  var id: String { rawValue }

  var label: String {
    switch self {
    case .ask: "Ask"
    case .allow: "Allow"
    case .deny: "Deny"
    }
  }

  var helpText: String {
    switch self {
    case .ask:
      "Matching access opens the normal approval flow unless a reusable approval is active."
    case .allow:
      "Matching access is approved locally without interrupting you."
    case .deny:
      "Matching access is blocked before execution."
    }
  }
}

struct ApprovalSettings: Decodable, Hashable {
  var mode: ApprovalMode
  var durationMs: Int

  static let defaultValue = ApprovalSettings(mode: .perTransaction, durationMs: 15 * 60 * 1000)
}

struct ApprovalGrantRecord: Decodable, Identifiable, Hashable {
  var id: String
  var handle: String
  var actionKey: String
  var mode: ApprovalMode
  var agentScope: ApprovalAgentScope?
  var agentName: String?
  var loginSessionId: String
  var createdAt: String
  var updatedAt: String
  var expiresAt: String?
  var lastRequestId: String?

  var scopeLabel: String {
    (agentScope ?? .sameAgent).label
  }

  var agentLabel: String {
    agentName ?? "All agents"
  }
}

struct ApprovalPolicyConditions: Decodable, Hashable {
  var handles: [String]?
  var secretTypes: [String]?
  var providers: [String]?
  var minSeverity: SecretSeverity?
  var agents: [String]?
  var actionKinds: [String]?
  var commands: [String]?
  var injectEnvs: [String]?
  var workingDirs: [String]?
  var sshTargets: [String]?
  var sshPorts: [Int]?

  var summary: String {
    var parts: [String] = []
    append("Handle", handles, to: &parts)
    append("Type", secretTypes, to: &parts)
    append("Provider", providers, to: &parts)
    append("Agent", agents, to: &parts)
    append("Action", actionKinds, to: &parts)
    append("Command", commands, to: &parts)
    append("Env", injectEnvs, to: &parts)
    append("SSH host", sshTargets, to: &parts)
    if let minSeverity {
      parts.append("Severity >= \(minSeverity.label)")
    }
    if let sshPorts, !sshPorts.isEmpty {
      parts.append("SSH port \(sshPorts.map(String.init).joined(separator: ", "))")
    }
    return parts.isEmpty ? "All matching credential requests" : parts.joined(separator: " · ")
  }

  private func append(_ label: String, _ values: [String]?, to parts: inout [String]) {
    guard let values, !values.isEmpty else { return }
    let clipped = values.prefix(2).joined(separator: ", ")
    let suffix = values.count > 2 ? " +" + String(values.count - 2) : ""
    parts.append("\(label): \(clipped)\(suffix)")
  }
}

struct ApprovalPolicyRuleRecord: Decodable, Identifiable, Hashable {
  var id: String
  var name: String
  var enabled: Bool
  var priority: Int
  var decision: ApprovalPolicyDecision
  var conditions: ApprovalPolicyConditions
  var expiresAt: String?
  var createdAt: String
  var updatedAt: String
}

struct ApprovalPolicyDraft: Hashable {
  var name = "Allow Codex for selected credential"
  var enabled = true
  var priority = 100
  var decision: ApprovalPolicyDecision = .allow
  var handle = ""
  var agent = "Codex"
  var actionKind = ""
  var command = ""
  var injectEnv = ""
  var sshTarget = ""
  var sshPort = 0
  var minSeverity: SecretSeverity?
  var durationMs = 0
}

struct ApprovalChoice: Hashable {
  var mode: ApprovalMode
  var durationMs: Int?
  var agentScope: ApprovalAgentScope

  static let oneTime = ApprovalChoice(mode: .perTransaction, durationMs: nil, agentScope: .sameAgent)

  static func timed(minutes: Int, scope: ApprovalAgentScope) -> ApprovalChoice {
    ApprovalChoice(mode: .timedSession, durationMs: minutes * 60 * 1000, agentScope: scope)
  }

  static func login(scope: ApprovalAgentScope) -> ApprovalChoice {
    ApprovalChoice(mode: .loginSession, durationMs: nil, agentScope: scope)
  }

  static func unlimited(scope: ApprovalAgentScope) -> ApprovalChoice {
    ApprovalChoice(mode: .always, durationMs: nil, agentScope: scope)
  }

  var resultLabel: String {
    switch mode {
    case .perTransaction: "one time"
    case .timedSession:
      durationMs.map { "for \(Self.durationLabel($0))" } ?? "for this timed session"
    case .loginSession: "until logout"
    case .always: "unlimited"
    }
  }

  private static func durationLabel(_ ms: Int) -> String {
    let minutes = max(1, ms / 60_000)
    if minutes < 60 { return "\(minutes)m" }
    if minutes < 24 * 60 { return "\(minutes / 60)h" }
    return "\(minutes / (24 * 60))d"
  }
}

enum MenuBarState {
  case healthy
  case pending(Int)
  case offline
  case locked
}

struct PathStatus: Decodable, Hashable {
  var path: String
  var exists: Bool
}

struct LaunchAgentStatus: Decodable, Hashable {
  var label: String
  var plistPath: String
  var installed: Bool
  var loaded: Bool
}

struct LaunchAgents: Decodable, Hashable {
  var console: LaunchAgentStatus
  var menuBar: LaunchAgentStatus
}

struct UnlockStatus: Decodable, Hashable {
  var envConfigured: Bool?
  var activeSource: String
  var keychain: KeychainStatus?

  struct KeychainStatus: Decodable, Hashable {
    var supported: Bool
    var service: String
    var account: String
    var provider: String
    var helperPath: String
    var configured: Bool
  }
}

struct Readiness: Decodable, Hashable {
  var ok: Bool
  var summary: String
  var blockers: [String]
}

struct StatusPayload: Decodable, Hashable {
  var packageRoot: String
  // `ready`/`readiness` were added to the CLI health payload later; keep them optional so a
  // freshly built app still decodes status from an older `s-gw` on PATH instead of erroring.
  var ready: Bool?
  var readiness: Readiness?
  var cliPath: PathStatus
  var mcpPath: PathStatus
  var keychainHelperPath: PathStatus
  var menuBarAppPath: PathStatus
  var menuBarBinaryPath: PathStatus
  var storePath: String
  var consoleUrl: String
  var unlock: UnlockStatus
  var launchAgents: LaunchAgents
}

struct SecretPolicy: Decodable, Hashable {
  var injectEnv: String?
  var allowedCommands: [String]
  var maxOutputBytes: Int
}

struct HandleSummary: Decodable, Identifiable, Hashable {
  var handle: String
  var name: String
  var type: String
  var backend: String?
  var provider: String?
  var ruleId: String?
  var severity: String?
  var confidence: Double?
  var createdAt: String
  var updatedAt: String
  var source: String?
  var fingerprint: String
  var policy: SecretPolicy

  var id: String { handle }
  var severityValue: SecretSeverity { SecretSeverity.parse(severity) }
  var providerLabel: String { (provider?.isEmpty == false ? provider! : type).uppercased() }
}

struct SshSessionSpec: Decodable, Hashable {
  var target: String
  var port: Int?
}

struct CommandAction: Decodable, Hashable {
  var kind: String
  var command: String
  var args: [String]
  var injectEnv: String
  var workingDir: String?
  var timeoutMs: Int
  var ssh: SshSessionSpec?
}

struct RequestRecord: Decodable, Identifiable, Hashable {
  var id: String
  var handle: String
  var reason: String
  var recordedAgentName: String?
  var action: CommandAction
  var state: RequestState
  var createdAt: String
  var updatedAt: String
  var approvedAt: String?
  var deniedAt: String?
  var executedAt: String?
  var error: String?

  enum CodingKeys: String, CodingKey {
    case id
    case handle
    case reason
    case recordedAgentName = "agentName"
    case action
    case state
    case createdAt
    case updatedAt
    case approvedAt
    case deniedAt
    case executedAt
    case error
  }

  var agentName: String {
    if let recordedAgentName, !recordedAgentName.isEmpty {
      return recordedAgentName
    }
    let lower = reason.lowercased()
    if lower.contains("codex") { return "Codex" }
    if lower.contains("claude") { return "Claude" }
    if lower.contains("cursor") { return "Cursor" }
    if lower.contains("console") { return "Console" }
    if lower.contains("mcp") { return "MCP" }
    return "Agent"
  }

  var commandName: String {
    if action.kind == "ssh_session" {
      return "ssh"
    }
    let normalized = action.command.replacingOccurrences(of: "\\", with: "/")
    return normalized.split(separator: "/").last.map(String.init) ?? action.command
  }

  var actionTarget: String {
    if action.kind == "ssh_session", let target = action.ssh?.target, !target.isEmpty {
      if let port = action.ssh?.port, port != 22 {
        return "\(target):\(port)"
      }
      return target
    }
    if let workingDir = action.workingDir, !workingDir.isEmpty {
      return workingDir
    }
    if action.args.first == "-e" {
      return "\(commandName) inline script"
    }
    for arg in action.args where !arg.hasPrefix("-") {
      return arg
    }
    return action.injectEnv.isEmpty ? "local command" : action.injectEnv
  }

  var actionLabel: String {
    let target = actionTarget
    if target.isEmpty || target == "local command" {
      return commandName
    }
    return "\(commandName) -> \(target)"
  }
}

struct UsageFlowRow: Identifiable, Hashable {
  var agent: String
  var handle: String
  var credential: String
  var action: String
  var command: String
  var target: String
  var count: Int
  var lastSeen: String
  var pending: Int
  var approved: Int
  var executing: Int
  var executed: Int
  var denied: Int
  var failed: Int

  var id: String { "\(agent)\n\(handle)\n\(action)" }

  var stateSummary: String {
    var parts: [String] = []
    if pending > 0 { parts.append("pending \(pending)") }
    if approved > 0 { parts.append("approved \(approved)") }
    if executing > 0 { parts.append("executing \(executing)") }
    if executed > 0 { parts.append("executed \(executed)") }
    if denied > 0 { parts.append("denied \(denied)") }
    if failed > 0 { parts.append("failed \(failed)") }
    return parts.joined(separator: " / ")
  }

  mutating func record(_ request: RequestRecord) {
    count += 1
    if request.updatedAt > lastSeen {
      lastSeen = request.updatedAt
    }
    switch request.state {
    case .pending: pending += 1
    case .approved: approved += 1
    case .executing: executing += 1
    case .executed: executed += 1
    case .denied: denied += 1
    case .failed: failed += 1
    }
  }
}

func requestSortKey(_ request: RequestRecord) -> String {
  request.updatedAt.isEmpty ? request.createdAt : request.updatedAt
}

struct AuditEvent: Decodable, Identifiable, Hashable {
  var id: String
  var ts: String
  var type: String
  var handle: String?
  var requestId: String?
  var message: String
}

struct StoreSnapshot: Decodable {
  var audit: [AuditEvent]
}

struct AgentProfile: Decodable, Identifiable, Hashable {
  var id: String
  var displayName: String
  var aliases: [String]?
  var defenseClawConnector: String?
  var mcpStatus: String?
  var mcpConfigPaths: [String]?
  var integration: AgentIntegrationStatus?

  var name: String { displayName }
  var status: String? { mcpStatus }
  var configPath: String? { mcpConfigPaths?.first }
  var connectionState: String { integration?.state ?? (mcpStatus == "supported" ? "available" : "manual") }
  var mcpConnected: Bool { integration?.mcp.state == "installed" || integration?.mcp.state == "existing" }
  var canInstall: Bool {
    integration?.detected == true && integration?.eligible == true && connectionState != "installed" && connectionState != "conflict"
  }
  var hasOwnedIntegration: Bool { integration?.mcp.owned == true || integration?.skill.owned == true }
}

struct AgentIntegrationStatus: Decodable, Hashable {
  var detected: Bool
  var eligible: Bool
  var state: String
  var mcp: AgentIntegrationResource
  var skill: AgentIntegrationResource
  var reason: String?
}

struct AgentIntegrationResource: Decodable, Hashable {
  var state: String
  var path: String?
  var owned: Bool
  var message: String?
}

struct NewSecretDraft {
  var name = ""
  var type = "api-token"
  var value = ""
  var injectEnv = ""
  var allowedCommand = ""
}

struct CLIResult: Sendable {
  var exitCode: Int32
  var output: String
  var succeeded: Bool { exitCode == 0 }
}
