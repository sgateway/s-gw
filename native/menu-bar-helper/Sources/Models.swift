import AppKit
import Foundation
import SwiftUI

struct SshSessionSpec: Decodable, Hashable, Sendable {
  let target: String
  let port: Int?
}

struct CommandAction: Decodable, Hashable, Sendable {
  let kind: String?
  let command: String
  let args: [String]
  let injectEnv: String
  let ssh: SshSessionSpec?
}

struct RequestRecord: Decodable, Identifiable, Hashable, Sendable {
  let id: String
  let handle: String
  let reason: String
  let recordedAgentName: String?
  let state: String
  let action: CommandAction
  let createdAt: String
  let updatedAt: String?

  enum CodingKeys: String, CodingKey {
    case id
    case handle
    case reason
    case recordedAgentName = "agentName"
    case state
    case action
    case createdAt
    case updatedAt
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

  var shortCommand: String {
    if action.kind == "ssh_session" { return "ssh" }
    return URL(fileURLWithPath: action.command).lastPathComponent
  }
}

enum ApprovalDestinationKind: Hashable, Sendable {
  case amazonEC2
  case sshHost
  case localMachine
}

struct ApprovalFlowDescriptor: Hashable, Sendable {
  let transportTitle: String
  let transportDetail: String
  let destinationTitle: String
  let destinationDetail: String
  let destinationKind: ApprovalDestinationKind

  init(request: RequestRecord) {
    let commandName = URL(fileURLWithPath: request.action.command).lastPathComponent
    let searchable = ([
      request.handle,
      request.reason,
      request.action.command,
      request.action.injectEnv,
      request.action.ssh?.target ?? ""
    ] + request.action.args).joined(separator: " ").lowercased()

    if request.action.kind == "ssh_session" {
      let host = Self.sshHost(from: request.action.ssh?.target)
      let isEC2 = searchable.contains("aws")
        || searchable.contains("ec2")
        || searchable.contains("amazonaws.com")

      transportTitle = "SSH"
      transportDetail = "Secure session"
      destinationTitle = host ?? "SSH host"
      destinationDetail = isEC2 ? "Amazon EC2" : "Remote host"
      destinationKind = isEC2 ? .amazonEC2 : .sshHost
      return
    }

    let isAwsCommand = commandName.lowercased() == "aws"
    let isEC2 = isAwsCommand && request.action.args.contains { $0.lowercased() == "ec2" }
    if isEC2 {
      transportTitle = "AWS CLI"
      transportDetail = "Local command"
      destinationTitle = Self.argument(after: "--instance-ids", in: request.action.args) ?? "Amazon EC2"
      destinationDetail = "Amazon EC2"
      destinationKind = .amazonEC2
      return
    }

    transportTitle = request.shortCommand.uppercased()
    transportDetail = "Local command"
    destinationTitle = "This Mac"
    destinationDetail = "Local machine"
    destinationKind = .localMachine
  }

  private static func sshHost(from target: String?) -> String? {
    guard let target = target?.trimmingCharacters(in: .whitespacesAndNewlines), !target.isEmpty else {
      return nil
    }

    return target.split(separator: "@").last.map(String.init)
  }

  private static func argument(after flag: String, in args: [String]) -> String? {
    guard let index = args.firstIndex(of: flag) else { return nil }
    let valueIndex = args.index(after: index)
    guard valueIndex < args.endIndex else { return nil }
    return args[valueIndex]
  }
}

struct UnlockStatus: Decodable, Hashable, Sendable {
  let activeSource: String
}

struct LaunchAgentStatus: Decodable, Hashable, Sendable {
  let loaded: Bool
}

struct LaunchAgents: Decodable, Hashable, Sendable {
  let console: LaunchAgentStatus
}

struct StatusPayload: Decodable, Hashable, Sendable {
  let storePath: String?
  let unlock: UnlockStatus
  let launchAgents: LaunchAgents?
}

struct SecretSummary: Decodable, Identifiable, Hashable, Sendable {
  let handle: String
  let name: String?
  let type: String?
  let backend: String?
  let provider: String?
  let severity: String?
  let updatedAt: String?

  var id: String { handle }

  var isHighRisk: Bool {
    let raw = severity?.lowercased()
    return raw == "high" || raw == "critical"
  }
}

struct AuditEvent: Decodable, Identifiable, Hashable, Sendable {
  let id: String
  let ts: String
  let type: String
  let handle: String?
  let requestId: String?
  let message: String
}

struct StoreSnapshot: Decodable, Sendable {
  var secrets: [SecretSummary]
  var requests: [RequestRecord]
  var audit: [AuditEvent]
}

struct OnePasswordStatus: Decodable, Sendable {
  let available: Bool
}

struct HelperState: Sendable {
  var daemonRunning = false
  var unlockSource = "none"
  var pending: [RequestRecord] = []
  var recentAudit: [AuditEvent] = []
  var credentialCount = 0
  var highRiskCount = 0
  var onePasswordAvailable = false
  var lastUpdated = Date()

  var credentialStoreReady: Bool {
    unlockSource != "none" && unlockSource != "unknown"
  }

  var isReady: Bool {
    daemonRunning && credentialStoreReady
  }
}

enum HelperRoute: String, CaseIterable, Sendable {
  case overview
  case approvals
  case credentials
  case activity
  case audit
  case settings

  static func parse(_ value: String?) -> HelperRoute? {
    guard let value else { return nil }
    return HelperRoute(rawValue: value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
  }
}

enum StatusCountMode: String, CaseIterable, Sendable {
  case pending
  case credentials
  case none

  var menuTitle: String {
    switch self {
    case .pending: return "Pending approvals"
    case .credentials: return "Stored credentials"
    case .none: return "Hide count"
    }
  }

  static func parse(_ value: String?) -> StatusCountMode? {
    guard let normalized = value?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() else {
      return nil
    }

    switch normalized {
    case "pending", "approval", "approvals", "authorization", "authorizations", "auth":
      return .pending
    case "credential", "credentials", "secret", "secrets", "handle", "handles":
      return .credentials
    case "none", "off", "hide", "hidden":
      return StatusCountMode.none
    default:
      return nil
    }
  }
}

struct ApprovalChoice: Hashable, Sendable {
  let mode: String
  let durationMs: Int?
  let agentScope: String

  static let oneTime = ApprovalChoice(mode: "per-transaction", durationMs: nil, agentScope: "same-agent")

  static func timed(minutes: Int, scope: String) -> ApprovalChoice {
    ApprovalChoice(mode: "timed-session", durationMs: minutes * 60 * 1000, agentScope: scope)
  }

  static func login(scope: String) -> ApprovalChoice {
    ApprovalChoice(mode: "login-session", durationMs: nil, agentScope: scope)
  }

  static func unlimited(scope: String) -> ApprovalChoice {
    ApprovalChoice(mode: "always", durationMs: nil, agentScope: scope)
  }

  var cliArgs: [String] {
    var args = ["--mode", mode, "--agent-scope", agentScope]
    if let durationMs {
      args += ["--duration-ms", String(durationMs)]
    }
    return args
  }
}

struct HelperMenuActions {
  let refresh: () -> Void
  let openApp: (HelperRoute) -> Void
  let openConsole: () -> Void
  let testNotification: () -> Void
  let approve: (String, ApprovalChoice) -> Void
  let deny: (String) -> Void
  let setCountMode: (StatusCountMode) -> Void
  let quit: () -> Void
}

struct DecisionOutcome: Sendable {
  let title: String
  let body: String
  let succeeded: Bool
}

struct DecisionFeedback: Identifiable, Equatable {
  let id = UUID()
  let title: String
  let message: String
  let succeeded: Bool
}

enum HelperPopoverMetrics {
  static let width: CGFloat = 400
  static let idleHeight: CGFloat = 420
  static let pendingHeight: CGFloat = 500

  static func size(for state: HelperState) -> NSSize {
    NSSize(width: width, height: state.pending.isEmpty ? idleHeight : pendingHeight)
  }
}

enum HelperTheme {
  static let teal = Color(red: 0.20, green: 0.78, blue: 0.65)
  static let green = Color(red: 0.20, green: 0.72, blue: 0.49)
  static let orange = Color(red: 0.94, green: 0.61, blue: 0.20)
  static let red = Color(red: 0.90, green: 0.27, blue: 0.25)
  static let blue = Color(red: 0.22, green: 0.60, blue: 0.92)
  static let surface = Color.primary.opacity(0.055)
  static let raised = Color.primary.opacity(0.085)
  static let hairline = Color.primary.opacity(0.11)
}

enum HelperDates {
  static func relative(_ value: String) -> String {
    guard let date = parse(value) else { return "now" }
    let seconds = max(0, Int(Date().timeIntervalSince(date)))
    if seconds < 60 { return "\(seconds)s" }
    if seconds < 3600 { return "\(seconds / 60)m" }
    if seconds < 86_400 { return "\(seconds / 3600)h" }
    return "\(seconds / 86_400)d"
  }

  static func clock(_ date: Date) -> String {
    let formatter = DateFormatter()
    formatter.timeStyle = .short
    return formatter.string(from: date)
  }

  static func parse(_ value: String?) -> Date? {
    guard let value else { return nil }
    let fractional = ISO8601DateFormatter()
    fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let date = fractional.date(from: value) {
      return date
    }
    return ISO8601DateFormatter().date(from: value)
  }
}

func helperShortHandle(_ handle: String) -> String {
  if handle.count <= 32 { return handle }
  return "\(handle.prefix(18))...\(handle.suffix(8))"
}

func helperActivityLabel(_ type: String) -> String {
  switch type {
  case "secret.added": return "Credential added"
  case "secret.matched": return "Credential matched"
  case "request.created": return "Approval requested"
  case "request.approved": return "Request approved"
  case "request.denied": return "Request denied"
  case "request.executed": return "Credential used"
  case "request.failed": return "Request failed"
  default:
    return type
      .replacingOccurrences(of: ".", with: " ")
      .capitalized
  }
}

func helperActivityColor(_ type: String) -> Color {
  if type.contains("denied") || type.contains("failed") { return HelperTheme.red }
  if type.contains("approved") || type.contains("executed") { return HelperTheme.green }
  if type.contains("request") { return HelperTheme.orange }
  return HelperTheme.teal
}
