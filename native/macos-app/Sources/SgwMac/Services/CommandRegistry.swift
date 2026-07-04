import Foundation

struct SgwCommandDefinition: Identifiable, Hashable {
  var id: String
  var title: String
  var category: String
  var summary: String
  var arguments: [String]
  var needsReview: Bool = false
  var sideEffects: [String] = []
  var suggestedNextAction: String?

  var commandLine: String {
    (["s-gw"] + arguments).map(CommandArgumentParser.quote).joined(separator: " ")
  }
}

enum CommandRegistry {
  static let commands: [SgwCommandDefinition] = [
    SgwCommandDefinition(
      id: "status",
      title: "Check Runtime Status",
      category: "Health",
      summary: "Refresh local readiness, launch agents, unlock source, and console URL.",
      arguments: ["status"],
      suggestedNextAction: "If readiness is blocked, run setup from the Setup screen."
    ),
    SgwCommandDefinition(
      id: "onepassword-status",
      title: "Check 1Password",
      category: "Integrations",
      summary: "Verify the local 1Password CLI is available without reading any secret.",
      arguments: ["onepassword", "status"]
    ),
    SgwCommandDefinition(
      id: "onepassword-import-dry-run",
      title: "Preview 1Password Import",
      category: "Integrations",
      summary: "Count importable Dev-vault items and companion fields without storing handles.",
      arguments: ["onepassword", "import", "--vault", "Dev", "--dry-run", "--include-companions"]
    ),
    SgwCommandDefinition(
      id: "guard-status",
      title: "Check Guard Mode",
      category: "Protection",
      summary: "Show available guarded-agent launch profiles.",
      arguments: ["guard", "status"]
    ),
    SgwCommandDefinition(
      id: "agent-list",
      title: "List Agent Profiles",
      category: "Agents",
      summary: "Show supported and profiled coding-agent integrations.",
      arguments: ["agent", "list"]
    ),
    SgwCommandDefinition(
      id: "active-requests",
      title: "Show Active Requests",
      category: "Approvals",
      summary: "List pending, approved, and executing local authorization requests.",
      arguments: ["requests", "--active", "--all"]
    ),
    SgwCommandDefinition(
      id: "request-cleanup",
      title: "Clean Up Old Requests",
      category: "Approvals",
      summary: "Remove stale terminal requests and deduplicate old pending work.",
      arguments: ["requests", "cleanup"],
      needsReview: true,
      sideEffects: ["May mark stale requests as cleaned or superseded."],
      suggestedNextAction: "Refresh Approvals after cleanup."
    ),
    SgwCommandDefinition(
      id: "setup",
      title: "Run Local Setup",
      category: "Setup",
      summary: "Configure local Keychain unlock, launch agents, and app integration.",
      arguments: ["setup", "--no-open-app"],
      needsReview: true,
      sideEffects: ["May install or update launch agents.", "May prompt for local Keychain setup."]
    ),
    SgwCommandDefinition(
      id: "start",
      title: "Start Local Services",
      category: "Setup",
      summary: "Start the local console daemon and menu-bar helper.",
      arguments: ["start", "--no-open-app"],
      needsReview: true,
      sideEffects: ["Loads user LaunchAgents for s-gw services."]
    ),
    SgwCommandDefinition(
      id: "stop",
      title: "Stop Local Services",
      category: "Setup",
      summary: "Stop the local console daemon and menu-bar helper.",
      arguments: ["stop"],
      needsReview: true,
      sideEffects: ["Stops local s-gw background services."]
    ),
    SgwCommandDefinition(
      id: "install-console-service",
      title: "Install Console Service",
      category: "Setup",
      summary: "Install and start the local loopback console LaunchAgent.",
      arguments: ["service", "install", "--start"],
      needsReview: true,
      sideEffects: ["Writes a user LaunchAgent plist.", "Starts the console service."]
    ),
    SgwCommandDefinition(
      id: "install-menubar-service",
      title: "Install Menu-Bar Helper",
      category: "Setup",
      summary: "Install and start the s-gw menu-bar helper.",
      arguments: ["menubar", "install", "--start"],
      needsReview: true,
      sideEffects: ["Writes a user LaunchAgent plist.", "Starts the menu-bar helper."]
    )
  ]

  static var setupCommands: [SgwCommandDefinition] {
    commands.filter { $0.category == "Setup" || $0.category == "Health" || $0.id == "onepassword-status" || $0.id == "guard-status" }
  }

  static var quickActions: [SgwCommandDefinition] {
    commands.filter { ["status", "active-requests", "guard-status", "onepassword-status"].contains($0.id) }
  }

  static func command(id: String) -> SgwCommandDefinition? {
    commands.first { $0.id == id }
  }
}

enum CommandArgumentParser {
  static func parse(_ text: String) -> [String] {
    var args: [String] = []
    var current = ""
    var quote: Character?
    var escaping = false

    for ch in text {
      if escaping {
        current.append(ch)
        escaping = false
        continue
      }
      if ch == "\\" {
        escaping = true
        continue
      }
      if let active = quote {
        if ch == active {
          quote = nil
        } else {
          current.append(ch)
        }
        continue
      }
      if ch == "\"" || ch == "'" {
        quote = ch
        continue
      }
      if ch.isWhitespace {
        if !current.isEmpty {
          args.append(current)
          current = ""
        }
        continue
      }
      current.append(ch)
    }

    if !current.isEmpty {
      args.append(current)
    }
    if args.first == "s-gw" || args.first == "sgw" {
      args.removeFirst()
    }
    return args
  }

  static func quote(_ value: String) -> String {
    if value.rangeOfCharacter(from: .whitespacesAndNewlines) == nil, !value.isEmpty {
      return value
    }
    return "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }
}

