import SwiftUI

struct SettingsView: View {
  @Environment(AppState.self) private var appState
  @AppStorage("showDockIcon") private var showDockIcon = true
  @AppStorage(CLIRunner.binaryOverrideKey) private var cliPath = ""
  @State private var clearApprovalsConfirm = false
  @State private var policySheetOpen = false
  @State private var policyDraft = ApprovalPolicyDraft()

  var body: some View {
    TabView {
      generalTab
        .tabItem { Label("General", systemImage: "gearshape") }
      approvalsTab
        .tabItem { Label("Approvals", systemImage: "checkmark.shield") }
      policiesTab
        .tabItem { Label("Policies", systemImage: "slider.horizontal.3") }
      integrationsTab
        .tabItem { Label("Integrations", systemImage: "puzzlepiece.extension") }
      updatesTab
        .tabItem { Label("Updates", systemImage: "arrow.down.circle") }
      connectionTab
        .tabItem { Label("Connection", systemImage: "terminal") }
    }
    .padding(20)
    .frame(width: 720, height: 560)
    .confirmationDialog("Revoke all reusable approvals?", isPresented: $clearApprovalsConfirm) {
      Button("Revoke All", role: .destructive) {
        appState.clearApprovalGrants()
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text("Future matching requests will ask again. Pending requests are not approved or denied by this action.")
    }
    .sheet(isPresented: $policySheetOpen) {
      PolicyRuleEditor(draft: $policyDraft, handles: appState.handles, agents: appState.agents) {
        Task {
          if await appState.addApprovalPolicyRule(policyDraft) {
            policySheetOpen = false
          }
        }
      }
    }
  }

  private var generalTab: some View {
    Form {
      Section("Application") {
        Toggle("Show Dock icon", isOn: $showDockIcon)
        Text("Restart the app after changing Dock visibility.")
          .font(.caption)
          .foregroundStyle(.secondary)
      }

      Section("Local Readiness") {
        LabeledContent("Daemon", value: appState.daemonRunning ? "Running" : "Stopped")
        LabeledContent("Unlock", value: appState.unlockActive ? (appState.status?.unlock.activeSource ?? "Active") : "Needed")
        LabeledContent("Pending approvals", value: "\(appState.pendingRequests.count)")
        Button("Open Command Palette") {
          appState.commandPalettePresented = true
        }
      }
    }
  }

  private var approvalsTab: some View {
    Form {
      Section("Default Approval Mode") {
        Picker("Mode", selection: Binding(
          get: { appState.approvalSettings.mode },
          set: { appState.setApprovalMode($0) }
        )) {
          ForEach(ApprovalMode.allCases) { mode in
            Text(mode.label).tag(mode)
          }
        }
        .pickerStyle(.segmented)

        Text(appState.approvalSettings.mode.helpText)
          .font(.caption)
          .foregroundStyle(.secondary)

        if appState.approvalSettings.mode == .timedSession {
          Picker("Reuse window", selection: Binding(
            get: { appState.approvalSettings.durationMs },
            set: { appState.setApprovalDuration($0) }
          )) {
            ForEach(approvalDurationOptions(current: appState.approvalSettings.durationMs), id: \.value) { option in
              Text(option.label).tag(option.value)
            }
          }
        }
      }

      Section("Active Reusable Approvals") {
        if appState.approvalGrants.isEmpty {
          Text("No reusable approvals are active.")
            .foregroundStyle(.secondary)
        } else {
          ForEach(appState.approvalGrants) { grant in
            approvalGrantRow(grant)
          }

          Button("Revoke All", role: .destructive) {
            clearApprovalsConfirm = true
          }
        }
      }
    }
  }

  private var policiesTab: some View {
    Form {
      Section("Policy Rules") {
        if appState.approvalPolicyRules.isEmpty {
          Text("No policy rules are configured.")
            .foregroundStyle(.secondary)
        } else {
          ForEach(appState.approvalPolicyRules) { rule in
            approvalPolicyRow(rule)
          }
        }

        Button {
          policyDraft = ApprovalPolicyDraft(priority: nextPolicyPriority())
          policySheetOpen = true
        } label: {
          Label("Add Policy Rule", systemImage: "plus.circle")
        }
      }
    }
  }

  private var integrationsTab: some View {
    Form {
      Section("macOS Keychain") {
        Text("New local handles can store their raw credential in macOS Keychain while s-gw keeps only an encrypted pointer in its ledger.")
          .font(.caption)
          .foregroundStyle(.secondary)
      }

      Section("1Password") {
        Button("Check 1Password Status") {
          runRegisteredCommand("onepassword-status")
        }
        Button("Preview Dev Vault Import") {
          runRegisteredCommand("onepassword-import-dry-run")
        }
        Text("Import previews never read raw secret values into the app.")
          .font(.caption)
          .foregroundStyle(.secondary)
      }

      Section("Guard Mode") {
        Button("Check Guard Mode") {
          runRegisteredCommand("guard-status")
        }
        Button("Show Agent Profiles") {
          runRegisteredCommand("agent-list")
        }
      }
    }
  }

  private var updatesTab: some View {
    Form {
      Section("Application Update") {
        LabeledContent("Installed version", value: UpdateChecker.currentVersion)
        TextField(
          "GitHub repository",
          text: Binding(
            get: { appState.updateRepository },
            set: { appState.updateRepository = $0 }
          )
        )
        .textFieldStyle(.roundedBorder)
        Text("Use `owner/repo` for the GitHub Releases feed that publishes s-gw packages.")
          .font(.caption)
          .foregroundStyle(.secondary)

        HStack {
          Button(appState.updateState == .checking ? "Checking..." : "Check for Updates") {
            Task { await appState.checkForUpdates(force: true) }
          }
          .disabled(appState.updateState.isBusy)

          if let release = appState.availableUpdate {
            Button("Open Release Notes") {
              appState.openAvailableRelease()
            }
            Button("Notify Again") {
              appState.requestUpdateReminder()
            }
            Button(appState.updateState.isBusy ? appState.updateState.label : "Install Package") {
              appState.installAvailableUpdate()
            }
            .disabled(!release.canInstallPackage || appState.updateState.isBusy)
          }
        }

        if let release = appState.availableUpdate {
          Text("Available: \(release.version)\(release.canInstallPackage ? "" : " · checksum required for automatic install")")
            .font(.caption)
            .foregroundStyle(release.canInstallPackage ? SGWTheme.teal : SGWTheme.orange)
        } else {
          Text(appState.updateState.label)
            .font(.caption)
            .foregroundStyle(.secondary)
        }

        if case .failed(let message) = appState.updateState {
          Text(message)
            .font(.caption)
            .foregroundStyle(SGWTheme.red)
        }
      }
    }
  }

  private var connectionTab: some View {
    Form {
      Section("CLI") {
        TextField("s-gw CLI path", text: $cliPath)
        Text("Leave blank to auto-detect `/opt/homebrew/bin/s-gw`, `/usr/local/bin/s-gw`, compatibility `sgw`, or the bundled `dist/cli.js`.")
          .font(.caption)
          .foregroundStyle(.secondary)
        Button("Refresh Now") {
          Task { await appState.refresh() }
        }
      }

      Section("Local Service") {
        LabeledContent("Console URL", value: appState.status?.consoleUrl ?? "-")
        LabeledContent("Store", value: appState.status?.storePath ?? "-")
        HStack {
          Button("Start Services") { appState.startServices() }
          Button("Stop Services") { appState.stopServices() }
          Button("Reveal Store") { appState.revealStore() }
        }
      }
    }
  }

  private func approvalGrantRow(_ grant: ApprovalGrantRecord) -> some View {
    HStack(alignment: .top, spacing: 10) {
      Image(systemName: "clock.badge.checkmark")
        .foregroundStyle(SGWTheme.teal)
        .frame(width: 22)
      VStack(alignment: .leading, spacing: 3) {
        Text("\(grant.agentLabel) / \(grant.scopeLabel)")
          .font(.callout.weight(.medium))
        Text("\(SGWText.shortHandle(grant.handle)) · \(grant.mode.label)")
          .font(.caption)
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
        Text(grant.expiresAt.map { "Expires \(SGWDates.until($0))" } ?? "No expiration")
          .font(.caption2)
          .foregroundStyle(.secondary)
      }
      Spacer()
      Button("Revoke", role: .destructive) {
        appState.revokeApprovalGrant(grant)
      }
      .controlSize(.small)
    }
  }

  private func approvalPolicyRow(_ rule: ApprovalPolicyRuleRecord) -> some View {
    HStack(alignment: .top, spacing: 10) {
      Toggle("", isOn: Binding(
        get: { rule.enabled },
        set: { appState.setApprovalPolicyRuleEnabled(rule, enabled: $0) }
      ))
      .labelsHidden()
      .toggleStyle(.switch)
      .controlSize(.small)

      Image(systemName: policyIcon(rule.decision))
        .foregroundStyle(policyColor(rule.decision))
        .frame(width: 22)

      VStack(alignment: .leading, spacing: 4) {
        HStack(spacing: 8) {
          Text(rule.name)
            .font(.callout.weight(.medium))
          Text(rule.decision.label)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(policyColor(rule.decision).opacity(0.14), in: Capsule())
            .foregroundStyle(policyColor(rule.decision))
        }
        Text(rule.conditions.summary)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(2)
        Text("Priority \(rule.priority) · \(policyStatusLabel(rule))")
          .font(.caption2)
          .foregroundStyle(.secondary)
      }

      Spacer()
      Button(role: .destructive) {
        appState.deleteApprovalPolicyRule(rule)
      } label: {
        Image(systemName: "trash")
      }
      .buttonStyle(.borderless)
    }
  }

  private func policyIcon(_ decision: ApprovalPolicyDecision) -> String {
    switch decision {
    case .ask: "hand.raised"
    case .allow: "checkmark.shield"
    case .deny: "xmark.shield"
    }
  }

  private func policyColor(_ decision: ApprovalPolicyDecision) -> Color {
    switch decision {
    case .ask: .orange
    case .allow: SGWTheme.green
    case .deny: SGWTheme.red
    }
  }

  private func policyStatusLabel(_ rule: ApprovalPolicyRuleRecord) -> String {
    if !rule.enabled {
      return "Disabled"
    }
    if let expiresAt = rule.expiresAt {
      return "Expires \(SGWDates.until(expiresAt))"
    }
    return "Active"
  }

  private func nextPolicyPriority() -> Int {
    let current = appState.approvalPolicyRules.map(\.priority).max() ?? 90
    return current + 10
  }

  private func approvalDurationOptions(current: Int) -> [(label: String, value: Int)] {
    var options: [(label: String, value: Int)] = [
      ("15 minutes", 15 * 60 * 1000),
      ("1 hour", 60 * 60 * 1000),
      ("4 hours", 4 * 60 * 60 * 1000),
      ("1 day", 24 * 60 * 60 * 1000),
      ("7 days", 7 * 24 * 60 * 60 * 1000)
    ]

    if !options.contains(where: { $0.value == current }) {
      options.append((label: "Custom \(friendlyDuration(current))", value: current))
    }
    return options
  }

  private func friendlyDuration(_ ms: Int) -> String {
    if ms % (24 * 60 * 60 * 1000) == 0 {
      return "\(ms / (24 * 60 * 60 * 1000))d"
    }
    if ms % (60 * 60 * 1000) == 0 {
      return "\(ms / (60 * 60 * 1000))h"
    }
    if ms % (60 * 1000) == 0 {
      return "\(ms / (60 * 1000))m"
    }
    return "\(ms)ms"
  }

  private func runRegisteredCommand(_ id: String) {
    guard let command = CommandRegistry.command(id: id) else {
      return
    }
    Task {
      await appState.runCommand(command)
      appState.selectedPanel = .activity
    }
  }
}

struct PolicyRuleEditor: View {
  @Binding var draft: ApprovalPolicyDraft
  let handles: [HandleSummary]
  let agents: [AgentProfile]
  let save: () -> Void
  @Environment(\.dismiss) private var dismiss

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      HStack {
        Label("Policy Rule", systemImage: "slider.horizontal.3")
          .font(.title3.weight(.semibold))
        Spacer()
        Toggle("Enabled", isOn: $draft.enabled)
      }

      Form {
        Section("Decision") {
          Picker("Decision", selection: $draft.decision) {
            ForEach(ApprovalPolicyDecision.allCases) { decision in
              Text(decision.label).tag(decision)
            }
          }
          .pickerStyle(.segmented)
          Text(draft.decision.helpText)
            .font(.caption)
            .foregroundStyle(.secondary)
        }

        Section("Match") {
          TextField("Name", text: $draft.name)

          Picker("Credential", selection: $draft.handle) {
            Text("Any credential").tag("")
            ForEach(handles) { handle in
              Text("\(handle.name) · \(SGWText.shortHandle(handle.handle))").tag(handle.handle)
            }
          }

          Picker("Agent", selection: $draft.agent) {
            Text("Any agent").tag("")
            ForEach(agentChoices, id: \.self) { agent in
              Text(agent).tag(agent)
            }
          }

          Picker("Action", selection: $draft.actionKind) {
            Text("Any action").tag("")
            Text("Env command").tag("env_command")
            Text("SSH session").tag("ssh_session")
          }

          TextField("Command", text: $draft.command)
          TextField("Environment name", text: $draft.injectEnv)

          HStack {
            TextField("SSH target", text: $draft.sshTarget)
            Stepper("Port \(draft.sshPort == 0 ? 22 : draft.sshPort)", value: $draft.sshPort, in: 0...65535)
          }

          Picker("Minimum severity", selection: Binding(
            get: { draft.minSeverity?.rawValue ?? "" },
            set: { draft.minSeverity = $0.isEmpty ? nil : SecretSeverity(rawValue: $0) }
          )) {
            Text("Any").tag("")
            ForEach(SecretSeverity.allCases) { severity in
              Text(severity.label).tag(severity.rawValue)
            }
          }
        }

        Section("Lifetime") {
          Picker("Expires", selection: $draft.durationMs) {
            Text("Never").tag(0)
            Text("15 minutes").tag(15 * 60 * 1000)
            Text("1 hour").tag(60 * 60 * 1000)
            Text("8 hours").tag(8 * 60 * 60 * 1000)
            Text("1 day").tag(24 * 60 * 60 * 1000)
            Text("7 days").tag(7 * 24 * 60 * 60 * 1000)
          }

          Stepper("Priority \(draft.priority)", value: $draft.priority, in: 0...10_000, step: 10)
        }
      }

      HStack {
        Spacer()
        Button("Cancel") {
          dismiss()
        }
        Button("Save Rule") {
          save()
        }
        .keyboardShortcut(.defaultAction)
        .disabled(draft.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
      }
    }
    .padding(20)
    .frame(width: 620)
  }

  private var agentChoices: [String] {
    var seen = Set<String>()
    var out: [String] = []
    for name in ["Codex", "Claude", "Cursor", "MCP"] + agents.map(\.displayName) {
      if seen.insert(name).inserted {
        out.append(name)
      }
    }
    return out
  }
}
