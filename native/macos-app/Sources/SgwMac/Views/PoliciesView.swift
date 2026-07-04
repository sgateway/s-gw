import SwiftUI

struct PoliciesView: View {
  @Environment(AppState.self) private var appState
  @State private var policySheetOpen = false
  @State private var draft = ApprovalPolicyDraft()
  @State private var selectedRequestId = ""

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 14) {
        HStack {
          VStack(alignment: .leading, spacing: 3) {
            Text("Policy Rules")
              .font(.title3.weight(.semibold))
            Text("Control which agents can use which credentials without asking again.")
              .foregroundStyle(.secondary)
          }
          Spacer()
          Button {
            draft = ApprovalPolicyDraft(priority: nextPriority())
            policySheetOpen = true
          } label: {
            Label("Add Rule", systemImage: "plus")
          }
          .buttonStyle(.borderedProminent)
          .tint(SGWTheme.teal)
        }

        HStack(spacing: 10) {
          MetricCard(title: "Rules", value: "\(appState.approvalPolicyRules.count)", systemImage: "slider.horizontal.3") {
            Text("\(appState.approvalPolicyRules.filter(\.enabled).count) enabled")
              .font(.caption)
              .foregroundStyle(.secondary)
          }
          MetricCard(title: "Allow", value: "\(count(.allow))", systemImage: "checkmark.shield", tint: SGWTheme.green)
          MetricCard(title: "Ask", value: "\(count(.ask))", systemImage: "hand.raised", tint: .orange)
          MetricCard(title: "Deny", value: "\(count(.deny))", systemImage: "xmark.shield", tint: SGWTheme.red)
        }

        policyTemplatesPanel
        policyTestPanel

        PanelCard("Rules", systemImage: "shield.lefthalf.filled") {
          if appState.approvalPolicyRules.isEmpty {
            EmptyPanel(
              title: "No policy rules",
              message: "Add a rule to allow trusted agent access, force approval for high-risk credentials, or block a credential path.",
              systemImage: "slider.horizontal.3"
            )
          } else {
            Table(appState.approvalPolicyRules) {
              TableColumn("Rule") { rule in
                VStack(alignment: .leading, spacing: 3) {
                  HStack(spacing: 6) {
                    Image(systemName: icon(rule.decision))
                      .foregroundStyle(color(rule.decision))
                    Text(rule.name)
                      .font(.callout.weight(.medium))
                  }
                  Text(rule.conditions.summary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                }
              }
              TableColumn("Decision") { rule in
                Text(rule.decision.label)
                  .font(.caption.weight(.semibold))
                  .foregroundStyle(color(rule.decision))
              }
              TableColumn("Priority") { rule in
                Text("\(rule.priority)")
                  .foregroundStyle(.secondary)
              }
              TableColumn("Status") { rule in
                Text(status(rule))
                  .foregroundStyle(rule.enabled ? .secondary : SGWTheme.red)
              }
              TableColumn("Actions") { rule in
                HStack {
                  Button(rule.enabled ? "Disable" : "Enable") {
                    appState.setApprovalPolicyRuleEnabled(rule, enabled: !rule.enabled)
                  }
                  Button(role: .destructive) {
                    appState.deleteApprovalPolicyRule(rule)
                  } label: {
                    Image(systemName: "trash")
                  }
                }
                .controlSize(.small)
              }
            }
            .frame(minHeight: 280)
          }
        }
      }
      .padding(18)
    }
    .background(SGWTheme.surface)
    .sheet(isPresented: $policySheetOpen) {
      PolicyRuleEditor(draft: $draft, handles: appState.handles, agents: appState.agents) {
        Task {
          if await appState.addApprovalPolicyRule(draft) {
            policySheetOpen = false
          }
        }
      }
    }
  }

  private var policyTemplatesPanel: some View {
    PanelCard("Templates", systemImage: "square.stack.3d.up") {
      LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 10), count: 3), spacing: 10) {
        ForEach(policyTemplates) { template in
          Button {
            draft = template.draft(nextPriority: nextPriority(), selectedHandle: selectedHandleForTemplate)
            policySheetOpen = true
          } label: {
            VStack(alignment: .leading, spacing: 8) {
              Image(systemName: template.icon)
                .foregroundStyle(color(template.decision))
              Text(template.title)
                .font(.callout.weight(.semibold))
                .foregroundStyle(.primary)
              Text(template.summary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(3)
            }
            .frame(maxWidth: .infinity, minHeight: 118, alignment: .topLeading)
            .padding(12)
            .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
          }
          .buttonStyle(.plain)
          .disabled(template.requiresHandle && selectedHandleForTemplate.isEmpty)
        }
      }
    }
  }

  private var policyTestPanel: some View {
    PanelCard("Test matching", systemImage: "target") {
      if appState.requests.isEmpty {
        EmptyPanel(title: "No requests to test", message: "Policy matching can be previewed after an agent creates a local authorization request.", systemImage: "target")
      } else {
        VStack(alignment: .leading, spacing: 12) {
          Picker("Request", selection: Binding(
            get: { selectedPolicyRequestId },
            set: { selectedRequestId = $0 }
          )) {
            ForEach(appState.requests.prefix(30)) { request in
              Text("\(request.agentName) · \(SGWText.shortHandle(request.handle)) · \(request.actionLabel)")
                .tag(request.id)
            }
          }

          if let request = selectedPolicyRequest {
            HStack(spacing: 10) {
              StatePill(label: request.agentName, color: SGWTheme.blue)
              RequestStateBadge(state: request.state)
              Text(request.actionLabel)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
              Spacer()
            }

            let matches = matchingRules(for: request)
            if matches.isEmpty {
              Text("No enabled policy rule matches this request. s-gw will use reusable grants or ask the user.")
                .font(.caption)
                .foregroundStyle(.secondary)
            } else {
              ForEach(matches) { rule in
                HStack(spacing: 10) {
                  Image(systemName: icon(rule.decision))
                    .foregroundStyle(color(rule.decision))
                  VStack(alignment: .leading, spacing: 2) {
                    Text(rule.name)
                      .font(.callout.weight(.medium))
                    Text("Priority \(rule.priority) · \(rule.conditions.summary)")
                      .font(.caption)
                      .foregroundStyle(.secondary)
                      .lineLimit(2)
                  }
                  Spacer()
                  Text(rule.decision.label)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(color(rule.decision))
                }
              }
            }
          }
        }
      }
    }
  }

  private var selectedPolicyRequestId: String {
    if !selectedRequestId.isEmpty, appState.requests.contains(where: { $0.id == selectedRequestId }) {
      return selectedRequestId
    }
    return appState.requests.first?.id ?? ""
  }

  private var selectedPolicyRequest: RequestRecord? {
    appState.requests.first { $0.id == selectedPolicyRequestId }
  }

  private var selectedHandleForTemplate: String {
    if let selected = appState.selectedCredentialHandle, !selected.isEmpty {
      return selected
    }
    return appState.handles.first?.handle ?? ""
  }

  private var policyTemplates: [PolicyTemplate] {
    [
      PolicyTemplate(
        id: "ask-high-risk",
        title: "Always ask high risk",
        summary: "Force explicit approval for high-risk and critical credentials.",
        icon: "exclamationmark.shield",
        decision: .ask
      ) { priority, _ in
        ApprovalPolicyDraft(
          name: "Always ask for high-risk credentials",
          enabled: true,
          priority: priority,
          decision: .ask,
          handle: "",
          agent: "",
          actionKind: "",
          command: "",
          injectEnv: "",
          sshTarget: "",
          sshPort: 0,
          minSeverity: .high,
          durationMs: 0
        )
      },
      PolicyTemplate(
        id: "ask-ssh",
        title: "Ask for SSH",
        summary: "Require approval before any agent starts an s-gw-owned SSH session.",
        icon: "terminal",
        decision: .ask
      ) { priority, _ in
        ApprovalPolicyDraft(
          name: "Always ask for SSH sessions",
          enabled: true,
          priority: priority,
          decision: .ask,
          handle: "",
          agent: "",
          actionKind: "ssh_session",
          command: "",
          injectEnv: "",
          sshTarget: "",
          sshPort: 0,
          minSeverity: nil,
          durationMs: 0
        )
      },
      PolicyTemplate(
        id: "allow-codex-selected",
        title: "Allow selected for Codex",
        summary: "Let Codex use one selected handle without interrupting you.",
        icon: "checkmark.shield",
        decision: .allow,
        requiresHandle: true
      ) { priority, handle in
        ApprovalPolicyDraft(
          name: "Allow Codex for selected credential",
          enabled: true,
          priority: priority,
          decision: .allow,
          handle: handle,
          agent: "Codex",
          actionKind: "",
          command: "",
          injectEnv: "",
          sshTarget: "",
          sshPort: 0,
          minSeverity: nil,
          durationMs: 8 * 60 * 60 * 1000
        )
      }
    ]
  }

  private func count(_ decision: ApprovalPolicyDecision) -> Int {
    appState.approvalPolicyRules.filter { $0.decision == decision }.count
  }

  private func nextPriority() -> Int {
    (appState.approvalPolicyRules.map(\.priority).max() ?? 90) + 10
  }

  private func icon(_ decision: ApprovalPolicyDecision) -> String {
    switch decision {
    case .ask: "hand.raised"
    case .allow: "checkmark.shield"
    case .deny: "xmark.shield"
    }
  }

  private func color(_ decision: ApprovalPolicyDecision) -> Color {
    switch decision {
    case .ask: .orange
    case .allow: SGWTheme.green
    case .deny: SGWTheme.red
    }
  }

  private func status(_ rule: ApprovalPolicyRuleRecord) -> String {
    if !rule.enabled {
      return "Disabled"
    }
    if let expiresAt = rule.expiresAt {
      return "Expires \(SGWDates.until(expiresAt))"
    }
    return "Active"
  }

  private func matchingRules(for request: RequestRecord) -> [ApprovalPolicyRuleRecord] {
    appState.approvalPolicyRules
      .filter { $0.enabled && matches($0, request: request) }
      .sorted { $0.priority < $1.priority }
  }

  private func matches(_ rule: ApprovalPolicyRuleRecord, request: RequestRecord) -> Bool {
    let handle = appState.handles.first { $0.handle == request.handle }
    let conditions = rule.conditions
    if !matchesString(conditions.handles, request.handle) { return false }
    if !matchesString(conditions.secretTypes, handle?.type ?? "") { return false }
    if !matchesString(conditions.providers, handle?.provider ?? "") { return false }
    if !matchesString(conditions.agents, request.agentName) { return false }
    if !matchesString(conditions.actionKinds, request.action.kind) { return false }
    if !matchesString(conditions.commands, request.action.command) { return false }
    if !matchesString(conditions.injectEnvs, request.action.injectEnv) { return false }
    if !matchesString(conditions.workingDirs, request.action.workingDir ?? "") { return false }
    if !matchesString(conditions.sshTargets, request.action.ssh?.target ?? "") { return false }
    if let ports = conditions.sshPorts, !ports.isEmpty, !ports.contains(request.action.ssh?.port ?? 22) {
      return false
    }
    if let min = conditions.minSeverity, (handle?.severityValue ?? .low) < min {
      return false
    }
    return true
  }

  private func matchesString(_ choices: [String]?, _ value: String) -> Bool {
    guard let choices, !choices.isEmpty else {
      return true
    }
    let normalized = value.lowercased()
    return choices.contains { $0.lowercased() == normalized }
  }
}

private struct PolicyTemplate: Identifiable {
  var id: String
  var title: String
  var summary: String
  var icon: String
  var decision: ApprovalPolicyDecision
  var requiresHandle = false
  var build: (_ nextPriority: Int, _ selectedHandle: String) -> ApprovalPolicyDraft

  func draft(nextPriority: Int, selectedHandle: String) -> ApprovalPolicyDraft {
    build(nextPriority, selectedHandle)
  }
}
