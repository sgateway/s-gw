import SwiftUI

struct OverviewView: View {
  @Environment(AppState.self) private var appState

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 16) {
        if !appState.isReady {
          ReadinessBanner(
            summary: appState.readinessSummary ?? "s-gw is not ready yet.",
            blockers: appState.readinessBlockers.isEmpty
              ? ["Local unlock is not active. Run `s-gw setup` to configure how secrets are unlocked."]
              : appState.readinessBlockers,
            onRunSetup: { appState.runSetup() }
          )
        }

        readinessPanel

        if !appState.pendingRequests.isEmpty {
          pendingApprovalsPanel(limit: 6)
        }

        metricsGrid

        HStack(alignment: .top, spacing: 12) {
          protectionPanel
          quickActionsPanel
        }

        usageAndCredentialsRow

        if appState.pendingRequests.isEmpty {
          pendingApprovalsPanel(limit: 4)
        }

        PanelCard("Recent audit", systemImage: "list.bullet.clipboard") {
          if appState.audit.isEmpty {
            EmptyPanel(title: "No audit events", message: "Local activity will appear here.", systemImage: "list.bullet.clipboard")
          } else {
            ForEach(appState.audit.prefix(6)) { event in
              AuditRow(event: event)
              Divider()
            }
          }
        }
      }
      .padding(18)
    }
    .background(SGWTheme.surface)
  }

  private var usageAndCredentialsRow: some View {
    LazyVGrid(
      columns: [GridItem(.adaptive(minimum: 520), spacing: 12, alignment: .top)],
      alignment: .leading,
      spacing: 12
    ) {
      usageFlowPreviewPanel
        .frame(minWidth: 0, maxWidth: .infinity, alignment: .topLeading)
      credentialHandlesPanel
        .frame(minWidth: 0, maxWidth: .infinity, alignment: .topLeading)
    }
  }

  private var usageFlowPreviewPanel: some View {
    let rows = appState.usageFlowRows

    return PanelCard("Usage Flow", systemImage: "arrow.triangle.branch") {
      if rows.isEmpty {
        EmptyPanel(
          title: "No credential flow yet",
          message: "Agent credential-use routes appear here after local approvals or executions.",
          systemImage: "point.3.connected.trianglepath.dotted"
        )
      } else {
        Button {
          appState.selectedPanel = .usageFlow
        } label: {
          ZStack(alignment: .topTrailing) {
            UsageFlowWebChart(url: appState.usageFlowConsoleURL(embed: true, compact: true))
              .frame(minWidth: 0, maxWidth: .infinity)
              .frame(height: 360)
              .allowsHitTesting(false)
            Image(systemName: "arrow.up.right")
              .font(.caption.weight(.semibold))
              .foregroundStyle(SGWTheme.teal)
              .padding(8)
              .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 8))
              .padding(10)
          }
          .frame(minWidth: 0, maxWidth: .infinity)
          .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Open Usage Flow details")
      }
    }
  }

  private var credentialHandlesPanel: some View {
    PanelCard("Credential handles", systemImage: "key") {
      if appState.handles.isEmpty {
        EmptyPanel(title: "No credentials", message: "Add a secret locally or scan a file to create handles.", systemImage: "key")
      } else {
        ForEach(appState.handles.prefix(5)) { handle in
          HStack {
            VStack(alignment: .leading, spacing: 2) {
              Text(handle.name).font(.callout.weight(.semibold))
              Text(SGWText.shortHandle(handle.handle))
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
            }
            Spacer()
            SeverityBadge(severity: handle.severityValue)
          }
          Divider()
        }
      }
    }
  }

  private var readinessPanel: some View {
    PanelCard("Operational readiness", systemImage: "checklist.checked") {
      LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 10) {
        readinessTile("Daemon", value: appState.daemonRunning ? "Running" : "Stopped", ok: appState.daemonRunning)
        readinessTile("Unlock", value: appState.unlockActive ? "Active" : "Needed", ok: appState.unlockActive)
        readinessTile("Menu bar", value: appState.status?.launchAgents.menuBar.loaded == true ? "Loaded" : "Stopped", ok: appState.status?.launchAgents.menuBar.loaded == true)
        readinessTile("Updates", value: appState.availableUpdate == nil ? "Current" : "Available", ok: appState.availableUpdate == nil)
      }
    }
  }

  private var metricsGrid: some View {
    LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 12) {
      MetricCard(title: "Local secrets", value: "\(appState.handles.count)", systemImage: "lock", tint: SGWTheme.teal) {
        Text("Handles stored securely").font(.caption2).foregroundStyle(.secondary)
      }
      MetricCard(title: "Pending approvals", value: "\(appState.pendingRequests.count)", systemImage: "clock", tint: SGWTheme.blue) {
        Text("Require your review").font(.caption2).foregroundStyle(.secondary)
      }
      MetricCard(title: "Agent profiles", value: "\(appState.agents.count)", systemImage: "person.2", tint: SGWTheme.purple) {
        Text("MCP and guard profiles").font(.caption2).foregroundStyle(.secondary)
      }
      Button {
        appState.credentialSeverityFilter = appState.highRiskCount > 0 ? .high : nil
        appState.selectedPanel = .credentials
      } label: {
        MetricCard(title: "High risk", value: "\(appState.highRiskCount)", systemImage: "exclamationmark.shield", tint: appState.highRiskCount > 0 ? SGWTheme.red : SGWTheme.green) {
          Text(appState.highRiskCount > 0 ? "Click to review" : "No high risk findings")
            .font(.caption2)
            .foregroundStyle(.secondary)
        }
      }
      .buttonStyle(.plain)
      .accessibilityLabel(appState.highRiskCount > 0 ? "Review \(appState.highRiskCount) high risk credentials" : "No high risk credentials")
    }
  }

  private var protectionPanel: some View {
    PanelCard("Protection posture", systemImage: "shield.lefthalf.filled") {
      VStack(alignment: .leading, spacing: 10) {
        postureRow("Tokenization", detail: "\(appState.handles.count) local handles", ok: !appState.handles.isEmpty)
        postureRow("Approval policies", detail: "\(appState.approvalPolicyRules.filter(\.enabled).count) enabled rules", ok: !appState.approvalPolicyRules.isEmpty)
        postureRow("Reusable approvals", detail: "\(appState.approvalGrants.count) active grants", ok: appState.approvalGrants.isEmpty)
        postureRow("Guard mode", detail: "Available through s-gw guard run", ok: true)
      }
    }
  }

  private var quickActionsPanel: some View {
    PanelCard("Quick actions", systemImage: "bolt") {
      VStack(alignment: .leading, spacing: 9) {
        ForEach(CommandRegistry.quickActions) { command in
          Button {
            runQuick(command)
          } label: {
            HStack {
              VStack(alignment: .leading, spacing: 2) {
                Text(command.title)
                  .font(.callout.weight(.medium))
                Text(command.summary)
                  .font(.caption)
                  .foregroundStyle(.secondary)
                  .lineLimit(1)
              }
              Spacer()
              Image(systemName: "play.fill")
                .foregroundStyle(SGWTheme.teal)
            }
          }
          .buttonStyle(.plain)
          Divider()
        }
        Button {
          appState.commandPalettePresented = true
        } label: {
          Label("More commands", systemImage: "command")
        }
        .controlSize(.small)
      }
    }
  }

  private func readinessTile(_ title: String, value: String, ok: Bool) -> some View {
    HStack(spacing: 9) {
      Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
        .foregroundStyle(ok ? SGWTheme.green : SGWTheme.orange)
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
          .font(.caption)
          .foregroundStyle(.secondary)
        Text(value)
          .font(.callout.weight(.semibold))
      }
      Spacer()
    }
    .padding(10)
    .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
  }

  private func postureRow(_ title: String, detail: String, ok: Bool) -> some View {
    HStack(spacing: 9) {
      Image(systemName: ok ? "checkmark.circle" : "info.circle")
        .foregroundStyle(ok ? SGWTheme.green : SGWTheme.orange)
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
          .font(.callout.weight(.medium))
        Text(detail)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer()
    }
  }

  private func runQuick(_ command: SgwCommandDefinition) {
    Task {
      await appState.runCommand(command)
      appState.selectedPanel = .activity
    }
  }

  private func pendingApprovalsPanel(limit: Int) -> some View {
    PanelCard(appState.pendingRequests.isEmpty ? "Pending approvals" : "Approval needed now", systemImage: "checkmark.shield") {
      if appState.pendingRequests.isEmpty {
        EmptyPanel(title: "No approvals", message: "Agents have not requested any local secret-backed actions.", systemImage: "checkmark.circle")
      } else {
        ForEach(appState.pendingRequests.prefix(limit)) { request in
          RequestRow(request: request)
          Divider()
        }
      }
    }
  }
}
