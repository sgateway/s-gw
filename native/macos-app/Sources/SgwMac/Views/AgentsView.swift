import SwiftUI

struct AgentsView: View {
  @Environment(AppState.self) private var appState
  @State private var selectedAgentID: String?

  private var selectedAgent: AgentProfile? {
    appState.agents.first { $0.id == selectedAgentID } ?? appState.agents.first
  }

  var body: some View {
    HStack(spacing: 0) {
      catalogList
        .frame(minWidth: 360, idealWidth: 420, maxWidth: 470)
      Divider()
      agentDetail
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    .background(SGWTheme.surface)
  }

  private var catalogList: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack {
        VStack(alignment: .leading, spacing: 3) {
          Text("Agent Catalog")
            .font(.title3.weight(.semibold))
          Text("Detected MCP connections, skills, and guard-mode launch targets.")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        Spacer()
        Button("Refresh") { Task { await appState.refresh() } }
          .controlSize(.small)
      }
      .padding([.horizontal, .top], 18)

      HStack(spacing: 10) {
        miniMetric("Connected", count: appState.agents.filter { $0.mcpConnected }.count, color: SGWTheme.green)
        miniMetric("Needs setup", count: appState.agents.filter { !$0.mcpConnected }.count, color: SGWTheme.orange)
      }
      .padding(.horizontal, 18)

      if appState.agents.isEmpty {
        EmptyPanel(title: "No agent profiles", message: "`s-gw agent list` did not return any local MCP profiles.", systemImage: "person.2")
      } else {
        List(selection: $selectedAgentID) {
          ForEach(appState.agents) { agent in
            AgentCatalogRow(agent: agent)
              .tag(agent.id)
          }
        }
        .listStyle(.sidebar)
      }
    }
    .background(.regularMaterial)
  }

  @ViewBuilder
  private var agentDetail: some View {
    if let agent = selectedAgent {
      ScrollView {
        VStack(alignment: .leading, spacing: 16) {
          PanelCard(agent.name, systemImage: "person.2.wave.2") {
            VStack(alignment: .leading, spacing: 12) {
              HStack {
                StatePill(
                  label: agent.connectionState,
                  color: agent.mcpConnected ? SGWTheme.green : SGWTheme.orange
                )
                if let connector = agent.defenseClawConnector, !connector.isEmpty {
                  StatePill(label: connector, color: SGWTheme.purple)
                }
                Spacer()
              }

              if let aliases = agent.aliases, !aliases.isEmpty {
                Text("Aliases: \(aliases.joined(separator: ", "))")
                  .font(.caption)
                  .foregroundStyle(.secondary)
                  .textSelection(.enabled)
              }

              if let paths = agent.mcpConfigPaths, !paths.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                  Text("Configuration paths")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                  ForEach(paths, id: \.self) { path in
                    Text(path)
                      .font(.caption.monospaced())
                      .foregroundStyle(.secondary)
                      .textSelection(.enabled)
                  }
                }
              }
            }
          }

          PanelCard("Actions", systemImage: "bolt") {
            VStack(alignment: .leading, spacing: 10) {
              HStack {
                if agent.canInstall {
                  Button {
                    Task { await appState.installIntegration(for: agent) }
                  } label: {
                    Label("Connect", systemImage: "link.badge.plus")
                  }
                  .accessibilityIdentifier("agent-install-\(agent.id)")
                }
                if agent.hasOwnedIntegration {
                  Button {
                    Task { await appState.uninstallIntegration(for: agent) }
                  } label: {
                    Label("Disconnect", systemImage: "link.badge.minus")
                  }
                  .accessibilityIdentifier("agent-uninstall-\(agent.id)")
                }
                Button {
                  appState.copySnippet(for: agent)
                  appState.selectedPanel = .activity
                } label: {
                  Label("Copy MCP Snippet", systemImage: "doc.on.doc")
                }
                Button {
                  copyToPasteboard("s-gw guard run \(agent.id)")
                  appState.operationMessage = "Copied guard launch command"
                } label: {
                  Label("Copy Guard Launch", systemImage: "shield")
                }
                Button {
                  showAgent(agent)
                } label: {
                  Label("Inspect Profile", systemImage: "info.circle")
                }
              }
              .controlSize(.small)

              Text(agent.connectionState == "manual" ? "Automatic registration is not safe for this profile. Review and apply the MCP snippet manually." : "s-gw backs up agent config before installing its MCP entry and packaged skill. Guard mode remains available for shell launches.")
                .font(.caption)
                .foregroundStyle(.secondary)
            }
          }

          PanelCard("Integration readiness", systemImage: "checklist.checked") {
            VStack(alignment: .leading, spacing: 9) {
              readinessRow("MCP registration", ok: agent.mcpConnected, detail: agent.integration?.mcp.state ?? "Manual setup")
              readinessRow("s-gw skill", ok: agent.integration?.skill.state == "installed" || agent.integration?.skill.state == "existing", detail: agent.integration?.skill.state ?? "Not managed")
              readinessRow("Guard launcher", ok: true, detail: "Available with `s-gw guard run \(agent.id)`")
              readinessRow("Approval queue", ok: appState.pendingRequests.isEmpty, detail: appState.pendingRequests.isEmpty ? "No pending agent requests" : "\(appState.pendingRequests.count) pending")
              if let reason = agent.integration?.reason, !reason.isEmpty {
                Text(reason)
                  .font(.caption)
                  .foregroundStyle(SGWTheme.orange)
              }
            }
          }
        }
        .padding(18)
      }
    } else {
      EmptyPanel(title: "No agent selected", message: "Select an agent profile to inspect configuration and actions.", systemImage: "person.2")
    }
  }

  private func miniMetric(_ title: String, count: Int, color: Color) -> some View {
    VStack(alignment: .leading, spacing: 3) {
      Text(title)
        .font(.caption)
        .foregroundStyle(.secondary)
      Text("\(count)")
        .font(.title3.weight(.semibold))
        .foregroundStyle(color)
    }
    .padding(10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(SGWTheme.raised, in: RoundedRectangle(cornerRadius: 8))
  }

  private func readinessRow(_ title: String, ok: Bool, detail: String) -> some View {
    HStack(spacing: 9) {
      Image(systemName: ok ? "checkmark.circle" : "exclamationmark.circle")
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

  private func showAgent(_ agent: AgentProfile) {
    Task {
      await appState.runCommand(
        title: "Inspect \(agent.name)",
        category: "Agents",
        arguments: ["agent", "show", agent.id],
        refreshAfter: false
      )
      appState.selectedPanel = .activity
    }
  }
}
private struct AgentCatalogRow: View {
  let agent: AgentProfile

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: agent.mcpConnected ? "checkmark.seal" : "person.crop.circle.badge.questionmark")
        .foregroundStyle(agent.mcpConnected ? SGWTheme.green : SGWTheme.orange)
        .frame(width: 20)
      VStack(alignment: .leading, spacing: 3) {
        Text(agent.name)
          .lineLimit(1)
        Text(agent.configPath ?? "Manual profile")
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
      }
      Spacer()
    }
    .padding(.vertical, 3)
  }
}
