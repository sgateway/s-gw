import SwiftUI

struct SetupView: View {
  @Environment(AppState.self) private var appState
  @State private var reviewCommand: SgwCommandDefinition?

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 16) {
        HStack {
          VStack(alignment: .leading, spacing: 3) {
            Text("Setup")
              .font(.title3.weight(.semibold))
            Text("Review and run the local commands that make s-gw ready for daily agent use.")
              .foregroundStyle(.secondary)
          }
          Spacer()
          Button {
            appState.commandPalettePresented = true
          } label: {
            Label("Command Palette", systemImage: "command")
          }
        }

        LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 3), spacing: 12) {
          setupStatusCard(
            title: "Runtime",
            value: appState.isReady ? "Ready" : "Needs setup",
            icon: "checkmark.seal",
            color: appState.isReady ? SGWTheme.green : SGWTheme.orange
          )
          setupStatusCard(
            title: "Services",
            value: appState.daemonRunning ? "Running" : "Stopped",
            icon: "switch.2",
            color: appState.daemonRunning ? SGWTheme.green : SGWTheme.red
          )
          setupStatusCard(
            title: "Unlock",
            value: appState.unlockActive ? (appState.status?.unlock.activeSource ?? "Active") : "Needed",
            icon: "key",
            color: appState.unlockActive ? SGWTheme.green : SGWTheme.red
          )
        }

        PanelCard("Setup checklist", systemImage: "list.bullet.rectangle") {
          VStack(alignment: .leading, spacing: 10) {
            checklistRow("CLI found", detail: appState.status?.cliPath.path ?? "s-gw CLI not found", ok: appState.status?.cliPath.exists == true)
            checklistRow("MCP entry point", detail: appState.status?.mcpPath.path ?? "-", ok: appState.status?.mcpPath.exists == true)
            checklistRow("Keychain helper", detail: appState.status?.keychainHelperPath.path ?? "-", ok: appState.status?.keychainHelperPath.exists == true)
            checklistRow("Console LaunchAgent", detail: appState.status?.launchAgents.console.plistPath ?? "-", ok: appState.status?.launchAgents.console.loaded == true)
            checklistRow("Menu-bar helper", detail: appState.status?.launchAgents.menuBar.plistPath ?? "-", ok: appState.status?.launchAgents.menuBar.loaded == true)
          }
        }

        PanelCard("Guided actions", systemImage: "wand.and.stars") {
          VStack(spacing: 10) {
            ForEach(CommandRegistry.setupCommands) { command in
              setupActionRow(command)
              Divider()
            }
          }
        }

        PanelCard("Local paths", systemImage: "folder") {
          KeyValueGrid(pairs: [
            ("Package root", appState.status?.packageRoot ?? "-"),
            ("Store", appState.status?.storePath ?? "-"),
            ("Console URL", appState.status?.consoleUrl ?? "-"),
            ("CLI", appState.status?.cliPath.path ?? "-"),
            ("MCP", appState.status?.mcpPath.path ?? "-")
          ])
          HStack {
            Button("Open Console") { appState.openWebConsole() }
            Button("Reveal Store") { appState.revealStore() }
            Button("Refresh") { Task { await appState.refresh() } }
          }
          .controlSize(.small)
        }
      }
      .padding(18)
    }
    .background(SGWTheme.surface)
    .confirmationDialog(
      "Review Setup Command",
      isPresented: Binding(
        get: { reviewCommand != nil },
        set: { if !$0 { reviewCommand = nil } }
      ),
      presenting: reviewCommand
    ) { command in
      Button("Run") {
        run(command)
      }
      Button("Cancel", role: .cancel) {}
    } message: { command in
      let effects = command.sideEffects.isEmpty ? "No declared side effects." : command.sideEffects.joined(separator: "\n")
      Text("\(command.commandLine)\n\n\(effects)")
    }
  }

  private func setupStatusCard(title: String, value: String, icon: String, color: Color) -> some View {
    MetricCard(title: title, value: value, systemImage: icon, tint: color) {
      EmptyView()
    }
  }

  private func checklistRow(_ title: String, detail: String, ok: Bool) -> some View {
    HStack(spacing: 10) {
      Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
        .foregroundStyle(ok ? SGWTheme.green : SGWTheme.orange)
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
          .font(.callout.weight(.medium))
        Text(detail)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .textSelection(.enabled)
      }
      Spacer()
    }
  }

  private func setupActionRow(_ command: SgwCommandDefinition) -> some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: command.needsReview ? "exclamationmark.triangle" : "terminal")
        .foregroundStyle(command.needsReview ? SGWTheme.orange : SGWTheme.teal)
        .frame(width: 22)
      VStack(alignment: .leading, spacing: 3) {
        Text(command.title)
          .font(.callout.weight(.semibold))
        Text(command.summary)
          .font(.caption)
          .foregroundStyle(.secondary)
        Text(command.commandLine)
          .font(.caption2.monospaced())
          .foregroundStyle(.secondary)
          .textSelection(.enabled)
      }
      Spacer()
      Button(command.needsReview ? "Review" : "Run") {
        if command.needsReview {
          reviewCommand = command
        } else {
          run(command)
        }
      }
      .controlSize(.small)
    }
  }

  private func run(_ command: SgwCommandDefinition) {
    Task {
      await appState.runCommand(command)
      appState.selectedPanel = .activity
      reviewCommand = nil
    }
  }
}

struct KeyValueGrid: View {
  let pairs: [(String, String)]

  var body: some View {
    Grid(alignment: .leading, horizontalSpacing: 16, verticalSpacing: 7) {
      ForEach(Array(pairs.enumerated()), id: \.offset) { _, pair in
        GridRow {
          Text(pair.0)
            .font(.caption)
            .foregroundStyle(.secondary)
          Text(pair.1)
            .font(.caption)
            .textSelection(.enabled)
        }
      }
    }
  }
}
