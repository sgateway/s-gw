import SwiftUI

struct CommandPaletteView: View {
  @Environment(AppState.self) private var appState
  @Environment(\.dismiss) private var dismiss
  @State private var search = ""
  @State private var selectedID: String? = CommandRegistry.commands.first?.id
  @State private var customCommand = ""
  @State private var reviewDefinition: SgwCommandDefinition?
  @State private var reviewCustomArgs: [String]?

  private var filteredCommands: [SgwCommandDefinition] {
    let needle = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard !needle.isEmpty else {
      return CommandRegistry.commands
    }
    return CommandRegistry.commands.filter { command in
      [
        command.title,
        command.category,
        command.summary,
        command.commandLine
      ].joined(separator: " ").lowercased().contains(needle)
    }
  }

  private var selectedCommand: SgwCommandDefinition? {
    filteredCommands.first { $0.id == selectedID } ?? filteredCommands.first
  }

  var body: some View {
    VStack(spacing: 0) {
      header
      Divider()
      HStack(spacing: 0) {
        commandList
          .frame(width: 310)
        Divider()
        commandDetail
          .frame(minWidth: 470, maxWidth: .infinity, maxHeight: .infinity)
      }
    }
    .frame(width: 820, height: 560)
    .searchable(text: $search, prompt: "Search commands")
    .confirmationDialog(
      "Review Command",
      isPresented: Binding(
        get: { reviewDefinition != nil },
        set: { if !$0 { reviewDefinition = nil } }
      ),
      presenting: reviewDefinition
    ) { definition in
      Button("Run") {
        run(definition)
      }
      Button("Cancel", role: .cancel) {}
    } message: { definition in
      Text(reviewText(for: definition))
    }
    .confirmationDialog(
      "Review Custom Command",
      isPresented: Binding(
        get: { reviewCustomArgs != nil },
        set: { if !$0 { reviewCustomArgs = nil } }
      )
    ) {
      Button("Run") {
        guard let args = reviewCustomArgs else { return }
        Task {
          await appState.runCommand(
            title: "Run custom command",
            category: "Custom",
            arguments: args,
            sideEffects: ["Custom commands can change local s-gw state depending on the arguments."],
            refreshAfter: true
          )
          appState.selectedPanel = .activity
          reviewCustomArgs = nil
          dismiss()
        }
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text((["s-gw"] + (reviewCustomArgs ?? [])).map(CommandArgumentParser.quote).joined(separator: " "))
    }
  }

  private var header: some View {
    HStack(spacing: 12) {
      Image(systemName: "command")
        .font(.title2)
        .foregroundStyle(SGWTheme.teal)
      VStack(alignment: .leading, spacing: 2) {
        Text("Command Palette")
          .font(.title3.weight(.semibold))
        Text("Run reviewed local s-gw commands and keep their output in Activity.")
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer()
      Button("Close") {
        dismiss()
      }
    }
    .padding(16)
  }

  private var commandList: some View {
    List(selection: $selectedID) {
      ForEach(groupedCommands, id: \.category) { group in
        Section(group.category) {
          ForEach(group.commands) { command in
            VStack(alignment: .leading, spacing: 3) {
              Text(command.title)
                .lineLimit(1)
              Text(command.summary)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(2)
            }
            .tag(command.id)
          }
        }
      }
    }
    .listStyle(.sidebar)
  }

  private var groupedCommands: [(category: String, commands: [SgwCommandDefinition])] {
    Dictionary(grouping: filteredCommands, by: \.category)
      .map { (category: $0.key, commands: $0.value.sorted { $0.title < $1.title }) }
      .sorted { $0.category < $1.category }
  }

  @ViewBuilder
  private var commandDetail: some View {
    if let command = selectedCommand {
      ScrollView {
        VStack(alignment: .leading, spacing: 16) {
          commandPreview(command)
          customCommandPanel
        }
        .padding(18)
      }
      .background(SGWTheme.surface)
    } else {
      EmptyPanel(title: "No commands", message: "No s-gw commands match this search.", systemImage: "command")
        .background(SGWTheme.surface)
    }
  }

  private func commandPreview(_ command: SgwCommandDefinition) -> some View {
    PanelCard(command.title, systemImage: "terminal") {
      VStack(alignment: .leading, spacing: 12) {
        Text(command.summary)
          .foregroundStyle(.secondary)

        Text(command.commandLine)
          .font(.system(.callout, design: .monospaced))
          .textSelection(.enabled)
          .padding(10)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 8))

        if !command.sideEffects.isEmpty {
          VStack(alignment: .leading, spacing: 5) {
            Text("Review")
              .font(.caption.weight(.semibold))
              .foregroundStyle(.secondary)
            ForEach(command.sideEffects, id: \.self) { effect in
              Label(effect, systemImage: "exclamationmark.triangle")
                .font(.caption)
                .foregroundStyle(SGWTheme.orange)
            }
          }
        }

        if let next = command.suggestedNextAction {
          Label(next, systemImage: "arrow.turn.down.right")
            .font(.caption)
            .foregroundStyle(.secondary)
        }

        HStack {
          Button {
            copyToPasteboard(command.commandLine)
            appState.operationMessage = "Copied command"
          } label: {
            Label("Copy", systemImage: "doc.on.doc")
          }
          Spacer()
          Button {
            if command.needsReview {
              reviewDefinition = command
            } else {
              run(command)
            }
          } label: {
            Label(command.needsReview ? "Review and Run" : "Run", systemImage: "play.fill")
          }
          .buttonStyle(.borderedProminent)
          .tint(SGWTheme.teal)
        }
      }
    }
  }

  private var customCommandPanel: some View {
    PanelCard("Advanced", systemImage: "wrench.and.screwdriver") {
      VStack(alignment: .leading, spacing: 10) {
        TextField("s-gw requests --active --all", text: $customCommand)
          .textFieldStyle(.roundedBorder)
          .onSubmit { reviewCustom() }
        Text("Custom commands run through the same local s-gw binary and appear in Activity.")
          .font(.caption)
          .foregroundStyle(.secondary)
        HStack {
          Spacer()
          Button("Review Custom Command") {
            reviewCustom()
          }
          .disabled(CommandArgumentParser.parse(customCommand).isEmpty)
        }
      }
    }
  }

  private func run(_ command: SgwCommandDefinition) {
    Task {
      await appState.runCommand(command)
      appState.selectedPanel = .activity
      reviewDefinition = nil
      dismiss()
    }
  }

  private func reviewCustom() {
    let args = CommandArgumentParser.parse(customCommand)
    guard !args.isEmpty else {
      return
    }
    reviewCustomArgs = args
  }

  private func reviewText(for definition: SgwCommandDefinition) -> String {
    let effects = definition.sideEffects.isEmpty
      ? "No declared side effects."
      : definition.sideEffects.joined(separator: "\n")
    return "\(definition.commandLine)\n\n\(effects)"
  }
}

