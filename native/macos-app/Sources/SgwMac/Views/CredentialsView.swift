import SwiftUI

struct CredentialsView: View {
  @Environment(AppState.self) private var appState
  @State private var search = ""
  @State private var deleteCandidate: HandleSummary?

  var body: some View {
    @Bindable var state = appState
    VStack(alignment: .leading, spacing: 12) {
      HStack {
        VStack(alignment: .leading, spacing: 3) {
          Text(appState.credentialSeverityFilter == .high ? "High-risk credentials" : "Credential handles")
            .font(.title3.weight(.semibold))
          Text(appState.credentialSeverityFilter == .high ? "\(filtered.count) handle(s) need review" : "\(appState.handles.count) local handle(s)")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        Spacer()
        if appState.credentialSeverityFilter != nil {
          Button("Show All") {
            appState.credentialSeverityFilter = nil
            appState.selectedCredentialHandle = nil
          }
          .controlSize(.small)
        }
        Button {
          appState.addSecretSheetOpen = true
        } label: {
          Label("Add Secret", systemImage: "plus")
        }
      }

      if appState.handles.isEmpty {
        EmptyPanel(title: "No credentials", message: "Use Add Secret or scan a file with the CLI to create local handles.", systemImage: "key")
      } else {
        HStack(alignment: .top, spacing: 12) {
          Table(filtered, selection: $state.selectedCredentialHandle) {
            TableColumn("Provider") { handle in
              Text(handle.providerLabel)
            }
            TableColumn("Name") { handle in
              VStack(alignment: .leading, spacing: 2) {
                Text(handle.name)
                Text(SGWText.shortHandle(handle.handle))
                  .font(.caption2.monospaced())
                  .foregroundStyle(.secondary)
              }
            }
            TableColumn("Type") { handle in
              Text(handle.type)
            }
            TableColumn("Severity") { handle in
              SeverityBadge(severity: handle.severityValue)
            }
            TableColumn("Policy") { handle in
              Text(policyText(handle.policy))
                .font(.caption)
                .foregroundStyle(.secondary)
            }
          }
          .frame(minWidth: 560)

          credentialDetail
            .frame(width: 340)
        }
      }
    }
    .padding(18)
    .searchable(text: $search, prompt: "Search handles")
    .background(SGWTheme.surface)
    .confirmationDialog(
      "Delete credential?",
      isPresented: Binding(
        get: { deleteCandidate != nil },
        set: { if !$0 { deleteCandidate = nil } }
      ),
      presenting: deleteCandidate
    ) { handle in
      Button("Delete Credential", role: .destructive) {
        appState.deleteCredential(handle)
        deleteCandidate = nil
      }
      Button("Cancel", role: .cancel) {
        deleteCandidate = nil
      }
    } message: { handle in
      Text("This removes \(handle.name) from s-gw, revokes reusable approvals for it, and fails unfinished requests that use it.")
    }
  }

  private var filtered: [HandleSummary] {
    var items = appState.handles
    if let filter = appState.credentialSeverityFilter {
      items = items.filter { $0.severityValue >= filter }
    }

    let trimmed = search.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else { return items }

    let needle = search.lowercased()
    return items.filter { item in
      [
        item.name,
        item.handle,
        item.type,
        item.provider ?? "",
        item.source ?? "",
        item.ruleId ?? ""
      ].joined(separator: " ")
        .lowercased()
        .contains(needle)
    }
  }

  @ViewBuilder
  private var credentialDetail: some View {
    if let selectedHandle = selectedHandle {
      VStack(alignment: .leading, spacing: 12) {
        HStack(alignment: .top) {
          VStack(alignment: .leading, spacing: 4) {
            Text(selectedHandle.name)
              .font(.headline)
              .lineLimit(2)
            Text(SGWText.shortHandle(selectedHandle.handle))
              .font(.caption.monospaced())
              .foregroundStyle(.secondary)
              .textSelection(.enabled)
          }
          Spacer()
          SeverityBadge(severity: selectedHandle.severityValue)
        }

        detailRow("Provider", selectedHandle.providerLabel)
        detailRow("Type", selectedHandle.type)
        detailRow("Backend", selectedHandle.backend ?? "local")
        if let source = selectedHandle.source, !source.isEmpty {
          detailRow("Source", source)
        }
        if let ruleId = selectedHandle.ruleId, !ruleId.isEmpty {
          detailRow("Detection", ruleId)
        }
        if let confidence = selectedHandle.confidence {
          detailRow("Confidence", String(format: "%.0f%%", confidence * 100))
        }
        detailRow("Fingerprint", selectedHandle.fingerprint)
        detailRow("Inject env", selectedHandle.policy.injectEnv ?? "Not configured")
        detailCommands(selectedHandle.policy.allowedCommands)
        Divider()
        HStack {
          Button {
            copyToPasteboard(selectedHandle.handle)
            appState.operationMessage = "Handle copied"
          } label: {
            Label("Copy Handle", systemImage: "doc.on.doc")
          }
          Spacer()
          Button(role: .destructive) {
            deleteCandidate = selectedHandle
          } label: {
            Label("Delete", systemImage: "trash")
          }
        }
        .controlSize(.small)
      }
      .padding(14)
      .background(SGWTheme.raised, in: RoundedRectangle(cornerRadius: 8))
    } else {
      EmptyPanel(title: "Select a handle", message: "Click a credential row to review its source, severity, fingerprint, and allowed commands.", systemImage: "sidebar.right")
        .frame(width: 340)
        .background(SGWTheme.raised, in: RoundedRectangle(cornerRadius: 8))
    }
  }

  private var selectedHandle: HandleSummary? {
    if let id = appState.selectedCredentialHandle,
       let match = filtered.first(where: { $0.handle == id }) {
      return match
    }
    return filtered.first
  }

  private func detailRow(_ label: String, _ value: String) -> some View {
    VStack(alignment: .leading, spacing: 3) {
      Text(label)
        .font(.caption.weight(.semibold))
        .foregroundStyle(.secondary)
      Text(value)
        .font(.caption)
        .textSelection(.enabled)
        .fixedSize(horizontal: false, vertical: true)
    }
  }

  @ViewBuilder
  private func detailCommands(_ commands: [String]) -> some View {
    VStack(alignment: .leading, spacing: 5) {
      Text("Allowed commands")
        .font(.caption.weight(.semibold))
        .foregroundStyle(.secondary)
      if commands.isEmpty {
        Text("None configured")
          .font(.caption)
          .foregroundStyle(.secondary)
      } else {
        ForEach(commands, id: \.self) { command in
          Text(command)
            .font(.caption.monospaced())
            .textSelection(.enabled)
            .fixedSize(horizontal: false, vertical: true)
        }
      }
    }
  }

  private func policyText(_ policy: SecretPolicy) -> String {
    let env = policy.injectEnv ?? "no env"
    let commands = policy.allowedCommands.isEmpty ? "no commands" : "\(policy.allowedCommands.count) command(s)"
    return "\(env), \(commands)"
  }
}

struct AddSecretSheet: View {
  @Environment(AppState.self) private var appState
  @Environment(\.dismiss) private var dismiss
  @State private var draft = NewSecretDraft()
  @State private var isSaving = false

  private let types = ["api-token", "ssh-key", "private-key", "password", "credential", "access-key", "unknown"]

  var body: some View {
    VStack(alignment: .leading, spacing: 14) {
      Text("Add Local Secret")
        .font(.title3.weight(.semibold))
      Text("The value is sent only to the local `s-gw` CLI over stdin and is never shown to an agent.")
        .font(.caption)
        .foregroundStyle(.secondary)

      Form {
        TextField("Name", text: $draft.name)
        Picker("Type", selection: $draft.type) {
          ForEach(types, id: \.self) { type in
            Text(type).tag(type)
          }
        }
        SecureField("Secret value", text: $draft.value)
        TextField("Inject environment variable", text: $draft.injectEnv)
        TextField("Allowed command", text: $draft.allowedCommand)
      }
      .formStyle(.grouped)

      HStack {
        Spacer()
        Button("Cancel") { dismiss() }
        Button {
          save()
        } label: {
          if isSaving {
            ProgressView().controlSize(.small)
          } else {
            Text("Add Secret")
          }
        }
        .buttonStyle(.borderedProminent)
        .disabled(draft.name.isEmpty || draft.value.isEmpty || isSaving)
      }
    }
    .padding(20)
    .frame(width: 520)
  }

  private func save() {
    isSaving = true
    Task {
      let ok = await appState.addSecret(draft)
      isSaving = false
      if ok {
        dismiss()
      }
    }
  }
}
