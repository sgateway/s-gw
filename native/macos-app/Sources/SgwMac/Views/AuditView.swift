import SwiftUI

struct AuditView: View {
  @Environment(AppState.self) private var appState
  @State private var search = ""

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack {
        Text("Audit timeline")
          .font(.title3.weight(.semibold))
        Spacer()
        Button("Reveal Store") { appState.revealStore() }
        Button("Refresh") { Task { await appState.refresh() } }
      }

      if appState.audit.isEmpty {
        EmptyPanel(title: "No audit events", message: "Secret enrollment, approvals, denials, and executions will be listed here.", systemImage: "list.bullet.clipboard")
      } else {
        Table(filtered) {
          TableColumn("Time") { event in
            Text(SGWDates.clock(event.ts))
          }
          TableColumn("Event") { event in
            Text(event.type.replacingOccurrences(of: ".", with: " "))
          }
          TableColumn("Details") { event in
            VStack(alignment: .leading, spacing: 2) {
              Text(event.message)
              if let handle = event.handle {
                Text(SGWText.token(handle))
                  .font(.caption2.monospaced())
                  .foregroundStyle(.secondary)
              }
            }
          }
          TableColumn("Request") { event in
            Text(event.requestId ?? "-")
              .font(.caption.monospaced())
          }
        }
      }
    }
    .padding(18)
    .searchable(text: $search, prompt: "Search audit")
    .background(SGWTheme.surface)
  }

  private var filtered: [AuditEvent] {
    if search.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      return appState.audit
    }
    let needle = search.lowercased()
    return appState.audit.filter { event in
      [event.type, event.message, event.handle ?? "", event.requestId ?? ""]
        .joined(separator: " ")
        .lowercased()
        .contains(needle)
    }
  }
}

struct AuditRow: View {
  let event: AuditEvent

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: icon)
        .foregroundStyle(color)
      VStack(alignment: .leading, spacing: 2) {
        Text(event.message)
          .font(.callout)
        Text("\(event.type) · \(SGWDates.relative(event.ts))")
          .font(.caption2)
          .foregroundStyle(.secondary)
      }
      Spacer()
      if let handle = event.handle {
        Text(SGWText.token(handle))
          .font(.caption2.monospaced())
          .foregroundStyle(.secondary)
      }
    }
  }

  private var icon: String {
    if event.type.contains("approved") { return "checkmark.circle" }
    if event.type.contains("denied") { return "xmark.octagon" }
    if event.type.contains("executed") { return "terminal" }
    if event.type.contains("secret") { return "key" }
    return "info.circle"
  }

  private var color: Color {
    if event.type.contains("approved") { return SGWTheme.green }
    if event.type.contains("denied") { return SGWTheme.red }
    if event.type.contains("executed") { return SGWTheme.blue }
    return SGWTheme.teal
  }
}
