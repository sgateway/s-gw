import SwiftUI

struct ApprovalsView: View {
  @Environment(AppState.self) private var appState

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack {
        Text("Local approval queue")
          .font(.title3.weight(.semibold))
        Spacer()
        Button("Refresh") { Task { await appState.refresh() } }
      }
      if !appState.pendingRequests.isEmpty {
        Text("This only approves local credential use; host-agent command prompts are separate.")
          .font(.caption)
          .foregroundStyle(.secondary)
      }

      if appState.pendingRequests.isEmpty {
        EmptyPanel(title: "No pending approvals", message: "Secret-backed actions will wait here until you approve or deny them.", systemImage: "checkmark.shield")
      } else {
        Table(appState.pendingRequests) {
          TableColumn("Agent") { request in
            Text(request.agentName)
          }
          TableColumn("Command") { request in
            Text(SGWText.shortPath(request.action.command))
          }
          TableColumn("Handle") { request in
            Text(SGWText.shortHandle(request.handle))
              .font(.system(.caption, design: .monospaced))
          }
          TableColumn("Requested") { request in
            Text(SGWDates.relative(request.createdAt))
          }
          TableColumn("Action") { request in
            HStack {
              ApprovalMenu(request: request)
              Button {
                appState.deny(request)
              } label: {
                Label("Deny", systemImage: "xmark")
              }
            }
            .controlSize(.small)
            .disabled(appState.isDeciding(request.id))
          }
        }
      }
    }
    .padding(18)
    .background(SGWTheme.surface)
  }
}

struct RequestRow: View {
  @Environment(AppState.self) private var appState
  let request: RequestRecord

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: "person.crop.circle.badge.questionmark")
        .foregroundStyle(SGWTheme.orange)
      VStack(alignment: .leading, spacing: 2) {
        Text("\(request.agentName) requested \(SGWText.shortPath(request.action.command))")
          .font(.callout.weight(.semibold))
        Text(SGWText.shortHandle(request.handle))
          .font(.caption2.monospaced())
          .foregroundStyle(.secondary)
      }
      Spacer()
      Text(SGWDates.relative(request.createdAt))
        .font(.caption)
        .foregroundStyle(.secondary)
      ApprovalMenu(request: request)
      Button {
        appState.deny(request)
      } label: {
        Label("Deny", systemImage: "xmark")
      }
        .controlSize(.small)
    }
    .disabled(appState.isDeciding(request.id))
  }
}

struct ApprovalMenu: View {
  @Environment(AppState.self) private var appState
  let request: RequestRecord

  var body: some View {
    Menu {
      Button("One time") {
        appState.approve(request, choice: .oneTime)
      }
      Divider()
      Section(request.agentName) {
        timedButtons(scope: .sameAgent)
        Button("Until logout") {
          appState.approve(request, choice: .login(scope: .sameAgent))
        }
        Button("Unlimited") {
          appState.approve(request, choice: .unlimited(scope: .sameAgent))
        }
      }
      Section("All agents") {
        timedButtons(scope: .anyAgent)
        Button("Until logout") {
          appState.approve(request, choice: .login(scope: .anyAgent))
        }
        Button("Unlimited") {
          appState.approve(request, choice: .unlimited(scope: .anyAgent))
        }
      }
    } label: {
      Label("Authorize", systemImage: "checkmark.shield")
    }
    .buttonStyle(.borderedProminent)
    .tint(SGWTheme.green)
    .controlSize(.small)
  }

  @ViewBuilder
  private func timedButtons(scope: ApprovalAgentScope) -> some View {
    Button("15 minutes") {
      appState.approve(request, choice: .timed(minutes: 15, scope: scope))
    }
    Button("1 hour") {
      appState.approve(request, choice: .timed(minutes: 60, scope: scope))
    }
    Button("8 hours") {
      appState.approve(request, choice: .timed(minutes: 8 * 60, scope: scope))
    }
    Button("1 day") {
      appState.approve(request, choice: .timed(minutes: 24 * 60, scope: scope))
    }
  }
}
