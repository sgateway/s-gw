import AppKit
import SwiftUI

struct HelperMenuDashboard: View {
  @ObservedObject var model: HelperViewModel
  let actions: HelperMenuActions

  var body: some View {
    VStack(spacing: 0) {
      header
        .padding(.horizontal, 12)
        .padding(.vertical, 9)

      Divider()

      if let feedback = model.feedback {
        feedbackBanner(feedback)
          .padding(.horizontal, 12)
          .padding(.top, 8)
      }

      ScrollView {
        Group {
          if let request = model.state.pending.first {
            pendingContent(request)
          } else {
            idleContent
          }
        }
        .padding(12)
      }

      Divider()
      footer
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
    }
    .frame(width: HelperPopoverMetrics.width, height: model.contentSize.height)
    .background(.regularMaterial)
    .animation(.easeInOut(duration: 0.16), value: model.state.pending.isEmpty)
  }

  private var header: some View {
    HStack(spacing: 9) {
      HelperBrandIcon()

      VStack(alignment: .leading, spacing: 1) {
        Text("s-gw")
          .font(.system(size: 13, weight: .semibold))
        Text(headerDetail)
          .font(.system(size: 11))
          .foregroundStyle(.secondary)
          .lineLimit(1)
      }

      Spacer(minLength: 8)
      statusLabel

      Button {
        actions.refresh()
      } label: {
        if model.isRefreshing {
          ProgressView()
            .controlSize(.small)
            .frame(width: 16, height: 16)
        } else {
          Image(systemName: "arrow.clockwise")
            .frame(width: 16, height: 16)
        }
      }
      .buttonStyle(HelperIconButtonStyle())
      .keyboardShortcut("r", modifiers: .command)
      .help("Refresh status")
      .accessibilityLabel("Refresh status")
      .disabled(model.isRefreshing)

      overflowMenu
    }
  }

  private var overflowMenu: some View {
    Menu {
      Button("Settings") { actions.openApp(.settings) }
      Button("Audit Log") { actions.openApp(.audit) }
      Button("Open web console") { actions.openConsole() }

      Divider()

      Menu("Menu-bar count") {
        ForEach(StatusCountMode.allCases, id: \.rawValue) { mode in
          Button {
            actions.setCountMode(mode)
          } label: {
            if model.countMode == mode {
              Label(mode.menuTitle, systemImage: "checkmark")
            } else {
              Text(mode.menuTitle)
            }
          }
        }
      }

      Button("Send test notification") { actions.testNotification() }

      Divider()
      Button("Quit s-gw helper") { actions.quit() }
    } label: {
      Image(systemName: "ellipsis")
        .frame(width: 16, height: 16)
    }
    .menuStyle(.borderlessButton)
    .buttonStyle(HelperIconButtonStyle())
    .help("More actions")
    .accessibilityLabel("More actions")
  }

  private var statusLabel: some View {
    HStack(spacing: 5) {
      Circle()
        .fill(statusColor)
        .frame(width: 8, height: 8)
      Text(statusText)
        .font(.system(size: 11, weight: .medium))
    }
    .foregroundStyle(statusColor)
    .padding(.horizontal, 7)
    .padding(.vertical, 4)
    .background(statusColor.opacity(0.11), in: Capsule())
    .accessibilityElement(children: .combine)
    .accessibilityLabel("s-gw status: \(statusText)")
  }

  private var idleContent: some View {
    VStack(alignment: .leading, spacing: 12) {
      if !model.state.isReady {
        readinessAlert
      }

      summaryStrip
      protectionSection
      recentActivitySection
    }
  }

  private var summaryStrip: some View {
    HStack(spacing: 0) {
      SummaryButton(
        value: "\(model.state.pending.count)",
        label: "Pending",
        symbol: "clock",
        color: model.state.pending.isEmpty ? HelperTheme.teal : HelperTheme.orange
      ) {
        actions.openApp(.approvals)
      }

      Divider().frame(height: 34)

      SummaryButton(
        value: "\(model.state.credentialCount)",
        label: "Credentials",
        symbol: "key",
        color: HelperTheme.teal
      ) {
        actions.openApp(.credentials)
      }

      Divider().frame(height: 34)

      SummaryButton(
        value: "\(model.state.highRiskCount)",
        label: "High risk",
        symbol: "exclamationmark.shield",
        color: model.state.highRiskCount == 0 ? HelperTheme.teal : HelperTheme.red
      ) {
        actions.openApp(.credentials)
      }
    }
    .padding(.vertical, 7)
    .background(HelperTheme.surface, in: RoundedRectangle(cornerRadius: 7))
    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(HelperTheme.hairline))
  }

  private var protectionSection: some View {
    VStack(alignment: .leading, spacing: 7) {
      Text("Local protection")
        .font(.system(size: 11, weight: .semibold))
        .foregroundStyle(.secondary)

      HStack(spacing: 8) {
        HealthBadge(
          title: "Daemon",
          ready: model.state.daemonRunning,
          detail: model.state.daemonRunning ? "Running" : "Offline"
        ) { actions.openApp(.overview) }

        HealthBadge(
          title: "Credential store",
          ready: model.state.credentialStoreReady,
          detail: model.state.credentialStoreReady ? "Unlocked" : "Locked"
        ) { actions.openApp(.settings) }

        HealthBadge(
          title: "1Password",
          ready: model.state.onePasswordAvailable,
          detail: model.state.onePasswordAvailable ? "Connected" : "Unavailable"
        ) { actions.openApp(.settings) }
      }
    }
  }

  private var recentActivitySection: some View {
    VStack(alignment: .leading, spacing: 0) {
      HStack {
        Text("Recent activity")
          .font(.system(size: 11, weight: .semibold))
          .foregroundStyle(.secondary)
        Spacer()
        Button("View all") { actions.openApp(.activity) }
          .buttonStyle(.plain)
          .font(.system(size: 11, weight: .medium))
          .foregroundStyle(HelperTheme.teal)
      }
      .padding(.bottom, 5)

      if model.state.recentAudit.isEmpty {
        Text("No credential activity yet")
          .font(.system(size: 12))
          .foregroundStyle(.secondary)
          .frame(maxWidth: .infinity, alignment: .leading)
          .padding(.vertical, 12)
      } else {
        ForEach(Array(model.state.recentAudit.prefix(3).enumerated()), id: \.element.id) { index, event in
          if index > 0 { Divider() }
          activityRow(event)
        }
      }
    }
  }

  private func activityRow(_ event: AuditEvent) -> some View {
    Button {
      actions.openApp(.activity)
    } label: {
      HStack(spacing: 8) {
        Image(systemName: activitySymbol(event.type))
          .font(.system(size: 11, weight: .semibold))
          .foregroundStyle(helperActivityColor(event.type))
          .frame(width: 17)

        VStack(alignment: .leading, spacing: 1) {
          Text(helperActivityLabel(event.type))
            .font(.system(size: 12, weight: .medium))
            .lineLimit(1)
          Text(event.message)
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
            .lineLimit(1)
        }

        Spacer(minLength: 8)
        Text(HelperDates.relative(event.ts))
          .font(.system(size: 11).monospacedDigit())
          .foregroundStyle(.tertiary)
      }
      .padding(.vertical, 6)
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .help("Open activity")
  }

  private var readinessAlert: some View {
    HStack(spacing: 9) {
      Image(systemName: "exclamationmark.triangle.fill")
        .foregroundStyle(HelperTheme.orange)
      VStack(alignment: .leading, spacing: 1) {
        Text(readinessTitle)
          .font(.system(size: 12, weight: .semibold))
        Text(readinessDetail)
          .font(.system(size: 11))
          .foregroundStyle(.secondary)
          .lineLimit(1)
      }
      Spacer()
      Button("Review") { actions.openApp(.settings) }
        .controlSize(.small)
    }
    .padding(9)
    .background(HelperTheme.orange.opacity(0.09), in: RoundedRectangle(cornerRadius: 7))
    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(HelperTheme.orange.opacity(0.24)))
  }

  private func pendingContent(_ request: RequestRecord) -> some View {
    VStack(alignment: .leading, spacing: 10) {
      HStack {
        VStack(alignment: .leading, spacing: 2) {
          Text("Approval required")
            .font(.system(size: 13, weight: .semibold))
          Text("Review the credential-backed action before it runs.")
            .font(.system(size: 11))
            .foregroundStyle(.secondary)
        }
        Spacer()
        Text("\(model.state.pending.count) pending")
          .font(.system(size: 11, weight: .medium).monospacedDigit())
          .foregroundStyle(HelperTheme.orange)
      }

      ApprovalPromptCard(request: request, model: model, actions: actions)

      if model.state.pending.count > 1 {
        Button {
          actions.openApp(.approvals)
        } label: {
          HStack {
            Image(systemName: "tray.full")
            Text("Review \(model.state.pending.count - 1) more in s-gw")
            Spacer()
            Image(systemName: "arrow.up.right")
          }
          .font(.system(size: 11, weight: .medium))
          .padding(8)
          .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(HelperTheme.teal)
        .background(HelperTheme.surface, in: RoundedRectangle(cornerRadius: 7))
      }
    }
  }

  private var footer: some View {
    HStack(spacing: 8) {
      Button {
        actions.openApp(model.state.pending.isEmpty ? .overview : .approvals)
      } label: {
        Label("Open s-gw", systemImage: "macwindow")
      }
      .controlSize(.small)
      .keyboardShortcut("o", modifiers: .command)

      Spacer()

      Text("Updated \(HelperDates.clock(model.state.lastUpdated))")
        .font(.system(size: 10).monospacedDigit())
        .foregroundStyle(.tertiary)
    }
  }

  private func feedbackBanner(_ feedback: DecisionFeedback) -> some View {
    let color = feedback.succeeded ? HelperTheme.green : HelperTheme.red
    return HStack(spacing: 7) {
      Image(systemName: feedback.succeeded ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
      VStack(alignment: .leading, spacing: 1) {
        Text(feedback.title)
          .font(.system(size: 11, weight: .semibold))
        Text(feedback.message)
          .font(.system(size: 10))
          .lineLimit(1)
      }
      Spacer()
    }
    .foregroundStyle(color)
    .padding(8)
    .background(color.opacity(0.09), in: RoundedRectangle(cornerRadius: 7))
  }

  private var headerDetail: String {
    if !model.state.daemonRunning { return "Local daemon offline" }
    if !model.state.credentialStoreReady { return "Credential store locked" }
    if !model.state.pending.isEmpty { return "Approval needs review" }
    return "Local credential control is ready"
  }

  private var statusText: String {
    if !model.state.daemonRunning { return "Offline" }
    if !model.state.credentialStoreReady { return "Locked" }
    if !model.state.pending.isEmpty { return "Pending" }
    return "Ready"
  }

  private var statusColor: Color {
    if !model.state.daemonRunning || !model.state.credentialStoreReady { return HelperTheme.red }
    if !model.state.pending.isEmpty { return HelperTheme.orange }
    return HelperTheme.green
  }

  private var readinessTitle: String {
    if !model.state.daemonRunning { return "Local daemon is offline" }
    return "Credential store is locked"
  }

  private var readinessDetail: String {
    if !model.state.daemonRunning { return "Open s-gw to restart local services." }
    return "Unlock the local store before approving requests."
  }

  private func activitySymbol(_ type: String) -> String {
    if type.contains("denied") || type.contains("failed") { return "xmark.circle.fill" }
    if type.contains("approved") || type.contains("executed") { return "checkmark.circle.fill" }
    if type.contains("request") { return "clock.fill" }
    return "key.fill"
  }
}

private struct HelperBrandIcon: View {
  var body: some View {
    Group {
      if let icon = Self.iconImage() {
        Image(nsImage: icon)
          .resizable()
          .interpolation(.high)
      } else {
        Image(systemName: "lock.shield.fill")
          .resizable()
          .scaledToFit()
          .padding(5)
          .foregroundStyle(HelperTheme.teal)
      }
    }
    .frame(width: 27, height: 27)
    .clipShape(RoundedRectangle(cornerRadius: 6))
    .accessibilityHidden(true)
  }

  private static func iconImage() -> NSImage? {
    Bundle.main.url(forResource: "AppIcon", withExtension: "icns")
      .flatMap { NSImage(contentsOf: $0) }
      ?? NSApp.applicationIconImage
  }
}

private struct SummaryButton: View {
  let value: String
  let label: String
  let symbol: String
  let color: Color
  let action: () -> Void

  var body: some View {
    Button(action: action) {
      HStack(spacing: 6) {
        Image(systemName: symbol)
          .font(.system(size: 11, weight: .semibold))
          .foregroundStyle(color)
        VStack(alignment: .leading, spacing: 0) {
          Text(value)
            .font(.system(size: 13, weight: .semibold).monospacedDigit())
          Text(label)
            .font(.system(size: 10))
            .foregroundStyle(.secondary)
        }
      }
      .frame(maxWidth: .infinity, alignment: .center)
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .help("Open \(label.lowercased())")
  }
}

private struct HealthBadge: View {
  let title: String
  let ready: Bool
  let detail: String
  let action: () -> Void

  var body: some View {
    Button(action: action) {
      VStack(alignment: .leading, spacing: 3) {
        HStack(spacing: 5) {
          Image(systemName: ready ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(ready ? HelperTheme.green : HelperTheme.orange)
          Text(title)
            .font(.system(size: 10, weight: .medium))
            .lineLimit(1)
        }
        Text(detail)
          .font(.system(size: 10))
          .foregroundStyle(.secondary)
          .lineLimit(1)
      }
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(7)
      .contentShape(Rectangle())
    }
    .buttonStyle(.plain)
    .background(HelperTheme.surface, in: RoundedRectangle(cornerRadius: 7))
    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(HelperTheme.hairline))
    .help("Open \(title.lowercased()) status")
  }
}

private struct HelperIconButtonStyle: ButtonStyle {
  func makeBody(configuration: Configuration) -> some View {
    configuration.label
      .frame(width: 28, height: 28)
      .foregroundStyle(configuration.isPressed ? HelperTheme.teal : Color.primary)
      .background(configuration.isPressed ? HelperTheme.teal.opacity(0.12) : Color.clear, in: RoundedRectangle(cornerRadius: 6))
      .contentShape(RoundedRectangle(cornerRadius: 6))
  }
}

struct ApprovalPromptCard: View {
  let request: RequestRecord
  @ObservedObject var model: HelperViewModel
  let actions: HelperMenuActions

  @State private var agentScope = "same-agent"
  @State private var confirmUnlimitedForAll = false

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      HStack(spacing: 6) {
        Text("Credential access request")
          .font(.system(size: 12, weight: .semibold))
          .help("This only approves local credential use; host-agent command prompts are separate.")
          .accessibilityHint("This only approves local credential use; host-agent command prompts are separate.")
        Spacer()
        Text("\(HelperDates.relative(request.createdAt)) ago")
          .font(.system(size: 10))
          .foregroundStyle(.secondary)
      }

      ApprovalTrustPath(request: request)

      VStack(alignment: .leading, spacing: 6) {
        requestLine("Command", commandPreview, monospaced: true)
        requestLine("Handle", helperShortHandle(request.handle), monospaced: true)
        requestLine("Reason", request.reason, monospaced: false)
      }

      Picker("Agent scope", selection: $agentScope) {
        Text("This agent").tag("same-agent")
        Text("All agents").tag("any-agent")
      }
      .pickerStyle(.segmented)
      .labelsHidden()
      .help("Choose which agents can reuse this authorization")

      if model.isDeciding(request.id) {
        HStack(spacing: 7) {
          ProgressView().controlSize(.small)
          Text("Applying decision...")
            .font(.system(size: 11, weight: .medium))
            .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .center)
        .frame(height: 28)
      } else {
        HStack(spacing: 7) {
          Button("Deny", role: .destructive) {
            actions.deny(request.id)
          }
          .keyboardShortcut(.cancelAction)

          approvalOptions

          Spacer(minLength: 2)

          Button("Once") {
            actions.approve(request.id, .oneTime)
          }

          Button("Allow 8 hours") {
            actions.approve(request.id, .timed(minutes: 8 * 60, scope: agentScope))
          }
          .buttonStyle(.borderedProminent)
          .tint(HelperTheme.teal)
        }
        .controlSize(.small)
      }
    }
    .padding(11)
    .background(HelperTheme.raised, in: RoundedRectangle(cornerRadius: 8))
    .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(HelperTheme.orange.opacity(0.26)))
    .confirmationDialog(
      "Allow every agent without an expiry?",
      isPresented: $confirmUnlimitedForAll,
      titleVisibility: .visible
    ) {
      Button("Allow unlimited", role: .destructive) {
        actions.approve(request.id, .unlimited(scope: "any-agent"))
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text("Any agent matching this credential and command policy could reuse the authorization until you revoke it.")
    }
  }

  private var approvalOptions: some View {
    Menu("More") {
      Section("Timed") {
        Button("15 minutes") { approveTimed(15) }
        Button("1 hour") { approveTimed(60) }
        Button("1 day") { approveTimed(24 * 60) }
      }

      Section(agentScope == "same-agent" ? request.agentName : "All agents") {
        Button("Until logout") {
          actions.approve(request.id, .login(scope: agentScope))
        }
        Button("Unlimited") {
          if agentScope == "any-agent" {
            confirmUnlimitedForAll = true
          } else {
            actions.approve(request.id, .unlimited(scope: agentScope))
          }
        }
      }
    }
  }

  private func approveTimed(_ minutes: Int) {
    actions.approve(request.id, .timed(minutes: minutes, scope: agentScope))
  }

  private func requestLine(_ label: String, _ value: String, monospaced: Bool) -> some View {
    HStack(alignment: .top, spacing: 8) {
      Text(label)
        .font(.system(size: 10, weight: .semibold))
        .foregroundStyle(.secondary)
        .frame(width: 51, alignment: .leading)

      Group {
        if monospaced {
          Text(value).font(.system(size: 10, design: .monospaced))
        } else {
          Text(value).font(.system(size: 11))
        }
      }
      .lineLimit(2)
      .textSelection(.enabled)
      Spacer(minLength: 0)
    }
  }

  private var commandPreview: String {
    if request.action.kind == "ssh_session", let target = request.action.ssh?.target {
      let port = request.action.ssh?.port
      let targetLabel = port != nil && port != 22 ? "\(target):\(port!)" : target
      let remote = request.action.args.isEmpty ? "true" : request.action.args.joined(separator: " ")
      return truncated("ssh -> \(targetLabel) · \(remote)")
    }

    return truncated(([request.action.command] + request.action.args).joined(separator: " "))
  }

  private func truncated(_ value: String) -> String {
    if value.count <= 116 { return value }
    return "\(value.prefix(112))..."
  }
}

private struct ApprovalTrustPath: View {
  let request: RequestRecord

  private var flow: ApprovalFlowDescriptor {
    ApprovalFlowDescriptor(request: request)
  }

  var body: some View {
    HStack(spacing: 0) {
      ApprovalIdentityNode(
        image: AgentIconResolver.image(for: request.agentName),
        openSourceIcon: "bot",
        title: request.agentName,
        detail: "Requesting agent",
        tint: HelperTheme.teal
      )

      ApprovalPathConnector()

      ApprovalIdentityNode(
        image: nil,
        openSourceIcon: "terminal",
        title: flow.transportTitle,
        detail: flow.transportDetail,
        tint: HelperTheme.orange
      )

      ApprovalPathConnector()

      ApprovalIdentityNode(
        image: destinationImage,
        openSourceIcon: destinationOpenSourceIcon,
        title: flow.destinationTitle,
        detail: flow.destinationDetail,
        tint: destinationTint
      )
    }
    .padding(.horizontal, 8)
    .padding(.vertical, 10)
    .background(HelperTheme.surface, in: RoundedRectangle(cornerRadius: 7))
    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(HelperTheme.hairline))
    .accessibilityElement(children: .combine)
    .accessibilityLabel("\(request.agentName) requests \(flow.transportTitle) access to \(flow.destinationTitle)")
  }

  private var destinationImage: NSImage? {
    guard flow.destinationKind == .amazonEC2,
          let url = Bundle.main.url(forResource: "AwsEc2", withExtension: "png") else {
      return nil
    }
    return NSImage(contentsOf: url)
  }

  private var destinationOpenSourceIcon: String {
    switch flow.destinationKind {
    case .amazonEC2: return "server"
    case .sshHost: return "server"
    case .localMachine: return "monitor"
    }
  }

  private var destinationTint: Color {
    flow.destinationKind == .amazonEC2 ? HelperTheme.orange : HelperTheme.teal
  }
}

private struct ApprovalIdentityNode: View {
  let image: NSImage?
  let openSourceIcon: String
  let title: String
  let detail: String
  let tint: Color

  var body: some View {
    VStack(spacing: 5) {
      Group {
        if let image {
          Image(nsImage: image)
            .resizable()
            .scaledToFit()
        } else if let icon = OpenSourceIconResolver.image(named: openSourceIcon) {
          Image(nsImage: icon)
            .renderingMode(.template)
            .resizable()
            .scaledToFit()
            .foregroundStyle(tint)
            .padding(6)
        } else {
          Image(systemName: "questionmark")
            .font(.system(size: 17, weight: .semibold))
            .foregroundStyle(tint)
            .padding(6)
        }
      }
      .frame(width: 30, height: 30)
      .background(tint.opacity(0.10), in: RoundedRectangle(cornerRadius: 7))

      Text(title)
        .font(.system(size: 10, weight: .semibold))
        .lineLimit(1)
        .minimumScaleFactor(0.75)
        .frame(maxWidth: .infinity)

      Text(detail)
        .font(.system(size: 9))
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .minimumScaleFactor(0.75)
        .frame(maxWidth: .infinity)
    }
    .frame(width: 88)
  }
}

private enum OpenSourceIconResolver {
  static func image(named name: String) -> NSImage? {
    guard let url = Bundle.main.url(forResource: "Lucide-\(name)", withExtension: "svg"),
          let image = NSImage(contentsOf: url) else {
      return nil
    }

    image.isTemplate = true
    return image
  }
}

private struct ApprovalPathConnector: View {
  var body: some View {
    HStack(spacing: 2) {
      Rectangle()
        .fill(HelperTheme.hairline)
        .frame(height: 1)
      Image(systemName: "chevron.right")
        .font(.system(size: 7, weight: .bold))
        .foregroundStyle(.tertiary)
    }
    .frame(maxWidth: .infinity)
    .offset(y: -17)
    .accessibilityHidden(true)
  }
}

private enum AgentIconResolver {
  private static let bundleIDs: [String: [String]] = [
    "codex": ["com.openai.codex"],
    "cursor": ["com.todesktop.230313mzl4w4u92"],
    "claude": ["com.anthropic.claudefordesktop", "com.anthropic.claude"]
  ]

  static func image(for agentName: String) -> NSImage? {
    let key = agentName.lowercased()
    guard let candidates = bundleIDs.first(where: { key.contains($0.key) })?.value else {
      return nil
    }

    for bundleID in candidates {
      guard let appURL = NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleID) else { continue }
      return NSWorkspace.shared.icon(forFile: appURL.path)
    }
    return nil
  }
}
