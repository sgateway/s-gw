import Foundation
import Observation
import SwiftUI
import UserNotifications

@MainActor
@Observable
final class AppState {
  let cli = CLIRunner()
  let store = StoreReader()
  let updater = UpdateChecker()
  let activity = CommandActivityStore()

  var selectedPanel: PanelID = .overview
  var commandPalettePresented = false
  var status: StatusPayload?
  var handles: [HandleSummary] = []
  var requests: [RequestRecord] = []
  var audit: [AuditEvent] = []
  var agents: [AgentProfile] = []
  var approvalSettings = ApprovalSettings.defaultValue
  var approvalGrants: [ApprovalGrantRecord] = []
  var approvalPolicyRules: [ApprovalPolicyRuleRecord] = []
  var isRefreshing = false
  var lastError: String?
  var lastUpdated: Date?
  var credentialSeverityFilter: SecretSeverity?
  var selectedCredentialHandle: String?
  var addSecretSheetOpen = false
  var operationMessage: String?
  // Requests with an approve/deny decision currently in flight. Used to block a
  // double-fire while the CLI round-trip is running, so a second tap on an
  // already-approved request can't race into a misleading "already approved" toast.
  var decidingRequestIds: Set<String> = []
  var availableUpdate: ReleaseInfo?
  var updateState: UpdateState = .idle
  var updateBannerDismissed = false
  var updateRepository = savedSgwUpdateRepository() {
    didSet {
      UserDefaults.standard.set(updateRepository, forKey: UpdateChecker.repositoryDefaultsKey)
    }
  }

  @ObservationIgnored private var refreshTask: Task<Void, Never>?
  @ObservationIgnored private var updateTask: Task<Void, Never>?
  @ObservationIgnored private let updateCheckInterval: TimeInterval = 6 * 60 * 60
  @ObservationIgnored private var seenPendingRequestIds = Set<String>()

  var pendingRequests: [RequestRecord] {
    requests.filter { $0.state == .pending }
      .sorted { requestSortKey($0) > requestSortKey($1) }
  }

  var daemonRunning: Bool {
    status?.launchAgents.console.loaded == true
  }

  var unlockActive: Bool {
    let source = status?.unlock.activeSource ?? "none"
    return source != "none" && source != "unknown"
  }

  // Prefer the CLI's own readiness verdict (it knows about build artifacts + unlock source).
  // Fall back to the unlock check so an older `s-gw` without the `ready` field still works.
  var isReady: Bool {
    if let ready = status?.ready { return ready }
    return unlockActive
  }

  var readinessBlockers: [String] {
    status?.readiness?.blockers ?? []
  }

  var readinessSummary: String? {
    status?.readiness?.summary
  }

  var highRiskCount: Int {
    handles.filter { $0.severityValue >= .high }.count
  }

  var usageFlowRows: [UsageFlowRow] {
    let credentialNames = Dictionary(uniqueKeysWithValues: handles.map { ($0.handle, $0.name) })
    var rows: [String: UsageFlowRow] = [:]
    for request in requests {
      let key = "\(request.agentName)\n\(request.handle)\n\(request.actionLabel)"
      if rows[key] == nil {
        rows[key] = UsageFlowRow(
          agent: request.agentName,
          handle: request.handle,
          credential: credentialNames[request.handle] ?? request.handle,
          action: request.actionLabel,
          command: request.commandName,
          target: request.actionTarget,
          count: 0,
          lastSeen: request.updatedAt,
          pending: 0,
          approved: 0,
          executing: 0,
          executed: 0,
          denied: 0,
          failed: 0
        )
      }
      if var row = rows[key] {
        row.record(request)
        rows[key] = row
      }
    }
    return rows.values.sorted {
      if $0.count == $1.count {
        return $0.lastSeen > $1.lastSeen
      }
      return $0.count > $1.count
    }
  }

  var menuBarState: MenuBarState {
    if !daemonRunning { return .offline }
    if !unlockActive { return .locked }
    if !pendingRequests.isEmpty { return .pending(pendingRequests.count) }
    return .healthy
  }

  func start() {
    if refreshTask != nil {
      return
    }
    Task {
      await refresh()
    }
    refreshTask = Task { [weak self] in
      while !Task.isCancelled {
        try? await Task.sleep(for: .seconds(4))
        await self?.refreshQuietly()
      }
    }
    updateTask = Task { [weak self] in
      while !Task.isCancelled {
        await self?.checkForUpdates()
        try? await Task.sleep(for: .seconds(60 * 60))
      }
    }
    UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .badge, .sound]) { _, _ in }
  }

  func stop() {
    refreshTask?.cancel()
    refreshTask = nil
    updateTask?.cancel()
    updateTask = nil
  }

  func refreshQuietly() async {
    await refresh(showSpinner: false)
  }

  func refresh(showSpinner: Bool = true) async {
    if showSpinner {
      isRefreshing = true
    }
    defer {
      isRefreshing = false
      lastUpdated = Date()
    }

    do {
      let newStatus = try await cli.runJSON(StatusPayload.self, arguments: ["status"])
      async let handleList = cli.runJSON([HandleSummary].self, arguments: ["secret", "list"])
      async let requestList = cli.runJSON([RequestRecord].self, arguments: ["requests"])
      async let agentList = cli.runJSON([AgentProfile].self, arguments: ["agent", "list"])
      async let approval = cli.runJSON(ApprovalSettings.self, arguments: ["approval", "settings"])
      async let grants = cli.runJSON([ApprovalGrantRecord].self, arguments: ["approval", "grants"])
      async let policies = cli.runJSON([ApprovalPolicyRuleRecord].self, arguments: ["approval", "policy", "list"])
      async let auditList = store.auditEvents(storePath: newStatus.storePath)

      status = newStatus
      handles = try await handleList.sorted { $0.updatedAt > $1.updatedAt }
      requests = try await requestList.sorted { requestSortKey($0) > requestSortKey($1) }
      agents = (try? await agentList.sorted { $0.name < $1.name }) ?? []
      approvalSettings = (try? await approval) ?? approvalSettings
      approvalGrants = (try? await grants.sorted { $0.updatedAt > $1.updatedAt }) ?? []
      approvalPolicyRules = (try? await policies.sorted { $0.priority < $1.priority }) ?? []
      audit = await auditList.sorted { $0.ts > $1.ts }
      routeToApprovalsIfNeeded()
      lastError = nil
    } catch {
      lastError = error.localizedDescription
    }
  }

  private func routeToApprovalsIfNeeded() {
    let pendingIds = Set(pendingRequests.map(\.id))
    defer { seenPendingRequestIds = pendingIds }

    if pendingIds.isEmpty {
      return
    }

    let newIds = pendingIds.subtracting(seenPendingRequestIds)
    if !newIds.isEmpty || selectedPanel == .overview {
      selectedPanel = .approvals
    }
  }

  func isDeciding(_ requestId: String) -> Bool {
    decidingRequestIds.contains(requestId)
  }

  func approve(_ request: RequestRecord, choice: ApprovalChoice = .oneTime) {
    decide(request, approving: true, choice: choice)
  }

  func deny(_ request: RequestRecord) {
    decide(request, approving: false, choice: nil)
  }

  func deleteCredential(_ handle: HandleSummary) {
    Task {
      let result = await runCommand(
        title: "Delete credential",
        category: "Credentials",
        arguments: ["secret", "delete", handle.handle],
        sideEffects: ["Deletes the local handle and revokes matching reusable approvals."],
        refreshAfter: false
      )
      if result.succeeded {
        operationMessage = "Deleted \(handle.name)"
        if selectedCredentialHandle == handle.handle {
          selectedCredentialHandle = nil
        }
        await refresh()
      } else {
        operationMessage = result.output
      }
    }
  }

  // Single guarded path for both approve and deny so the in-flight check and the
  // success/failure messaging can't drift apart between the two decisions.
  private func decide(_ request: RequestRecord, approving: Bool, choice: ApprovalChoice?) {
    // Ignore a repeat tap (or an approve-then-deny race) while a decision is running.
    guard !decidingRequestIds.contains(request.id) else { return }
    decidingRequestIds.insert(request.id)

    Task {
      defer { decidingRequestIds.remove(request.id) }
      let verb = approving ? "approve" : "deny"
      var args = [verb, request.id]
      if approving, let choice {
        args += ["--mode", choice.mode.rawValue, "--agent-scope", choice.agentScope.rawValue]
        if let durationMs = choice.durationMs {
          args += ["--duration-ms", String(durationMs)]
        }
      }

      let result = await runCommand(
        title: approving ? "Approve request" : "Deny request",
        category: "Approvals",
        arguments: args,
        sideEffects: approving ? ["Authorizes this local secret-backed action."] : ["Denies this pending local request."],
        refreshAfter: false
      )
      if result.succeeded {
        if approving, let choice {
          operationMessage = "Authorized \(request.agentName) \(choice.resultLabel)"
        } else {
          operationMessage = "Denied \(request.id)"
        }
      } else {
        operationMessage = result.output
      }
      await refresh()
    }
  }

  func setApprovalMode(_ mode: ApprovalMode) {
    let next = ApprovalSettings(mode: mode, durationMs: approvalSettings.durationMs)
    saveApprovalSettings(next)
  }

  func setApprovalDuration(_ durationMs: Int) {
    let next = ApprovalSettings(mode: approvalSettings.mode, durationMs: durationMs)
    saveApprovalSettings(next)
  }

  private func saveApprovalSettings(_ next: ApprovalSettings) {
    approvalSettings = next
    Task {
      let result = await runCommand(
        title: "Update approval settings",
        category: "Approvals",
        arguments: [
          "approval", "set",
          "--mode", next.mode.rawValue,
          "--duration-ms", String(next.durationMs)
        ],
        sideEffects: ["Changes the default approval reuse behavior."],
        refreshAfter: false
      )
      operationMessage = result.succeeded ? "Approval settings updated" : result.output
      await refresh()
    }
  }

  func revokeApprovalGrant(_ grant: ApprovalGrantRecord) {
    Task {
      let result = await runCommand(
        title: "Revoke reusable approval",
        category: "Approvals",
        arguments: ["approval", "revoke", grant.id],
        sideEffects: ["Future matching requests will ask again."],
        refreshAfter: false
      )
      operationMessage = result.succeeded ? "Revoked reusable approval" : result.output
      await refresh()
    }
  }

  func clearApprovalGrants() {
    Task {
      let result = await runCommand(
        title: "Clear reusable approvals",
        category: "Approvals",
        arguments: ["approval", "clear"],
        sideEffects: ["Revokes every reusable authorization grant."],
        refreshAfter: false
      )
      operationMessage = result.succeeded ? "Revoked all reusable approvals" : result.output
      await refresh()
    }
  }

  func addApprovalPolicyRule(_ draft: ApprovalPolicyDraft) async -> Bool {
    var args = [
      "approval", "policy", "add",
      "--name", draft.name,
      "--decision", draft.decision.rawValue,
      "--priority", String(draft.priority)
    ]
    if !draft.enabled {
      args.append("--disabled")
    }
    if !draft.handle.isEmpty {
      args += ["--handle", draft.handle]
    }
    if !draft.agent.isEmpty {
      args += ["--agent", draft.agent]
    }
    if !draft.command.isEmpty {
      args += ["--command", draft.command]
    }
    if !draft.injectEnv.isEmpty {
      args += ["--inject-env", draft.injectEnv]
    }
    if !draft.actionKind.isEmpty {
      args += ["--action-kind", draft.actionKind]
    }
    if !draft.sshTarget.isEmpty {
      args += ["--ssh-target", draft.sshTarget]
    }
    if draft.sshPort > 0 {
      args += ["--ssh-port", String(draft.sshPort)]
    }
    if let severity = draft.minSeverity {
      args += ["--min-severity", severity.rawValue]
    }
    if draft.durationMs > 0 {
      args += ["--duration-ms", String(draft.durationMs)]
    }

    let result = await runCommand(
      title: "Add approval policy",
      category: "Policies",
      arguments: args,
      sideEffects: ["Adds a local authorization policy rule."],
      refreshAfter: false
    )
    if result.succeeded {
      operationMessage = "Policy rule added"
      await refresh()
      return true
    }
    operationMessage = result.output
    return false
  }

  func setApprovalPolicyRuleEnabled(_ rule: ApprovalPolicyRuleRecord, enabled: Bool) {
    Task {
      let result = await runCommand(
        title: enabled ? "Enable approval policy" : "Disable approval policy",
        category: "Policies",
        arguments: [
          "approval", "policy", enabled ? "enable" : "disable",
          "--id", rule.id
        ],
        sideEffects: ["Changes local policy matching for future requests."],
        refreshAfter: false
      )
      operationMessage = result.succeeded ? "\(enabled ? "Enabled" : "Disabled") policy rule" : result.output
      await refresh()
    }
  }

  func deleteApprovalPolicyRule(_ rule: ApprovalPolicyRuleRecord) {
    Task {
      let result = await runCommand(
        title: "Delete approval policy",
        category: "Policies",
        arguments: ["approval", "policy", "delete", "--id", rule.id],
        sideEffects: ["Removes the rule from future authorization decisions."],
        refreshAfter: false
      )
      operationMessage = result.succeeded ? "Deleted policy rule" : result.output
      await refresh()
    }
  }

  func addSecret(_ draft: NewSecretDraft) async -> Bool {
    var args = [
      "secret", "add",
      "--name", draft.name,
      "--type", draft.type,
      "--value-stdin"
    ]
    if !draft.injectEnv.isEmpty {
      args += ["--inject-env", draft.injectEnv]
    }
    if !draft.allowedCommand.isEmpty {
      args += ["--allow-command", draft.allowedCommand]
    }

    let result = await runCommand(
      title: "Add local secret",
      category: "Credentials",
      arguments: args,
      input: draft.value,
      sideEffects: ["Stores a tokenized handle in the local encrypted ledger."],
      refreshAfter: false
    )
    if result.succeeded {
      operationMessage = "Secret added locally"
      await refresh()
      return true
    }
    operationMessage = result.output
    return false
  }

  func runSetup() {
    Task {
      let result = await runRegisteredCommand(id: "setup", fallbackTitle: "Run local setup", fallbackArguments: ["setup", "--no-open-app"])
      operationMessage = result.succeeded ? "Setup completed" : result.output
      await refresh()
    }
  }

  func startServices() {
    Task {
      let result = await runRegisteredCommand(id: "start", fallbackTitle: "Start services", fallbackArguments: ["start", "--no-open-app"])
      operationMessage = result.succeeded ? "Services started" : result.output
      await refresh()
    }
  }

  func stopServices() {
    Task {
      let result = await runRegisteredCommand(id: "stop", fallbackTitle: "Stop services", fallbackArguments: ["stop"])
      operationMessage = result.succeeded ? "Services stopped" : result.output
      await refresh()
    }
  }

  func openWebConsole() {
    guard let urlText = status?.consoleUrl, let url = URL(string: urlText) else {
      return
    }
    NSWorkspace.shared.open(url)
  }

  func consoleURL(for panel: PanelID? = nil) -> URL? {
    guard
      let urlText = status?.consoleUrl,
      var components = URLComponents(string: urlText)
    else {
      return nil
    }

    let selected = panel ?? selectedPanel
    components.path = "/" + selected.consoleRoute
    components.queryItems = [URLQueryItem(name: "native-shell", value: "1")]
    return components.url
  }

  func usageFlowConsoleURL(embed: Bool = false, compact: Bool = false) -> URL? {
    guard
      let urlText = status?.consoleUrl,
      var components = URLComponents(string: urlText)
    else {
      return nil
    }

    var items = components.queryItems ?? []
    items.removeAll { $0.name == "view" || $0.name == "embed" || $0.name == "compact" }
    items.append(URLQueryItem(name: "view", value: "usage-flow"))
    if embed {
      items.append(URLQueryItem(name: "embed", value: "usage-flow"))
    }
    if compact {
      items.append(URLQueryItem(name: "compact", value: "1"))
    }
    components.queryItems = items
    return components.url
  }

  func openUsageFlowConsole() {
    guard let url = usageFlowConsoleURL() else {
      return
    }
    NSWorkspace.shared.open(url)
  }

  func revealStore() {
    guard let path = status?.storePath else {
      return
    }
    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
  }

  func copySnippet(for agent: AgentProfile) {
    Task {
      let result = await runCommand(
        title: "Copy \(agent.name) MCP snippet",
        category: "Agents",
        arguments: ["agent", "mcp-snippet", agent.id],
        suggestedNextAction: "Paste the snippet into the agent's MCP configuration.",
        refreshAfter: false
      )
      if result.succeeded {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(result.output, forType: .string)
        operationMessage = "Copied \(agent.name) MCP snippet"
      } else {
        operationMessage = result.output
      }
    }
  }

  @discardableResult
  func runCommand(_ definition: SgwCommandDefinition, refreshAfter: Bool = true) async -> CLIResult {
    await runCommand(
      title: definition.title,
      category: definition.category,
      arguments: definition.arguments,
      sideEffects: definition.sideEffects,
      suggestedNextAction: definition.suggestedNextAction,
      refreshAfter: refreshAfter
    )
  }

  @discardableResult
  func runCommand(
    title: String,
    category: String,
    arguments: [String],
    input: String? = nil,
    sideEffects: [String] = [],
    suggestedNextAction: String? = nil,
    refreshAfter: Bool = true
  ) async -> CLIResult {
    let runID = activity.begin(
      title: title,
      category: category,
      arguments: arguments,
      sideEffects: sideEffects,
      suggestedNextAction: suggestedNextAction
    )
    let result = await cli.run(arguments: arguments, input: input, runID: runID)
    activity.finish(id: runID, result: result)
    operationMessage = result.succeeded ? "\(title) finished" : result.output
    if refreshAfter {
      await refresh(showSpinner: false)
    }
    return result
  }

  func cancelCommand(_ record: CommandActivityRecord) {
    Task {
      await cli.cancel(runID: record.id)
      activity.markCancelled(id: record.id)
    }
  }

  private func runRegisteredCommand(id: String, fallbackTitle: String, fallbackArguments: [String]) async -> CLIResult {
    if let command = CommandRegistry.command(id: id) {
      return await runCommand(command, refreshAfter: false)
    }
    return await runCommand(
      title: fallbackTitle,
      category: "Setup",
      arguments: fallbackArguments,
      refreshAfter: false
    )
  }

  func cliPathForDisplay() async -> String {
    await cli.locateBinaryPathForDisplay()
  }

  func checkForUpdates(force: Bool = false) async {
    if updateState.isBusy {
      return
    }
    if !force && !shouldCheckForUpdates() {
      return
    }

    let repo = updateRepository.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !repo.isEmpty, repo.contains("/") else {
      updateState = force ? .failed("Set a GitHub release repository first.") : .idle
      return
    }

    updateState = .checking
    let release = await updater.latestRelease(repository: repo)
    UserDefaults.standard.set(Date().timeIntervalSince1970, forKey: UpdateChecker.lastCheckDefaultsKey)

    guard let release else {
      updateState = force ? .failed("Could not check for updates.") : .idle
      if force {
        operationMessage = "Could not check for updates."
      }
      return
    }

    if UpdateChecker.isNewer(release.version, than: UpdateChecker.currentVersion) {
      if availableUpdate?.version != release.version {
        updateBannerDismissed = false
      }
      availableUpdate = release
      updateState = .idle
      if force {
        operationMessage = "s-gw \(release.version) is available"
      }
      return
    }

    availableUpdate = nil
    updateBannerDismissed = false
    updateState = .idle
    if force {
      operationMessage = "s-gw is up to date"
    }
  }

  func dismissUpdateBanner() {
    updateBannerDismissed = true
  }

  func openAvailableRelease() {
    guard let text = availableUpdate?.htmlURL, let url = URL(string: text) else {
      return
    }
    NSWorkspace.shared.open(url)
  }

  func installAvailableUpdate() {
    guard let release = availableUpdate else {
      return
    }

    Task {
      updateState = .downloading
      let failure = await updater.downloadAndInstall(release) { [weak self] state in
        Task { @MainActor in
          self?.updateState = state
        }
      }

      if let failure {
        updateState = .failed(failure)
        operationMessage = failure
      }
    }
  }

  private func shouldCheckForUpdates() -> Bool {
    let lastCheck = UserDefaults.standard.double(forKey: UpdateChecker.lastCheckDefaultsKey)
    if lastCheck <= 0 {
      return true
    }
    return Date().timeIntervalSince1970 - lastCheck > updateCheckInterval
  }

}

private extension PanelID {
  var consoleRoute: String {
    switch self {
    case .overview: "overview"
    case .usageFlow: "usage-flow"
    case .approvals: "approvals"
    case .credentials: "credentials"
    case .audit: "activity"
    case .activity: "activity"
    case .policies: "policies"
    case .agents: "agents"
    case .setup: "settings"
    }
  }
}

extension Notification.Name {
  static let sgwRefreshPanel = Notification.Name("sgwRefreshPanel")
  static let sgwOpenMainWindow = Notification.Name("com.s-gw.sgw.openMainWindow")
}

private func savedSgwUpdateRepository() -> String {
  let saved = UserDefaults.standard.string(forKey: UpdateChecker.repositoryDefaultsKey)
  return saved ?? UpdateChecker.defaultRepository
}
