import Combine
import Foundation

@MainActor
final class HelperViewModel: ObservableObject {
  @Published private(set) var state = HelperState()
  @Published private(set) var countMode: StatusCountMode
  @Published private(set) var isRefreshing = false
  @Published private(set) var decidingRequestIds = Set<String>()
  @Published private(set) var feedback: DecisionFeedback?

  private var feedbackTask: Task<Void, Never>?

  init(countMode: StatusCountMode) {
    self.countMode = countMode
  }

  var contentSize: NSSize {
    HelperPopoverMetrics.size(for: state)
  }

  func beginRefresh() {
    isRefreshing = true
  }

  func apply(_ snapshot: HelperState) {
    state = snapshot
    isRefreshing = false
  }

  func finishRefreshWithoutUpdate() {
    isRefreshing = false
  }

  func setCountMode(_ mode: StatusCountMode) {
    countMode = mode
  }

  func setDecidingRequestIds(_ ids: Set<String>) {
    decidingRequestIds = ids
  }

  func isDeciding(_ requestID: String) -> Bool {
    decidingRequestIds.contains(requestID)
  }

  func showFeedback(_ outcome: DecisionOutcome) {
    feedbackTask?.cancel()
    let next = DecisionFeedback(
      title: outcome.title,
      message: outcome.body,
      succeeded: outcome.succeeded
    )
    feedback = next

    feedbackTask = Task { [weak self] in
      try? await Task.sleep(for: .seconds(4))
      guard !Task.isCancelled, self?.feedback?.id == next.id else { return }
      self?.feedback = nil
    }
  }
}

@MainActor
final class DecisionController {
  private nonisolated let runCli: @Sendable ([String]) -> CliRunResult
  private let notify: (DecisionOutcome) -> Void
  private let afterDecision: () -> Void
  private let onInFlightChange: (Set<String>) -> Void

  private(set) var decidingRequestIds = Set<String>()

  init(
    runCli: @escaping @Sendable ([String]) -> CliRunResult,
    notify: @escaping (DecisionOutcome) -> Void,
    afterDecision: @escaping () -> Void,
    onInFlightChange: @escaping (Set<String>) -> Void = { _ in }
  ) {
    self.runCli = runCli
    self.notify = notify
    self.afterDecision = afterDecision
    self.onInFlightChange = onInFlightChange
  }

  func isDeciding(_ id: String) -> Bool {
    decidingRequestIds.contains(id)
  }

  func approve(_ id: String, choice: ApprovalChoice = .oneTime) {
    decide(
      id,
      args: ["approve", id] + choice.cliArgs,
      successTitle: "s-gw approved",
      successBody: "Approved request \(id).",
      failureTitle: "Approve failed"
    )
  }

  func approvePolicy(_ id: String) {
    decide(
      id,
      args: ["approve-policy", id],
      successTitle: "s-gw policy added",
      successBody: "Allowed this request scope and approved request \(id).",
      failureTitle: "Allow policy failed"
    )
  }

  func deny(_ id: String) {
    decide(
      id,
      args: ["deny", id],
      successTitle: "s-gw denied",
      successBody: "Denied request \(id).",
      failureTitle: "Deny failed"
    )
  }

  private func decide(
    _ id: String,
    args: [String],
    successTitle: String,
    successBody: String,
    failureTitle: String
  ) {
    guard !decidingRequestIds.contains(id) else { return }
    decidingRequestIds.insert(id)
    onInFlightChange(decidingRequestIds)

    let run = runCli

    Task {
      let result = await Task.detached { run(args) }.value
      self.decidingRequestIds.remove(id)
      self.onInFlightChange(self.decidingRequestIds)

      if result.ok {
        self.notify(DecisionOutcome(
          title: successTitle,
          body: successBody,
          succeeded: true
        ))
      } else {
        self.notify(DecisionOutcome(
          title: failureTitle,
          body: Self.failureReason(result.stderr ?? result.stdout, id: id),
          succeeded: false
        ))
      }

      self.afterDecision()
    }
  }

  nonisolated static func failureReason(_ output: String?, id: String) -> String {
    let trimmed = output?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if trimmed.isEmpty {
      return "Could not update request \(id). It may already be approved, denied, or the store is locked."
    }

    if let data = trimmed.data(using: .utf8),
       let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
       let message = object["error"] as? String, !message.isEmpty {
      return message
    }

    let lastLine = trimmed.split(separator: "\n").last.map(String.init) ?? trimmed
    let cleaned = lastLine.hasPrefix("s-gw error: ")
      ? String(lastLine.dropFirst("s-gw error: ".count))
      : lastLine
    return String(cleaned.prefix(180))
  }
}
