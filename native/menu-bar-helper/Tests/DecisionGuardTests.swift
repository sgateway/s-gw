import Foundation

// Standalone test driver for the menu-bar helper's approve/deny decision core.
//
// This compiles against the real production sources (built with -DSGW_TEST so
// the shipping @main is excluded), not a re-implementation.
// It exercises the DecisionController that owns the approve/deny in-flight guard
// and the honest-failure messaging — the one approval surface that earlier
// iterations could verify only via `swift build` + a CLI-error-contract check,
// never driven against the shipping code.
//
// The controller's CLI hook is injected, so the test points it at a controllable
// fake that logs each invocation by verb. To hold a decision "in flight" the fake
// blocks on a FIFO, exactly like a user double-clicking Approve before the first
// CLI call returns.

private func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data(("FAIL: " + message + "\n").utf8))
  exit(1)
}

private func check(_ cond: Bool, _ message: String) {
  if !cond { fail(message) }
}

private final class FakeHelperUpdateRunner: @unchecked Sendable {
  private let lock = NSLock()
  private var results: [CliRunResult]

  init(_ results: [CliRunResult]) {
    self.results = results
  }

  func run() -> CliRunResult {
    lock.lock()
    defer { lock.unlock() }
    if results.isEmpty { return CliRunResult(ok: false, stdout: nil, stderr: "no result") }
    return results.removeFirst()
  }
}

private func helperUpdateResult(_ version: String, available: Bool = true) -> CliRunResult {
  let json = """
  {"checked":true,"currentVersion":"0.1.2","latestVersion":"\(version)","available":\(available),"releaseUrl":"https://example.test/releases/v\(version)"}
  """
  return CliRunResult(ok: true, stdout: json, stderr: nil)
}

// Scratch dir holding the fake CLI, its invocation log, and the FIFO it blocks on.
fileprivate struct Scratch {
  let dir: URL
  let fakeCli: URL
  let invocationLog: URL
  let gate: URL

  init() {
    let base = URL(fileURLWithPath: NSTemporaryDirectory())
      .appendingPathComponent("sgw-menubar-test-\(ProcessInfo.processInfo.processIdentifier)", isDirectory: true)
    try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
    dir = base
    fakeCli = base.appendingPathComponent("fake-s-gw.sh")
    invocationLog = base.appendingPathComponent("invocations.log")
    gate = base.appendingPathComponent("gate.fifo")
    mkfifo(gate.path, 0o600)

    // approve/deny block on the FIFO so the decision is genuinely in flight;
    // any other verb returns at once.
    let script = """
    #!/bin/zsh
    verb="$1"
    print -- "$verb" >> "\(invocationLog.path)"
    case "$verb" in
      approve|deny)
        read _line < "\(gate.path)"
        print -- '{"ok":true}'
        exit 0
        ;;
      *)
        print -- '{}'
        exit 0
        ;;
    esac
    """
    try? script.write(to: fakeCli, atomically: true, encoding: .utf8)
    chmod(fakeCli.path, 0o755)
  }

  func decisionCount() -> Int {
    verbs().filter { $0 == "approve" || $0 == "deny" }.count
  }

  func verbs() -> [String] {
    guard let text = try? String(contentsOf: invocationLog, encoding: .utf8) else { return [] }
    return text.split(whereSeparator: \.isNewline).map { String($0) }
  }

  func releaseOneInFlight() {
    if let handle = FileHandle(forWritingAtPath: gate.path) {
      handle.write(Data("go\n".utf8))
      try? handle.close()
    }
  }

  func cleanup() {
    try? FileManager.default.removeItem(at: dir)
  }
}

// Run the real fake CLI through a Process, the same way the helper's runCliResult
// does (separate stdout/stderr pipes drained before waitUntilExit). The
// DecisionController in the real source uses the app's runCliResult; the test
// supplies an equivalent so it can target the fake CLI without an AppKit delegate.
private func runFakeCli(_ cliPath: String, _ args: [String]) -> CliRunResult {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: cliPath)
  process.arguments = args
  let out = Pipe()
  let err = Pipe()
  process.standardOutput = out
  process.standardError = err
  do {
    try process.run()
  } catch {
    return CliRunResult(ok: false, stdout: nil, stderr: error.localizedDescription)
  }
  let outData = out.fileHandleForReading.readDataToEndOfFile()
  let errData = err.fileHandleForReading.readDataToEndOfFile()
  process.waitUntilExit()
  return CliRunResult(
    ok: process.terminationStatus == 0,
    stdout: String(data: outData, encoding: .utf8),
    stderr: String(data: errData, encoding: .utf8)
  )
}

@MainActor
private func waitUntil(_ timeoutSeconds: Double, _ predicate: () -> Bool) async -> Bool {
  let deadline = Date().addingTimeInterval(timeoutSeconds)
  while Date() < deadline {
    if predicate() { return true }
    try? await Task.sleep(for: .milliseconds(20))
  }
  return predicate()
}

@main
struct DecisionGuardTests {
  static func main() async {
    let scratch = Scratch()
    defer { scratch.cleanup() }

    await runInFlightGuardTest(scratch)
    await runGuardReleaseTest(scratch)
    runFailureReasonTest()
    runRouteAndSizingTest()
    runApprovalFlowTest()
    runLaunchLockTest(scratch)
    await runPersistentUpdateMonitorTest()

    print("ALL_MENUBAR_TESTS_OK")
  }

  // Test 1: a double-fire while a decision is in flight reaches the CLI exactly
  // once, and the toast is the honest success — not a "already approved" failure.
  @MainActor
  fileprivate static func runInFlightGuardTest(_ scratch: Scratch) async {
    var outcomes: [DecisionOutcome] = []
    let controller = DecisionController(
      runCli: { args in runFakeCli(scratch.fakeCli.path, args) },
      notify: { outcomes.append($0) },
      afterDecision: {}
    )

    // decide() runs the CLI off the main actor, so this returns immediately and
    // the decision is held in flight (blocking on the FIFO). The competing taps
    // below then race exactly as in the live popover.
    let id = "req-guard"
    controller.approve(id)

    let inFlight = await waitUntil(3.0) { scratch.decisionCount() == 1 && controller.isDeciding(id) }
    check(inFlight, "first approve should reach the CLI and be marked in flight")

    // Competing taps a user could fire during the round-trip.
    controller.approve(id)
    controller.deny(id)
    try? await Task.sleep(for: .milliseconds(150))

    check(scratch.decisionCount() == 1,
          "in-flight guard must collapse the double-fire to ONE decision call, saw \(scratch.decisionCount()): \(scratch.verbs())")

    scratch.releaseOneInFlight()

    let cleared = await waitUntil(3.0) { !controller.isDeciding(id) }
    check(cleared, "request id should be released after the decision completes")

    let success = outcomes.first { $0.succeeded }
    check(success != nil, "an honest success outcome should have been emitted")
    check(success?.title == "s-gw approved",
          "success title expected, got: \(success?.title ?? "nil")")
    // The competing taps must NOT have produced a misleading failure toast.
    check(!outcomes.contains { !$0.succeeded },
          "no failure toast should fire for taps the guard suppressed, got: \(outcomes.map(\.title))")
    check(scratch.decisionCount() == 1,
          "still exactly one decision call after release, saw \(scratch.decisionCount()): \(scratch.verbs())")
  }

  // Test 2: proves the harness genuinely measures CLI invocations (so Test 1's
  // "1" means something) and that the guard releases — a separate later decision
  // on a fresh id DOES reach the CLI.
  @MainActor
  fileprivate static func runGuardReleaseTest(_ scratch: Scratch) async {
    let before = scratch.decisionCount()
    let controller = DecisionController(
      runCli: { args in runFakeCli(scratch.fakeCli.path, args) },
      notify: { _ in },
      afterDecision: {}
    )
    let id = "req-release"
    controller.deny(id)
    let started = await waitUntil(3.0) { scratch.decisionCount() == before + 1 }
    check(started, "a separate later decision must reach the CLI (guard is not a permanent lockout)")
    scratch.releaseOneInFlight()
    let done = await waitUntil(3.0) { !controller.isDeciding(id) }
    check(done, "second decision should clear its in-flight id too")
  }

  // Test 3: the honest-failure parser pulls a clean reason out of the CLI's real
  // error shapes (JSON {"error":...} and the "s-gw error: " stderr prefix), and
  // falls back sanely on empty output.
  static func runFailureReasonTest() {
    let jsonReason = DecisionController.failureReason("{\"error\":\"Only pending requests can be approved. Current state: denied\"}", id: "r1")
    check(jsonReason == "Only pending requests can be approved. Current state: denied",
          "JSON error message should be extracted, got: \(jsonReason)")

    let prefixed = DecisionController.failureReason("noise\ns-gw error: Unknown request: bogus", id: "r2")
    check(prefixed == "Unknown request: bogus",
          "the s-gw error: prefix should be stripped, got: \(prefixed)")

    let empty = DecisionController.failureReason("   \n  ", id: "r3")
    check(empty.contains("r3") && empty.contains("locked"),
          "empty output should fall back to an actionable hint, got: \(empty)")
  }

  static func runRouteAndSizingTest() {
    check(HelperRoute.parse(" credentials ") == .credentials,
          "helper routes should trim and validate destinations")
    check(HelperRoute.parse("admin") == nil,
          "unknown helper routes must be rejected")

    var idle = HelperState()
    let idleSize = HelperPopoverMetrics.size(for: idle)
    check(idleSize.width == 400 && idleSize.height == 420,
          "idle popover should use the compact 400x420 layout")

    idle.pending = [RequestRecord(
      id: "req-size",
      handle: "s-gw:test",
      reason: "Test",
      recordedAgentName: "Codex",
      state: "pending",
      action: CommandAction(kind: nil, command: "/usr/bin/true", args: [], injectEnv: "TOKEN", ssh: nil),
      createdAt: "2026-07-02T00:00:00Z",
      updatedAt: nil
    )]
    let pendingSize = HelperPopoverMetrics.size(for: idle)
    check(pendingSize.width == 400 && pendingSize.height == 500,
          "pending popover should expand to 400x500")
  }

  @MainActor
  static func runPersistentUpdateMonitorTest() async {
    let suite = "com.s-gw.tests.helper-updates.\(UUID().uuidString)"
    let defaults = UserDefaults(suiteName: suite)!
    defaults.removePersistentDomain(forName: suite)
    defer { defaults.removePersistentDomain(forName: suite) }
    var notified: [String] = []
    let firstRunner = FakeHelperUpdateRunner([
      helperUpdateResult("9.1.0"),
      helperUpdateResult("9.1.0")
    ])
    let first = UpdateMonitor(
      defaults: defaults,
      runCheck: { firstRunner.run() },
      notify: { update in notified.append(update.version); return true }
    )

    await first.checkNow()
    await first.checkNow()
    check(notified == ["9.1.0"], "the helper should notify once per available version")

    let afterRestartRunner = FakeHelperUpdateRunner([
      helperUpdateResult("9.1.0"),
      helperUpdateResult("9.2.0")
    ])
    let afterRestart = UpdateMonitor(
      defaults: defaults,
      runCheck: { afterRestartRunner.run() },
      notify: { update in notified.append(update.version); return true }
    )
    await afterRestart.checkNow()
    await afterRestart.checkNow()
    check(notified == ["9.1.0", "9.2.0"],
          "persisted update history should suppress a duplicate after helper restart")

    let retryRunner = FakeHelperUpdateRunner([
      CliRunResult(ok: false, stdout: nil, stderr: "offline"),
      CliRunResult(ok: true, stdout: "not-json", stderr: nil),
      helperUpdateResult("9.3.0")
    ])
    let retry = UpdateMonitor(
      defaults: defaults,
      runCheck: { retryRunner.run() },
      notify: { update in notified.append(update.version); return true }
    )
    await retry.checkNow()
    await retry.checkNow()
    await retry.checkNow()
    check(notified.last == "9.3.0", "failed and invalid checks must retry without consuming a version")
  }

  static func runApprovalFlowTest() {
    let sshRequest = RequestRecord(
      id: "req-flow",
      handle: "s-gw:private-key:prod-api-01",
      reason: "Connect to AWS EC2 instance for deployment",
      recordedAgentName: "Codex",
      state: "pending",
      action: CommandAction(
        kind: "ssh_session",
        command: "ssh",
        args: ["sudo", "systemctl", "restart", "api"],
        injectEnv: "",
        ssh: SshSessionSpec(target: "ec2-user@prod-api-01", port: 22)
      ),
      createdAt: "2026-07-02T00:00:00Z",
      updatedAt: nil
    )

    let sshFlow = ApprovalFlowDescriptor(request: sshRequest)
    check(sshFlow.transportTitle == "SSH", "SSH requests should identify the transport")
    check(sshFlow.destinationTitle == "prod-api-01", "SSH user names should be removed from the destination")
    check(sshFlow.destinationKind == .amazonEC2, "AWS SSH requests should use the EC2 destination")

    let localRequest = RequestRecord(
      id: "req-local",
      handle: "s-gw:token:local",
      reason: "Run a local command",
      recordedAgentName: "Agent",
      state: "pending",
      action: CommandAction(kind: "env_command", command: "/usr/bin/curl", args: [], injectEnv: "TOKEN", ssh: nil),
      createdAt: "2026-07-02T00:00:00Z",
      updatedAt: nil
    )
    let localFlow = ApprovalFlowDescriptor(request: localRequest)
    check(localFlow.destinationKind == .localMachine, "ordinary commands should not be labeled as cloud access")
  }

  @MainActor
  fileprivate static func runLaunchLockTest(_ scratch: Scratch) {
    let lock = scratch.dir.appendingPathComponent("helper.lock").path
    let primary = HelperLaunchGuard.acquireLock(at: lock)
    check(primary >= 0, "first helper process should acquire the singleton lock")
    defer { HelperLaunchGuard.releaseLock(primary) }

    let duplicate = HelperLaunchGuard.acquireLock(at: lock)
    check(duplicate < 0, "a duplicate helper process must be rejected")
  }
}
