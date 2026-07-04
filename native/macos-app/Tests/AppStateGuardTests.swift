import Foundation

// Standalone test driver for the native macOS app's AppState.
//
// This compiles against the REAL production AppState/Models/CLIRunner sources
// (see scripts/test-macos-app.mjs), not a re-implementation. It exercises two
// things that earlier overnight iterations could only verify via a hand-rolled
// logic probe or `nm` symbol checks:
//
//   1. The approve/deny in-flight guard (AppState.decide) actually collapses a
//      double-fire to a single CLI invocation while a decision is in flight, and
//      surfaces an honest "Approved" message (not a misleading "already approved"
//      failure) for the decision that landed.
//   2. The readiness derivation (isReady / readinessBlockers / menuBarState)
//      maps the CLI's real status JSON the way the GUI relies on.
//
// The CLI is driven through CLIRunner's real Process path by pointing the
// `sgwBinaryPath` UserDefaults override at a controllable fake CLI script. The
// fake CLI blocks on a FIFO for the approve/deny verbs so the test can hold a
// decision in flight and fire competing taps, exactly like a user double-clicking
// Approve in the live app.

private func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data(("FAIL: " + message + "\n").utf8))
  exit(1)
}

private func check(_ cond: Bool, _ message: String) {
  if !cond { fail(message) }
}

// A throwaway scratch dir for the fake CLI, its invocation log, and the FIFO it
// blocks on. Cleaned up at the end.
fileprivate struct Scratch {
  let dir: URL
  let fakeCli: URL
  let invocationLog: URL
  let gate: URL  // FIFO the fake CLI reads from to stay "in flight"

  init() {
    let base = URL(fileURLWithPath: NSTemporaryDirectory())
      .appendingPathComponent("sgw-appstate-test-\(ProcessInfo.processInfo.processIdentifier)", isDirectory: true)
    try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
    dir = base
    fakeCli = base.appendingPathComponent("fake-s-gw.sh")
    invocationLog = base.appendingPathComponent("invocations.log")
    gate = base.appendingPathComponent("gate.fifo")

    // Named pipe: the fake CLI blocks reading from it for approve/deny, so the
    // decision stays in flight until the test writes a release token.
    mkfifo(gate.path, 0o600)

    // The fake CLI logs every invocation (one line per call, by verb) and, for
    // approve/deny, blocks on the FIFO before exiting 0. Read verbs return at once.
    let script = """
    #!/bin/zsh
    verb="$1"
    print -- "$verb" >> "\(invocationLog.path)"
    case "$verb" in
      approve|deny)
        # Block until the test releases us, so the decision is genuinely in flight.
        read _line < "\(gate.path)"
        print -- '{"ok":true}'
        exit 0
        ;;
      nonl)
        printf '{"ok":true,"note":"no-newline"}'
        exit 0
        ;;
      silent)
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

  func invocationCount() -> Int {
    verbs().count
  }

  // Count only decision verbs (approve/deny). After a decision completes the app
  // calls refresh(), which fires benign read verbs (status/requests/...) — those
  // must not be mistaken for a leaked second decision.
  func decisionCount() -> Int {
    verbs().filter { $0 == "approve" || $0 == "deny" }.count
  }

  func verbs() -> [String] {
    guard let text = try? String(contentsOf: invocationLog, encoding: .utf8) else { return [] }
    return text.split(whereSeparator: \.isNewline).map { String($0) }
  }

  func releaseOneInFlight() {
    // Open for writing unblocks the fake CLI's `read`.
    if let handle = FileHandle(forWritingAtPath: gate.path) {
      handle.write(Data("go\n".utf8))
      try? handle.close()
    }
  }

  func cleanup() {
    try? FileManager.default.removeItem(at: dir)
  }
}

private func makeRequest(id: String) -> RequestRecord {
  // Build a RequestRecord straight from CLI-shaped JSON so we exercise the real
  // Decodable, not a Swift initializer that could drift from the wire format.
  let json = """
  {
    "id": "\(id)",
    "handle": "sgw_demo",
    "reason": "test",
    "action": {"kind":"env-command","command":"printenv","args":["DEMO"],"injectEnv":"DEMO","timeoutMs":1000},
    "state": "pending",
    "createdAt": "2026-06-15T00:00:00.000Z",
    "updatedAt": "2026-06-15T00:00:00.000Z"
  }
  """
  return try! JSONDecoder().decode(RequestRecord.self, from: Data(json.utf8))
}

// Poll a @MainActor predicate without blocking the main actor's run loop.
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
struct AppStateGuardTests {
  static func main() async {
    let scratch = Scratch()
    defer { scratch.cleanup() }

    // Point the real CLIRunner at the fake CLI via the documented override key.
    UserDefaults.standard.set(scratch.fakeCli.path, forKey: CLIRunner.binaryOverrideKey)

    await runInFlightGuardTest(scratch)
    await runGuardReleaseTest(scratch)
    await runReadinessDerivationTest()
    await runCommandOutputCaptureTest()

    print("ALL_NATIVE_TESTS_OK")
  }

  // Test 1: a double-fire while a decision is in flight reaches the CLI exactly once.
  @MainActor
  fileprivate static func runInFlightGuardTest(_ scratch: Scratch) async {
    let app = AppState()
    let req = makeRequest(id: "req-guard")

    app.approve(req)  // starts the (blocking) approve in flight

    let inFlight = await waitUntil(3.0) { scratch.decisionCount() == 1 && app.isDeciding(req.id) }
    check(inFlight, "first approve should reach the CLI and be marked in flight")

    // Competing taps a user could fire during the round-trip.
    app.approve(req)
    app.deny(req)
    // Give any (buggy) extra calls a chance to land before we release.
    try? await Task.sleep(for: .milliseconds(150))

    check(scratch.decisionCount() == 1,
          "in-flight guard must collapse the double-fire to ONE decision call, saw \(scratch.decisionCount()): \(scratch.verbs())")

    scratch.releaseOneInFlight()

    let cleared = await waitUntil(3.0) { !app.isDeciding(req.id) }
    check(cleared, "request id should be released after the decision completes")

    check(app.operationMessage == "Authorized Agent one time",
          "honest success message expected, got: \(app.operationMessage ?? "nil")")
    check(scratch.decisionCount() == 1,
          "still exactly one decision call after release, saw \(scratch.decisionCount()): \(scratch.verbs())")
  }

  // Test 2: proves the harness genuinely measures CLI invocations (so Test 1's
  // "1" is meaningful) and that the guard releases — a fresh decision on the same
  // id after the first one finished DOES reach the CLI. If the guard were a
  // permanent lockout, this second call would never register.
  @MainActor
  fileprivate static func runGuardReleaseTest(_ scratch: Scratch) async {
    let before = scratch.decisionCount()
    let app = AppState()
    let req = makeRequest(id: "req-release")

    app.deny(req)
    let started = await waitUntil(3.0) { scratch.decisionCount() == before + 1 }
    check(started, "a separate later decision must reach the CLI (guard is not a permanent lockout)")
    scratch.releaseOneInFlight()
    let done = await waitUntil(3.0) { !app.isDeciding(req.id) }
    check(done, "second decision should clear its in-flight id too")
  }

  // Test 3: readiness derivation from the CLI's real status JSON shape.
  @MainActor
  static func runReadinessDerivationTest() async {
    let app = AppState()

    let notReady = statusPayload(ready: false,
                                 summary: "Not ready yet",
                                 blockers: ["No local unlock material. Run `s-gw setup` to configure unlock."],
                                 activeSource: "none",
                                 consoleLoaded: true)
    app.status = notReady
    check(!app.isReady, "isReady must be false when CLI reports ready:false")
    check(app.readinessBlockers.first?.contains("s-gw setup") == true,
          "blocker text should be relayed verbatim from the CLI")
    // daemon loaded + locked => menu bar shows the locked state, not healthy.
    if case .locked = app.menuBarState {} else {
      fail("menuBarState should be .locked when unlock source is none")
    }

    let ready = statusPayload(ready: true,
                              summary: "ready to store and redeem secrets",
                              blockers: [],
                              activeSource: "env",
                              consoleLoaded: true)
    app.status = ready
    check(app.isReady, "isReady must be true when CLI reports ready:true")
    check(app.readinessBlockers.isEmpty, "no blockers when ready")
    if case .healthy = app.menuBarState {} else {
      fail("menuBarState should be .healthy when ready, unlocked, daemon loaded, no pending")
    }
  }

  @MainActor
  static func runCommandOutputCaptureTest() async {
    let app = AppState()

    let noNewline = await app.runCommand(
      title: "No newline output",
      category: "Tests",
      arguments: ["nonl"],
      refreshAfter: false
    )
    check(noNewline.output == #"{"ok":true,"note":"no-newline"}"#,
          "CLI output without a trailing newline should be captured exactly, got: \(noNewline.output)")
    check(app.activity.records.first?.output == noNewline.output,
          "activity record should store compact no-newline output")

    let silent = await app.runCommand(
      title: "Silent success",
      category: "Tests",
      arguments: ["silent"],
      refreshAfter: false
    )
    check(silent.output.isEmpty, "silent CLI command should still return an empty raw output")
    let activityOutput = app.activity.records.first?.output ?? ""
    check(activityOutput.contains("Command completed successfully"),
          "silent success should get a useful activity message, got: \(activityOutput)")
  }

  static func statusPayload(ready: Bool, summary: String, blockers: [String],
                            activeSource: String, consoleLoaded: Bool) -> StatusPayload {
    let blockerJson = blockers.map { "\"\($0)\"" }.joined(separator: ",")
    let json = """
    {
      "packageRoot": "/tmp/sgw",
      "ready": \(ready),
      "readiness": {"ok": \(ready), "summary": "\(summary)", "blockers": [\(blockerJson)]},
      "cliPath": {"path":"/tmp/cli.js","exists":true},
      "mcpPath": {"path":"/tmp/mcp.js","exists":true},
      "keychainHelperPath": {"path":"/tmp/helper","exists":true},
      "menuBarAppPath": {"path":"/tmp/mb.app","exists":true},
      "menuBarBinaryPath": {"path":"/tmp/mb","exists":true},
      "storePath": "/tmp/store.json",
      "consoleUrl": "http://127.0.0.1:8718/",
      "unlock": {"activeSource":"\(activeSource)"},
      "launchAgents": {
        "console": {"label":"c","plistPath":"/tmp/c.plist","installed":\(consoleLoaded),"loaded":\(consoleLoaded)},
        "menuBar": {"label":"m","plistPath":"/tmp/m.plist","installed":false,"loaded":false}
      }
    }
    """
    return try! JSONDecoder().decode(StatusPayload.self, from: Data(json.utf8))
  }
}
