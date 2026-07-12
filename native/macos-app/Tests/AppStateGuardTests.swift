import CryptoKit
import Foundation
import UserNotifications

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

private enum FakeUpdateFailure: Error {
  case offline
}

private actor FakeUpdateChecker: UpdateChecking {
  enum Step: Sendable {
    case failure
    case release(ReleaseInfo?)
  }

  private var steps: [Step]
  private var checks = 0

  init(_ steps: [Step]) {
    self.steps = steps
  }

  func latestRelease(repository: String) async throws -> ReleaseInfo? {
    checks += 1
    let step = steps.isEmpty ? .release(nil) : steps.removeFirst()
    switch step {
    case .failure:
      throw FakeUpdateFailure.offline
    case .release(let release):
      return release
    }
  }

  func downloadAndInstall(
    _ release: ReleaseInfo,
    progress: @Sendable @escaping (UpdateState) -> Void
  ) async -> String? {
    "not used"
  }

  func checkCount() -> Int { checks }
}

@MainActor
private final class FakeNotificationCenter: UpdateNotificationCenterClient {
  var status: UNAuthorizationStatus
  var authorizationResult: Bool
  var authorizationRequests = 0
  var requests: [UNNotificationRequest] = []

  init(status: UNAuthorizationStatus, authorizationResult: Bool = false) {
    self.status = status
    self.authorizationResult = authorizationResult
  }

  func authorizationStatus() async -> UNAuthorizationStatus { status }

  func requestAuthorization() async -> Bool {
    authorizationRequests += 1
    if authorizationResult { status = .authorized }
    return authorizationResult
  }

  func add(_ request: UNNotificationRequest) async throws {
    requests.append(request)
  }
}

private func makeRelease(
  _ version: String,
  checksumName: String = "SHA256SUMS.txt",
  installable: Bool = true
) -> ReleaseInfo {
  ReleaseInfo(
    tag: "v\(version)",
    version: version,
    assetName: installable ? "s-gw-\(version).tgz" : "",
    assetURL: installable ? "https://example.test/s-gw-\(version).tgz" : "",
    checksumAssetName: installable ? checksumName : "",
    checksumAssetURL: installable ? "https://example.test/\(checksumName)" : "",
    htmlURL: "https://example.test/releases/v\(version)",
    notes: ""
  )
}

private func isolatedDefaults(_ name: String) -> UserDefaults {
  let suite = "com.s-gw.tests.\(name).\(UUID().uuidString)"
  let defaults = UserDefaults(suiteName: suite)!
  defaults.removePersistentDomain(forName: suite)
  return defaults
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
    await runUpdateRetryTest()
    await runIncompleteReleaseRetryTest()
    await runUpdateNotificationTest()
    await runDeniedNotificationFallbackTest()
    runSemVerComparisonTest()
    runAtomFallbackParsingTest()
    runChecksumManifestTest()

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

  @MainActor
  static func runUpdateRetryTest() async {
    let defaults = isolatedDefaults("update-retry")
    let release = makeRelease("9.0.0")
    let checker = FakeUpdateChecker([.failure, .release(release)])
    let center = FakeNotificationCenter(status: .denied)
    let notifier = UpdateNotifier(center: center, defaults: defaults)
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let app = AppState(
      updater: checker,
      updateNotifier: notifier,
      defaults: defaults,
      now: { now }
    )

    await app.checkForUpdates()
    check(defaults.double(forKey: UpdateChecker.lastCheckDefaultsKey) == 0,
          "a failed fetch must not consume the successful-check interval")
    check(await checker.checkCount() == 1, "the first update attempt should reach the checker")

    await app.checkForUpdates()
    check(await checker.checkCount() == 2,
          "a second check after failure should retry without waiting six hours")
    check(app.availableUpdate?.version == release.version,
          "the retry should publish the newly available release")
    check(defaults.double(forKey: UpdateChecker.lastCheckDefaultsKey) == now.timeIntervalSince1970,
          "the successful retry should persist its timestamp")
  }

  @MainActor
  static func runIncompleteReleaseRetryTest() async {
    let defaults = isolatedDefaults("update-assets-pending")
    let incomplete = makeRelease("9.0.1", installable: false)
    let complete = makeRelease("9.0.1")
    let checker = FakeUpdateChecker([.release(incomplete), .release(complete)])
    let center = FakeNotificationCenter(status: .authorized)
    let notifier = UpdateNotifier(center: center, defaults: defaults)
    let now = Date(timeIntervalSince1970: 1_800_000_100)
    defaults.set(now.timeIntervalSince1970 - 60 * 60, forKey: UpdateChecker.lastCheckDefaultsKey)
    let app = AppState(
      updater: checker,
      updateNotifier: notifier,
      defaults: defaults,
      now: { now }
    )

    await app.checkForUpdates(force: true)
    check(app.availableUpdate == incomplete, "the published release should remain visible while assets upload")
    check(defaults.double(forKey: UpdateChecker.lastCheckDefaultsKey) == 0,
          "a release missing its verified package must not consume the six-hour interval")
    check(center.requests.isEmpty, "an incomplete release should not notify before it can be installed")

    await app.checkForUpdates()
    check(await checker.checkCount() == 2,
          "an incomplete release should retry on the next polling cycle")
    check(app.availableUpdate == complete, "the retry should pick up the completed release assets")
    check(center.requests.count == 1, "the completed release should send exactly one notification")
    check(defaults.double(forKey: UpdateChecker.lastCheckDefaultsKey) == now.timeIntervalSince1970,
          "the completed release should start the successful-check interval")
  }

  @MainActor
  static func runUpdateNotificationTest() async {
    let defaults = isolatedDefaults("update-notification")
    let release = makeRelease("9.1.0")
    let center = FakeNotificationCenter(status: .notDetermined, authorizationResult: true)
    let notifier = UpdateNotifier(center: center, defaults: defaults)

    let first = await notifier.notifyIfNeeded(for: release)
    let second = await notifier.notifyIfNeeded(for: release)
    check(first == .systemDelivered, "the first sighting of a version should send a system notification")
    check(second == .alreadyDelivered, "the same version should not notify twice in one process")
    check(center.requests.count == 1, "exactly one notification request expected for a version")
    check(center.authorizationRequests == 1,
          "notification permission should be requested only when an update first needs it")
    check(center.requests.first?.identifier == "s-gw-update-9.1.0",
          "the notification identifier should be stable per version")
    check(defaults.string(forKey: UpdateNotifier.notifiedVersionDefaultsKey) == release.version,
          "the notified version should be persisted")

    let afterRestartCenter = FakeNotificationCenter(status: .authorized)
    let afterRestart = UpdateNotifier(center: afterRestartCenter, defaults: defaults)
    let persisted = await afterRestart.notifyIfNeeded(for: release)
    check(persisted == .alreadyDelivered,
          "the persisted version should suppress a duplicate after restart")
    check(afterRestartCenter.requests.isEmpty,
          "restart suppression should happen before notification delivery")

    let next = await afterRestart.notifyIfNeeded(for: makeRelease("9.2.0"))
    check(next == .systemDelivered, "a later version should produce a new notification")
    check(afterRestartCenter.requests.count == 1,
          "the later version should add exactly one new request")
    let olderAgain = await afterRestart.notifyIfNeeded(for: release)
    check(olderAgain == .alreadyDelivered,
          "a version must stay deduplicated after another version was delivered")
    check(afterRestartCenter.requests.count == 1,
          "returning to an older release must not enqueue a duplicate")
  }

  @MainActor
  static func runDeniedNotificationFallbackTest() async {
    let defaults = isolatedDefaults("update-denied")
    let release = makeRelease("9.3.0")
    let checker = FakeUpdateChecker([.release(release)])
    let center = FakeNotificationCenter(status: .denied)
    let notifier = UpdateNotifier(center: center, defaults: defaults)
    let app = AppState(updater: checker, updateNotifier: notifier, defaults: defaults)

    await app.checkForUpdates()
    check(app.availableUpdate == release, "denied notification permission must not hide the update banner")
    check(!app.updateBannerDismissed, "the in-app update banner should start visible")
    check(app.updateUsesInAppFallback, "the banner should identify itself as the notification fallback")
    check(center.requests.isEmpty, "denied permission should not enqueue a system notification")
    check(defaults.string(forKey: UpdateNotifier.notifiedVersionDefaultsKey) == nil,
          "a denied notification must not be recorded as delivered")
  }

  static func runChecksumManifestTest() {
    let asset = "s-gw-9.4.0.tgz"
    let manifest = "SHA256SUMS.txt"
    check(UpdateChecker.packageAssetName(
      for: "v9.4.0",
      assetNames: ["unrelated.tgz", asset]
    ) == asset, "release selection should bind the package name to the release version")
    check(UpdateChecker.packageAssetName(
      for: "9.4.0",
      assetNames: ["unrelated.tgz"]
    ) == nil, "an unrelated tarball must not be selected for installation")
    check(UpdateChecker.checksumAssetName(for: asset, assetNames: [manifest]) == manifest,
          "SHA256SUMS.txt should be accepted when no per-file checksum is present")
    check(UpdateChecker.checksumAssetName(for: asset, assetNames: ["SHA256SUMS"]) == "SHA256SUMS",
          "the extensionless SHA256SUMS form should also be accepted")
    check(UpdateChecker.checksumAssetName(
      for: asset,
      assetNames: [manifest, "\(asset).sha256"]
    ) == "\(asset).sha256", "a matching per-file checksum should be preferred")
    check(UpdateChecker.checksumAssetName(
      for: asset,
      assetNames: ["some-other-package.tgz.sha256"]
    ) == nil, "an unrelated per-file checksum must not authorize this package")

    let file = FileManager.default.temporaryDirectory
      .appendingPathComponent("sgw-checksum-\(UUID().uuidString).tgz")
    let data = Data("verified package".utf8)
    try! data.write(to: file)
    defer { try? FileManager.default.removeItem(at: file) }
    let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()

    do {
      try UpdateChecker.verifyChecksum(
        for: file,
        assetName: asset,
        checksumAssetName: manifest,
        checksumText: "\(digest)  \(asset)\n"
      )
    } catch {
      fail("the manifest entry matching the package should verify: \(error)")
    }

    do {
      try UpdateChecker.verifyChecksum(
        for: file,
        assetName: asset,
        checksumAssetName: manifest,
        checksumText: "\(digest)  prefixed-\(asset)\n"
      )
      fail("a checksum for a different package name must not verify")
    } catch {}

    do {
      try UpdateChecker.verifyChecksum(
        for: file,
        assetName: asset,
        checksumAssetName: "\(asset).sha256",
        checksumText: "\(digest)\n"
      )
    } catch {
      fail("a raw digest should remain valid in an exact per-file checksum: \(error)")
    }
  }

  static func runSemVerComparisonTest() {
    check(!UpdateChecker.isNewer("0.2.0-preview.1", than: "0.2.0"),
          "a preview must not outrank its stable release")
    check(UpdateChecker.isNewer("0.2.0", than: "0.2.0-preview.1"),
          "preview users must receive the stable release")
    check(UpdateChecker.isNewer("0.2.0-preview.10", than: "0.2.0-preview.2"),
          "numeric prerelease identifiers must compare numerically")
    check(UpdateChecker.isNewer("0.2.0-beta", than: "0.2.0-alpha"),
          "text prerelease identifiers must compare lexically")
    check(!UpdateChecker.isNewer("0.2.0-1", than: "0.2.0-alpha"),
          "numeric prerelease identifiers must sort before text identifiers")
    check(!UpdateChecker.isNewer("0.2.0+build.2", than: "0.2.0+build.1"),
          "build metadata must not affect precedence")
  }

  static func runAtomFallbackParsingTest() {
    let xml = """
    <?xml version="1.0"?>
    <feed>
      <entry>
        <id>tag:github.com,2008:Repository/1/v9.3.1</id>
        <updated>2026-07-11T12:00:00Z</updated>
        <link rel="alternate" type="text/html" href="https://github.com/sgateway/s-gw/releases/tag/v9.3.1"/>
        <title>s-gw 9.3.1</title>
      </entry>
    </feed>
    """
    guard let release = UpdateChecker.releaseFromAtom(xml, repository: "sgateway/s-gw") else {
      fail("the GitHub Atom fallback should parse the newest release entry")
    }
    check(release.version == "9.3.1", "Atom fallback should parse the release version")
    check(release.assetName == "s-gw-9.3.1.tgz", "Atom fallback should bind the exact package name")
    check(release.checksumAssetName == "s-gw-9.3.1.tgz.sha256",
          "Atom fallback should prefer the exact per-file checksum")
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
