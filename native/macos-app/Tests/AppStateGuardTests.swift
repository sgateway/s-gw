import CryptoKit
import Foundation
import SgwUpdateState

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

private func storedRelease(_ release: ReleaseInfo) -> UpdateNoticeRelease {
  UpdateNoticeRelease(
    tag: release.tag,
    version: release.version,
    assetName: release.assetName,
    assetURL: release.assetURL,
    checksumAssetName: release.checksumAssetName,
    checksumAssetURL: release.checksumAssetURL,
    htmlURL: release.htmlURL,
    notes: release.notes
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
  let migrationGate: URL

  init() {
    let base = URL(fileURLWithPath: NSTemporaryDirectory())
      .appendingPathComponent("sgw-appstate-test-\(ProcessInfo.processInfo.processIdentifier)", isDirectory: true)
    try? FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
    dir = base
    fakeCli = base.appendingPathComponent("fake-s-gw.sh")
    invocationLog = base.appendingPathComponent("invocations.log")
    gate = base.appendingPathComponent("gate.fifo")
    migrationGate = base.appendingPathComponent("migration-gate.fifo")

    // Named pipe: the fake CLI blocks reading from it for approve/deny, so the
    // decision stays in flight until the test writes a release token.
    mkfifo(gate.path, 0o600)
    mkfifo(migrationGate.path, 0o600)

    // The fake CLI logs every invocation (one line per call, by verb) and, for
    // approve/deny, blocks on the FIFO before exiting 0. Read verbs return at once.
    let script = """
    #!/bin/zsh
    verb="$1"
    print -- "$*" >> "\(invocationLog.path)"
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
      status)
        print -- '{"version":"0.1.19","packageRoot":"/tmp/sgw","ready":true,"readiness":{"ok":true,"summary":"ready","blockers":[]},"cliPath":{"path":"/tmp/cli.js","exists":true},"mcpPath":{"path":"/tmp/mcp.js","exists":true},"keychainHelperPath":{"path":"/tmp/helper","exists":true},"menuBarAppPath":{"path":"/tmp/mb.app","exists":true},"menuBarBinaryPath":{"path":"/tmp/mb","exists":true},"storePath":"/tmp/store.json","consoleUrl":"http://127.0.0.1:8718/","unlock":{"activeSource":"env"},"launchAgents":{"console":{"label":"c","plistPath":"/tmp/c.plist","installed":true,"loaded":true},"menuBar":{"label":"m","plistPath":"/tmp/m.plist","installed":true,"loaded":true}}}'
        exit 0
        ;;
      app)
        if [[ "$2" == "refresh-services" ]]; then
          read _line < "\(migrationGate.path)"
          print -- '{"ok":true,"services":{}}'
          exit 0
        fi
        print -- '{"ok":true,"agents":[]}'
        exit 0
        ;;
      secret|requests|agent)
        print -- '[]'
        exit 0
        ;;
      approval)
        if [[ "$2" == "settings" ]]; then
          print -- '{"mode":"per-transaction","durationMs":900000}'
        else
          print -- '[]'
        fi
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
    commands().compactMap { $0.split(separator: " ").first.map(String.init) }
  }

  func commands() -> [String] {
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

  func releaseRuntimeMigration() {
    if let handle = FileHandle(forWritingAtPath: migrationGate.path) {
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

    await runStartupOrderingTest(scratch)
    await runInFlightGuardTest(scratch)
    await runGuardReleaseTest(scratch)
    await runReadinessDerivationTest()
    await runInstalledVersionTest()
    await runCommandOutputCaptureTest()
    await runUpdateRetryTest()
    await runIncompleteReleaseRetryTest()
    await runUpdateAvailabilityPersistenceTest()
    await runUpdateAcknowledgementAndReminderTest()
    runUpdateStateClearAfterInstallTest()
    runSharedUpdateStateConsistencyTest()
    await runBundledRuntimeRefreshTest()
    runSemVerComparisonTest()
    runAtomFallbackParsingTest()
    runChecksumManifestTest()

    print("ALL_NATIVE_TESTS_OK")
  }

  @MainActor
  fileprivate static func runStartupOrderingTest(_ scratch: Scratch) async {
    let defaults = isolatedDefaults("startup-ordering")
    let app = AppState(updater: FakeUpdateChecker([.release(nil)]), defaults: defaults)

    app.start(refreshBundledRuntime: true)
    let statusFirst = await waitUntil(3.0) {
      app.initialStatusResolved && app.status != nil &&
        scratch.commands().contains("app refresh-services --no-agents")
    }
    check(statusFirst, "status must render before bundled runtime migration can finish")
    check(app.daemonRunning, "the healthy console should be visible while migration is still waiting")

    scratch.releaseRuntimeMigration()
    let agentsSeparated = await waitUntil(3.0) {
      scratch.commands().contains("app refresh-agents --lock-timeout-ms 5000")
    }
    check(agentsSeparated, "managed agent rewrites must use their own bounded migration step")
    app.stop()
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
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let notice = UpdateNoticeStore(defaults: defaults, now: { now })
    notice.clear()
    defer { notice.clear() }
    let app = AppState(
      updater: checker,
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
  static func runInstalledVersionTest() async {
    let defaults = isolatedDefaults("installed-version")
    let notice = UpdateNoticeStore(defaults: defaults)
    notice.clear()
    defer { notice.clear() }
    let app = AppState(
      updater: FakeUpdateChecker([.release(makeRelease("9.4.0"))]),
      defaults: defaults
    )

    check(app.installedVersion == UpdateChecker.currentVersion,
          "the app bundle version should remain the fallback before CLI status loads")
    app.status = statusPayload(
      ready: true,
      summary: "Ready",
      blockers: [],
      activeSource: "environment",
      consoleLoaded: true,
      version: "9.5.0"
    )
    check(app.installedVersion == "9.5.0",
          "the installed CLI runtime version must override a stale app bundle version")

    await app.checkForUpdates(force: true)
    check(app.availableUpdate == nil,
          "a release older than the installed CLI runtime must not be offered as an update")
  }

  @MainActor
  static func runIncompleteReleaseRetryTest() async {
    let defaults = isolatedDefaults("update-assets-pending")
    let incomplete = makeRelease("9.0.1", installable: false)
    let complete = makeRelease("9.0.1")
    let checker = FakeUpdateChecker([.release(incomplete), .release(complete)])
    let now = Date(timeIntervalSince1970: 1_800_000_100)
    let notice = UpdateNoticeStore(defaults: defaults, now: { now })
    notice.clear()
    defer { notice.clear() }
    defaults.set(now.timeIntervalSince1970 - 60 * 60, forKey: UpdateChecker.lastCheckDefaultsKey)
    let app = AppState(
      updater: checker,
      defaults: defaults,
      now: { now }
    )

    await app.checkForUpdates(force: true)
    check(app.availableUpdate == incomplete, "the published release should remain visible while assets upload")
    check(defaults.double(forKey: UpdateChecker.lastCheckDefaultsKey) == 0,
          "a release missing its verified package must not consume the six-hour interval")

    await app.checkForUpdates()
    check(await checker.checkCount() == 2,
          "an incomplete release should retry on the next polling cycle")
    check(app.availableUpdate == complete, "the retry should pick up the completed release assets")
    check(defaults.double(forKey: UpdateChecker.lastCheckDefaultsKey) == now.timeIntervalSince1970,
          "the completed release should start the successful-check interval")
  }

  @MainActor
  static func runUpdateAvailabilityPersistenceTest() async {
    let defaults = isolatedDefaults("update-persistence")
    let release = makeRelease("9.1.0")
    let now = Date(timeIntervalSince1970: 1_800_000_200)
    let notice = UpdateNoticeStore(defaults: defaults, now: { now })
    notice.clear()
    defer { notice.clear() }
    let first = AppState(
      updater: FakeUpdateChecker([.release(release)]),
      defaults: defaults,
      now: { now }
    )

    await first.checkForUpdates()
    check(first.availableUpdate == release, "a discovered update should be visible in the app")
    check(!first.updateBannerDismissed, "a discovered update should begin unacknowledged")

    let afterRestart = AppState(
      updater: FakeUpdateChecker([]),
      defaults: defaults,
      now: { now }
    )
    check(afterRestart.availableUpdate == release,
          "an available update must survive an app restart even if the next feed check has not run")
    check(!afterRestart.updateBannerDismissed,
          "restart must not turn an unacknowledged update into a dismissal")
  }

  @MainActor
  static func runUpdateAcknowledgementAndReminderTest() async {
    let defaults = isolatedDefaults("update-acknowledgement")
    let release = makeRelease("9.2.0")
    var now = Date(timeIntervalSince1970: 1_800_000_300)
    let notice = UpdateNoticeStore(defaults: defaults, now: { now })
    notice.clear()
    defer { notice.clear() }
    let app = AppState(
      updater: FakeUpdateChecker([.release(release)]),
      defaults: defaults,
      now: { now }
    )

    await app.checkForUpdates()
    app.dismissUpdateBanner()

    let afterDismiss = AppState(
      updater: FakeUpdateChecker([]),
      defaults: defaults,
      now: { now }
    )
    check(afterDismiss.availableUpdate == release,
          "dismissing the banner must not discard the release details")
    check(afterDismiss.updateBannerDismissed,
          "a banner dismissal must survive app restart")

    afterDismiss.requestUpdateReminder()
    for attempt in 1...3 {
      check(notice.reserveNotificationAttempt(version: release.version),
            "an eligible reminder should reserve exactly one queue attempt")
      check(notice.recordQueuedNotification(version: release.version),
            "a reserved reminder should record only after the system queue accepts it")
      if attempt < 3,
         let nextEligibleAt = notice.available(installedVersion: UpdateChecker.currentVersion)?.notification.nextEligibleAt {
        now = nextEligibleAt.addingTimeInterval(1)
      }
    }
    check(!notice.shouldQueueNotification(version: release.version),
          "automatic reminders must stop after their bounded queue attempts")

    afterDismiss.dismissUpdateBanner()
    afterDismiss.requestUpdateReminder()
    let reset = notice.available(installedVersion: UpdateChecker.currentVersion)
    check(reset?.notification.attemptCount == 0,
          "an explicit Notify Again request should start a fresh bounded reminder sequence")
    check(notice.shouldQueueNotification(version: release.version),
          "Notify Again should make the selected update eligible immediately")

    let afterReminder = AppState(
      updater: FakeUpdateChecker([]),
      defaults: defaults,
      now: { now }
    )
    check(!afterReminder.updateBannerDismissed,
          "an explicit reminder request should restore the in-app banner after restart")
  }

  static func runUpdateStateClearAfterInstallTest() {
    let defaults = isolatedDefaults("update-installed")
    let now = Date(timeIntervalSince1970: 1_800_000_400)
    let notice = UpdateNoticeStore(defaults: defaults, now: { now })
    notice.clear()
    defer { notice.clear() }
    let release = storedRelease(makeRelease("9.3.0"))

    _ = notice.observe(release, installedVersion: "9.0.0")
    check(notice.available(installedVersion: "9.0.0")?.release.version == release.version,
          "a newer release should remain available before installation")
    check(notice.available(installedVersion: "9.3.0") == nil,
          "installing the available version must clear its stale reminder state")
    check(defaults.data(forKey: UpdateNoticeStore.defaultsKey) == nil,
          "clearing an installed update must remove the persisted notice")
  }

  static func runSharedUpdateStateConsistencyTest() {
    let defaults = isolatedDefaults("update-shared-state")
    var now = Date(timeIntervalSince1970: 1_800_000_500)
    let helperState = UpdateNoticeStore(defaults: defaults, now: { now })
    let appState = UpdateNoticeStore(defaults: defaults, now: { now })
    helperState.clear()
    defer { helperState.clear() }

    let release = storedRelease(makeRelease("9.5.0"))
    _ = helperState.observe(release, installedVersion: "9.0.0")
    check(appState.available(installedVersion: "9.0.0")?.release.version == release.version,
          "independent app and helper stores must read the same durable update snapshot")

    check(helperState.reserveNotificationAttempt(version: release.version),
          "the helper should reserve before submitting a notification")
    appState.acknowledge(version: release.version)
    check(!helperState.recordQueuedNotification(version: release.version),
          "a late helper completion must not overwrite a newer app acknowledgement")
    let acknowledged = appState.available(installedVersion: "9.0.0")
    check(acknowledged?.acknowledgedAt != nil && acknowledged?.notification.inFlightAt == nil,
          "acknowledgement must survive a concurrent helper completion")

    now = now.addingTimeInterval(1)
    check(appState.requestReminder(version: release.version),
          "the app should be able to reset the reminder schedule after acknowledgement")
    let reset = helperState.available(installedVersion: "9.0.0")
    check(reset?.acknowledgedAt == nil && reset?.notification.attemptCount == 0,
          "the helper must observe the app's reset rather than writing a stale snapshot")
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
      assetNames: ["0-s-gw-legacy-9.4.0.tgz", "unrelated.tgz"]
    ) == nil, "the legacy bridge and unrelated tarballs must not be selected for installation")
    let bridgeRelease = ReleaseInfo(
      tag: "v9.4.0",
      version: "9.4.0",
      assetName: "0-s-gw-legacy-9.4.0.tgz",
      assetURL: "https://example.com/0-s-gw-legacy-9.4.0.tgz",
      checksumAssetName: "0-s-gw-legacy-9.4.0.tgz.sha256",
      checksumAssetURL: "https://example.com/0-s-gw-legacy-9.4.0.tgz.sha256",
      htmlURL: "https://example.com/release",
      notes: ""
    )
    check(!bridgeRelease.canInstallPackage,
          "a preselected legacy bridge must still fail closed before download")
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

  @MainActor
  static func runBundledRuntimeRefreshTest() {
    check(!AppState.needsBundledRuntimeRefresh(
      previousVersion: "9.3.1",
      previousPath: "/Applications/s-gw.app",
      version: "9.3.1",
      appPath: "/Applications/s-gw.app"
    ), "the same bundled app version and path should not refresh services")
    check(AppState.needsBundledRuntimeRefresh(
      previousVersion: "9.3.1",
      previousPath: "/Applications/s-gw.app",
      version: "9.3.1",
      appPath: "/Users/test/Applications/s-gw.app"
    ), "moving a bundled app must refresh absolute service and MCP paths")
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
    check(release.assetName == "s-gw.dmg", "Atom fallback should bind the primary installer name")
    check(release.checksumAssetName == "s-gw.dmg.sha256",
          "Atom fallback should prefer the exact per-file checksum")
  }

  static func statusPayload(ready: Bool, summary: String, blockers: [String],
                            activeSource: String, consoleLoaded: Bool,
                            version: String? = nil) -> StatusPayload {
    let blockerJson = blockers.map { "\"\($0)\"" }.joined(separator: ",")
    let versionJson = version.map { "\"version\":\"\($0)\"," } ?? ""
    let json = """
    {
      \(versionJson)
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
