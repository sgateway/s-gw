import Foundation
import SgwUpdateState

struct HelperUpdate: Sendable {
  let currentVersion: String
  let version: String
  let releaseURL: URL

  var noticeRelease: UpdateNoticeRelease {
    UpdateNoticeRelease(
      tag: "v\(version)",
      version: version,
      assetName: "",
      assetURL: "",
      checksumAssetName: "",
      checksumAssetURL: "",
      htmlURL: releaseURL.absoluteString,
      notes: ""
    )
  }
}

@MainActor
final class UpdateMonitor {
  // The login helper owns automatic system alerts so the main app can safely
  // keep its durable banner without competing for notification permission.
  static let command = ["update", "check"]
  static let pollInterval: TimeInterval = 15 * 60

  private let state: UpdateNoticeStore
  private let runCheck: @Sendable () -> CliRunResult
  private let canQueueNotification: @MainActor () async -> Bool
  private let notify: @MainActor (HelperUpdate) async -> Bool
  private var checking = false
  private var timer: Timer?

  init(
    defaults: UserDefaults = UserDefaults(suiteName: "com.s-gw.sgw.app") ?? .standard,
    now: @escaping () -> Date = Date.init,
    runCheck: @escaping @Sendable () -> CliRunResult,
    canQueueNotification: @escaping @MainActor () async -> Bool = { true },
    notify: @escaping @MainActor (HelperUpdate) async -> Bool
  ) {
    state = UpdateNoticeStore(defaults: defaults, now: now)
    self.runCheck = runCheck
    self.canQueueNotification = canQueueNotification
    self.notify = notify
  }

  func start() {
    guard timer == nil else { return }
    Task { await checkNow() }
    timer = Timer.scheduledTimer(withTimeInterval: Self.pollInterval, repeats: true) { [weak self] _ in
      Task { @MainActor in
        await self?.checkNow()
      }
    }
  }

  func stop() {
    timer?.invalidate()
    timer = nil
  }

  func requestReminder(version: String) {
    guard state.requestReminder(version: version) else { return }
    Task { [weak self] in
      await self?.checkNow()
    }
  }

  func checkNow() async {
    guard !checking else { return }
    checking = true
    defer { checking = false }

    let check = runCheck
    let result = await Task.detached(priority: .utility) {
      check()
    }.value
    guard let checked = Self.checkedUpdate(from: result) else { return }

    _ = state.available(installedVersion: checked.currentVersion)
    guard let update = checked.availableUpdate,
          let snapshot = state.observe(update.noticeRelease, installedVersion: update.currentVersion),
          snapshot.release.version == update.version else {
      return
    }

    guard await canQueueNotification(), state.reserveNotificationAttempt(version: update.version) else {
      return
    }

    if await notify(update) {
      state.recordQueuedNotification(version: update.version)
    } else {
      state.cancelNotificationAttempt(version: update.version)
    }
  }

  private static func checkedUpdate(from result: CliRunResult) -> CliUpdateCheck? {
    guard result.ok, let output = result.stdout, let data = output.data(using: .utf8),
          let checked = try? JSONDecoder().decode(CliUpdateCheck.self, from: data),
          UpdateNoticeStore.isValidVersion(checked.currentVersion) else {
      return nil
    }
    return checked
  }
}

private struct CliUpdateCheck: Decodable {
  let currentVersion: String
  let available: Bool
  let installerReady: Bool
  let latestVersion: String?
  let releaseUrl: String?

  var availableUpdate: HelperUpdate? {
    guard available, installerReady,
          let version = latestVersion?.trimmingCharacters(in: .whitespacesAndNewlines),
          !version.isEmpty,
          let urlText = releaseUrl,
          let url = URL(string: urlText),
          url.scheme == "https" || url.scheme == "http" else {
      return nil
    }
    return HelperUpdate(currentVersion: currentVersion, version: version, releaseURL: url)
  }
}
