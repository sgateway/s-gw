import Foundation

struct HelperUpdate: Sendable {
  let version: String
  let releaseURL: URL
}

@MainActor
final class UpdateMonitor {
  // The login helper owns the recurring update check so quitting the main app cannot silence it.
  static let command = ["update", "check"]
  static let pollInterval: TimeInterval = 15 * 60

  private static let lastVersionKey = "lastNotifiedUpdateVersion"
  private static let versionsKey = "notifiedUpdateVersions"

  private let defaults: UserDefaults
  private let runCheck: @Sendable () -> CliRunResult
  private let notify: @MainActor (HelperUpdate) async -> Bool
  private var checking = false
  private var timer: Timer?

  init(
    defaults: UserDefaults = UserDefaults(suiteName: "com.s-gw.sgw.app") ?? .standard,
    runCheck: @escaping @Sendable () -> CliRunResult,
    notify: @escaping @MainActor (HelperUpdate) async -> Bool
  ) {
    self.defaults = defaults
    self.runCheck = runCheck
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

  func checkNow() async {
    guard !checking else { return }
    checking = true
    defer { checking = false }

    let check = runCheck
    let result = await Task.detached(priority: .utility) {
      check()
    }.value
    guard let update = Self.availableUpdate(from: result), !wasNotified(update.version) else {
      return
    }

    if await notify(update) {
      recordNotified(update.version)
    }
  }

  private static func availableUpdate(from result: CliRunResult) -> HelperUpdate? {
    guard result.ok, let output = result.stdout, let data = output.data(using: .utf8) else {
      return nil
    }
    guard let checked = try? JSONDecoder().decode(CliUpdateCheck.self, from: data),
          checked.available,
          let version = checked.latestVersion?.trimmingCharacters(in: .whitespacesAndNewlines),
          !version.isEmpty,
          let urlText = checked.releaseUrl,
          let url = URL(string: urlText),
          url.scheme == "https" || url.scheme == "http" else {
      return nil
    }
    return HelperUpdate(version: version, releaseURL: url)
  }

  private func wasNotified(_ version: String) -> Bool {
    if defaults.string(forKey: Self.lastVersionKey) == version { return true }
    return defaults.stringArray(forKey: Self.versionsKey)?.contains(version) == true
  }

  private func recordNotified(_ version: String) {
    var versions = defaults.stringArray(forKey: Self.versionsKey) ?? []
    if let previous = defaults.string(forKey: Self.lastVersionKey), !versions.contains(previous) {
      versions.append(previous)
    }
    if !versions.contains(version) {
      versions.append(version)
    }
    defaults.set(Array(versions.suffix(32)), forKey: Self.versionsKey)
    defaults.set(version, forKey: Self.lastVersionKey)
  }
}

private struct CliUpdateCheck: Decodable {
  let available: Bool
  let latestVersion: String?
  let releaseUrl: String?
}
