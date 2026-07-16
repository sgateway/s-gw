import Foundation

#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public struct UpdateNoticeRelease: Codable, Equatable, Identifiable, Sendable {
  public let tag: String
  public let version: String
  public let assetName: String
  public let assetURL: String
  public let checksumAssetName: String
  public let checksumAssetURL: String
  public let htmlURL: String
  public let notes: String

  public init(
    tag: String,
    version: String,
    assetName: String,
    assetURL: String,
    checksumAssetName: String,
    checksumAssetURL: String,
    htmlURL: String,
    notes: String
  ) {
    self.tag = tag
    self.version = version
    self.assetName = assetName
    self.assetURL = assetURL
    self.checksumAssetName = checksumAssetName
    self.checksumAssetURL = checksumAssetURL
    self.htmlURL = htmlURL
    self.notes = notes
  }

  public var id: String { tag }

  public var canInstallPackage: Bool {
    assetName.lowercased().hasSuffix(".tgz") && !assetURL.isEmpty && !checksumAssetURL.isEmpty
  }

  func merged(with update: UpdateNoticeRelease) -> UpdateNoticeRelease {
    UpdateNoticeRelease(
      tag: update.tag.isEmpty ? tag : update.tag,
      version: update.version.isEmpty ? version : update.version,
      assetName: update.assetName.isEmpty ? assetName : update.assetName,
      assetURL: update.assetURL.isEmpty ? assetURL : update.assetURL,
      checksumAssetName: update.checksumAssetName.isEmpty ? checksumAssetName : update.checksumAssetName,
      checksumAssetURL: update.checksumAssetURL.isEmpty ? checksumAssetURL : update.checksumAssetURL,
      htmlURL: update.htmlURL.isEmpty ? htmlURL : update.htmlURL,
      notes: update.notes.isEmpty ? notes : update.notes
    )
  }
}

public struct UpdateNotificationSchedule: Codable, Equatable, Sendable {
  public var lastQueuedAt: Date?
  public var attemptCount: Int
  public var nextEligibleAt: Date?
  public var inFlightAt: Date?

  public init(
    lastQueuedAt: Date? = nil,
    attemptCount: Int = 0,
    nextEligibleAt: Date? = nil,
    inFlightAt: Date? = nil
  ) {
    self.lastQueuedAt = lastQueuedAt
    self.attemptCount = attemptCount
    self.nextEligibleAt = nextEligibleAt
    self.inFlightAt = inFlightAt
  }
}

public struct UpdateNoticeSnapshot: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public var release: UpdateNoticeRelease
  public var discoveredAt: Date
  public var acknowledgedAt: Date?
  public var notification: UpdateNotificationSchedule

  public init(
    schemaVersion: Int = 1,
    release: UpdateNoticeRelease,
    discoveredAt: Date,
    acknowledgedAt: Date? = nil,
    notification: UpdateNotificationSchedule = UpdateNotificationSchedule()
  ) {
    self.schemaVersion = schemaVersion
    self.release = release
    self.discoveredAt = discoveredAt
    self.acknowledgedAt = acknowledgedAt
    self.notification = notification
  }
}

public final class UpdateNoticeStore {
  public static let defaultsKey = "updateNoticeState"
  public static let legacyLastVersionKey = "lastNotifiedUpdateVersion"
  public static let legacyVersionsKey = "notifiedUpdateVersions"
  public static let maxNotificationAttempts = 3

  private static let notificationAttemptLease: TimeInterval = 5 * 60

  private let defaults: UserDefaults
  private let now: () -> Date
  private let stateURL: URL
  private let lockURL: URL

  public init(
    defaults: UserDefaults = .standard,
    now: @escaping () -> Date = Date.init,
    storageURL: URL? = nil
  ) {
    self.defaults = defaults
    self.now = now
    stateURL = storageURL ?? Self.defaultStateURL()
    lockURL = stateURL.deletingPathExtension().appendingPathExtension("lock")
  }

  public func available(installedVersion: String) -> UpdateNoticeSnapshot? {
    mutate { snapshot in
      guard let current = snapshot else {
        return Mutation(value: nil, changed: false)
      }
      guard Self.isNewerVersion(current.release.version, than: installedVersion) else {
        snapshot = nil
        return Mutation(value: nil, changed: true, clearLegacy: true)
      }
      return Mutation(value: current, changed: false)
    }
  }

  @discardableResult
  public func observe(_ release: UpdateNoticeRelease, installedVersion: String) -> UpdateNoticeSnapshot? {
    mutate { snapshot in
      var changed = false
      if let existing = snapshot, !Self.isNewerVersion(existing.release.version, than: installedVersion) {
        snapshot = nil
        changed = true
      }

      guard Self.isNewerVersion(release.version, than: installedVersion) else {
        return Mutation(value: snapshot, changed: changed)
      }

      if var existing = snapshot {
        if existing.release.version == release.version {
          let mergedRelease = existing.release.merged(with: release)
          if mergedRelease != existing.release {
            existing.release = mergedRelease
            snapshot = existing
            changed = true
          }
          return Mutation(value: existing, changed: changed)
        }
        if Self.isNewerVersion(existing.release.version, than: release.version) {
          return Mutation(value: existing, changed: changed)
        }
      }

      let legacy = legacyVersions()
      let timestamp = now()
      let legacyVersion = legacy.contains(release.version)
      // Older clients only knew that they had submitted a notification request.
      // It was not an acknowledgement or a reliable attempt, so retry on a fresh schedule.
      let notification = legacyVersion
        ? UpdateNotificationSchedule(nextEligibleAt: timestamp)
        : UpdateNotificationSchedule()
      let next = UpdateNoticeSnapshot(
        release: release,
        discoveredAt: timestamp,
        notification: notification
      )
      snapshot = next
      return Mutation(value: next, changed: true, clearLegacy: !legacy.isEmpty)
    }
  }

  public func acknowledge(version: String) {
    mutate { snapshot in
      guard var current = snapshot, current.release.version == version else {
        return Mutation(value: (), changed: false)
      }
      guard current.acknowledgedAt == nil || current.notification.inFlightAt != nil else {
        return Mutation(value: (), changed: false)
      }
      current.acknowledgedAt = current.acknowledgedAt ?? now()
      current.notification.inFlightAt = nil
      snapshot = current
      return Mutation(value: (), changed: true)
    }
  }

  @discardableResult
  public func requestReminder(version: String) -> Bool {
    mutate { snapshot in
      guard var current = snapshot, current.release.version == version else {
        return Mutation(value: false, changed: false)
      }
      current.acknowledgedAt = nil
      current.notification = UpdateNotificationSchedule(nextEligibleAt: now())
      snapshot = current
      return Mutation(value: true, changed: true)
    }
  }

  public func shouldQueueNotification(version: String) -> Bool {
    mutate { snapshot in
      guard var current = snapshot, current.release.version == version else {
        return Mutation(value: false, changed: false)
      }
      let recovered = recoverExpiredAttempt(&current)
      if recovered {
        snapshot = current
      }
      return Mutation(
        value: canQueue(current),
        changed: recovered
      )
    }
  }

  @discardableResult
  public func reserveNotificationAttempt(version: String) -> Bool {
    mutate { snapshot in
      guard var current = snapshot, current.release.version == version else {
        return Mutation(value: false, changed: false)
      }
      let recovered = recoverExpiredAttempt(&current)
      guard canQueue(current) else {
        if recovered { snapshot = current }
        return Mutation(value: false, changed: recovered)
      }
      current.notification.inFlightAt = now()
      snapshot = current
      return Mutation(value: true, changed: true)
    }
  }

  @discardableResult
  public func recordQueuedNotification(version: String) -> Bool {
    mutate { snapshot in
      guard var current = snapshot,
            current.release.version == version,
            current.notification.inFlightAt != nil else {
        return Mutation(value: false, changed: false)
      }
      guard current.acknowledgedAt == nil,
            current.notification.attemptCount < Self.maxNotificationAttempts else {
        current.notification.inFlightAt = nil
        snapshot = current
        return Mutation(value: false, changed: true)
      }
      let queuedAt = now()
      recordQueued(&current, at: queuedAt)
      snapshot = current
      return Mutation(value: true, changed: true)
    }
  }

  public func cancelNotificationAttempt(version: String) {
    mutate { snapshot in
      guard var current = snapshot,
            current.release.version == version,
            current.notification.inFlightAt != nil else {
        return Mutation(value: (), changed: false)
      }
      current.notification.inFlightAt = nil
      snapshot = current
      return Mutation(value: (), changed: true)
    }
  }

  public func clear() {
    withStateLock {
      try? FileManager.default.removeItem(at: stateURL)
      defaults.removeObject(forKey: Self.defaultsKey)
      clearLegacyValues()
    }
  }

  public static func isNewerVersion(_ candidate: String, than current: String) -> Bool {
    guard let left = semanticVersion(candidate), let right = semanticVersion(current) else {
      return false
    }
    return compare(left, right) == .orderedDescending
  }

  public static func isValidVersion(_ version: String) -> Bool {
    semanticVersion(version) != nil
  }

  private func canQueue(_ snapshot: UpdateNoticeSnapshot) -> Bool {
    guard snapshot.acknowledgedAt == nil else { return false }
    guard snapshot.notification.inFlightAt == nil else { return false }
    guard snapshot.notification.attemptCount < Self.maxNotificationAttempts else { return false }
    guard let nextEligibleAt = snapshot.notification.nextEligibleAt else { return true }
    return now() >= nextEligibleAt
  }

  private func recoverExpiredAttempt(_ snapshot: inout UpdateNoticeSnapshot) -> Bool {
    guard let inFlightAt = snapshot.notification.inFlightAt,
          now().timeIntervalSince(inFlightAt) >= Self.notificationAttemptLease else {
      return false
    }
    guard snapshot.acknowledgedAt == nil,
          snapshot.notification.attemptCount < Self.maxNotificationAttempts else {
      snapshot.notification.inFlightAt = nil
      return true
    }
    recordQueued(&snapshot, at: inFlightAt)
    return true
  }

  private func recordQueued(_ snapshot: inout UpdateNoticeSnapshot, at queuedAt: Date) {
    snapshot.notification.lastQueuedAt = queuedAt
    snapshot.notification.attemptCount += 1
    snapshot.notification.inFlightAt = nil
    snapshot.notification.nextEligibleAt = nextReminderDate(
      after: snapshot.notification.attemptCount,
      from: queuedAt
    )
  }

  private func nextReminderDate(after attempts: Int, from queuedAt: Date) -> Date? {
    switch attempts {
    case 1:
      return queuedAt.addingTimeInterval(24 * 60 * 60)
    case 2:
      return queuedAt.addingTimeInterval(7 * 24 * 60 * 60)
    default:
      return nil
    }
  }

  private func mutate<Value>(_ operation: (inout UpdateNoticeSnapshot?) -> Mutation<Value>) -> Value {
    withStateLock {
      let loaded = readState()
      var snapshot = loaded.snapshot
      let mutation = operation(&snapshot)
      let needsWrite = mutation.changed || loaded.fromDefaults
      if needsWrite, write(snapshot) {
        defaults.removeObject(forKey: Self.defaultsKey)
        if mutation.clearLegacy {
          clearLegacyValues()
        }
      }
      return mutation.value
    }
  }

  private func readState() -> LoadedState {
    if let data = try? Data(contentsOf: stateURL),
       let snapshot = decode(data) {
      return LoadedState(snapshot: snapshot, fromDefaults: false)
    }
    if let data = defaults.data(forKey: Self.defaultsKey),
       let snapshot = decode(data) {
      return LoadedState(snapshot: snapshot, fromDefaults: true)
    }
    return LoadedState(snapshot: nil, fromDefaults: false)
  }

  private func decode(_ data: Data) -> UpdateNoticeSnapshot? {
    guard let snapshot = try? JSONDecoder().decode(UpdateNoticeSnapshot.self, from: data),
          snapshot.schemaVersion == 1,
          !snapshot.release.version.isEmpty else {
      return nil
    }
    return snapshot
  }

  private func write(_ snapshot: UpdateNoticeSnapshot?) -> Bool {
    if let snapshot {
      guard let data = try? JSONEncoder().encode(snapshot) else { return false }
      do {
        try FileManager.default.createDirectory(
          at: stateURL.deletingLastPathComponent(),
          withIntermediateDirectories: true
        )
        try data.write(to: stateURL, options: .atomic)
        return true
      } catch {
        return false
      }
    }

    guard FileManager.default.fileExists(atPath: stateURL.path) else { return true }
    do {
      try FileManager.default.removeItem(at: stateURL)
      return true
    } catch {
      return false
    }
  }

  private func legacyVersions() -> Set<String> {
    var versions = Set(defaults.stringArray(forKey: Self.legacyVersionsKey) ?? [])
    if let version = defaults.string(forKey: Self.legacyLastVersionKey), !version.isEmpty {
      versions.insert(version)
    }
    return versions
  }

  private func clearLegacyValues() {
    defaults.removeObject(forKey: Self.legacyLastVersionKey)
    defaults.removeObject(forKey: Self.legacyVersionsKey)
  }

  private func withStateLock<Value>(_ body: () -> Value) -> Value {
    let directory = stateURL.deletingLastPathComponent()
    try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

    let fd = open(lockURL.path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
    guard fd >= 0 else { return body() }
    guard flock(fd, LOCK_EX) == 0 else {
      close(fd)
      return body()
    }
    defer {
      flock(fd, LOCK_UN)
      close(fd)
    }
    return body()
  }

  private static func defaultStateURL() -> URL {
    if let override = ProcessInfo.processInfo.environment["SGW_UPDATE_NOTICE_STATE_PATH"], !override.isEmpty {
      return URL(fileURLWithPath: override)
    }
    let support = FileManager.default.urls(
      for: .applicationSupportDirectory,
      in: .userDomainMask
    ).first ?? FileManager.default.temporaryDirectory
    return support
      .appendingPathComponent("s-gw", isDirectory: true)
      .appendingPathComponent("update-notice-state.json")
  }

  private struct LoadedState {
    let snapshot: UpdateNoticeSnapshot?
    let fromDefaults: Bool
  }

  private struct Mutation<Value> {
    let value: Value
    let changed: Bool
    let clearLegacy: Bool

    init(value: Value, changed: Bool, clearLegacy: Bool = false) {
      self.value = value
      self.changed = changed
      self.clearLegacy = clearLegacy
    }
  }

  private static func semanticVersion(_ version: String) -> SemanticVersion? {
    let cleaned = cleanVersion(version)
    let buildParts = cleaned.split(separator: "+", maxSplits: 1, omittingEmptySubsequences: false)
    guard buildParts.count <= 2 else { return nil }
    if buildParts.count == 2 && !validIdentifiers(buildParts[1], rejectLeadingZeroes: false) {
      return nil
    }

    let precedence = buildParts[0]
    let prereleaseParts = precedence.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false)
    let core = prereleaseParts[0].split(separator: ".", omittingEmptySubsequences: false)
    guard core.count == 3, core.allSatisfy(validCoreIdentifier) else { return nil }

    var prerelease: [String] = []
    if prereleaseParts.count == 2 {
      guard validIdentifiers(prereleaseParts[1], rejectLeadingZeroes: true) else { return nil }
      prerelease = prereleaseParts[1].split(separator: ".").map(String.init)
    }
    return SemanticVersion(core: core.map(String.init), prerelease: prerelease)
  }

  private static func compare(_ left: SemanticVersion, _ right: SemanticVersion) -> ComparisonResult {
    for index in 0..<3 {
      let result = compareNumeric(left.core[index], right.core[index])
      if result != .orderedSame { return result }
    }

    if left.prerelease.isEmpty || right.prerelease.isEmpty {
      if left.prerelease.isEmpty == right.prerelease.isEmpty { return .orderedSame }
      return left.prerelease.isEmpty ? .orderedDescending : .orderedAscending
    }

    let count = max(left.prerelease.count, right.prerelease.count)
    for index in 0..<count {
      guard index < left.prerelease.count else { return .orderedAscending }
      guard index < right.prerelease.count else { return .orderedDescending }
      let a = left.prerelease[index]
      let b = right.prerelease[index]
      let aNumeric = isNumeric(a)
      let bNumeric = isNumeric(b)

      if aNumeric && bNumeric {
        let result = compareNumeric(a, b)
        if result != .orderedSame { return result }
        continue
      }
      if aNumeric != bNumeric {
        return aNumeric ? .orderedAscending : .orderedDescending
      }
      if a != b { return a < b ? .orderedAscending : .orderedDescending }
    }
    return .orderedSame
  }

  private static func cleanVersion(_ version: String) -> String {
    var cleaned = version.trimmingCharacters(in: .whitespacesAndNewlines)
    if cleaned.lowercased().hasPrefix("v") {
      cleaned.removeFirst()
    }
    return cleaned
  }

  private static func compareNumeric(_ left: String, _ right: String) -> ComparisonResult {
    if left.count != right.count {
      return left.count < right.count ? .orderedAscending : .orderedDescending
    }
    if left == right { return .orderedSame }
    return left < right ? .orderedAscending : .orderedDescending
  }

  private static func validCoreIdentifier(_ value: Substring) -> Bool {
    isNumeric(value) && (value.count == 1 || value.first != "0")
  }

  private static func validIdentifiers(_ value: Substring, rejectLeadingZeroes: Bool) -> Bool {
    let identifiers = value.split(separator: ".", omittingEmptySubsequences: false)
    guard !identifiers.isEmpty else { return false }
    return identifiers.allSatisfy { identifier in
      guard !identifier.isEmpty, identifier.utf8.allSatisfy(isSemVerByte) else { return false }
      if rejectLeadingZeroes && isNumeric(identifier) && identifier.count > 1 && identifier.first == "0" {
        return false
      }
      return true
    }
  }

  private static func isNumeric<S: StringProtocol>(_ value: S) -> Bool {
    !value.isEmpty && value.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
  }

  private static func isSemVerByte(_ value: UInt8) -> Bool {
    (value >= 48 && value <= 57)
      || (value >= 65 && value <= 90)
      || (value >= 97 && value <= 122)
      || value == 45
  }
}

private struct SemanticVersion {
  let core: [String]
  let prerelease: [String]
}
