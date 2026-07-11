import Foundation
import UserNotifications

enum UpdateNotificationResult: Equatable {
    case systemDelivered
    case alreadyDelivered
    case inAppOnly
}

@MainActor
protocol UpdateNotificationCenterClient: AnyObject {
    func authorizationStatus() async -> UNAuthorizationStatus
    func requestAuthorization() async -> Bool
    func add(_ request: UNNotificationRequest) async throws
}

@MainActor
final class SystemUpdateNotificationCenter: UpdateNotificationCenterClient {
    private let center: UNUserNotificationCenter

    init(center: UNUserNotificationCenter = .current()) {
        self.center = center
    }

    func authorizationStatus() async -> UNAuthorizationStatus {
        await center.notificationSettings().authorizationStatus
    }

    func requestAuthorization() async -> Bool {
        (try? await center.requestAuthorization(options: [.alert, .badge, .sound])) == true
    }

    func add(_ request: UNNotificationRequest) async throws {
        try await center.add(request)
    }
}

@MainActor
final class UpdateNotifier {
    static let notifiedVersionDefaultsKey = "lastNotifiedUpdateVersion"
    static let notifiedVersionsDefaultsKey = "notifiedUpdateVersions"

    private let configuredCenter: (any UpdateNotificationCenterClient)?
    private let defaults: UserDefaults
    private var inFlightVersions = Set<String>()

    init(
        center: (any UpdateNotificationCenterClient)? = nil,
        defaults: UserDefaults = .standard
    ) {
        configuredCenter = center
        self.defaults = defaults
    }

    func notifyIfNeeded(for release: ReleaseInfo) async -> UpdateNotificationResult {
        let version = release.version.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !version.isEmpty else { return .inAppOnly }
        if wasNotified(version) {
            return .alreadyDelivered
        }
        guard inFlightVersions.insert(version).inserted else { return .alreadyDelivered }
        defer { inFlightVersions.remove(version) }

        let center = configuredCenter ?? SystemUpdateNotificationCenter()
        var status = await center.authorizationStatus()
        if status == .notDetermined {
            guard await center.requestAuthorization() else { return .inAppOnly }
            status = await center.authorizationStatus()
        }
        guard Self.canDeliver(status) else { return .inAppOnly }

        let content = UNMutableNotificationContent()
        content.title = "s-gw \(version) is available"
        content.body = "You have \(UpdateChecker.currentVersion). Open s-gw to review and upgrade."
        content.sound = .default
        content.userInfo = ["releaseURL": release.htmlURL]

        let request = UNNotificationRequest(
            identifier: "s-gw-update-\(version)",
            content: content,
            trigger: nil
        )
        do {
            try await center.add(request)
            recordNotified(version)
            return .systemDelivered
        } catch {
            return .inAppOnly
        }
    }

    private static func canDeliver(_ status: UNAuthorizationStatus) -> Bool {
        switch status {
        case .authorized, .provisional, .ephemeral:
            return true
        case .denied, .notDetermined:
            return false
        @unknown default:
            return false
        }
    }

    private func wasNotified(_ version: String) -> Bool {
        if defaults.string(forKey: Self.notifiedVersionDefaultsKey) == version {
            return true
        }
        return defaults.stringArray(forKey: Self.notifiedVersionsDefaultsKey)?.contains(version) == true
    }

    private func recordNotified(_ version: String) {
        var versions = defaults.stringArray(forKey: Self.notifiedVersionsDefaultsKey) ?? []
        if let previous = defaults.string(forKey: Self.notifiedVersionDefaultsKey),
           !versions.contains(previous) {
            versions.append(previous)
        }
        if !versions.contains(version) {
            versions.append(version)
        }
        defaults.set(versions, forKey: Self.notifiedVersionsDefaultsKey)
        defaults.set(version, forKey: Self.notifiedVersionDefaultsKey)
    }
}
