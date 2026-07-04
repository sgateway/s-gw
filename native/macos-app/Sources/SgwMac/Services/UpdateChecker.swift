import AppKit
import CryptoKit
import Foundation

struct ReleaseInfo: Identifiable, Equatable, Sendable {
    let tag: String
    let version: String
    let assetName: String
    let assetURL: String
    let checksumAssetName: String
    let checksumAssetURL: String
    let htmlURL: String
    let notes: String

    var id: String { tag }
    var canInstallPackage: Bool {
        assetName.lowercased().hasSuffix(".tgz") && !assetURL.isEmpty && !checksumAssetURL.isEmpty
    }
}

enum UpdateState: Equatable {
    case idle
    case checking
    case downloading
    case installing
    case failed(String)

    var isBusy: Bool {
        switch self {
        case .checking, .downloading, .installing:
            return true
        case .idle, .failed:
            return false
        }
    }

    var label: String {
        switch self {
        case .idle:
            return "Idle"
        case .checking:
            return "Checking..."
        case .downloading:
            return "Downloading..."
        case .installing:
            return "Installing..."
        case .failed(let message):
            return message
        }
    }
}

actor UpdateChecker {
    static let defaultRepository = "sgateway/s-gw"
    static let repositoryDefaultsKey = "updateRepository"
    static let lastCheckDefaultsKey = "lastUpdateCheckAt"

    static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1.0"
    }

    static func isNewer(_ candidate: String, than current: String) -> Bool {
        let left = versionParts(candidate)
        let right = versionParts(current)
        let count = max(left.count, right.count)

        for index in 0..<count {
            let a = index < left.count ? left[index] : 0
            let b = index < right.count ? right[index] : 0
            if a > b { return true }
            if a < b { return false }
        }

        return false
    }

    func latestRelease(repository: String) async -> ReleaseInfo? {
        let trimmed = repository.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.contains("/") else { return nil }

        guard let url = URL(string: "https://api.github.com/repos/\(trimmed)/releases?per_page=20") else {
            return nil
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 20
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("s-gw-updater", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                return nil
            }

            let releases = try JSONDecoder().decode([GitHubRelease].self, from: data)
            guard let release = releases
                .filter({ !$0.draft })
                .sorted(by: { Self.isNewer($0.tagName, than: $1.tagName) })
                .first else {
                return nil
            }
            return releaseInfo(from: release)
        } catch {
            return nil
        }
    }

    func downloadAndInstall(_ release: ReleaseInfo, progress: @Sendable @escaping (UpdateState) -> Void) async -> String? {
        guard release.assetName.lowercased().hasSuffix(".tgz"), let assetURL = URL(string: release.assetURL) else {
            return "This release does not include an installable s-gw package asset."
        }
        guard let checksumURL = URL(string: release.checksumAssetURL) else {
            return "This release is missing a SHA-256 checksum asset, so s-gw will not install it automatically."
        }

        progress(.downloading)

        do {
            let downloadURL = try await downloadAsset(assetURL, named: release.assetName)
            let checksumText = try await downloadTextAsset(checksumURL)
            try verifyChecksum(for: downloadURL, assetName: release.assetName, checksumText: checksumText)
            progress(.installing)

            let result = try await Self.runProcess(Self.npmCommand(), ["install", "-g", downloadURL.path])
            if result.exitCode != 0 {
                return result.output.isEmpty ? "npm install failed." : result.output
            }

            relaunchInstalledApp()
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    private func releaseInfo(from release: GitHubRelease) -> ReleaseInfo? {
        let version = Self.parseVersion(release.tagName)
        guard !version.isEmpty else { return nil }

        let preferredAsset = release.assets.first { asset in
            asset.name.lowercased().hasSuffix(".tgz")
        } ?? release.assets.first { asset in
            asset.name.lowercased().contains("s-gw")
        }
        let checksumAsset = checksumAsset(for: preferredAsset, in: release.assets)

        return ReleaseInfo(
            tag: release.tagName,
            version: version,
            assetName: preferredAsset?.name ?? "",
            assetURL: preferredAsset?.browserDownloadURL ?? "",
            checksumAssetName: checksumAsset?.name ?? "",
            checksumAssetURL: checksumAsset?.browserDownloadURL ?? "",
            htmlURL: release.htmlURL,
            notes: release.body ?? ""
        )
    }

    private func checksumAsset(for package: GitHubAsset?, in assets: [GitHubAsset]) -> GitHubAsset? {
        guard let package else {
            return assets.first { $0.name.lowercased().hasSuffix(".sha256") }
        }

        let packageName = package.name.lowercased()
        let packageBase = (packageName as NSString).deletingPathExtension
        return assets.first { asset in
            let name = asset.name.lowercased()
            return name == "\(packageName).sha256" || name == "\(packageBase).sha256"
        } ?? assets.first { $0.name.lowercased().hasSuffix(".sha256") }
    }

    private func downloadAsset(_ url: URL, named assetName: String) async throws -> URL {
        let (tmpURL, response) = try await URLSession.shared.download(from: url)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw UpdateError.downloadFailed
        }

        let safeName = assetName.isEmpty ? "s-gw-update.tgz" : assetName
        let destination = FileManager.default.temporaryDirectory
            .appendingPathComponent("s-gw-update-\(UUID().uuidString)")
            .appendingPathExtension((safeName as NSString).pathExtension)

        if FileManager.default.fileExists(atPath: destination.path) {
            try FileManager.default.removeItem(at: destination)
        }
        try FileManager.default.moveItem(at: tmpURL, to: destination)
        return destination
    }

    private func downloadTextAsset(_ url: URL) async throws -> String {
        let (data, response) = try await URLSession.shared.data(from: url)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw UpdateError.downloadFailed
        }
        return String(decoding: data, as: UTF8.self)
    }

    private func verifyChecksum(for fileURL: URL, assetName: String, checksumText: String) throws {
        guard let expected = expectedSHA256(from: checksumText, assetName: assetName) else {
            throw UpdateError.missingChecksum
        }

        let data = try Data(contentsOf: fileURL)
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        if digest.lowercased() != expected.lowercased() {
            throw UpdateError.checksumMismatch
        }
    }

    private func expectedSHA256(from text: String, assetName: String) -> String? {
        let lines = text.split(whereSeparator: \.isNewline).map(String.init)
        let preferred = lines.first { $0.contains(assetName) }
        let candidates = preferred.map { [$0] } ?? lines
        for line in candidates {
            for part in line.split(whereSeparator: \.isWhitespace) {
                if part.count == 64 && part.allSatisfy({ $0.isHexDigit }) {
                    return String(part)
                }
            }
        }
        return nil
    }

    private func relaunchInstalledApp() {
        let script = """
        sleep 1
        /usr/bin/env s-gw service start >/dev/null 2>&1 || true
        /usr/bin/env s-gw menubar install --start --count pending >/dev/null 2>&1 || true
        /usr/bin/env s-gw app open >/dev/null 2>&1 || true
        """

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", script]
        try? process.run()

        Task { @MainActor in
            NSApp.terminate(nil)
        }
    }

    private static func parseVersion(_ tag: String) -> String {
        var cleaned = tag.trimmingCharacters(in: .whitespacesAndNewlines)
        if cleaned.lowercased().hasPrefix("v") {
            cleaned.removeFirst()
        }
        return cleaned
    }

    private static func versionParts(_ version: String) -> [Int] {
        parseVersion(version)
            .split(separator: ".")
            .map { part in
                let digits = part.prefix { $0.isNumber }
                return Int(digits) ?? 0
            }
    }

    private static func npmCommand() -> String {
        let candidates = [
            "/opt/homebrew/bin/npm",
            "/usr/local/bin/npm",
            "/usr/bin/npm"
        ]

        for path in candidates where FileManager.default.isExecutableFile(atPath: path) {
            return path
        }

        return "/usr/bin/env"
    }

    private static func runProcess(_ executable: String, _ arguments: [String]) async throws -> ProcessResult {
        try await withCheckedThrowingContinuation { continuation in
            let process = Process()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = executable == "/usr/bin/env" ? ["npm"] + arguments : arguments

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe

            do {
                try process.run()
            } catch {
                continuation.resume(throwing: error)
                return
            }

            DispatchQueue.global(qos: .utility).async {
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                process.waitUntilExit()
                let output = String(data: data, encoding: .utf8) ?? ""
                continuation.resume(returning: ProcessResult(exitCode: process.terminationStatus, output: output))
            }
        }
    }
}

private struct GitHubRelease: Decodable {
    let tagName: String
    let htmlURL: String
    let body: String?
    let assets: [GitHubAsset]
    let draft: Bool

    enum CodingKeys: String, CodingKey {
        case tagName = "tag_name"
        case htmlURL = "html_url"
        case body
        case assets
        case draft
    }
}

private struct GitHubAsset: Decodable {
    let name: String
    let browserDownloadURL: String

    enum CodingKeys: String, CodingKey {
        case name
        case browserDownloadURL = "browser_download_url"
    }
}

private struct ProcessResult {
    let exitCode: Int32
    let output: String
}

private enum UpdateError: LocalizedError {
    case downloadFailed
    case missingChecksum
    case checksumMismatch

    var errorDescription: String? {
        switch self {
        case .downloadFailed:
            return "Could not download the update asset."
        case .missingChecksum:
            return "The release checksum file does not contain a SHA-256 digest."
        case .checksumMismatch:
            return "The downloaded package did not match the release checksum."
        }
    }
}
