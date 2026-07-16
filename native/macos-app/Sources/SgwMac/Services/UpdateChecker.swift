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

protocol UpdateChecking: Sendable {
    func latestRelease(repository: String) async throws -> ReleaseInfo?
    func downloadAndInstall(
        _ release: ReleaseInfo,
        progress: @Sendable @escaping (UpdateState) -> Void
    ) async -> String?
}

actor UpdateChecker: UpdateChecking {
    static let defaultRepository = "sgateway/s-gw"
    static let repositoryDefaultsKey = "updateRepository"
    static let lastCheckDefaultsKey = "lastUpdateCheckAt"
    private let cli = CLIRunner()

    static var currentVersion: String {
        Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.1.14"
    }

    static func isNewer(_ candidate: String, than current: String) -> Bool {
        guard let left = semanticVersion(candidate), let right = semanticVersion(current) else {
            return false
        }
        return compare(left, right) == .orderedDescending
    }

    func latestRelease(repository: String) async throws -> ReleaseInfo? {
        let trimmed = repository.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.contains("/") else {
            throw UpdateError.invalidRepository
        }

        guard let url = URL(string: "https://api.github.com/repos/\(trimmed)/releases?per_page=20") else {
            throw UpdateError.invalidRepository
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = 20
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("s-gw-updater", forHTTPHeaderField: "User-Agent")

        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                throw UpdateError.releaseCheckFailed
            }
            let releases = try JSONDecoder().decode([GitHubRelease].self, from: data)
            guard let release = releases
                .filter({ !$0.draft })
                .filter({ Self.semanticVersion($0.tagName) != nil })
                .sorted(by: { Self.isNewer($0.tagName, than: $1.tagName) })
                .first else {
                return nil
            }
            return releaseInfo(from: release)
        } catch {
            return try await latestReleaseFromAtom(repository: trimmed)
        }
    }

    private func latestReleaseFromAtom(repository: String) async throws -> ReleaseInfo? {
        guard let feedURL = URL(string: "https://github.com/\(repository)/releases.atom") else {
            throw UpdateError.invalidRepository
        }
        var request = URLRequest(url: feedURL)
        request.timeoutInterval = 20
        request.setValue("application/atom+xml", forHTTPHeaderField: "Accept")
        request.setValue("s-gw-updater", forHTTPHeaderField: "User-Agent")

        let (data, response) = try await URLSession.shared.data(for: request)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw UpdateError.releaseCheckFailed
        }
        guard let parsed = Self.releaseFromAtom(String(decoding: data, as: UTF8.self), repository: repository) else {
            throw UpdateError.invalidReleaseFeed
        }
        if !Self.isNewer(parsed.version, than: Self.currentVersion) {
            return parsed
        }

        guard let packageURL = URL(string: parsed.assetURL), await assetExists(packageURL) else {
            return Self.withoutInstallAssets(parsed)
        }
        if let checksumURL = URL(string: parsed.checksumAssetURL), await assetExists(checksumURL) {
            return parsed
        }

        let manifestName = "SHA256SUMS.txt"
        let manifestURLText = "https://github.com/\(repository)/releases/download/\(parsed.tag)/\(manifestName)"
        if let manifestURL = URL(string: manifestURLText), await assetExists(manifestURL) {
            return ReleaseInfo(
                tag: parsed.tag,
                version: parsed.version,
                assetName: parsed.assetName,
                assetURL: parsed.assetURL,
                checksumAssetName: manifestName,
                checksumAssetURL: manifestURLText,
                htmlURL: parsed.htmlURL,
                notes: parsed.notes
            )
        }
        return Self.withoutInstallAssets(parsed)
    }

    private func assetExists(_ url: URL) async -> Bool {
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        request.timeoutInterval = 10
        request.setValue("s-gw-updater", forHTTPHeaderField: "User-Agent")
        do {
            let (_, response) = try await URLSession.shared.data(for: request)
            guard let http = response as? HTTPURLResponse else { return false }
            return (200..<300).contains(http.statusCode)
        } catch {
            return false
        }
    }

    static func releaseFromAtom(_ xml: String, repository: String) -> ReleaseInfo? {
        guard let entry = firstCapture(#"<entry>([\s\S]*?)</entry>"#, in: xml) else { return nil }
        let link = firstCapture(#"<link\b[^>]*\brel="alternate"[^>]*\bhref="([^"]+)""#, in: entry)
            .map(decodeXML)
        let id = firstCapture(#"<id>([^<]+)</id>"#, in: entry).map(decodeXML)
        let tag = link.flatMap { URL(string: $0)?.lastPathComponent.removingPercentEncoding }
            ?? id?.split(separator: "/").last.map(String.init)
            ?? ""
        let version = parseVersion(tag)
        guard !tag.isEmpty, semanticVersion(version) != nil else { return nil }

        let packageName = "s-gw-\(version).tgz"
        let downloadBase = "https://github.com/\(repository)/releases/download/\(tag)"
        return ReleaseInfo(
            tag: tag,
            version: version,
            assetName: packageName,
            assetURL: "\(downloadBase)/\(packageName)",
            checksumAssetName: "\(packageName).sha256",
            checksumAssetURL: "\(downloadBase)/\(packageName).sha256",
            htmlURL: link ?? "https://github.com/\(repository)/releases/tag/\(tag)",
            notes: ""
        )
    }

    private static func withoutInstallAssets(_ release: ReleaseInfo) -> ReleaseInfo {
        ReleaseInfo(
            tag: release.tag,
            version: release.version,
            assetName: "",
            assetURL: "",
            checksumAssetName: "",
            checksumAssetURL: "",
            htmlURL: release.htmlURL,
            notes: release.notes
        )
    }

    private static func firstCapture(_ pattern: String, in text: String) -> String? {
        guard let expression = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]),
              let match = expression.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              match.numberOfRanges > 1,
              let range = Range(match.range(at: 1), in: text) else {
            return nil
        }
        return String(text[range])
    }

    private static func decodeXML(_ value: String) -> String {
        value
            .replacingOccurrences(of: "&amp;", with: "&")
            .replacingOccurrences(of: "&quot;", with: "\"")
            .replacingOccurrences(of: "&apos;", with: "'")
            .replacingOccurrences(of: "&lt;", with: "<")
            .replacingOccurrences(of: "&gt;", with: ">")
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
            defer { try? FileManager.default.removeItem(at: downloadURL) }
            let checksumText = try await downloadTextAsset(checksumURL)
            try Self.verifyChecksum(
                for: downloadURL,
                assetName: release.assetName,
                checksumAssetName: release.checksumAssetName,
                checksumText: checksumText
            )
            progress(.installing)

            let result = await cli.run(arguments: [
                "update", "install", "--package", downloadURL.path, "--keep-app-running"
            ])
            if !result.succeeded {
                return result.output.isEmpty ? "s-gw update install failed." : result.output
            }

            try relaunchInstalledApp(cliPath: Self.installedCLIPath(from: result.output))
            return nil
        } catch {
            return error.localizedDescription
        }
    }

    private func releaseInfo(from release: GitHubRelease) -> ReleaseInfo? {
        let version = Self.parseVersion(release.tagName)
        guard !version.isEmpty else { return nil }

        let preferredName = Self.packageAssetName(
            for: version,
            assetNames: release.assets.map(\.name)
        )
        let preferredAsset = preferredName.flatMap { name in
            release.assets.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }
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
        guard let package else { return nil }
        guard let name = Self.checksumAssetName(
            for: package.name,
            assetNames: assets.map(\.name)
        ) else { return nil }
        return assets.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }
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

    static func checksumAssetName(for packageName: String, assetNames: [String]) -> String? {
        let lowerPackage = packageName.lowercased()
        let packageBase = (lowerPackage as NSString).deletingPathExtension
        let exactNames = ["\(lowerPackage).sha256", "\(packageBase).sha256"]

        for expected in exactNames {
            if let match = assetNames.first(where: { $0.lowercased() == expected }) {
                return match
            }
        }

        return assetNames.first {
            let name = $0.lowercased()
            return name == "sha256sums.txt" || name == "sha256sums"
        }
    }

    static func packageAssetName(for version: String, assetNames: [String]) -> String? {
        let expected = "s-gw-\(parseVersion(version)).tgz"
        return assetNames.first { $0.caseInsensitiveCompare(expected) == .orderedSame }
    }

    static func verifyChecksum(
        for fileURL: URL,
        assetName: String,
        checksumAssetName: String,
        checksumText: String
    ) throws {
        guard let expected = expectedSHA256(
            from: checksumText,
            assetName: assetName,
            checksumAssetName: checksumAssetName
        ) else {
            throw UpdateError.missingChecksum
        }

        let data = try Data(contentsOf: fileURL)
        let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        if digest.lowercased() != expected.lowercased() {
            throw UpdateError.checksumMismatch
        }
    }

    static func expectedSHA256(
        from text: String,
        assetName: String,
        checksumAssetName: String
    ) -> String? {
        let perFileChecksum = checksumAssetName.lowercased().hasSuffix(".sha256")
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if let entry = parseChecksumLine(line), entry.fileName == assetName {
                return entry.digest
            }

            if perFileChecksum, isSHA256(line) {
                return line
            }
        }
        return nil
    }

    private static func parseChecksumLine(_ line: String) -> (digest: String, fileName: String)? {
        if line.hasPrefix("SHA256 (") || line.hasPrefix("SHA256(") {
            guard let close = line.firstIndex(of: ")"),
                  let equals = line[close...].firstIndex(of: "=") else { return nil }
            let open = line.firstIndex(of: "(")!
            let nameStart = line.index(after: open)
            let digestStart = line.index(after: equals)
            let fileName = String(line[nameStart..<close])
            let digest = line[digestStart...].trimmingCharacters(in: .whitespaces)
            return isSHA256(digest) ? (digest, fileName) : nil
        }

        let fields = line.split(maxSplits: 1, whereSeparator: \.isWhitespace)
        guard fields.count == 2 else { return nil }
        let digest = String(fields[0])
        guard isSHA256(digest) else { return nil }

        var fileName = String(fields[1]).trimmingCharacters(in: .whitespaces)
        if fileName.hasPrefix("*") { fileName.removeFirst() }
        if fileName.hasPrefix("./") { fileName.removeFirst(2) }
        return (digest, fileName)
    }

    private static func isSHA256(_ value: String) -> Bool {
        value.count == 64 && value.allSatisfy(\.isHexDigit)
    }

    private func relaunchInstalledApp(cliPath: String?) throws {
        let script = """
        attempt=0
        while kill -0 "$SGW_UPDATE_OLD_PID" >/dev/null 2>&1 && [ "$attempt" -lt 120 ]; do
          sleep 0.1
          attempt=$((attempt + 1))
        done
        if kill -0 "$SGW_UPDATE_OLD_PID" >/dev/null 2>&1; then
          echo "Timed out waiting for the previous s-gw app to exit."
          exit 1
        fi

        run_sgw() {
          if [ -n "$SGW_UPDATE_CLI" ] && [ -x "$SGW_UPDATE_CLI" ]; then
            "$SGW_UPDATE_CLI" "$@"
          else
            PATH="/opt/homebrew/bin:/usr/local/bin:$PATH" /usr/bin/env s-gw "$@"
          fi
        }

        run_sgw setup --no-open-app --no-agents || exit 1
        attempt=0
        while [ "$attempt" -lt 20 ]; do
          if run_sgw app open; then
            exit 0
          fi
          sleep 0.25
          attempt=$((attempt + 1))
        done
        echo "The updated s-gw app could not be reopened."
        exit 1
        """

        let logDirectory = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".s-gw/logs", isDirectory: true)
        try FileManager.default.createDirectory(at: logDirectory, withIntermediateDirectories: true)
        let logURL = logDirectory.appendingPathComponent("update-relaunch.log")
        if !FileManager.default.fileExists(atPath: logURL.path) {
            _ = FileManager.default.createFile(atPath: logURL.path, contents: nil)
        }
        let logHandle = try FileHandle(forWritingTo: logURL)
        try logHandle.seekToEnd()
        defer { try? logHandle.close() }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/nohup")
        process.arguments = ["/bin/sh", "-c", script]
        var environment = ProcessInfo.processInfo.environment
        environment["SGW_UPDATE_CLI"] = cliPath ?? ""
        environment["SGW_UPDATE_OLD_PID"] = String(ProcessInfo.processInfo.processIdentifier)
        process.environment = environment
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = logHandle
        process.standardError = logHandle
        try process.run()

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

    private static func semanticVersion(_ version: String) -> SemanticVersion? {
        let cleaned = parseVersion(version)
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

    private static func installedCLIPath(from output: String) -> String? {
        guard let data = output.data(using: .utf8),
              let result = try? JSONDecoder().decode(PackageUpdateCommandResult.self, from: data) else {
            return nil
        }
        let path = URL(fileURLWithPath: result.installed.binDir)
            .appendingPathComponent("s-gw")
            .path
        return FileManager.default.isExecutableFile(atPath: path) ? path : nil
    }

}

private struct SemanticVersion {
    let core: [String]
    let prerelease: [String]
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

private struct PackageUpdateCommandResult: Decodable {
    struct Installed: Decodable {
        let binDir: String
    }

    let installed: Installed
}

private enum UpdateError: LocalizedError {
    case invalidRepository
    case releaseCheckFailed
    case invalidReleaseFeed
    case downloadFailed
    case missingChecksum
    case checksumMismatch

    var errorDescription: String? {
        switch self {
        case .invalidRepository:
            return "The update repository must use owner/repo format."
        case .releaseCheckFailed:
            return "Could not check the GitHub release feed."
        case .invalidReleaseFeed:
            return "GitHub returned an invalid release feed."
        case .downloadFailed:
            return "Could not download the update asset."
        case .missingChecksum:
            return "The release checksum file does not contain a SHA-256 digest for this package."
        case .checksumMismatch:
            return "The downloaded package did not match the release checksum."
        }
    }
}
