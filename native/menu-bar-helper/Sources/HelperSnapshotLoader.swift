import Foundation

struct CliRunResult: Sendable {
  let ok: Bool
  let stdout: String?
  let stderr: String?
}

struct HelperStatusRefreshSchedule {
  static let fallbackInterval: TimeInterval = 5 * 60

  let interval: TimeInterval
  private(set) var lastAttempt: Date?

  init(interval: TimeInterval = fallbackInterval) {
    self.interval = interval
  }

  func isDue(at date: Date) -> Bool {
    guard let lastAttempt else { return true }
    return date.timeIntervalSince(lastAttempt) >= interval
  }

  mutating func markAttempt(at date: Date) {
    lastAttempt = date
  }
}

struct HelperLoadResult: Sendable {
  let state: HelperState
  let status: StatusPayload?
}

func runSgwCli(
  node: String,
  cli: String,
  repoRoot: String,
  args: [String],
  environment: [String: String] = ProcessInfo.processInfo.environment
) -> CliRunResult {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: node)
  process.arguments = node.hasSuffix("/env") ? ["node", cli] + args : [cli] + args
  process.currentDirectoryURL = URL(fileURLWithPath: repoRoot)
  process.environment = environment

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

struct HelperSnapshotLoader: Sendable {
  let nodePath: String
  let cliPath: String
  let repoRoot: String
  let consoleURL: URL
  let environment: [String: String]

  func load(cachedStatus: StatusPayload?, refreshRuntimeStatus: Bool) -> HelperLoadResult {
    let status = refreshRuntimeStatus ? (readStatus() ?? cachedStatus) : cachedStatus
    let store = readStore(path: status?.storePath)
    let requests = readRequests()

    var snapshot = HelperState()
    snapshot.daemonRunning = checkDaemon() || (status?.launchAgents?.console.loaded ?? false)
    snapshot.unlockSource = status?.unlock.activeSource ?? "unknown"
    snapshot.pending = requests
      .filter { $0.state == "pending" }
      .sorted { ($0.updatedAt ?? $0.createdAt) > ($1.updatedAt ?? $1.createdAt) }
    let agentRequestIds = Set(store.requests.map(\.id))
    snapshot.recentAudit = store.audit
      .filter { event in
        guard let requestId = event.requestId else { return false }
        return agentRequestIds.contains(requestId)
      }
      .sorted { $0.ts > $1.ts }
    snapshot.credentialCount = store.secrets.count
    snapshot.highRiskCount = store.secrets.filter(\.isHighRisk).count
    snapshot.onePasswordAvailable = readOnePasswordAvailable()
    snapshot.lastUpdated = Date()
    return HelperLoadResult(state: snapshot, status: status)
  }

  private func runCli(_ args: [String]) -> String? {
    let result = runSgwCli(
      node: nodePath,
      cli: cliPath,
      repoRoot: repoRoot,
      args: args,
      environment: environment
    )
    return result.ok ? result.stdout : nil
  }

  private func readStatus() -> StatusPayload? {
    guard let output = runCli(["status"]) else { return nil }
    return try? JSONDecoder().decode(StatusPayload.self, from: Data(output.utf8))
  }

  private func readRequests() -> [RequestRecord] {
    guard let output = runCli(["requests"]) else { return [] }
    return (try? JSONDecoder().decode([RequestRecord].self, from: Data(output.utf8))) ?? []
  }

  private func readStore(path: String?) -> StoreSnapshot {
    let storePath = path ?? defaultStorePath()
    guard FileManager.default.isReadableFile(atPath: storePath) else {
      return StoreSnapshot(secrets: [], requests: [], audit: [])
    }

    do {
      let data = try Data(contentsOf: URL(fileURLWithPath: storePath))
      return try JSONDecoder().decode(StoreSnapshot.self, from: data)
    } catch {
      return StoreSnapshot(secrets: [], requests: [], audit: [])
    }
  }

  private func defaultStorePath() -> String {
    if let home = environment["SGW_HOME"], !home.isEmpty {
      return URL(fileURLWithPath: home).appendingPathComponent("store.json").path
    }

    return FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".s-gw/store.json")
      .path
  }

  private func readOnePasswordAvailable() -> Bool {
    guard let output = runCli(["onepassword", "status"]) else { return false }
    return (try? JSONDecoder().decode(OnePasswordStatus.self, from: Data(output.utf8)).available) ?? false
  }

  private func checkDaemon() -> Bool {
    return checkDaemonPath("auth/status") || checkDaemonPath("api/health")
  }

  private func checkDaemonPath(_ path: String) -> Bool {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
    process.arguments = [
      "-fsS",
      "--max-time", "0.6",
      "--max-filesize", "4096",
      consoleURL.appendingPathComponent(path).absoluteString
    ]
    let out = Pipe()
    process.standardOutput = out
    process.standardError = Pipe()

    do {
      try process.run()
      let data = out.fileHandleForReading.readData(ofLength: 4097)
      if data.count > 4096 {
        process.terminate()
        process.waitUntilExit()
        return false
      }
      process.waitUntilExit()
      guard process.terminationStatus == 0,
            let response = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        return false
      }
      return response["ok"] as? Bool == true && response["name"] as? String == "s-gw"
    } catch {
      return false
    }
  }
}
