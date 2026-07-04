import Foundation

actor StoreReader {
  func auditEvents(storePath: String?) async -> [AuditEvent] {
    let path = storePath ?? defaultStorePath()
    guard FileManager.default.isReadableFile(atPath: path) else {
      return []
    }

    do {
      let data = try Data(contentsOf: URL(fileURLWithPath: path))
      return try JSONDecoder().decode(StoreSnapshot.self, from: data).audit
    } catch {
      return []
    }
  }

  private func defaultStorePath() -> String {
    let env = ProcessInfo.processInfo.environment
    if let home = env["SGW_HOME"], !home.isEmpty {
      return URL(fileURLWithPath: home).appendingPathComponent("store.json").path
    }
    return FileManager.default.homeDirectoryForCurrentUser
      .appendingPathComponent(".s-gw/store.json")
      .path
  }
}
