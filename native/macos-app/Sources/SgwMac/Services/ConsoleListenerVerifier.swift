import Foundation

@MainActor
enum ConsoleListenerVerifier {
  enum Navigation {
    case console
    case external
    case reject
  }

  static func rootURL(for target: URL) -> URL? {
    guard target.scheme == "http", target.host == "127.0.0.1",
          target.user == nil, target.password == nil,
          let port = target.port, port > 0, port <= 65535 else {
      return nil
    }
    return URL(string: "http://127.0.0.1:\(port)/")
  }

  static func verify(_ target: URL, using cli: CLIRunner) async -> Bool {
    guard let root = rootURL(for: target) else { return false }
    let result = await cli.run(arguments: ["console", "verify-listener", "--console-url", root.absoluteString])
    return result.succeeded
  }

  static func navigation(to target: URL, from expected: URL) -> Navigation {
    guard let expectedRoot = rootURL(for: expected) else { return .reject }
    if rootURL(for: target) == expectedRoot { return .console }
    guard (target.scheme == "http" || target.scheme == "https"),
          target.user == nil, target.password == nil,
          let host = target.host?.lowercased(), !host.isEmpty else {
      return .reject
    }

    let name = host.hasSuffix(".") ? String(host.dropLast()) : host
    if name == "localhost" || name.hasSuffix(".localhost") || name.hasSuffix(".local") ||
        name == "0.0.0.0" || name == "::" || name == "::1" ||
        name.hasPrefix("::ffff:127.") || name.hasPrefix("127.") ||
        name.range(of: "^[0-9][0-9.xXa-fA-F]*$", options: .regularExpression) != nil {
      return .reject
    }
    return .external
  }
}
