import Foundation

actor CLIRunner {
  static let binaryOverrideKey = "sgwBinaryPath"

  private var cachedCommand: (path: String, prefix: [String])?
  private var runningProcesses: [String: Process] = [:]
  private var cancellationRequests = Set<String>()

  func run(
    arguments: [String],
    input: String? = nil,
    runID: String? = nil,
    onLine: (@Sendable (String) -> Void)? = nil
  ) async -> CLIResult {
    guard let command = locateCommand() else {
      return CLIResult(exitCode: 127, output: "s-gw CLI not found. Set the path in Settings.")
    }

    let process = Process()
    process.executableURL = URL(fileURLWithPath: command.path)
    process.arguments = command.prefix + arguments
    process.environment = processEnvironment()

    let out = Pipe()
    let inputPipe = Pipe()
    process.standardOutput = out
    process.standardError = out
    process.standardInput = inputPipe

    do {
      try process.run()
    } catch {
      return CLIResult(exitCode: 126, output: "Failed to launch \(command.path): \(error.localizedDescription)")
    }

    // Drain bytes, not lines. Some CLI paths print compact JSON or short status
    // text without a trailing newline; AsyncBytes.lines can make that look like
    // "no output" in the activity inspector.
    let readHandle = out.fileHandleForReading
    let outputTask = Task.detached(priority: .utility) {
      let data = readHandle.readDataToEndOfFile()
      return String(decoding: data, as: UTF8.self)
    }

    if let runID {
      runningProcesses[runID] = process
      if cancellationRequests.remove(runID) != nil {
        process.terminate()
      }
    }

    defer {
      if let runID {
        runningProcesses.removeValue(forKey: runID)
        cancellationRequests.remove(runID)
      }
    }

    if let input {
      inputPipe.fileHandleForWriting.write(Data(input.utf8))
    }
    try? inputPipe.fileHandleForWriting.close()

    process.waitUntilExit()
    let collected = await outputTask.value
    emitLines(from: collected, to: onLine)
    return CLIResult(exitCode: process.terminationStatus, output: collected)
  }

  func cancel(runID: String) {
    if let process = runningProcesses[runID] {
      process.terminate()
      cancellationRequests.remove(runID)
      return
    }
    cancellationRequests.insert(runID)
  }

  func runJSON<T: Decodable>(_ type: T.Type, arguments: [String], input: String? = nil) async throws -> T {
    let result = await run(arguments: arguments, input: input)
    guard result.succeeded else {
      throw CLIError(result.output.trimmingCharacters(in: .whitespacesAndNewlines))
    }
    let data = Data(result.output.utf8)
    return try JSONDecoder().decode(T.self, from: data)
  }

  func locateBinaryPathForDisplay() -> String {
    locateCommand()?.path ?? "not found"
  }

  private func locateCommand() -> (path: String, prefix: [String])? {
    if let cachedCommand, FileManager.default.isExecutableFile(atPath: cachedCommand.path) {
      return cachedCommand
    }

    if let override = UserDefaults.standard.string(forKey: Self.binaryOverrideKey), !override.isEmpty {
      if override.hasSuffix(".js"), let command = commandForJavascriptCli(override) {
        cachedCommand = command
        return command
      }
      if FileManager.default.isExecutableFile(atPath: override) {
        let command = (path: override, prefix: [String]())
        cachedCommand = command
        return command
      }
    }

    let env = ProcessInfo.processInfo.environment
    if let cliPath = env["SGW_CLI_PATH"], let command = commandForJavascriptCli(cliPath) {
      cachedCommand = command
      return command
    }

    for candidate in bundledCliCandidates() {
      if let command = commandForJavascriptCli(candidate) {
        cachedCommand = command
        return command
      }
    }

    for candidate in ["/opt/homebrew/bin/s-gw", "/usr/local/bin/s-gw", "/opt/homebrew/bin/sgw", "/usr/local/bin/sgw"] {
      if FileManager.default.isExecutableFile(atPath: candidate) {
        let command = (path: candidate, prefix: [String]())
        cachedCommand = command
        return command
      }
    }

    if let found = which("s-gw") ?? which("sgw") {
      let command = (path: found, prefix: [String]())
      cachedCommand = command
      return command
    }

    return nil
  }

  private func commandForJavascriptCli(_ cliPath: String) -> (path: String, prefix: [String])? {
    guard FileManager.default.isReadableFile(atPath: cliPath) else {
      return nil
    }
    let node = locateNode()
    return (path: node.path, prefix: node.prefix + [cliPath])
  }

  private func bundledCliCandidates() -> [String] {
    var candidates: [String] = []
    let env = ProcessInfo.processInfo.environment
    if let root = env["SGW_REPO_ROOT"] {
      candidates.append(URL(fileURLWithPath: root).appendingPathComponent("dist/cli.js").path)
    }
    let distDir = Bundle.main.bundleURL.deletingLastPathComponent()
    candidates.append(distDir.appendingPathComponent("cli.js").path)
    candidates.append(FileManager.default.currentDirectoryPath + "/dist/cli.js")
    return candidates
  }

  private func locateNode() -> (path: String, prefix: [String]) {
    let env = ProcessInfo.processInfo.environment
    if let node = env["SGW_NODE_PATH"], FileManager.default.isExecutableFile(atPath: node) {
      return (node, [])
    }
    for candidate in ["/opt/homebrew/bin/node", "/usr/local/bin/node", "/usr/bin/node"] {
      if FileManager.default.isExecutableFile(atPath: candidate) {
        return (candidate, [])
      }
    }
    return ("/usr/bin/env", ["node"])
  }

  private func which(_ name: String) -> String? {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/which")
    process.arguments = [name]
    process.environment = processEnvironment()
    let pipe = Pipe()
    process.standardOutput = pipe
    process.standardError = Pipe()
    guard (try? process.run()) != nil else { return nil }
    process.waitUntilExit()
    let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
      .trimmingCharacters(in: .whitespacesAndNewlines)
    return process.terminationStatus == 0 && !out.isEmpty ? out : nil
  }

  private func processEnvironment() -> [String: String] {
    var env = ProcessInfo.processInfo.environment
    env["NO_COLOR"] = "1"

    let home = FileManager.default.homeDirectoryForCurrentUser.path
    let fallbackPaths = [
      "\(home)/.local/bin",
      "\(home)/bin",
      "\(home)/.docker/bin",
      "/opt/homebrew/bin",
      "/opt/homebrew/sbin",
      "/usr/local/bin",
      "/usr/local/sbin",
      "/Applications/Docker.app/Contents/Resources/bin",
      "/usr/bin",
      "/bin",
      "/usr/sbin",
      "/sbin"
    ]

    var seen = Set<String>()
    var pathParts: [String] = []
    for part in (env["PATH"] ?? "").split(separator: ":").map(String.init) + fallbackPaths {
      guard !part.isEmpty, seen.insert(part).inserted else {
        continue
      }
      pathParts.append(part)
    }
    env["PATH"] = pathParts.joined(separator: ":")
    return env
  }

  private func emitLines(from output: String, to onLine: (@Sendable (String) -> Void)?) {
    guard let onLine else {
      return
    }
    output.enumerateLines { line, _ in
      onLine(line)
    }
  }
}

struct CLIError: LocalizedError {
  let message: String

  init(_ message: String) {
    self.message = message.isEmpty ? "s-gw command failed." : message
  }

  var errorDescription: String? { message }
}
