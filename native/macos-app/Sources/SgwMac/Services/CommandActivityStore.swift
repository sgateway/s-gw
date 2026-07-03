import Foundation
import Observation

enum CommandRunStatus: String, CaseIterable, Hashable {
  case running
  case succeeded
  case failed
  case cancelled

  var label: String {
    switch self {
    case .running: "Running"
    case .succeeded: "Succeeded"
    case .failed: "Failed"
    case .cancelled: "Cancelled"
    }
  }
}

struct CommandActivityRecord: Identifiable, Hashable {
  let id: String
  var title: String
  var category: String
  var arguments: [String]
  var startedAt: Date
  var endedAt: Date?
  var status: CommandRunStatus
  var exitCode: Int?
  var output: String
  var sideEffects: [String]
  var suggestedNextAction: String?

  var commandLine: String {
    (["s-gw"] + arguments).map(CommandArgumentParser.quote).joined(separator: " ")
  }

  var durationLabel: String {
    let end = endedAt ?? Date()
    let seconds = max(0.0, end.timeIntervalSince(startedAt))
    if seconds < 1 {
      return "<1s"
    }
    if seconds < 60 {
      return "\(Int(seconds))s"
    }
    let minutes = Int(seconds / 60)
    return "\(minutes)m \(Int(seconds) % 60)s"
  }
}

@MainActor
@Observable
final class CommandActivityStore {
  private(set) var records: [CommandActivityRecord] = []

  private let maxRecords = 120
  private let maxOutputCharacters = 60_000

  func begin(
    title: String,
    category: String,
    arguments: [String],
    sideEffects: [String] = [],
    suggestedNextAction: String? = nil
  ) -> String {
    let id = "cmd_\(UUID().uuidString.replacingOccurrences(of: "-", with: "").prefix(10))"
    let record = CommandActivityRecord(
      id: id,
      title: title,
      category: category,
      arguments: arguments,
      startedAt: Date(),
      endedAt: nil,
      status: .running,
      exitCode: nil,
      output: "",
      sideEffects: sideEffects,
      suggestedNextAction: suggestedNextAction
    )
    records.insert(record, at: 0)
    trim()
    return id
  }

  func appendOutput(_ line: String, to id: String) {
    guard let idx = records.firstIndex(where: { $0.id == id }) else {
      return
    }
    records[idx].output = clipped(records[idx].output + line + "\n")
  }

  func finish(id: String, result: CLIResult) {
    guard let idx = records.firstIndex(where: { $0.id == id }) else {
      return
    }
    records[idx].endedAt = Date()
    records[idx].exitCode = Int(result.exitCode)
    records[idx].status = result.succeeded ? .succeeded : .failed
    let finalOutput = result.output.isEmpty ? emptyOutputMessage(result: result) : result.output
    if records[idx].output.isEmpty || records[idx].output != finalOutput {
      records[idx].output = clipped(finalOutput)
    }
  }

  func markCancelled(id: String) {
    guard let idx = records.firstIndex(where: { $0.id == id }) else {
      return
    }
    records[idx].endedAt = Date()
    records[idx].status = .cancelled
  }

  func clearFinished() {
    records.removeAll { $0.status != .running }
  }

  func clearAll() {
    records.removeAll()
  }

  func record(with id: String?) -> CommandActivityRecord? {
    guard let id else { return records.first }
    return records.first { $0.id == id } ?? records.first
  }

  private func trim() {
    if records.count > maxRecords {
      records.removeLast(records.count - maxRecords)
    }
  }

  private func clipped(_ text: String) -> String {
    guard text.count > maxOutputCharacters else {
      return text
    }
    return String(text.suffix(maxOutputCharacters))
  }

  private func emptyOutputMessage(result: CLIResult) -> String {
    if result.succeeded {
      return "Command completed successfully. The CLI did not write stdout or stderr."
    }
    return "Command exited with code \(result.exitCode) and did not write stdout or stderr."
  }
}
