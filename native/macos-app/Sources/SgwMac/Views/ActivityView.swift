import Foundation
import SwiftUI

struct ActivityView: View {
  @Environment(AppState.self) private var appState
  @State private var selectedID: String?
  @State private var search = ""
  @State private var outputMode: ActivityOutputMode = .summary

  private var filtered: [CommandActivityRecord] {
    let records = appState.activity.records
    let needle = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    guard !needle.isEmpty else {
      return records
    }
    return records.filter { record in
      [
        record.title,
        record.category,
        record.commandLine,
        record.output
      ].joined(separator: " ").lowercased().contains(needle)
    }
  }

  private var selectedRecord: CommandActivityRecord? {
    appState.activity.record(with: selectedID) ?? filtered.first
  }

  var body: some View {
    HStack(spacing: 0) {
      activityList
        .frame(minWidth: 330, idealWidth: 380, maxWidth: 430)
      Divider()
      activityInspector
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    .searchable(text: $search, prompt: "Search command activity")
    .background(SGWTheme.surface)
  }

  private var activityList: some View {
    VStack(alignment: .leading, spacing: 10) {
      HStack {
        Text("Command Activity")
          .font(.title3.weight(.semibold))
        Spacer()
        Button {
          appState.commandPalettePresented = true
        } label: {
          Label("Run", systemImage: "command")
        }
        .controlSize(.small)
      }
      .padding(.horizontal, 16)
      .padding(.top, 16)

      if filtered.isEmpty {
        EmptyPanel(title: "No commands yet", message: "Use the Command Palette or setup actions to run local s-gw commands.", systemImage: "terminal")
      } else {
        List(selection: $selectedID) {
          ForEach(filtered) { record in
            ActivityListRow(record: record)
              .tag(record.id)
          }
        }
        .listStyle(.sidebar)
      }

      HStack {
        Button("Clear Finished") {
          appState.activity.clearFinished()
        }
        Button("Clear All") {
          appState.activity.clearAll()
        }
      }
      .controlSize(.small)
      .padding([.horizontal, .bottom], 16)
    }
    .background(.regularMaterial)
  }

  @ViewBuilder
  private var activityInspector: some View {
    if let record = selectedRecord {
      ScrollView {
        VStack(alignment: .leading, spacing: 16) {
          inspectorHeader(record)
          outputPanel(record)
          metadataPanel(record)
        }
        .padding(18)
      }
      .onChange(of: record.id) { _, _ in
        outputMode = .summary
      }
    } else {
      EmptyPanel(title: "No command selected", message: "Select a command run to inspect its output.", systemImage: "terminal")
    }
  }

  private func inspectorHeader(_ record: CommandActivityRecord) -> some View {
    PanelCard(record.title, systemImage: "terminal") {
      VStack(alignment: .leading, spacing: 12) {
        HStack {
          CommandStatusPill(status: record.status)
          Text(record.category)
            .font(.caption)
            .foregroundStyle(.secondary)
          Spacer()
          if record.status == .running {
            Button(role: .destructive) {
              appState.cancelCommand(record)
            } label: {
              Label("Cancel", systemImage: "stop.fill")
            }
            .controlSize(.small)
          }
        }

        Text(record.commandLine)
          .font(.system(.callout, design: .monospaced))
          .textSelection(.enabled)
          .padding(10)
          .frame(maxWidth: .infinity, alignment: .leading)
          .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 8))

        HStack {
          Button {
            copyToPasteboard(record.commandLine)
            appState.operationMessage = "Copied command"
          } label: {
            Label("Copy Command", systemImage: "doc.on.doc")
          }
          Button {
            copyToPasteboard(record.output)
            appState.operationMessage = "Copied output"
          } label: {
            Label("Copy Output", systemImage: "text.page")
          }
          .disabled(record.output.isEmpty)
        }
        .controlSize(.small)
      }
    }
  }

  private func outputPanel(_ record: CommandActivityRecord) -> some View {
    let presentation = ActivityOutputPresentation(output: record.output, status: record.status)
    return PanelCard(presentation.panelTitle, systemImage: presentation.systemImage) {
      VStack(alignment: .leading, spacing: 12) {
        if presentation.isStructured {
          Picker("Output view", selection: $outputMode) {
            ForEach(ActivityOutputMode.allCases) { mode in
              Text(mode.label).tag(mode)
            }
          }
          .pickerStyle(.segmented)
          .frame(width: 180)

          if outputMode == .summary {
            ActivityOutputSummaryView(presentation: presentation)
          } else {
            RawOutputBlock(text: presentation.rawDisplay)
          }
        } else {
          RawOutputBlock(text: presentation.rawDisplay)
        }
      }
    }
  }

  private func metadataPanel(_ record: CommandActivityRecord) -> some View {
    PanelCard("Run Details", systemImage: "info.circle") {
      VStack(alignment: .leading, spacing: 9) {
        KeyValueGrid(pairs: [
          ("Started", record.startedAt.formatted(date: .abbreviated, time: .standard)),
          ("Duration", record.durationLabel),
          ("Exit code", record.exitCode.map(String.init) ?? "-"),
          ("Run ID", record.id)
        ])

        if !record.sideEffects.isEmpty {
          Divider()
          ForEach(record.sideEffects, id: \.self) { effect in
            Label(effect, systemImage: "exclamationmark.triangle")
              .font(.caption)
              .foregroundStyle(SGWTheme.orange)
          }
        }

        if let next = record.suggestedNextAction {
          Divider()
          Label(next, systemImage: "arrow.turn.down.right")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
      }
    }
  }
}

private enum ActivityOutputMode: String, CaseIterable, Identifiable {
  case summary
  case raw

  var id: String { rawValue }

  var label: String {
    switch self {
    case .summary: "Summary"
    case .raw: "Raw"
    }
  }
}

private struct ActivityOutputSummaryView: View {
  let presentation: ActivityOutputPresentation

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack(spacing: 10) {
        ActivityOutputMetric(
          title: "Result",
          value: presentation.resultLabel,
          systemImage: presentation.systemImage,
          tint: presentation.tint
        )
        ActivityOutputMetric(
          title: presentation.countTitle,
          value: presentation.countLabel,
          systemImage: presentation.countImage,
          tint: SGWTheme.blue
        )
      }

      if !presentation.headline.isEmpty {
        Text(presentation.headline)
          .font(.callout.weight(.medium))
          .textSelection(.enabled)
      }

      if !presentation.pairs.isEmpty {
        KeyValueGrid(pairs: presentation.pairs)
      } else {
        Text("Structured output parsed successfully.")
          .font(.caption)
          .foregroundStyle(.secondary)
      }
    }
  }
}

private struct ActivityOutputMetric: View {
  let title: String
  let value: String
  let systemImage: String
  let tint: Color

  var body: some View {
    HStack(spacing: 9) {
      Image(systemName: systemImage)
        .foregroundStyle(tint)
        .frame(width: 26, height: 26)
        .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 6))
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
          .font(.caption2)
          .foregroundStyle(.secondary)
        Text(value)
          .font(.caption.weight(.semibold))
          .lineLimit(1)
      }
      Spacer(minLength: 0)
    }
    .padding(10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
  }
}

private struct RawOutputBlock: View {
  let text: String

  var body: some View {
    ScrollView([.vertical, .horizontal]) {
      Text(displayText)
        .font(.system(.caption, design: .monospaced))
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(10)
    }
    .frame(minHeight: 120, maxHeight: 340)
    .background(Color.black.opacity(0.06), in: RoundedRectangle(cornerRadius: 8))
  }

  private var displayText: String {
    text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      ? "No output captured."
      : text
  }
}

private struct ActivityOutputPresentation {
  let raw: String
  let status: CommandRunStatus
  let json: ActivityJSONValue?

  init(output: String, status: CommandRunStatus) {
    self.raw = output
    self.status = status
    self.json = ActivityJSONValue.parse(output)
  }

  var isStructured: Bool {
    json != nil
  }

  var rawDisplay: String {
    raw
  }

  var panelTitle: String {
    isStructured ? "Result Summary" : "Output"
  }

  var systemImage: String {
    switch tone {
    case .success: "checkmark.circle"
    case .warning: "exclamationmark.triangle"
    case .failure: "xmark.octagon"
    case .neutral: "text.alignleft"
    }
  }

  var tint: Color {
    switch tone {
    case .success: SGWTheme.green
    case .warning: SGWTheme.orange
    case .failure: SGWTheme.red
    case .neutral: SGWTheme.teal
    }
  }

  var resultLabel: String {
    switch tone {
    case .success: "OK"
    case .warning: "Needs review"
    case .failure: "Failed"
    case .neutral: status.label
    }
  }

  var countTitle: String {
    guard let json else { return "Lines" }
    switch json {
    case .array:
      return "Items"
    case .object:
      return "Fields"
    default:
      return "Value"
    }
  }

  var countLabel: String {
    guard let json else {
      let lines = raw.split(whereSeparator: \.isNewline).count
      return String(max(1, lines))
    }
    switch json {
    case .array(let values):
      return String(values.count)
    case .object(let fields):
      return String(fields.count)
    default:
      return "1"
    }
  }

  var countImage: String {
    guard let json else { return "text.alignleft" }
    switch json {
    case .array:
      return "list.bullet"
    case .object:
      return "tablecells"
    default:
      return "textformat"
    }
  }

  var headline: String {
    guard let json else { return "" }
    if let error = json.string(at: ["error"]) {
      return "Error: \(error)"
    }
    if let summary = json.string(at: ["readiness", "summary"]) {
      return summary
    }
    if let message = json.string(at: ["message"]) {
      return message
    }
    if let summary = json.string(at: ["summary"]) {
      return summary
    }
    if let ready = json.bool(at: ["ready"]) {
      return ready ? "s-gw is ready." : "s-gw is not ready yet."
    }
    if let ok = json.bool(at: ["ok"]) {
      return ok ? "Command completed successfully." : "Command reported a problem."
    }
    if let state = json.string(at: ["state"]) {
      return "State: \(state)"
    }
    if let name = json.string(at: ["name"]), let version = json.string(at: ["version"]) {
      return "\(name) \(version)"
    }
    switch json {
    case .array(let values):
      return "\(values.count) item\(values.count == 1 ? "" : "s") returned."
    case .object(let fields):
      return "\(fields.count) field\(fields.count == 1 ? "" : "s") returned."
    default:
      return "Structured output returned."
    }
  }

  var pairs: [(String, String)] {
    guard let json else { return [] }
    var items: [(String, String, Int)] = []
    collectPairs(from: json, prefix: [], depth: 0, into: &items)
    return items
      .sorted { left, right in
        if left.2 != right.2 { return left.2 < right.2 }
        return left.0 < right.0
      }
      .prefix(16)
      .map { (humanLabel($0.0), clip($0.1, limit: 180)) }
  }

  private var tone: ActivityOutputTone {
    if status == .failed || json?.string(at: ["error"]) != nil {
      return .failure
    }
    if status == .cancelled {
      return .warning
    }
    if let ready = json?.bool(at: ["ready"]), !ready {
      return .warning
    }
    if let ok = json?.bool(at: ["ok"]), !ok {
      return .warning
    }
    if status == .succeeded {
      return .success
    }
    return .neutral
  }

  private func collectPairs(
    from value: ActivityJSONValue,
    prefix: [String],
    depth: Int,
    into items: inout [(String, String, Int)]
  ) {
    guard items.count < 48 else { return }

    switch value {
    case .object(let fields):
      if depth >= 2, !prefix.isEmpty {
        items.append((prefix.joined(separator: "."), value.brief, priority(for: prefix)))
        return
      }
      for key in fields.keys.sorted() {
        collectPairs(from: fields[key] ?? .null, prefix: prefix + [key], depth: depth + 1, into: &items)
      }
    case .array(let values):
      guard !prefix.isEmpty else {
        items.append(("items", "\(values.count) item\(values.count == 1 ? "" : "s")", 30))
        return
      }
      items.append((prefix.joined(separator: "."), value.brief, priority(for: prefix)))
    default:
      guard !prefix.isEmpty else { return }
      items.append((prefix.joined(separator: "."), value.brief, priority(for: prefix)))
    }
  }

  private func priority(for path: [String]) -> Int {
    let joined = path.joined(separator: ".")
    let key = path.last ?? joined
    if ["error", "message", "summary"].contains(key) { return 0 }
    if ["ok", "ready", "state", "status"].contains(key) { return 1 }
    if ["name", "version", "handle", "id", "mode"].contains(key) { return 2 }
    if joined.contains("activeSource") || joined.contains("launchAgents") { return 3 }
    if joined.contains("path") || joined.contains("url") { return 8 }
    return 5
  }

  private func humanLabel(_ value: String) -> String {
    let words = value
      .replacingOccurrences(of: ".", with: " ")
      .replacingOccurrences(of: "_", with: " ")
      .replacingOccurrences(of: "-", with: " ")
      .split(separator: " ")
      .map { word -> String in
        let text = String(word)
        let expanded = text.replacingOccurrences(
          of: "([a-z0-9])([A-Z])",
          with: "$1 $2",
          options: .regularExpression
        )
        return expanded.split(separator: " ").map(capitalizedWord).joined(separator: " ")
      }
    return words.joined(separator: " ")
  }

  private func capitalizedWord(_ word: Substring) -> String {
    let lower = word.lowercased()
    if ["id", "url", "cli", "mcp", "json", "api"].contains(lower) {
      return lower.uppercased()
    }
    if lower == "ok" { return "OK" }
    return lower.prefix(1).uppercased() + String(lower.dropFirst())
  }

  private func clip(_ value: String, limit: Int) -> String {
    guard value.count > limit else { return value }
    return String(value.prefix(max(0, limit - 1))) + "..."
  }
}

private enum ActivityOutputTone {
  case success
  case warning
  case failure
  case neutral
}

private enum ActivityJSONValue {
  case object([String: ActivityJSONValue])
  case array([ActivityJSONValue])
  case string(String)
  case number(String)
  case bool(Bool)
  case null

  static func parse(_ output: String) -> ActivityJSONValue? {
    let trimmed = output.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let data = trimmed.data(using: .utf8), !data.isEmpty else {
      return nil
    }
    guard let object = try? JSONSerialization.jsonObject(with: data) else {
      return nil
    }
    return ActivityJSONValue(any: object)
  }

  init?(any: Any) {
    if let dict = any as? [String: Any] {
      var values: [String: ActivityJSONValue] = [:]
      for (key, value) in dict {
        values[key] = ActivityJSONValue(any: value) ?? .null
      }
      self = .object(values)
      return
    }
    if let array = any as? [Any] {
      self = .array(array.map { ActivityJSONValue(any: $0) ?? .null })
      return
    }
    if let string = any as? String {
      self = .string(string)
      return
    }
    if let number = any as? NSNumber {
      if String(cString: number.objCType) == "c" {
        self = .bool(number.boolValue)
      } else {
        self = .number(number.stringValue)
      }
      return
    }
    if any is NSNull {
      self = .null
      return
    }
    return nil
  }

  var brief: String {
    switch self {
    case .object(let fields):
      return "\(fields.count) field\(fields.count == 1 ? "" : "s")"
    case .array(let values):
      if values.isEmpty {
        return "0 items"
      }
      let preview = values.prefix(3).map(\.briefScalar).filter { !$0.isEmpty }
      let suffix = values.count > preview.count ? " +" + String(values.count - preview.count) : ""
      return preview.isEmpty ? "\(values.count) items" : preview.joined(separator: ", ") + suffix
    case .string(let value):
      return value.isEmpty ? "-" : value
    case .number(let value):
      return value
    case .bool(let value):
      return value ? "Yes" : "No"
    case .null:
      return "-"
    }
  }

  private var briefScalar: String {
    switch self {
    case .string(let value): value
    case .number(let value): value
    case .bool(let value): value ? "Yes" : "No"
    case .null: "-"
    case .object(let fields): "\(fields.count) fields"
    case .array(let values): "\(values.count) items"
    }
  }

  func string(at path: [String]) -> String? {
    guard let value = value(at: path) else { return nil }
    if case .string(let string) = value {
      return string.isEmpty ? nil : string
    }
    return nil
  }

  func bool(at path: [String]) -> Bool? {
    guard let value = value(at: path) else { return nil }
    if case .bool(let bool) = value {
      return bool
    }
    return nil
  }

  private func value(at path: [String]) -> ActivityJSONValue? {
    guard let head = path.first else {
      return self
    }
    guard case .object(let fields) = self, let next = fields[head] else {
      return nil
    }
    return next.value(at: Array(path.dropFirst()))
  }
}

private struct ActivityListRow: View {
  let record: CommandActivityRecord

  var body: some View {
    HStack(spacing: 10) {
      Image(systemName: icon)
        .foregroundStyle(color)
        .frame(width: 18)
      VStack(alignment: .leading, spacing: 3) {
        Text(record.title)
          .lineLimit(1)
        Text(record.commandLine)
          .font(.caption)
          .foregroundStyle(.secondary)
          .lineLimit(1)
      }
      Spacer()
      Text(record.durationLabel)
        .font(.caption2)
        .foregroundStyle(.secondary)
    }
    .padding(.vertical, 3)
  }

  private var icon: String {
    switch record.status {
    case .running: "play.circle"
    case .succeeded: "checkmark.circle"
    case .failed: "xmark.octagon"
    case .cancelled: "stop.circle"
    }
  }

  private var color: Color {
    switch record.status {
    case .running: SGWTheme.blue
    case .succeeded: SGWTheme.green
    case .failed: SGWTheme.red
    case .cancelled: SGWTheme.orange
    }
  }
}

private struct CommandStatusPill: View {
  let status: CommandRunStatus

  var body: some View {
    StatePill(label: status.label, color: color)
  }

  private var color: Color {
    switch status {
    case .running: SGWTheme.blue
    case .succeeded: SGWTheme.green
    case .failed: SGWTheme.red
    case .cancelled: SGWTheme.orange
    }
  }
}
