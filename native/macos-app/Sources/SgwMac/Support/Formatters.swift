import Foundation

enum SGWDates {
  static func date(_ value: String) -> Date? {
    let formatter = ISO8601DateFormatter()
    formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let parsed = formatter.date(from: value) {
      return parsed
    }
    let fallback = ISO8601DateFormatter()
    return fallback.date(from: value)
  }

  static func relative(_ value: String) -> String {
    guard let date = date(value) else { return "unknown" }
    return relative(date)
  }

  static func relative(_ date: Date) -> String {
    let seconds = max(0, Int(Date().timeIntervalSince(date)))
    if seconds < 60 { return "\(seconds)s ago" }
    if seconds < 3600 { return "\(seconds / 60)m ago" }
    if seconds < 86400 { return "\(seconds / 3600)h ago" }
    return "\(seconds / 86400)d ago"
  }

  static func until(_ value: String) -> String {
    guard let date = date(value) else { return "unknown" }
    let seconds = Int(date.timeIntervalSince(Date()))
    if seconds <= 0 { return "expired" }
    if seconds < 60 { return "in \(seconds)s" }
    if seconds < 3600 { return "in \(seconds / 60)m" }
    if seconds < 86400 { return "in \(seconds / 3600)h" }
    return "in \(seconds / 86400)d"
  }

  static func clock(_ value: String) -> String {
    guard let date = date(value) else { return "-" }
    return date.formatted(date: .omitted, time: .standard)
  }
}

enum SGWText {
  static func shortHandle(_ value: String, middle: Int = 10) -> String {
    if value.count <= 34 { return value }
    return "\(value.prefix(middle))...\(value.suffix(8))"
  }

  static func shortPath(_ value: String) -> String {
    let url = URL(fileURLWithPath: value)
    let name = url.lastPathComponent
    return name.isEmpty ? value : name
  }

  static func token(_ handle: String) -> String {
    "<<SGW_SECRET:\(shortHandle(handle, middle: 12))>>"
  }
}
