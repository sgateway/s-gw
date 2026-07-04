import SwiftUI

extension Color {
  init(hex: UInt32) {
    self.init(
      .sRGB,
      red: Double((hex >> 16) & 0xFF) / 255,
      green: Double((hex >> 8) & 0xFF) / 255,
      blue: Double(hex & 0xFF) / 255
    )
  }

  static func adaptive(light: UInt32, dark: UInt32) -> Color {
    Color(nsColor: NSColor(name: nil) { appearance in
      let isDark = appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua
      return NSColor(Color(hex: isDark ? dark : light))
    })
  }
}

enum SGWTheme {
  static let teal = Color.adaptive(light: 0x00857A, dark: 0x21C7B7)
  static let blue = Color.adaptive(light: 0x0B6FD3, dark: 0x58A6FF)
  static let green = Color(hex: 0x21A67A)
  static let red = Color(hex: 0xD92D20)
  static let orange = Color(hex: 0xC77700)
  static let yellow = Color(hex: 0xD6A100)
  static let purple = Color(hex: 0x6E56CF)
  static let surface = Color.adaptive(light: 0xF6F8FA, dark: 0x101820)
  static let raised = Color.adaptive(light: 0xFFFFFF, dark: 0x17212B)

  static func severity(_ severity: SecretSeverity) -> Color {
    switch severity {
    case .low: green
    case .medium: orange
    case .high: red
    case .critical: red
    }
  }

  static func requestState(_ state: RequestState) -> Color {
    switch state {
    case .pending: orange
    case .approved: green
    case .executing: blue
    case .denied: red
    case .executed: blue
    case .failed: red
    }
  }
}
