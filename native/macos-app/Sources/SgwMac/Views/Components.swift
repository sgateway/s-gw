import SwiftUI

struct MetricCard<Detail: View>: View {
  let title: String
  let value: String
  let systemImage: String
  var tint: Color = SGWTheme.teal
  @ViewBuilder var detail: Detail

  init(
    title: String,
    value: String,
    systemImage: String,
    tint: Color = SGWTheme.teal,
    @ViewBuilder detail: () -> Detail = { EmptyView() }
  ) {
    self.title = title
    self.value = value
    self.systemImage = systemImage
    self.tint = tint
    self.detail = detail()
  }

  var body: some View {
    HStack(spacing: 12) {
      Image(systemName: systemImage)
        .font(.title2)
        .foregroundStyle(tint)
        .frame(width: 42, height: 42)
        .background(tint.opacity(0.14), in: RoundedRectangle(cornerRadius: 8))
      VStack(alignment: .leading, spacing: 3) {
        Text(title)
          .font(.caption)
          .foregroundStyle(.secondary)
        Text(value)
          .font(.system(size: 25, weight: .bold, design: .rounded))
        detail
      }
      Spacer(minLength: 0)
    }
    .padding(14)
    .background(SGWTheme.raised, in: RoundedRectangle(cornerRadius: 8))
  }
}

struct PanelCard<Content: View>: View {
  let title: String
  var systemImage: String?
  @ViewBuilder var content: Content

  init(_ title: String, systemImage: String? = nil, @ViewBuilder content: () -> Content) {
    self.title = title
    self.systemImage = systemImage
    self.content = content()
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack(spacing: 8) {
        if let systemImage {
          Image(systemName: systemImage).foregroundStyle(SGWTheme.teal)
        }
        Text(title).font(.headline)
        Spacer()
      }
      content
    }
    .padding(14)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(SGWTheme.raised, in: RoundedRectangle(cornerRadius: 8))
  }
}

struct SeverityBadge: View {
  let severity: SecretSeverity

  var body: some View {
    Text(severity.label)
      .font(.caption2.weight(.semibold))
      .padding(.horizontal, 7)
      .padding(.vertical, 3)
      .background(SGWTheme.severity(severity).opacity(0.14), in: Capsule())
      .foregroundStyle(SGWTheme.severity(severity))
  }
}

struct StatePill: View {
  let label: String
  let color: Color

  var body: some View {
    HStack(spacing: 5) {
      Circle().fill(color).frame(width: 7, height: 7)
      Text(label)
        .font(.caption.weight(.medium))
    }
    .padding(.horizontal, 8)
    .padding(.vertical, 4)
    .background(color.opacity(0.12), in: Capsule())
  }
}

struct RequestStateBadge: View {
  let state: RequestState

  var body: some View {
    Text(state.rawValue.capitalized)
      .font(.caption2.weight(.semibold))
      .padding(.horizontal, 7)
      .padding(.vertical, 3)
      .background(SGWTheme.requestState(state).opacity(0.14), in: Capsule())
      .foregroundStyle(SGWTheme.requestState(state))
  }
}

/// Shown when `s-gw status` reports the gateway is not ready to store/redeem secrets.
/// Surfaces the CLI's own actionable blockers instead of a green-looking-but-locked state.
struct ReadinessBanner: View {
  let summary: String
  let blockers: [String]
  var onRunSetup: (() -> Void)?

  var body: some View {
    HStack(alignment: .top, spacing: 12) {
      Image(systemName: "exclamationmark.triangle.fill")
        .font(.title3)
        .foregroundStyle(SGWTheme.orange)
      VStack(alignment: .leading, spacing: 6) {
        Text(summary.isEmpty ? "s-gw is not ready yet." : summary)
          .font(.callout.weight(.semibold))
        ForEach(Array(blockers.enumerated()), id: \.offset) { _, blocker in
          HStack(alignment: .top, spacing: 6) {
            Text("•").foregroundStyle(.secondary)
            Text(blocker)
              .font(.caption)
              .foregroundStyle(.secondary)
              .textSelection(.enabled)
          }
        }
        if let onRunSetup {
          Button("Run Setup", action: onRunSetup)
            .controlSize(.small)
            .buttonStyle(.borderedProminent)
            .tint(SGWTheme.teal)
            .padding(.top, 2)
            .accessibilityIdentifier("s-gw-readiness-run-setup")
        }
      }
      Spacer(minLength: 0)
    }
    .padding(14)
    .background(SGWTheme.orange.opacity(0.10), in: RoundedRectangle(cornerRadius: 8))
    .overlay(
      RoundedRectangle(cornerRadius: 8)
        .strokeBorder(SGWTheme.orange.opacity(0.35), lineWidth: 1)
    )
    .accessibilityElement(children: .combine)
    .accessibilityLabel("s-gw readiness")
    .accessibilityIdentifier("s-gw-readiness-banner")
  }
}

struct EmptyPanel: View {
  let title: String
  let message: String
  var systemImage = "tray"

  var body: some View {
    ContentUnavailableView {
      Label(title, systemImage: systemImage)
    } description: {
      Text(message)
    }
    .frame(maxWidth: .infinity, minHeight: 180)
  }
}

extension View {
  func copyToPasteboard(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
  }
}
