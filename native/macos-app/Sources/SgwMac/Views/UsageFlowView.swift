import SwiftUI
import WebKit

struct UsageFlowView: View {
  @Environment(AppState.self) private var appState

  var body: some View {
    let rows = appState.usageFlowRows

    VStack(alignment: .leading, spacing: 0) {
      PanelCard("Agent credential flow", systemImage: "arrow.triangle.branch") {
        if rows.isEmpty {
          EmptyPanel(
            title: "No credential use yet",
            message: "Agent requests will appear after they ask s-gw to use a credential.",
            systemImage: "point.3.connected.trianglepath.dotted"
          )
        } else {
          HStack {
            Spacer()
            Button {
              appState.openUsageFlowConsole()
            } label: {
              Label("Open Sankey Chart", systemImage: "safari")
            }
            .buttonStyle(.bordered)
          }
          UsageFlowWebChart(url: appState.usageFlowConsoleURL(embed: true))
            .frame(minHeight: 560)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
      }
      .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    }
    .padding(18)
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    .background(SGWTheme.surface)
  }
}

struct UsageFlowWebChart: View {
  let url: URL?

  var body: some View {
    Group {
      if let url {
        SankeyWebView(url: url)
          .clipShape(RoundedRectangle(cornerRadius: 8))
          .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.secondary.opacity(0.18)))
      } else {
        EmptyPanel(
          title: "Console unavailable",
          message: "Start the local daemon to load the d3-sankey chart.",
          systemImage: "safari"
        )
      }
    }
  }
}

private struct SankeyWebView: NSViewRepresentable {
  let url: URL

  func makeNSView(context: Context) -> WKWebView {
    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .nonPersistent()

    let webView = WKWebView(frame: .zero, configuration: configuration)
    webView.load(URLRequest(url: url))
    return webView
  }

  func updateNSView(_ webView: WKWebView, context: Context) {
    if webView.url?.absoluteString == url.absoluteString {
      return
    }
    webView.load(URLRequest(url: url))
  }
}
