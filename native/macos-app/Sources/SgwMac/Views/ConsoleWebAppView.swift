import AppKit
import SwiftUI
import WebKit

struct ConsoleWebAppView: NSViewRepresentable {
  let url: URL

  func makeCoordinator() -> Coordinator {
    Coordinator()
  }

  func makeNSView(context: Context) -> WKWebView {
    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .nonPersistent()
    let webView = WKWebView(frame: .zero, configuration: configuration)
    webView.navigationDelegate = context.coordinator
    webView.allowsBackForwardNavigationGestures = true
    webView.underPageBackgroundColor = NSColor(red: 0.02, green: 0.04, blue: 0.07, alpha: 1)
    context.coordinator.load(url, in: webView)
    return webView
  }

  func updateNSView(_ webView: WKWebView, context: Context) {
    context.coordinator.load(url, in: webView)
  }

  @MainActor
  final class Coordinator: NSObject, WKNavigationDelegate {
    private var requestedURL: URL?
    private var retryTask: Task<Void, Never>?

    func load(_ url: URL, in webView: WKWebView) {
      if requestedURL == url {
        if webView.isLoading || webView.url == url || retryTask != nil {
          return
        }
      } else {
        retryTask?.cancel()
        retryTask = nil
        requestedURL = url
      }
      webView.load(URLRequest(url: url))
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
      retryTask?.cancel()
      retryTask = nil
    }

    func webView(
      _ webView: WKWebView,
      didFail navigation: WKNavigation!,
      withError error: any Error
    ) {
      retry(webView)
    }

    func webView(
      _ webView: WKWebView,
      didFailProvisionalNavigation navigation: WKNavigation!,
      withError error: any Error
    ) {
      retry(webView)
    }

    private func retry(_ webView: WKWebView) {
      guard retryTask == nil else { return }
      retryTask = Task { @MainActor [weak self, weak webView] in
        do {
          try await Task.sleep(for: .milliseconds(500))
        } catch {
          return
        }
        guard let self, let webView, let requestedURL else { return }
        retryTask = nil
        webView.load(URLRequest(url: requestedURL))
      }
    }
  }
}
