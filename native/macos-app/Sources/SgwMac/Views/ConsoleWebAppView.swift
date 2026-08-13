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
    let webView = ConsoleWebView(frame: .zero, configuration: configuration)
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

final class ConsoleWebView: WKWebView {
  static let dragSurfaceSelector = "[data-sgw-window-drag]"
  static let interactiveSelector = "button, a, input, select, textarea, summary, [role='button'], [role='link'], [contenteditable='true'], [data-sgw-window-no-drag]"

  override func mouseDown(with event: NSEvent) {
    guard let window, shouldStartWindowDrag(at: convert(event.locationInWindow, from: nil)) else {
      super.mouseDown(with: event)
      return
    }

    window.performDrag(with: event)
  }

  func shouldStartWindowDrag(at point: NSPoint) -> Bool {
    let clientY = isFlipped ? point.y : bounds.height - point.y
    guard clientY >= 0, clientY <= 84 else {
      return false
    }

    let script = """
    (() => {
      const hit = document.elementFromPoint(\(point.x), \(clientY));
      if (!hit || hit.closest(\(Self.javaScriptString(Self.interactiveSelector)))) return false;
      return Boolean(hit.closest(\(Self.javaScriptString(Self.dragSurfaceSelector))));
    })()
    """

    var isDragSurface = false
    let wait = DispatchSemaphore(value: 0)
    evaluateJavaScript(script) { value, _ in
      isDragSurface = value as? Bool ?? false
      wait.signal()
    }

    let deadline = Date(timeIntervalSinceNow: 0.1)
    while Date() < deadline {
      if wait.wait(timeout: .now()) == .success {
        return isDragSurface
      }
      RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.001))
    }
    return false
  }

  private static func javaScriptString(_ value: String) -> String {
    let data = try? JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed])
    return data.flatMap { String(data: $0, encoding: .utf8) } ?? "\"\""
  }
}
