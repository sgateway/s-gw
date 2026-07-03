import SwiftUI
import WebKit

struct ConsoleWebAppView: NSViewRepresentable {
  let url: URL

  func makeNSView(context: Context) -> WKWebView {
    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .nonPersistent()
    let webView = WKWebView(frame: .zero, configuration: configuration)
    webView.allowsBackForwardNavigationGestures = true
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
