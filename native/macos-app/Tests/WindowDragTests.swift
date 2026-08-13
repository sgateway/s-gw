import AppKit
import Foundation
import WebKit

private func fail(_ message: String) -> Never {
  FileHandle.standardError.write(Data(("FAIL: \(message)\n").utf8))
  exit(1)
}

private func check(_ condition: Bool, _ message: String) {
  if !condition { fail(message) }
}

@MainActor
private func waitForDocument(_ webView: WKWebView) -> Bool {
  let deadline = Date(timeIntervalSinceNow: 5)
  while Date() < deadline {
    var complete = false
    var ready = false
    webView.evaluateJavaScript("document.getElementById('blank') !== null") { value, _ in
      ready = value as? Bool == true
      complete = true
    }
    while !complete, Date() < deadline {
      RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.002))
    }
    if ready { return true }
  }
  return false
}

@MainActor
private func evaluate(_ script: String, in webView: WKWebView) -> Any? {
  let deadline = Date(timeIntervalSinceNow: 2)
  var result: Any?
  var complete = false
  webView.evaluateJavaScript(script) { value, _ in
    result = value
    complete = true
  }
  while !complete, Date() < deadline {
    RunLoop.current.run(mode: .default, before: Date(timeIntervalSinceNow: 0.002))
  }
  return result
}

@main
struct WindowDragTests {
  @MainActor
  static func main() {
    _ = NSApplication.shared
    let configuration = WKWebViewConfiguration()
    configuration.websiteDataStore = .nonPersistent()
    let webView = ConsoleWebView(
      frame: NSRect(x: 0, y: 0, width: 400, height: 200),
      configuration: configuration
    )
    webView.loadHTMLString(
      """
      <!doctype html>
      <style>
        html, body { margin: 0; width: 400px; height: 200px; }
        [data-sgw-window-drag] { position: fixed; inset: 0 0 auto 0; height: 52px; }
        button { position: absolute; left: 10px; top: 10px; width: 80px; height: 30px; }
        [role=button] { position: absolute; left: 100px; top: 10px; width: 80px; height: 30px; }
      </style>
      <div data-sgw-window-drag>
        <button>Action</button>
        <span role="button">Menu</span>
        <span id="blank">Move</span>
      </div>
      """,
      baseURL: nil
    )

    check(waitForDocument(webView), "test document did not load")
    check(webView.isFlipped, "WKWebView should use top-left event coordinates")
    let blank = evaluate("document.elementFromPoint(300, 20)?.outerHTML", in: webView) as? String ?? "none"
    check(webView.shouldStartWindowDrag(at: NSPoint(x: 300, y: 20)), "blank title chrome should drag, found \(blank)")
    check(!webView.shouldStartWindowDrag(at: NSPoint(x: 30, y: 25)), "button should stay clickable")
    check(!webView.shouldStartWindowDrag(at: NSPoint(x: 130, y: 25)), "ARIA button should stay clickable")
    check(!webView.shouldStartWindowDrag(at: NSPoint(x: 300, y: 100)), "page content should not drag")

    print("WINDOW_DRAG_TESTS_OK")
  }
}
