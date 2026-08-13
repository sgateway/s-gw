import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();

describe("native macOS window drag surface", () => {
  it("hands only marked web chrome to AppKit window dragging", async () => {
    const [webView, app, css] = await Promise.all([
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/Views/ConsoleWebAppView.swift"), "utf8"),
      readFile(path.join(root, "src/console-ui/src/App.tsx"), "utf8"),
      readFile(path.join(root, "src/console-ui/src/index.css"), "utf8")
    ]);

    expect(webView).toContain("final class ConsoleWebView: WKWebView");
    expect(webView).toContain("override func mouseDown(with event: NSEvent)");
    expect(webView).toContain("window.performDrag(with: event)");
    expect(webView).toContain("super.mouseDown(with: event)");
    expect(webView).toContain('dragSurfaceSelector = "[data-sgw-window-drag]"');
    expect(webView).toContain("interactiveSelector");
    expect(webView).toContain("if (!hit || hit.closest(\\(Self.javaScriptString(Self.interactiveSelector)))) return false;");
    expect(webView).toContain("return Boolean(hit.closest(\\(Self.javaScriptString(Self.dragSurfaceSelector))));");
    expect(webView).toContain("[data-sgw-window-no-drag]");
    for (const interactive of ["button", " a,", "input", "select", "textarea", "summary", "[role='button']", "[role='link']"]) {
      expect(webView).toContain(interactive);
    }
    expect(webView).toContain("document.elementFromPoint");
    expect(webView).toContain("let clientY = isFlipped ? point.y : bounds.height - point.y");
    expect(webView).toContain("guard clientY >= 0, clientY <= 84");
    expect(webView).toContain("document.elementFromPoint(\\(point.x), \\(clientY))");
    expect(webView).toContain("Date(timeIntervalSinceNow: 0.1)");
    expect(webView).toMatch(/while Date\(\) < deadline[\s\S]+return false/u);
    expect(webView).toContain("return false");
    expect(webView).toContain("options: [.fragmentsAllowed]");

    expect(app).toContain('className="sgw-native-drag-surface" data-sgw-window-drag');
    expect(app).toContain('className="sgw-sidebar-titlebar');
    expect(app).toContain("data-sgw-window-drag>");
    expect(app).not.toMatch(/<button[^>]*data-sgw-window-drag/u);
    expect(css).toContain(".sgw-native-drag-surface {");
    expect(css).toContain("position: absolute;");
    expect(css).toContain("z-index: 40;");
    expect(css).toContain(".sgw-native-actions {");
    expect(css).toContain("z-index: 50;");
  });
});
