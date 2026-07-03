import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");

describe("React Usage Flow Sankey renderer contract", () => {
  it("uses d3-sankey in the React console instead of a decorative chart", async () => {
    const sankey = await readFile(path.join(repoRoot, "src/console-ui/src/components/UsageFlowSankey.tsx"), "utf8");
    const app = await readFile(path.join(repoRoot, "src/console-ui/src/App.tsx"), "utf8");

    expect(sankey).toContain('from "d3-sankey"');
    expect(sankey).toContain("sankey<SankeyDatum, SankeyEdge>()");
    expect(sankey).toContain("sankeyLinkHorizontal");
    expect(sankey).toContain('data-engine="d3-sankey"');
    expect(sankey).toContain('data-d3-sankey-renderer="true"');
    expect(sankey).toContain('data-flow-node={node.id}');
    expect(sankey).toContain('data-flow-link-source={source.id}');
    expect(sankey).toContain("Agent");
    expect(sankey).toContain("Authentication type");
    expect(sankey).toContain("Target type");
    expect(sankey).toContain("textAnchor={heading.textAnchor}");
    expect(sankey).toContain('textAnchor: "middle" as const');
    expect(sankey).toContain('textAnchor: "end" as const');
    expect(sankey).toContain("SheetContent");
    expect(sankey).toContain("ResizablePanelGroup");
    expect(sankey).toContain("<ResizableHandle");
    expect(sankey).toContain("withHandle");
    expect(sankey).toContain("data-flow-detail-resize");
    expect(sankey).toContain("onPointerDownCapture={startResize}");
    expect(sankey).toContain("Date.now() - lastResizeAt.current < 200");
    expect(sankey).toContain('document.addEventListener("pointerup", closeOutside, true)');
    expect(sankey).toContain("onPointerDownOutside={(event) => event.preventDefault()}");
    expect(sankey).toContain("flow.entries.filter");
    expect(sankey).toContain("<UsageFlowDetailRow");
    expect(sankey).not.toContain("sankeymatic");
    expect(sankey).not.toContain("function sankeyFlowPath");

    expect(app).toContain("UsageFlowSankey");
    expect(app).toContain("ResizablePanelGroup");
    expect(app).toContain("react-grid-layout");
    expect(app).toContain("DASHBOARD_LAYOUT_KEY");
    expect(app).toContain("/menubar");
  });

  it("keeps the native app as a WebView shell around the local console", async () => {
    const [mainWindow, consoleView, appState] = await Promise.all([
      readFile(path.join(repoRoot, "native/macos-app/Sources/SgwMac/Views/MainWindow.swift"), "utf8"),
      readFile(path.join(repoRoot, "native/macos-app/Sources/SgwMac/Views/ConsoleWebAppView.swift"), "utf8"),
      readFile(path.join(repoRoot, "native/macos-app/Sources/SgwMac/App/AppState.swift"), "utf8")
    ]);

    expect(consoleView).toContain("import WebKit");
    expect(consoleView).toContain("WKWebView");
    expect(consoleView).toContain("configuration.websiteDataStore = .nonPersistent()");
    expect(mainWindow).toContain("ConsoleWebAppView(url: url)");
    expect(mainWindow).toContain("SetupView()");
    expect(appState).toContain("func consoleURL(for panel: PanelID? = nil) -> URL?");
    expect(appState).toContain('URLQueryItem(name: "native-shell", value: "1")');
    expect(appState).toContain('case .usageFlow: "usage-flow"');
  });
});
