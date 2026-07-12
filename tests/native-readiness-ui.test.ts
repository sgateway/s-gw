import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "../native/macos-app/Sources/SgwMac");

describe("native readiness UI contract", () => {
  it("keeps the Overview readiness banner visible and accessible", async () => {
    const [overview, components] = await Promise.all([
      readFile(path.join(appRoot, "Views/OverviewView.swift"), "utf8"),
      readFile(path.join(appRoot, "Views/Components.swift"), "utf8")
    ]);

    expect(overview).toContain("if !appState.isReady");
    expect(overview).toContain("ReadinessBanner(");
    expect(overview).toContain("onRunSetup: { appState.runSetup() }");

    expect(components).toContain("struct ReadinessBanner");
    expect(components).toContain('Button("Run Setup"');
    expect(components).toContain('.accessibilityIdentifier("s-gw-readiness-banner")');
    expect(components).toContain('.accessibilityLabel("s-gw readiness")');
    expect(components).toContain('.accessibilityIdentifier("s-gw-readiness-run-setup")');
  });

  it("offers managed agent install and uninstall actions with manual snippet fallback", async () => {
    const [agents, appState, models] = await Promise.all([
      readFile(path.join(appRoot, "Views/AgentsView.swift"), "utf8"),
      readFile(path.join(appRoot, "App/AppState.swift"), "utf8"),
      readFile(path.join(appRoot, "Models/Models.swift"), "utf8")
    ]);

    expect(agents).toContain('Label("Connect", systemImage: "link.badge.plus")');
    expect(agents).toContain('Label("Disconnect", systemImage: "link.badge.minus")');
    expect(agents).toContain("appState.copySnippet(for: agent)");
    expect(appState).toContain('arguments: ["agent", "install", agent.id]');
    expect(appState).toContain('arguments: ["agent", "uninstall", agent.id]');
    expect(models).toContain("struct AgentIntegrationStatus");
  });

  it("shows native recovery UI while the console is stopped and retries transient web failures", async () => {
    const [mainWindow, consoleWebApp] = await Promise.all([
      readFile(path.join(appRoot, "Views/MainWindow.swift"), "utf8"),
      readFile(path.join(appRoot, "Views/ConsoleWebAppView.swift"), "utf8")
    ]);

    expect(mainWindow).toContain("if appState.daemonRunning, let url = appState.consoleURL()");
    expect(mainWindow).toContain("SetupView()");
    expect(consoleWebApp).toContain("webView.navigationDelegate = context.coordinator");
    expect(consoleWebApp).toContain("didFailProvisionalNavigation");
    expect(consoleWebApp).toContain("try await Task.sleep(for: .milliseconds(500))");
  });
});
