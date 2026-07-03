import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "../native/macos-app/Sources/SgwMac");

async function source(rel: string): Promise<string> {
  return readFile(path.join(appRoot, rel), "utf8");
}

describe("native command and policy surface", () => {
  it("keeps CLI runs auditable, cancellable, and PATH-hardened", async () => {
    const [runner, activity, registry, appState] = await Promise.all([
      source("Services/CLIRunner.swift"),
      source("Services/CommandActivityStore.swift"),
      source("Services/CommandRegistry.swift"),
      source("App/AppState.swift")
    ]);

    expect(runner).toContain("runID: String?");
    expect(runner).toContain("onLine: (@Sendable (String) -> Void)?");
    expect(runner).toContain("func cancel(runID: String)");
    expect(runner).toContain("/opt/homebrew/sbin");
    expect(runner).toContain("/Applications/Docker.app/Contents/Resources/bin");
    expect(runner).not.toContain('process.arguments = ["zsh", "-lc", "command -v');

    expect(activity).toContain("final class CommandActivityStore");
    expect(activity).toContain("maxOutputCharacters");
    expect(activity).toContain("markCancelled");
    expect(registry).toContain("enum CommandRegistry");
    expect(registry).toContain("Preview 1Password Import");
    expect(registry).toContain("CommandArgumentParser");
    expect(appState).toContain("let activity = CommandActivityStore()");
    expect(appState).toContain("func runCommand(");
    expect(appState).toContain("func cancelCommand");
  });

  it("wires command palette, activity inspector, settings tabs, and guided setup", async () => {
    const [palette, activity, mainWindow, consoleView, app, settings, setup] = await Promise.all([
      source("Views/CommandPaletteView.swift"),
      source("Views/ActivityView.swift"),
      source("Views/MainWindow.swift"),
      source("Views/ConsoleWebAppView.swift"),
      source("App/SgwApp.swift"),
      source("Views/SettingsView.swift"),
      source("Views/SetupView.swift")
    ]);

    expect(palette).toContain("struct CommandPaletteView");
    expect(palette).toContain("confirmationDialog");
    expect(palette).toContain("Review Custom Command");
    expect(palette).toContain("CommandArgumentParser.parse");
    expect(activity).toContain("struct ActivityView");
    expect(activity).toContain("Cancel");
    expect(activity).toContain("Copy Output");
    expect(activity).toContain("ActivityOutputPresentation");
    expect(activity).toContain("JSONSerialization.jsonObject");
    expect(activity).toContain("Result Summary");
    expect(activity).toContain("Output view");
    expect(activity).toContain("RawOutputBlock");
    expect(activity).toContain("KeyValueGrid(pairs: presentation.pairs)");
    expect(activity).not.toContain("Text(record.output.trimmingCharacters");

    expect(mainWindow).toContain("ConsoleWebAppView(url: url)");
    expect(mainWindow).toContain("SetupView()");
    expect(mainWindow).toContain("CommandPaletteView()");
    expect(mainWindow).toContain(".ignoresSafeArea(.container, edges: .top)");
    expect(mainWindow).not.toContain(".toolbar {");
    expect(mainWindow).not.toContain("ToolbarItemGroup");
    expect(consoleView).toContain("WKWebView");
    expect(consoleView).toContain("websiteDataStore = .nonPersistent()");
    expect(app).toContain('CommandMenu("Commands")');
    expect(app).toContain("Check for Updates");
    expect(app).toContain('.keyboardShortcut("p", modifiers: [.command, .shift])');
    expect(app).toContain(".windowStyle(.hiddenTitleBar)");
    expect(app).toContain("applyMainWindowChrome");
    expect(app).toContain("titleVisibility = .hidden");
    expect(app).toContain("titlebarAppearsTransparent = true");
    expect(app).toContain("styleMask.insert(.fullSizeContentView)");
    expect(app).toContain("window.toolbar = nil");
    expect(app).not.toContain("toolbarStyle = .unifiedCompact");
    expect(app).not.toContain("displayMode = .iconOnly");
    expect(app).toContain("isMovableByWindowBackground = true");
    expect(app).not.toContain("MenuBarExtra {");
    expect(app).toContain("OpenMainWindowListener()");
    expect(app).toContain('notification.userInfo?["view"]');
    expect(app).toContain("enum HelperDestination: String");

    expect(settings).toContain("TabView");
    expect(settings).toContain('Label("Integrations"');
    expect(settings).toContain("Preview Dev Vault Import");
    expect(setup).toContain("Setup checklist");
    expect(setup).toContain("Guided actions");
    expect(setup).toContain("Review Setup Command");
  });

  it("keeps policy templates and request matching visible in the native app", async () => {
    const policies = await source("Views/PoliciesView.swift");

    expect(policies).toContain("policyTemplatesPanel");
    expect(policies).toContain("policyTestPanel");
    expect(policies).toContain("Always ask for high-risk credentials");
    expect(policies).toContain("Always ask for SSH sessions");
    expect(policies).toContain("Allow Codex for selected credential");
    expect(policies).toContain("matchingRules(for request");
    expect(policies).toContain("matchesString");
  });
});
