import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();

describe("native macOS update lifecycle", () => {
  it("starts polling with the app process instead of a visible window", async () => {
    const app = await readFile(
      path.join(root, "native/macos-app/Sources/SgwMac/App/SgwApp.swift"),
      "utf8"
    );

    expect(app).toContain("state.start()\n  }");
    expect(app).not.toContain(".onAppear { appState.start() }");
  });

  it("delivers foreground system notifications and keeps an in-app fallback", async () => {
    const [app, state, notifier, window] = await Promise.all([
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/App/SgwApp.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/App/AppState.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/Services/UpdateNotifier.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/Views/MainWindow.swift"), "utf8")
    ]);

    expect(app).toContain("UNUserNotificationCenter.current().delegate = self");
    expect(app).toContain("completionHandler([.banner, .list, .sound])");
    expect(notifier).toContain('identifier: "s-gw-update-\\(version)"');
    expect(notifier).toContain("lastNotifiedUpdateVersion");
    expect(state).toContain("notificationResult == .inAppOnly");
    expect(window).toContain("This banner is your update notice.");
  });

  it("retries failed fetches and accepts either checksum release format", async () => {
    const [state, checker] = await Promise.all([
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/App/AppState.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/Services/UpdateChecker.swift"), "utf8")
    ]);

    const updateMethod = state.slice(
      state.indexOf("func checkForUpdates"),
      state.indexOf("func dismissUpdateBanner")
    );
    const failedFetch = updateMethod.indexOf("} catch {");
    const persistedCheck = updateMethod.indexOf("UpdateChecker.lastCheckDefaultsKey");
    expect(persistedCheck).toBeGreaterThan(failedFetch);
    expect(updateMethod).toContain("if !release.canInstallPackage");
    expect(state).toContain("updateRetryInterval: TimeInterval = 15 * 60");
    expect(checker).toContain('"sha256sums.txt"');
    expect(checker).toContain("entry.fileName == assetName");
    expect(checker).toContain('"update", "install", "--package", downloadURL.path');
    expect(checker).toContain("s-gw setup --no-open-app");
    expect(checker).not.toContain('npmCommand()');
  });
});
