import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();

describe("native macOS update lifecycle", () => {
  it("keeps recurring update polling in the login-started menu helper", async () => {
    const [app, state, helper, install] = await Promise.all([
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/App/SgwApp.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/App/AppState.swift"), "utf8"),
      readFile(path.join(root, "native/menu-bar-helper/Sources/UpdateMonitor.swift"), "utf8"),
      readFile(path.join(root, "src/install.ts"), "utf8")
    ]);

    expect(app).toContain("state.start()\n  }");
    expect(app).not.toContain(".onAppear { appState.start() }");
    expect(state).not.toContain("private var updateTask");
    expect(helper).toContain("final class UpdateMonitor");
    expect(helper).toContain("pollInterval: TimeInterval = 15 * 60");
    expect(helper).toContain('["update", "check"]');
    expect(install).toContain("runAtLoad: true");
  });

  it("persists update availability and leaves automatic system alerts to the helper", async () => {
    const [app, state, helper, helperApp, noticeState, window] = await Promise.all([
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/App/SgwApp.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/App/AppState.swift"), "utf8"),
      readFile(path.join(root, "native/menu-bar-helper/Sources/UpdateMonitor.swift"), "utf8"),
      readFile(path.join(root, "native/menu-bar-helper/Sources/AppDelegate.swift"), "utf8"),
      readFile(path.join(root, "native/update-state/Sources/SgwUpdateState/UpdateNoticeState.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/Views/MainWindow.swift"), "utf8")
    ]);

    expect(app).toContain("UNUserNotificationCenter.current().delegate = self");
    expect(app).toContain("completionHandler([.banner, .list, .sound])");
    expect(state).toContain("UpdateNoticeStore");
    expect(state).toContain("restoreAvailableUpdate()");
    expect(state).toContain("requestUpdateReminder()");
    expect(state).not.toContain("updateNotifier");
    expect(helper).toContain("canQueueNotification");
    expect(helper).toContain("reserveNotificationAttempt");
    expect(helper).toContain("recordQueuedNotification");
    expect(helper).toContain("cancelNotificationAttempt");
    expect(helper).not.toContain("lastNotifiedUpdateVersion");
    expect(helperApp).toContain('"updateVersion": update.version');
    expect(noticeState).toContain("acknowledgedAt");
    expect(noticeState).toContain("inFlightAt");
    expect(noticeState).toContain("maxNotificationAttempts = 3");
    expect(noticeState).toContain("applicationSupportDirectory");
    expect(noticeState).toContain("update-notice-state.json");
    expect(noticeState).toContain("flock(fd, LOCK_EX)");
    expect(window).toContain("This update stays available here");
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
    expect(updateMethod).toContain("if !release.hasVerifiedAsset");
    expect(state).not.toContain("updateRetryInterval");
    expect(checker).toContain('"sha256sums.txt"');
    expect(checker).toContain("entry.fileName == assetName");
    expect(checker).toContain('return "s-gw-\\(cleanVersion)-macos.dmg"');
    expect(checker).toContain("static var usesSelfContainedRuntime");
    expect(checker).toContain('$0.state?.lowercased() == "uploaded"');
    expect(checker).toContain("for release in candidates");
    expect(checker).toContain(".filter({ !$0.preRelease })");
    expect(checker).toContain("if let info = await releaseInfo(from: release), info.hasVerifiedAsset");
    expect(checker).toContain("await assetExists(assetURL)");
    expect(checker).toContain("await assetExists(checksumURL)");
    expect(checker).toContain('"update", "install", "--package", downloadURL.path');
    expect(checker).toContain("run_sgw setup --no-open-app --no-agents");
    expect(checker).toContain('process.executableURL = URL(fileURLWithPath: "/usr/bin/nohup")');
    expect(checker).toContain('environment["SGW_UPDATE_OLD_PID"]');
    expect(checker).toContain("while kill -0 \"$SGW_UPDATE_OLD_PID\"");
    expect(checker).toContain("update-relaunch.log");
    expect(checker).not.toContain('run_sgw app open >/dev/null 2>&1 || true');
    expect(checker).not.toContain('npmCommand()');
  });

  it("holds installer migration until an uploaded, reachable DMG is available", async () => {
    const [state, checker, runner, window, settings] = await Promise.all([
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/App/AppState.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/Services/UpdateChecker.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/Services/CLIRunner.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/Views/MainWindow.swift"), "utf8"),
      readFile(path.join(root, "native/macos-app/Sources/SgwMac/Views/SettingsView.swift"), "utf8")
    ]);

    expect(state).toContain("guard release.hasVerifiedAsset else");
    expect(state).toContain("if release.isMacInstaller");
    expect(state).toContain('cli.run(arguments: ["app", "refresh-services"])');
    expect(state).toContain("bundledRuntimeVersionDefaultsKey");
    expect(state).toContain("bundledRuntimePathDefaultsKey");
    expect(state).toContain("needsBundledRuntimeRefresh");
    expect(state).not.toContain("guard let previousVersion");
    expect(checker).toContain("var isMacInstaller");
    expect(checker).toContain("static var bundledAppPath");
    expect(checker).toContain("for release in candidates");
    expect(checker).toContain("return nil");
    expect(window).toContain(".disabled(!release.hasVerifiedAsset || appState.updateState.isBusy)");
    expect(settings).toContain(".disabled(!release.hasVerifiedAsset || appState.updateState.isBusy)");
    expect(window).toContain("release.isMacInstaller ? \"Download\" : \"Upgrade\"");
    expect(settings).toContain("release.isMacInstaller ? \"Download Installer\" : \"Install Package\"");
    expect(runner).toContain("managedRuntimeEnvironment()");
    expect(runner).toContain('"com.s-gw.sgw.console", "com.s-gw.sgw.menubar"');
    expect(runner).toContain('"SGW_HOME", "SGW_KEYCHAIN_SERVICE", "SGW_KEYCHAIN_ACCOUNT"');
  });
});
