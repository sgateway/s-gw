import AppKit
import Darwin
import SwiftUI

@main
struct SgwApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
  @State private var appState = AppState()
  @AppStorage("showDockIcon") private var showDockIcon = true

  init() {
    let launchGuard = SgwLaunchGuard.shared
    guard launchGuard.isPrimary else {
      launchGuard.focusPrimaryInstance()
      exit(0)
    }

    SgwDistributedOpenBridge.shared.start()
  }

  var body: some Scene {
    WindowGroup("s-gw", id: "main") {
      MainWindow()
        .environment(appState)
        .frame(minWidth: 980, minHeight: 640)
        .background(OpenMainWindowListener().environment(appState))
        .onAppear { appState.start() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
          Task {
            await appState.refresh()
            if !appState.pendingRequests.isEmpty {
              appState.selectedPanel = .approvals
            }
          }
        }
    }
    .defaultSize(width: 1180, height: 760)
    .windowStyle(.hiddenTitleBar)
    .commands {
      CommandGroup(after: .toolbar) {
        Button("Command Palette") {
          appState.commandPalettePresented = true
        }
        Button("Refresh") {
          NotificationCenter.default.post(name: .sgwRefreshPanel, object: nil)
        }
        .keyboardShortcut("r", modifiers: .command)
        Button("Check for Updates") {
          Task { await appState.checkForUpdates(force: true) }
        }
        .keyboardShortcut("u", modifiers: [.command, .shift])
      }
      CommandMenu("Go") {
        ForEach(Array(PanelID.allCases.enumerated()), id: \.element) { index, panel in
          Button(panel.title) {
            appState.selectedPanel = panel
          }
          .keyboardShortcut(KeyEquivalent(Character("\(index + 1)")), modifiers: .command)
        }
      }
      CommandMenu("Commands") {
        Button("Open Command Palette") {
          appState.commandPalettePresented = true
        }
        .keyboardShortcut("p", modifiers: [.command, .shift])
        Button("Show Activity") {
          appState.selectedPanel = .activity
        }
        Divider()
        ForEach(CommandRegistry.quickActions) { command in
          Button(command.title) {
            Task {
              await appState.runCommand(command)
              appState.selectedPanel = .activity
            }
          }
        }
      }
    }

    Settings {
      SettingsView()
        .environment(appState)
    }
  }
}

private struct OpenMainWindowListener: View {
  @Environment(\.openWindow) private var openWindow
  @Environment(AppState.self) private var appState

  var body: some View {
    Color.clear
      .frame(width: 0, height: 0)
      .onAppear {
        if let route = SgwDistributedOpenBridge.shared.takePendingRoute() {
          apply(route)
        }
      }
      .onReceive(NotificationCenter.default.publisher(for: .sgwOpenMainWindow)) { notification in
        let route = HelperDestination.parse(notification.userInfo?["view"] as? String)
          ?? SgwDistributedOpenBridge.shared.takePendingRoute()

        if !AppDelegate.openMainWindow() {
          openWindow(id: "main")
          DispatchQueue.main.async {
            _ = AppDelegate.openMainWindow()
          }
        }

        Task {
          await appState.refresh()
          if let route {
            apply(route)
          } else if !appState.pendingRequests.isEmpty {
            appState.selectedPanel = .approvals
          }
        }
      }
  }

  private func apply(_ destination: HelperDestination) {
    appState.selectedPanel = destination.panel
  }
}

private enum HelperDestination: String {
  case overview
  case approvals
  case credentials
  case activity
  case audit
  case settings

  static func parse(_ value: String?) -> HelperDestination? {
    guard let value else { return nil }
    return HelperDestination(rawValue: value)
  }

  var panel: PanelID {
    switch self {
    case .overview: return .overview
    case .approvals: return .approvals
    case .credentials: return .credentials
    case .activity: return .activity
    case .audit: return .audit
    case .settings: return .setup
    }
  }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
  private var windowChromeObserver: NSObjectProtocol?

  func applicationDidFinishLaunching(_ notification: Notification) {
    UserDefaults.standard.register(defaults: [
      "NSQuitAlwaysKeepsWindows": false,
      "showDockIcon": true
    ])
    applyActivationPolicy()
    windowChromeObserver = NotificationCenter.default.addObserver(
      forName: NSWindow.didBecomeKeyNotification,
      object: nil,
      queue: .main
    ) { notification in
      guard let window = notification.object as? NSWindow else { return }
      MainActor.assumeIsolated {
        Self.applyMainWindowChrome(window)
      }
    }
    DispatchQueue.main.async {
      for window in NSApp.windows {
        Self.applyMainWindowChrome(window)
      }
    }
    NSApp.activate(ignoringOtherApps: true)
  }

  func applicationWillTerminate(_ notification: Notification) {
    if let windowChromeObserver {
      NotificationCenter.default.removeObserver(windowChromeObserver)
    }
    SgwDistributedOpenBridge.shared.stop()
    SgwLaunchGuard.shared.release()
  }

  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    false
  }

  func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
    if !flag {
      Self.openMainWindow()
    }
    return true
  }

  func applyActivationPolicy() {
    let showDock = UserDefaults.standard.object(forKey: "showDockIcon") as? Bool ?? true
    NSApp.setActivationPolicy(showDock ? .regular : .accessory)
  }

  @discardableResult
  static func openMainWindow() -> Bool {
    let showDock = UserDefaults.standard.object(forKey: "showDockIcon") as? Bool ?? true
    NSApp.setActivationPolicy(showDock ? .regular : .accessory)
    NSApp.activate(ignoringOtherApps: true)
    for window in NSApp.windows where window.canBecomeKey {
      applyMainWindowChrome(window)
      if window.isMiniaturized {
        window.deminiaturize(nil)
      }
      window.makeKeyAndOrderFront(nil)
      return true
    }
    return false
  }

  static func applyMainWindowChrome(_ window: NSWindow) {
    guard window.title == "s-gw", !(window is NSPanel) else {
      return
    }

    window.titleVisibility = .hidden
    window.titlebarAppearsTransparent = true
    window.styleMask.insert(.fullSizeContentView)
    window.toolbar = nil
    window.isMovableByWindowBackground = true
  }
}

@MainActor
private final class SgwDistributedOpenBridge: NSObject {
  static let shared = SgwDistributedOpenBridge()

  private var started = false
  private var pendingRoute: HelperDestination?

  func start() {
    guard !started else {
      return
    }

    started = true
    DistributedNotificationCenter.default().addObserver(
      self,
      selector: #selector(handleOpenMainWindowNotification(_:)),
      name: .sgwOpenMainWindow,
      object: nil
    )
  }

  func stop() {
    guard started else {
      return
    }

    DistributedNotificationCenter.default().removeObserver(
      self,
      name: .sgwOpenMainWindow,
      object: nil
    )
    started = false
  }

  func takePendingRoute() -> HelperDestination? {
    defer { pendingRoute = nil }
    return pendingRoute
  }

  @objc private func handleOpenMainWindowNotification(_ notification: Notification) {
    let route = HelperDestination.parse(notification.userInfo?["view"] as? String)
    pendingRoute = route

    DispatchQueue.main.async {
      NotificationCenter.default.post(
        name: .sgwOpenMainWindow,
        object: nil,
        userInfo: route.map { ["view": $0.rawValue] }
      )
      NotificationCenter.default.post(name: .sgwRefreshPanel, object: nil)
      _ = AppDelegate.openMainWindow()
    }
  }
}

@MainActor
private final class SgwLaunchGuard {
  static let shared = SgwLaunchGuard()

  private(set) var isPrimary = false
  private var instanceLockFd: CInt = -1

  private init() {
    isPrimary = acquireInstanceLock()
  }

  private func acquireInstanceLock() -> Bool {
    let path = Self.instanceLockPath()
    let fd = open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
    guard fd >= 0 else {
      return Self.runningPrimaryInstance() == nil
    }

    guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
      close(fd)
      return false
    }

    instanceLockFd = fd
    Self.writeProcessRecord()
    return true
  }

  func focusPrimaryInstance() {
    DistributedNotificationCenter.default().postNotificationName(
      .sgwOpenMainWindow,
      object: nil,
      userInfo: nil,
      deliverImmediately: true
    )
    Self.runningPrimaryInstance()?.activate(options: [
      .activateAllWindows,
      .activateIgnoringOtherApps
    ])
  }

  func release() {
    guard instanceLockFd >= 0 else {
      return
    }

    flock(instanceLockFd, LOCK_UN)
    close(instanceLockFd)
    instanceLockFd = -1
    Self.removeProcessRecord()
  }

  private static func runningPrimaryInstance() -> NSRunningApplication? {
    guard let bundleIdentifier = Bundle.main.bundleIdentifier else {
      return nil
    }

    let currentPid = ProcessInfo.processInfo.processIdentifier
    return NSRunningApplication.runningApplications(withBundleIdentifier: bundleIdentifier)
      .first { app in
        app.processIdentifier != currentPid && !app.isTerminated
      }
  }

  private static func instanceLockPath() -> String {
    if let dir = appSupportDir() {
      return dir.appendingPathComponent("s-gw-app.lock").path
    }

    return NSTemporaryDirectory() + "s-gw-app.lock"
  }

  private static func processRecordUrl() -> URL {
    if let dir = appSupportDir() {
      return dir.appendingPathComponent("s-gw-app.process.json")
    }

    return URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("s-gw-app.process.json")
  }

  private static func appSupportDir() -> URL? {
    let fm = FileManager.default
    if let appSupport = fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
      let dir = appSupport.appendingPathComponent("s-gw", isDirectory: true)
      do {
        try fm.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
      } catch {
        // Falling back to /tmp is good enough for the rare directory failure.
      }
    }

    return nil
  }

  private static func writeProcessRecord() {
    let now = ISO8601DateFormatter().string(from: Date())
    let payload: [String: Any] = [
      "pid": Int(ProcessInfo.processInfo.processIdentifier),
      "bundleIdentifier": Bundle.main.bundleIdentifier ?? "com.s-gw.sgw.app",
      "bundlePath": Bundle.main.bundleURL.path,
      "executablePath": Bundle.main.executableURL?.path ?? "",
      "startedAt": now,
      "updatedAt": now
    ]

    do {
      let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
      try data.write(to: processRecordUrl(), options: [.atomic])
    } catch {
      // The lock still protects single-instance behavior if this best-effort record fails.
    }
  }

  private static func removeProcessRecord() {
    let url = processRecordUrl()
    let currentPid = Int(ProcessInfo.processInfo.processIdentifier)
    if let data = try? Data(contentsOf: url),
       let parsed = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
       let pid = parsed["pid"] as? Int,
       pid != currentPid {
      return
    }

    try? FileManager.default.removeItem(at: url)
  }
}
