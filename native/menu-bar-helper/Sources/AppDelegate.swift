import AppKit
import Darwin
import Foundation
import SgwUpdateState
import SwiftUI
@preconcurrency import UserNotifications

extension Notification.Name {
  static let sgwShowMenuHelper = Notification.Name("com.s-gw.sgw.showMenuHelper")
  static let sgwOpenMainWindow = Notification.Name("com.s-gw.sgw.openMainWindow")
  static let sgwRequestUpdateReminder = Notification.Name("com.s-gw.sgw.requestUpdateReminder")
}

@MainActor
final class HelperLaunchGuard {
  static let shared = HelperLaunchGuard()

  private(set) var isPrimary = false
  private var lockFd: CInt = -1

  private init() {
    lockFd = Self.acquireLock(at: Self.lockPath())
    isPrimary = lockFd >= 0
  }

  func revealPrimary() {
    DistributedNotificationCenter.default().postNotificationName(
      .sgwShowMenuHelper,
      object: nil,
      userInfo: nil,
      deliverImmediately: true
    )
  }

  func release() {
    guard lockFd >= 0 else { return }
    Self.releaseLock(lockFd)
    lockFd = -1
    isPrimary = false
  }

  static func acquireLock(at path: String) -> CInt {
    let fd = open(path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)
    guard fd >= 0 else { return -1 }
    guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
      close(fd)
      return -1
    }
    return fd
  }

  static func releaseLock(_ fd: CInt) {
    flock(fd, LOCK_UN)
    close(fd)
  }

  static func lockPath() -> String {
    if let override = ProcessInfo.processInfo.environment["SGW_MENU_BAR_LOCK_PATH"], !override.isEmpty {
      return override
    }
    let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
      ?? FileManager.default.temporaryDirectory
    let dir = base.appendingPathComponent("s-gw", isDirectory: true)
    try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    return dir.appendingPathComponent("menu-helper.lock").path
  }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, UNUserNotificationCenterDelegate, NSPopoverDelegate {
  private static let countModeDefaultsKey = "menuBarCountMode"

  private let statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
  private let popover = NSPopover()
  private let model: HelperViewModel
  private let snapshotLoader: HelperSnapshotLoader
  private let repoRoot: String
  private let cliPath: String
  private let nodePath: String
  private let consoleURL: URL
  private let appURL: URL?
  private let showOnLaunch: Bool
  private let notificationsEnabled: Bool

  private var timer: Timer?
  private var outsideClickMonitor: Any?
  private var deferredStatusTitle: String?
  private var refreshQueued = false
  private var notifiedRequestIds = Set<String>()
  private var hostingController: NSHostingController<HelperMenuDashboard>?

  private lazy var decisions: DecisionController = {
    let node = nodePath
    let cli = cliPath
    let root = repoRoot
    let environment = ProcessInfo.processInfo.environment

    return DecisionController(
      runCli: { args in
        runSgwCli(node: node, cli: cli, repoRoot: root, args: args, environment: environment)
      },
      notify: { [weak self] outcome in
        self?.model.showFeedback(outcome)
        self?.sendNotification(title: outcome.title, body: outcome.body)
      },
      afterDecision: { [weak self] in
        self?.refreshState()
      },
      onInFlightChange: { [weak self] ids in
        self?.model.setDecidingRequestIds(ids)
      }
    )
  }()

  private lazy var updateMonitor: UpdateMonitor = {
    let node = nodePath
    let cli = cliPath
    let root = repoRoot
    let environment = ProcessInfo.processInfo.environment
    let args = UpdateMonitor.command
    return UpdateMonitor(
      runCheck: {
        runSgwCli(
          node: node,
          cli: cli,
          repoRoot: root,
          args: args,
          environment: environment
        )
      },
      canQueueNotification: { [weak self] in
        guard let self else { return false }
        return await self.canQueueUpdateNotification()
      },
      notify: { [weak self] update in
        guard let self else { return false }
        return await self.sendUpdateNotification(update)
      }
    )
  }()

  override init() {
    let env = ProcessInfo.processInfo.environment
    let cwd = FileManager.default.currentDirectoryPath
    let bundledRoot = Bundle.main.bundleURL
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let discoveredRoot = FileManager.default.fileExists(
      atPath: bundledRoot.appendingPathComponent("dist/cli.js").path
    ) ? bundledRoot.path : cwd
    let root = env["SGW_REPO_ROOT"] ?? discoveredRoot
    let cli = env["SGW_CLI_PATH"] ?? URL(fileURLWithPath: root)
      .appendingPathComponent("dist/cli.js")
      .path
    let node = env["SGW_NODE_PATH"] ?? "/usr/bin/env"
    let console = URL(string: env["SGW_CONSOLE_URL"] ?? "http://127.0.0.1:8718/")!
    let countMode = StatusCountMode.parse(UserDefaults.standard.string(forKey: Self.countModeDefaultsKey))
      ?? StatusCountMode.parse(env["SGW_MENU_BAR_COUNT_MODE"])
      ?? .pending

    repoRoot = root
    cliPath = cli
    nodePath = node
    consoleURL = console
    appURL = Self.resolveAppURL(env["SGW_APP_PATH"])
    showOnLaunch = CommandLine.arguments.contains("--show-on-launch")
    notificationsEnabled = !CommandLine.arguments.contains("--no-notify")
    model = HelperViewModel(countMode: countMode)
    snapshotLoader = HelperSnapshotLoader(
      nodePath: node,
      cliPath: cli,
      repoRoot: root,
      consoleURL: console,
      environment: env
    )
    super.init()
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    NSApp.setActivationPolicy(.accessory)
    UNUserNotificationCenter.current().delegate = self

    popover.behavior = .transient
    popover.animates = true
    popover.delegate = self

    configureStatusItem()
    installOutsideClickMonitor()
    installDistributedObservers()
    requestNotificationPermission()
    refreshState()
    updateMonitor.start()

    timer = Timer.scheduledTimer(withTimeInterval: 4, repeats: true) { [weak self] _ in
      guard let delegate = self else { return }
      Task { @MainActor [delegate] in delegate.refreshState() }
    }

    if showOnLaunch {
      DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
        self?.showStatusPopover()
      }
    }
  }

  func applicationWillTerminate(_ notification: Notification) {
    timer?.invalidate()
    updateMonitor.stop()
    removeOutsideClickMonitor()
    DistributedNotificationCenter.default().removeObserver(self)
    HelperLaunchGuard.shared.release()
  }

  func applicationDidResignActive(_ notification: Notification) {
    closePopoverForOutsideInteraction()
  }

  private static func resolveAppURL(_ configuredPath: String?) -> URL? {
    if let configuredPath, !configuredPath.isEmpty {
      return URL(fileURLWithPath: configuredPath)
    }

    let siblingApp = Bundle.main.bundleURL
      .deletingLastPathComponent()
      .appendingPathComponent("s-gw.app")
    return FileManager.default.fileExists(atPath: siblingApp.path) ? siblingApp : nil
  }

  private func configureStatusItem() {
    if let button = statusItem.button {
      button.image = menuBarIcon()
      button.imagePosition = .imageLeading
      button.imageScaling = .scaleProportionallyDown
      button.title = ""
      button.target = self
      button.action = #selector(togglePopover(_:))
    }

    let controller = NSHostingController(rootView: HelperMenuDashboard(
      model: model,
      actions: helperActions()
    ))
    hostingController = controller
    popover.contentViewController = controller
    popover.contentSize = model.contentSize
  }

  private func installDistributedObservers() {
    DistributedNotificationCenter.default().addObserver(
      self,
      selector: #selector(showMenuHelper(_:)),
      name: .sgwShowMenuHelper,
      object: nil
    )
    DistributedNotificationCenter.default().addObserver(
      self,
      selector: #selector(requestUpdateReminder(_:)),
      name: .sgwRequestUpdateReminder,
      object: nil
    )
  }

  @objc private func showMenuHelper(_ notification: Notification) {
    showStatusPopover()
  }

  @objc private func requestUpdateReminder(_ notification: Notification) {
    guard let version = notification.userInfo?["version"] as? String else { return }
    updateMonitor.requestReminder(version: version)
  }

  private func refreshState() {
    if model.isRefreshing {
      refreshQueued = true
      return
    }

    model.beginRefresh()
    let loader = snapshotLoader

    Task { [weak self] in
      let snapshot = await Task.detached(priority: .utility) {
        loader.load()
      }.value

      guard let self else { return }
      self.model.apply(snapshot)
      self.updateStatusTitle()
      self.updatePopoverSize()
      self.notifyForNewPendingRequests(snapshot.pending)

      if self.refreshQueued {
        self.refreshQueued = false
        self.refreshState()
      }
    }
  }

  private func notifyForNewPendingRequests(_ pending: [RequestRecord]) {
    let pendingIds = Set(pending.map(\.id))
    notifiedRequestIds = notifiedRequestIds.intersection(pendingIds)
    let newRequests = pending.filter { !notifiedRequestIds.contains($0.id) }
    guard !newRequests.isEmpty else { return }

    for request in newRequests {
      notifiedRequestIds.insert(request.id)
      if notificationsEnabled {
        sendNotification(
          title: "Approval required for s-gw",
          body: "\(request.agentName) requested \(helperShortHandle(request.handle)) for \(request.shortCommand)."
        )
      }
    }

    showStatusPopover()
  }

  private func updateStatusTitle() {
    guard let button = statusItem.button else { return }

    let nextTitle: String
    switch model.countMode {
    case .pending:
      nextTitle = model.state.pending.isEmpty ? "" : " \(model.state.pending.count)"
    case .credentials:
      nextTitle = " \(model.state.credentialCount)"
    case .none:
      nextTitle = ""
    }

    if popover.isShown && button.title != nextTitle {
      deferredStatusTitle = nextTitle
    } else if button.title != nextTitle {
      button.title = nextTitle
      deferredStatusTitle = nil
    }

    button.toolTip = "s-gw: \(model.state.pending.count) pending approvals, \(model.state.credentialCount) stored credentials"
  }

  private func updatePopoverSize() {
    let size = model.contentSize
    if popover.contentSize != size {
      popover.contentSize = size
    }
  }

  private func helperActions() -> HelperMenuActions {
    HelperMenuActions(
      refresh: { [weak self] in self?.refreshState() },
      openApp: { [weak self] route in self?.openAppAction(route) },
      openConsole: { [weak self] in self?.openConsoleAction() },
      testNotification: { [weak self] in self?.showTestNotificationAction() },
      approve: { [weak self] id, choice in self?.decisions.approve(id, choice: choice) },
      deny: { [weak self] id in self?.decisions.deny(id) },
      setCountMode: { [weak self] mode in self?.setCountMode(mode) },
      quit: { NSApp.terminate(nil) }
    )
  }

  @objc private func togglePopover(_ sender: Any?) {
    if popover.isShown {
      popover.performClose(sender)
    } else {
      showStatusPopover()
    }
  }

  private func openAppAction(_ route: HelperRoute) {
    guard let appURL, FileManager.default.fileExists(atPath: appURL.path) else {
      NSWorkspace.shared.open(consoleURL(for: route))
      return
    }

    postOpenRoute(route)
    let config = NSWorkspace.OpenConfiguration()
    config.activates = true
    NSWorkspace.shared.openApplication(at: appURL, configuration: config) { [weak self] _, _ in
      Task { @MainActor in
        try? await Task.sleep(for: .milliseconds(180))
        self?.postOpenRoute(route)
      }
    }
  }

  private func postOpenRoute(_ route: HelperRoute) {
    DistributedNotificationCenter.default().postNotificationName(
      .sgwOpenMainWindow,
      object: nil,
      userInfo: ["view": route.rawValue],
      deliverImmediately: true
    )
  }

  private func consoleURL(for route: HelperRoute) -> URL {
    var components = URLComponents(url: consoleURL, resolvingAgainstBaseURL: false)
    components?.path = "/\(route.rawValue)"
    return components?.url ?? consoleURL
  }

  private func openConsoleAction() {
    NSWorkspace.shared.open(consoleURL)
  }

  private func showTestNotificationAction() {
    if let first = model.state.pending.first {
      sendNotification(
        title: "Approval required for \(first.agentName)",
        body: "\(first.shortCommand) requested \(helperShortHandle(first.handle))."
      )
      return
    }

    sendNotification(
      title: "s-gw is watching",
      body: "No pending approvals. Local daemon status: \(model.state.daemonRunning ? "running" : "offline")."
    )
  }

  private func setCountMode(_ mode: StatusCountMode) {
    model.setCountMode(mode)
    UserDefaults.standard.set(mode.rawValue, forKey: Self.countModeDefaultsKey)
    updateStatusTitle()
  }

  private func showStatusPopover() {
    guard let button = statusItem.button else { return }
    updatePopoverSize()
    refreshState()

    if !popover.isShown {
      popover.show(relativeTo: popoverAnchorRect(in: button), of: button, preferredEdge: .minY)
      NSApp.activate(ignoringOtherApps: true)
    }
  }

  private func installOutsideClickMonitor() {
    outsideClickMonitor = NSEvent.addGlobalMonitorForEvents(
      matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown]
    ) { [weak self] _ in
      Task { @MainActor in self?.closePopoverForOutsideInteraction() }
    }
  }

  private func removeOutsideClickMonitor() {
    if let outsideClickMonitor {
      NSEvent.removeMonitor(outsideClickMonitor)
      self.outsideClickMonitor = nil
    }
  }

  private func closePopoverForOutsideInteraction() {
    guard popover.isShown else { return }
    popover.performClose(nil)
  }

  private func popoverAnchorRect(in button: NSStatusBarButton) -> NSRect {
    let side = min(max(button.bounds.height, 18), button.bounds.width)
    return NSRect(
      x: button.bounds.maxX - side,
      y: button.bounds.minY,
      width: side,
      height: button.bounds.height
    )
  }

  func popoverDidClose(_ notification: Notification) {
    guard let button = statusItem.button else {
      deferredStatusTitle = nil
      return
    }

    if let title = deferredStatusTitle, button.title != title {
      button.title = title
    }
    deferredStatusTitle = nil
  }

  private func menuBarIcon() -> NSImage? {
    let loadedImage = Bundle.main.url(forResource: "MenuBarTemplate", withExtension: "png")
      .flatMap { NSImage(contentsOf: $0) }
      ?? Bundle.main.url(forResource: "AppIcon", withExtension: "icns")
        .flatMap { NSImage(contentsOf: $0) }
      ?? NSImage(systemSymbolName: "lock.shield", accessibilityDescription: "s-gw")

    guard let image = loadedImage?.copy() as? NSImage else { return nil }
    image.size = NSSize(width: 18, height: 18)
    image.isTemplate = true
    image.accessibilityDescription = "s-gw"
    return image
  }

  private func requestNotificationPermission() {
    guard notificationsEnabled else { return }
    Task {
      _ = try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound])
    }
  }

  private func sendNotification(title: String, body: String) {
    let content = UNMutableNotificationContent()
    content.title = title
    content.body = body
    content.sound = .default
    content.interruptionLevel = .timeSensitive

    UNUserNotificationCenter.current().add(UNNotificationRequest(
      identifier: "s-gw-\(UUID().uuidString)",
      content: content,
      trigger: nil
    ))
  }

  private func sendUpdateNotification(_ update: HelperUpdate) async -> Bool {
    guard await canQueueUpdateNotification() else { return false }
    let center = UNUserNotificationCenter.current()

    let content = UNMutableNotificationContent()
    content.title = "s-gw \(update.version) is available"
    content.body = "Open s-gw to review and upgrade."
    content.sound = .default
    content.userInfo = [
      "releaseURL": update.releaseURL.absoluteString,
      "updateVersion": update.version
    ]

    do {
      try await center.add(UNNotificationRequest(
        identifier: "s-gw-update-\(update.version)",
        content: content,
        trigger: nil
      ))
      return true
    } catch {
      return false
    }
  }

  private func canQueueUpdateNotification() async -> Bool {
    guard notificationsEnabled else { return false }
    let center = UNUserNotificationCenter.current()
    var settings = await center.notificationSettings()
    if settings.authorizationStatus == .notDetermined {
      guard (try? await center.requestAuthorization(options: [.alert, .sound])) == true else {
        return false
      }
      settings = await center.notificationSettings()
    }
    guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else {
      return false
    }
    return settings.alertSetting == .enabled
  }

  nonisolated func userNotificationCenter(
    _ center: UNUserNotificationCenter,
    willPresent notification: UNNotification,
    withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
  ) {
    completionHandler([.banner, .sound])
  }

  nonisolated func userNotificationCenter(
    _ center: UNUserNotificationCenter,
    didReceive response: UNNotificationResponse,
    withCompletionHandler completionHandler: @escaping () -> Void
  ) {
    let releaseURL = response.notification.request.content.userInfo["releaseURL"] as? String
    let updateVersion = response.notification.request.content.userInfo["updateVersion"] as? String
    completionHandler()
    Task { @MainActor in
      if let updateVersion {
        let defaults = UserDefaults(suiteName: "com.s-gw.sgw.app") ?? .standard
        UpdateNoticeStore(defaults: defaults).acknowledge(version: updateVersion)
      }
      if let releaseURL, let url = URL(string: releaseURL) {
        NSWorkspace.shared.open(url)
      }
    }
  }
}
