import AppKit

#if !SGW_TEST
@main
@MainActor
enum SgwMenuBarMain {
  private static var delegate: AppDelegate?

  static func main() {
    let launchGuard = HelperLaunchGuard.shared
    guard launchGuard.isPrimary else {
      launchGuard.revealPrimary()
      return
    }

    let app = NSApplication.shared
    delegate = AppDelegate()
    app.delegate = delegate
    app.run()
  }
}
#endif
