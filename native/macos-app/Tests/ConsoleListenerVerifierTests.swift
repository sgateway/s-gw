import Foundation

actor CLIRunner {
  private let success: Bool
  private var invocations: [[String]] = []

  init(success: Bool) { self.success = success }

  func run(arguments: [String]) -> CLIResult {
    invocations.append(arguments)
    return CLIResult(succeeded: success)
  }

  func calls() -> [[String]] { invocations }
}

struct CLIResult {
  let succeeded: Bool
}

@main
struct ConsoleListenerVerifierTests {
  @MainActor
  static func main() async {
    let customPort = URL(string: "http://127.0.0.1:9842/usage?view=usage-flow")!
    let cli = CLIRunner(success: true)
    let accepted = await ConsoleListenerVerifier.verify(customPort, using: cli)
    let firstCalls = await cli.calls()
    precondition(accepted)
    precondition(firstCalls == [["console", "verify-listener", "--console-url", "http://127.0.0.1:9842/"]])

    let failedCli = CLIRunner(success: false)
    let rejected = await ConsoleListenerVerifier.verify(customPort, using: failedCli)
    precondition(!rejected)

    for raw in ["http://localhost:9842/", "http://127.0.0.2:9842/",
                "https://127.0.0.1:9842/", "http://user@127.0.0.1:9842/",
                "http://127.0.0.1/"] {
      let permitted = await ConsoleListenerVerifier.verify(URL(string: raw)!, using: cli)
      precondition(!permitted)
    }
    let finalCalls = await cli.calls()
    precondition(finalCalls.count == 1)

    precondition(ConsoleListenerVerifier.navigation(to: customPort, from: customPort) == .console)
    for raw in ["http://localhost:9842/", "http://127.0.0.2:9842/",
                "http://[::1]:9842/", "http://127.0.0.1:9843/", "file:///tmp/index.html"] {
      precondition(ConsoleListenerVerifier.navigation(to: URL(string: raw)!, from: customPort) == .reject)
    }
    precondition(ConsoleListenerVerifier.navigation(to: URL(string: "https://example.com/docs")!, from: customPort) == .external)
    print("CONSOLE_LISTENER_VERIFIER_TESTS_OK")
  }
}
