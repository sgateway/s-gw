import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Menu-bar helper coverage for the approve/deny in-flight guard + honest-failure
// reasoning. These live in the helper's @MainActor DecisionController, which the
// TypeScript console-server / CLI suites can't reach. Earlier iterations could
// only verify them via `swift build` + a CLI-error-contract check (iter 12),
// never driven against the shipping decision core.
//
// This compiles the REAL production main.swift with -DSGW_TEST (so its @main is
// excluded) together with Tests/DecisionGuardTests.swift, which supplies its own
// @main and drives the genuine DecisionController. The fake CLI it injects blocks
// on a FIFO so a decision is held in flight exactly like a user double-clicking
// Approve before the first CLI call returns.
//
// Skips cleanly off-macOS or when `swift` isn't installed so other environments
// stay green — same pattern as the native-appstate + headless-Chrome E2E suites.

const here = path.dirname(fileURLToPath(import.meta.url));
const helperRoot = path.resolve(here, "../native/menu-bar-helper");
const updateStateSource = path.resolve(here, "../native/update-state/Sources/SgwUpdateState/UpdateNoticeState.swift");
const helperSources = readdirSync(path.join(helperRoot, "Sources"))
  .filter((name) => name.endsWith(".swift"))
  .sort()
  .map((name) => path.join(helperRoot, "Sources", name));
const sources = [...helperSources, path.join(helperRoot, "Tests/DecisionGuardTests.swift")];

function helperSource(): string {
  return helperSources.map((sourcePath) => readFileSync(sourcePath, "utf8")).join("\n");
}

function hasSwift(): boolean {
  if (process.platform !== "darwin") return false;
  const probe = spawnSync("swift", ["--version"], { stdio: ["ignore", "pipe", "pipe"] });
  return probe.status === 0;
}

const enabled = hasSwift() && existsSync(updateStateSource) && sources.every((p) => existsSync(p));
const describeNative = enabled ? describe : describe.skip;

let workDir = "";
let binary = "";

describe("menu-bar helper approval surface contract", () => {
  it("keeps approval decisions in one popover instead of stacking a second panel", () => {
    const source = helperSource();

    expect(source).toContain("ApprovalPromptCard(");
    expect(source).toContain("private func showStatusPopover()");
    expect(source).not.toContain("NSPanel(");
    expect(source).not.toContain("approvalPromptWindow");
    expect(source).not.toContain("showApprovalPrompt");
    expect(source).not.toContain("syncApprovalPrompt");
  });

  it("keeps dashboard cards, status rows, providers, requests, and audit rows interactive", () => {
    const source = helperSource();

    expect(source).toContain("final class HelperViewModel: ObservableObject");
    expect(source).toContain("@ObservedObject var model: HelperViewModel");
    expect(source).toContain("private var summaryStrip: some View");
    expect(source).toContain("private var protectionSection: some View");
    expect(source).toContain("private var recentActivitySection: some View");
    expect(source.match(/Text\("Recent activity"\)/g)).toHaveLength(1);
    expect(source).toContain("private func pendingContent(_ request: RequestRecord)");
    expect(source).toContain("actions.openApp(.approvals)");
    expect(source).toContain("actions.openApp(.credentials)");
    expect(source).toContain("actions.openApp(.activity)");
    expect(source).toContain('Button("Audit Log") { actions.openApp(.audit) }');
    expect(source).toContain("let agentRequestIds = Set(store.requests.map(\\.id))");
    expect(source).toContain("return agentRequestIds.contains(requestId)");
    expect(source).not.toContain("HelperDashboardFocus");
    expect(source).not.toContain("pickerStyle(.segmented)\n    .labelsHidden()\n  }\n\n  private var overviewSections");
    expect(source).not.toContain("private func metricBar");
  });

  it("uses adaptive action-first dimensions instead of the old fixed dashboard", () => {
    const source = helperSource();

    expect(source).toContain("static let width: CGFloat = 400");
    expect(source).toContain("static let idleHeight: CGFloat = 420");
    expect(source).toContain("static let pendingHeight: CGFloat = 500");
    expect(source).not.toContain(".frame(width: 448, height: 510)");
    expect(source).toContain('Button("Allow 8 hours")');
    expect(source).toContain('Button("Once")');
    expect(source).toContain("confirmUnlimitedForAll = true");
    expect(source).toContain("Allow every agent without an expiry?");
  });

  it("shows approval requests as an agent-to-transport-to-destination path", () => {
    const source = helperSource();

    expect(source).toContain("ApprovalTrustPath(request: request)");
    expect(source).toContain("struct ApprovalFlowDescriptor");
    expect(source).toContain('transportTitle = "SSH"');
    expect(source).toContain('destinationDetail = isEC2 ? "Amazon EC2" : "Remote host"');
    expect(source).toContain('Bundle.main.url(forResource: "AwsEc2", withExtension: "png")');
    expect(source).toContain('"codex": ["com.openai.codex"]');
    expect(source).toContain('openSourceIcon: "terminal"');
    expect(source).toContain('openSourceIcon: "bot"');
    expect(source).toContain('Bundle.main.url(forResource: "Lucide-\\(name)", withExtension: "svg")');
    expect(existsSync(path.resolve(here, "../assets/icons/aws-ec2.png"))).toBe(true);
    for (const name of ["bot", "terminal", "server", "monitor"]) {
      expect(existsSync(path.resolve(here, `../assets/icons/lucide/${name}.svg`))).toBe(true);
    }
  });

  it("keeps the native SwiftUI helper menu instead of embedding the React menubar route", () => {
    const source = helperSource();

    expect(source).toContain("NSHostingController(rootView: HelperMenuDashboard(");
    expect(source).not.toContain("import WebKit");
    expect(source).not.toContain("final class MenubarWebViewController");
    expect(source).not.toContain("MenubarWebViewController(url: menubarConsoleURL())");
    expect(source).not.toContain('consoleURL.appendingPathComponent("menubar")');
  });

  it("dismisses the helper popover immediately when the user clicks elsewhere", () => {
    const source = helperSource();

    expect(source).toContain("popover.behavior = .transient");
    expect(source).toContain("NSEvent.addGlobalMonitorForEvents(");
    expect(source).toContain("matching: [.leftMouseDown, .rightMouseDown, .otherMouseDown]");
    expect(source).toContain("func applicationDidResignActive");
    expect(source).toContain("closePopoverForOutsideInteraction()");
    expect(source).not.toContain("focusDismissDelay");
    expect(source).not.toContain("focusDismissTimer");
    expect(source).not.toContain("scheduleFocusDismissIfNeeded");
    expect(source).not.toContain("dismissHelperUIAfterFocusLoss");
  });

  it("keeps one live model and rejects duplicate helper processes", () => {
    const source = helperSource();

    expect(source).toContain("private var hostingController: NSHostingController<HelperMenuDashboard>?");
    expect(source).toContain("Task.detached(priority: .utility)");
    expect(source).toContain("HelperLaunchGuard.shared");
    expect(source).toContain("flock(fd, LOCK_EX | LOCK_NB)");
    expect(source).toContain("com.s-gw.sgw.showMenuHelper");
    expect(source).not.toContain("popoverNeedsRefreshOnClose");
  });

  it("routes deep helper actions into the native app", () => {
    const source = helperSource();

    expect(source).toContain("enum HelperRoute: String");
    expect(source).toContain('userInfo: ["view": route.rawValue]');
    expect(source).toContain("let openApp: (HelperRoute) -> Void");
  });

  it("uses actor-safe async notification APIs", () => {
    const source = helperSource();

    expect(source).toContain("try? await UNUserNotificationCenter.current().requestAuthorization");
    expect(source).toContain("var settings = await center.notificationSettings()");
    expect(source).toContain("settings.alertSetting == .enabled");
    expect(source).not.toMatch(/requestAuthorization\(options: \[\.alert, \.sound\]\) \{/);
    expect(source).not.toContain("withCheckedContinuation");
  });
});

describeNative("menu-bar helper DecisionController (real Swift source)", () => {
  beforeAll(async () => {
    workDir = await mkdtemp(path.join(os.tmpdir(), "sgw-menubar-test-"));
    binary = path.join(workDir, "menubar-tests");
    const updateStateModule = path.join(workDir, "SgwUpdateState.swiftmodule");
    const updateStateLibrary = path.join(workDir, "libSgwUpdateState.dylib");
    const compileUpdateState = spawnSync(
      "swiftc",
      [
        "-O",
        "-parse-as-library",
        "-emit-library",
        "-emit-module",
        "-module-name", "SgwUpdateState",
        "-emit-module-path", updateStateModule,
        updateStateSource,
        "-o", updateStateLibrary
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
    );
    if (compileUpdateState.status !== 0) {
      throw new Error(`swiftc shared update state failed:\n${compileUpdateState.stderr || compileUpdateState.stdout}`);
    }
    const compile = spawnSync(
      "swiftc",
      [
        "-O",
        "-parse-as-library",
        "-DSGW_TEST",
        "-I", workDir,
        "-L", workDir,
        "-lSgwUpdateState",
        "-Xlinker", "-rpath",
        "-Xlinker", "@executable_path",
        ...sources,
        "-o", binary
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
    );
    if (compile.status !== 0) {
      throw new Error(`swiftc failed:\n${compile.stderr || compile.stdout}`);
    }
  }, 180_000);

  afterAll(async () => {
    if (workDir) await rm(workDir, { recursive: true, force: true });
  });

  it("enforces the approve/deny in-flight guard and honest-failure reasons", () => {
    const run = spawnSync(binary, [], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        DYLD_LIBRARY_PATH: workDir,
        SGW_UPDATE_NOTICE_STATE_PATH: path.join(workDir, "update-notice-state.json")
      }
    });
    const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
    expect(output, output).toContain("ALL_MENUBAR_TESTS_OK");
    expect(run.status).toBe(0);
  }, 30_000);
});
