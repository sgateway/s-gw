import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  buildConsoleLaunchAgentPlist,
  buildMenuBarLaunchAgentPlist,
  consoleLabel,
  getPackageLayout,
  macAppProcessRecordPath,
  menuBarLabel,
  packageHealth
} from "../src/install.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, "..");

describe("customer package layout", () => {
  it("finds package artifacts from the runtime module location", () => {
    const layout = getPackageLayout();

    expect(layout.cliPath).toMatch(/dist\/cli\.js$/);
    expect(layout.mcpPath).toMatch(/dist\/mcp-server\.js$/);
    expect(layout.keychainHelperPath).toBe(
      path.join(layout.packageRoot, "dist", "native", `${process.platform}-${process.arch}`, "s-gw-keychain-helper")
    );
    expect(layout.packagedMacAppPath).toBe(path.join(layout.packageRoot, "dist", "s-gw.app"));
    expect(layout.packagedMacAppBinaryPath).toContain("dist/s-gw.app/Contents/MacOS/s-gw");
    expect(layout.installedMacAppPath).toMatch(/Applications\/s-gw\.app$/);
    expect(layout.macAppPath).toContain("s-gw.app");
    expect(layout.macAppBinaryPath).toContain("s-gw.app/Contents/MacOS/s-gw");
    expect(layout.menuBarAppPath).toContain("s-gw Menu Bar.app");
    expect(layout.windowsClientScriptPath).toMatch(/dist\/windows\/s-gw-client\.ps1$/);
    expect(layout.windowsHelperScriptPath).toMatch(/dist\/windows\/s-gw-helper\.ps1$/);
    expect(layout.windowsCredentialHelperPath).toMatch(/dist\/windows\/s-gw-credential\.ps1$/);
  });

  it("routes app installation through the native app command", async () => {
    const cliSource = await readFile(path.join(repoRoot, "src/cli.ts"), "utf8");
    const menuBarHandler = cliSource.slice(
      cliSource.indexOf("async function handleMenuBarCommand"),
      cliSource.indexOf("async function handleOnePasswordCommand")
    );
    const appHandler = cliSource.slice(
      cliSource.indexOf("async function handleAppCommand"),
      cliSource.indexOf("async function handleGuardCommand")
    );

    expect(menuBarHandler).not.toContain("installMacAppBundle");
    expect(appHandler).toContain("installMacAppBundle");
    expect(cliSource).toContain("const appInstall = process.platform === \"darwin\" ? installMacAppBundle() : undefined");
    expect(cliSource).toContain("installPersistentKeychainHelper()");
  });

  it("tracks a running native app so open focuses instead of relaunching", async () => {
    const [installSource, appSource] = await Promise.all([
      readFile(path.join(repoRoot, "src/install.ts"), "utf8"),
      readFile(path.join(repoRoot, "native/macos-app/Sources/SgwMac/App/SgwApp.swift"), "utf8")
    ]);

    expect(macAppProcessRecordPath()).toMatch(/Library\/Application Support\/s-gw\/s-gw-app\.process\.json$/);
    expect(installSource).toContain("existingMacAppProcess");
    expect(installSource).toContain("postOpenMainWindowNotification");
    expect(installSource).not.toContain("pkill");
    expect(appSource).toContain("writeProcessRecord");
    expect(appSource).toContain("s-gw-app.process.json");

    const stopSource = installSource.slice(
      installSource.indexOf("export function stopMacApp"),
      installSource.indexOf("export function stopWindowsSurfaces")
    );
    expect(stopSource).toContain("runningApplicationsWithBundleIdentifier");
    expect(stopSource).toContain("com.s-gw.sgw.app");
    expect(stopSource).toContain("pids.push(Number(app.processIdentifier))");
    expect(stopSource).not.toContain("valueForKey");
    expect(stopSource).not.toContain("macAppBinaryPath");
    expect(installSource).toContain("assertMacExecutableCompatible");
    expect(installSource).toContain('"-verify_arch", arch');
    expect(installSource).toContain("Intel Macs must build them from source");
  });

  it("reports install health without exposing unlock passphrases", () => {
    const oldValue = process.env.SGW_MASTER_PASSPHRASE;
    process.env.SGW_MASTER_PASSPHRASE = "do not serialize this value";

    try {
      const health = JSON.stringify(packageHealth());
      expect(health).toContain("s-gw.app");
      expect(health).toContain("s-gw Menu Bar.app");
      expect(health).toContain("s-gw-client.ps1");
      expect(health).toContain("s-gw-helper.ps1");
      expect(health).not.toContain("do not serialize this value");
    } finally {
      if (oldValue === undefined) {
        delete process.env.SGW_MASTER_PASSPHRASE;
      } else {
        process.env.SGW_MASTER_PASSPHRASE = oldValue;
      }
    }
  }, 30_000);
});

describe("install readiness", () => {
  it("reports ready when an unlock source is configured", () => {
    const oldValue = process.env.SGW_MASTER_PASSPHRASE;
    process.env.SGW_MASTER_PASSPHRASE = "configured-passphrase";

    try {
      const health = packageHealth();
      // Build artifacts exist in this repo and env unlock is set, so we are ready.
      expect(health.ready).toBe(true);
      expect(health.readiness.ok).toBe(true);
      expect(health.readiness.blockers).toEqual([]);
    } finally {
      if (oldValue === undefined) {
        delete process.env.SGW_MASTER_PASSPHRASE;
      } else {
        process.env.SGW_MASTER_PASSPHRASE = oldValue;
      }
    }
  }, 30_000);

  it("flags missing unlock material as a readiness blocker", () => {
    const oldPass = process.env.SGW_MASTER_PASSPHRASE;
    const oldDisable = process.env.SGW_DISABLE_KEYCHAIN;
    delete process.env.SGW_MASTER_PASSPHRASE;
    process.env.SGW_DISABLE_KEYCHAIN = "1";

    try {
      const health = packageHealth();
      expect(health.ready).toBe(false);
      expect(health.readiness.ok).toBe(false);
      expect(health.readiness.blockers.join(" ")).toContain("unlock");
      // Never leak how to find a value, just how to configure one.
      expect(JSON.stringify(health)).not.toContain("configured-passphrase");
    } finally {
      if (oldPass === undefined) {
        delete process.env.SGW_MASTER_PASSPHRASE;
      } else {
        process.env.SGW_MASTER_PASSPHRASE = oldPass;
      }
      if (oldDisable === undefined) {
        delete process.env.SGW_DISABLE_KEYCHAIN;
      } else {
        process.env.SGW_DISABLE_KEYCHAIN = oldDisable;
      }
    }
  });
});

describe("launch-agent packaging", () => {
  it("generates a console daemon plist with exact local paths", () => {
    const plist = buildConsoleLaunchAgentPlist(8718, "/tmp/s-gw logs");

    expect(plist).toContain(`<string>${consoleLabel}</string>`);
    expect(plist).toContain("<string>console</string>");
    expect(plist).toContain("<string>--no-open</string>");
    expect(plist).toContain("<string>8718</string>");
    expect(plist).toContain("<true/>");
    expect(plist).not.toContain("SGW_MASTER_PASSPHRASE");
  });

  it("generates a menu-bar plist with CLI and console environment", () => {
    const plist = buildMenuBarLaunchAgentPlist({
      consoleUrl: "http://127.0.0.1:9900/",
      countMode: "credentials"
    }, "/tmp/s-gw logs");

    expect(plist).toContain(`<string>${menuBarLabel}</string>`);
    expect(plist).toContain("s-gw-menu-bar-helper");
    expect(plist).toContain("<key>SGW_CLI_PATH</key>");
    expect(plist).toContain("<key>SGW_APP_PATH</key>");
    expect(plist).toContain("s-gw.app");
    expect(plist).toContain("<key>SGW_CONSOLE_URL</key>");
    expect(plist).toContain("<key>SGW_MENU_BAR_COUNT_MODE</key>");
    expect(plist).toContain("<string>credentials</string>");
    expect(plist).toContain("<string>--notify-on-launch</string>");
    expect(plist).toContain("http://127.0.0.1:9900/");
    expect(plist).toContain("<string>Aqua</string>");
    expect(plist).not.toContain("SGW_MASTER_PASSPHRASE");
  });

  it("can explicitly install the menu-bar helper in quiet mode", () => {
    const plist = buildMenuBarLaunchAgentPlist({
      consoleUrl: "http://127.0.0.1:9900/",
      notify: false
    }, "/tmp/s-gw logs");

    expect(plist).toContain("<string>--no-notify</string>");
    expect(plist).not.toContain("<string>--notify-on-launch</string>");
  });
});
