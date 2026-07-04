import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { isNewerVersion, ReleaseChecker, UPDATE_CHECK_INTERVAL_MS } from "../src/update-check.js";
import { CURRENT_VERSION } from "../src/version.js";

let tmpDir = "";

afterEach(async () => {
  if (tmpDir) await rm(tmpDir, { recursive: true, force: true });
  tmpDir = "";
});

describe("release update checks", () => {
  it("includes preview releases, ignores drafts, and refreshes after the cache interval", async () => {
    tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-update-check-"));
    let calls = 0;
    let now = Date.parse("2026-07-03T12:00:00.000Z");
    const responses = [
      [
        release("v9.0.0", { draft: true }),
        release("v0.2.0", { prerelease: true }),
        release("v0.1.0")
      ],
      [release("v0.3.0", { prerelease: true })]
    ];
    const checker = new ReleaseChecker({
      cachePath: path.join(tmpDir, "update.json"),
      currentVersion: "0.1.0",
      enabled: true,
      now: () => now,
      fetcher: async () => new Response(JSON.stringify(responses[Math.min(calls++, responses.length - 1)]), { status: 200 })
    });

    const first = await checker.check();
    expect(first).toMatchObject({ checked: true, available: true, latestVersion: "0.2.0", prerelease: true });
    expect(calls).toBe(1);

    const cached = await checker.check();
    expect(cached.latestVersion).toBe("0.2.0");
    expect(calls).toBe(1);

    now += UPDATE_CHECK_INTERVAL_MS + 1;
    const refreshed = await checker.check();
    expect(refreshed.latestVersion).toBe("0.3.0");
    expect(calls).toBe(2);

    const cache = await readFile(path.join(tmpDir, "update.json"), "utf8");
    expect(cache).toContain('"latestVersion": "0.3.0"');
  });

  it("fails quietly when the public release feed is unavailable", async () => {
    tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-update-offline-"));
    const checker = new ReleaseChecker({
      cachePath: path.join(tmpDir, "update.json"),
      enabled: true,
      fetcher: async () => {
        throw new Error("offline");
      }
    });

    await expect(checker.check()).resolves.toMatchObject({
      checked: false,
      available: false,
      error: "offline"
    });
  });

  it("compares tagged release versions numerically", () => {
    expect(isNewerVersion("v0.10.0", "0.9.9")).toBe(true);
    expect(isNewerVersion("v0.1.1-preview.1", "0.1.0")).toBe(true);
    expect(isNewerVersion("v0.1.0", "0.1.0")).toBe(false);
    expect(isNewerVersion("v0.0.9", "0.1.0")).toBe(false);
  });

  it("keeps the updater version aligned with the package", async () => {
    const pkg = JSON.parse(await readFile(path.join(process.cwd(), "package.json"), "utf8"));
    expect(CURRENT_VERSION).toBe(pkg.version);
  });

  it("wires manual and periodic checks into the CLI and macOS client", async () => {
    const [cli, swiftChecker, appState] = await Promise.all([
      readFile(path.join(process.cwd(), "src/cli.ts"), "utf8"),
      readFile(path.join(process.cwd(), "native/macos-app/Sources/SgwMac/Services/UpdateChecker.swift"), "utf8"),
      readFile(path.join(process.cwd(), "native/macos-app/Sources/SgwMac/App/AppState.swift"), "utf8")
    ]);

    expect(cli).toContain('first === "update"');
    expect(cli).toContain("s-gw update check [--force]");
    expect(swiftChecker).toContain("/releases?per_page=20");
    expect(swiftChecker).toContain(".filter({ !$0.draft })");
    expect(appState).toContain("private var updateTask");
    expect(appState).toContain("Task.sleep(for: .seconds(60 * 60))");
  });
});

function release(tag: string, options: { draft?: boolean; prerelease?: boolean } = {}) {
  return {
    tag_name: tag,
    html_url: `https://github.com/sgateway/s-gw/releases/tag/${tag}`,
    draft: options.draft ?? false,
    prerelease: options.prerelease ?? false,
    published_at: "2026-07-03T12:00:00.000Z"
  };
}
