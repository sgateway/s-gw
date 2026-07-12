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
      feedEndpoint: null,
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

  it("falls back to the public Atom feed when the GitHub API is rate-limited", async () => {
    tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-update-atom-"));
    const calls: string[] = [];
    const api = "https://api.github.test/releases";
    const atom = "https://github.test/releases.atom";
    const checker = new ReleaseChecker({
      cachePath: path.join(tmpDir, "update.json"),
      currentVersion: "0.1.0",
      endpoint: api,
      feedEndpoint: atom,
      enabled: true,
      fetcher: async (input) => {
        const url = String(input);
        calls.push(url);
        if (url === api) return new Response("rate limited", { status: 403 });
        return new Response(`<?xml version="1.0"?>
          <feed>
            <entry>
              <id>tag:github.com,2008:Repository/1/v0.1.2</id>
              <updated>2026-07-11T12:00:00Z</updated>
              <link rel="alternate" type="text/html" href="https://github.com/sgateway/s-gw/releases/tag/v0.1.2"/>
              <title>s-gw 0.1.2</title>
            </entry>
          </feed>`, { status: 200, headers: { "Content-Type": "application/atom+xml" } });
      }
    });

    const result = await checker.check(true);
    expect(result.error).toBeUndefined();
    expect(result).toMatchObject({
      checked: true,
      currentVersion: "0.1.0",
      latestVersion: "0.1.2",
      available: true,
      releaseUrl: "https://github.com/sgateway/s-gw/releases/tag/v0.1.2",
      publishedAt: "2026-07-11T12:00:00Z"
    });
    expect(calls).toEqual([api, atom]);
  });

  it("compares tagged release versions numerically", () => {
    expect(isNewerVersion("v0.10.0", "0.9.9")).toBe(true);
    expect(isNewerVersion("v0.1.1-preview.1", "0.1.0")).toBe(true);
    expect(isNewerVersion("0.2.0-preview.1", "0.2.0")).toBe(false);
    expect(isNewerVersion("0.2.0", "0.2.0-preview.1")).toBe(true);
    expect(isNewerVersion("0.2.0-preview.10", "0.2.0-preview.2")).toBe(true);
    expect(isNewerVersion("0.2.0-preview.2", "0.2.0-preview.10")).toBe(false);
    expect(isNewerVersion("0.2.0-beta", "0.2.0-alpha")).toBe(true);
    expect(isNewerVersion("0.2.0-1", "0.2.0-alpha")).toBe(false);
    expect(isNewerVersion("0.2.0-preview", "0.2.0-preview.1")).toBe(false);
    expect(isNewerVersion("0.2.0+build.2", "0.2.0+build.1")).toBe(false);
    expect(isNewerVersion("v0.1.0", "0.1.0")).toBe(false);
    expect(isNewerVersion("v0.0.9", "0.1.0")).toBe(false);
    expect(isNewerVersion("not-a-version", "0.1.0")).toBe(false);
  });

  it("offers the stable release to users running its preview", async () => {
    tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-update-stable-"));
    const checker = new ReleaseChecker({
      cachePath: path.join(tmpDir, "update.json"),
      currentVersion: "0.2.0-preview.1",
      enabled: true,
      fetcher: async () => new Response(JSON.stringify([
        release("v0.2.0-preview.2", { prerelease: true }),
        release("v0.2.0"),
        release("not-a-version")
      ]), { status: 200 })
    });

    await expect(checker.check(true)).resolves.toMatchObject({
      available: true,
      latestVersion: "0.2.0",
      prerelease: false
    });
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
    expect(swiftChecker).toContain("releases.atom");
    expect(swiftChecker).toContain(".filter({ !$0.draft })");
    const helper = await readFile(
      path.join(process.cwd(), "native/menu-bar-helper/Sources/UpdateMonitor.swift"),
      "utf8"
    );
    expect(appState).not.toContain("private var updateTask");
    expect(helper).toContain("update check");
    expect(helper).toContain("15 * 60");
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
