import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  filesForWindowsTestGroup,
  parseWindowsTestGroup,
  testNamePatternForWindowsTestGroup,
  windowsTestGroups
} from "../scripts/windows-test-groups.mjs";

describe("Windows test groups", () => {
  it("partitions every test file exactly once", async () => {
    const allFiles = await discoverTests(path.resolve("tests"));
    const shardFiles = windowsTestGroups
      .filter((group) => group !== "all")
      .flatMap((group) => filesForWindowsTestGroup(group, allFiles));

    expect([...new Set(shardFiles)].sort()).toEqual(allFiles);
    const counts = new Map<string, number>();
    for (const file of shardFiles) counts.set(file, (counts.get(file) || 0) + 1);
    for (const file of allFiles) {
      expect(counts.get(file)).toBe(file === "tests/windows-client.test.ts" ? 3 : 1);
    }
    expect(filesForWindowsTestGroup("all", allFiles)).toEqual(allFiles);
    expect(allFiles).not.toContain("tests/fixtures/fully-skipped.test.ts");
  });

  it("accepts only the supported command line", () => {
    expect(parseWindowsTestGroup([])).toBe("all");
    expect(parseWindowsTestGroup(["--group", "client-package"])).toBe("client-package");
    expect(() => parseWindowsTestGroup(["--group", "missing"])).toThrow("Unknown Windows test group");
    expect(() => parseWindowsTestGroup(["--pool", "threads"])).toThrow("Usage:");
  });

  it("fails when a dedicated test disappears", () => {
    expect(() => filesForWindowsTestGroup("core", ["tests/example.test.ts"]))
      .toThrow("Windows test group references a missing file");
  });

  it("keeps the stable aggregate CI check over every shard", async () => {
    const workflow = await readFile(path.resolve(".github/workflows/ci.yml"), "utf8");
    expect(workflow).toContain(
      "group: [core, store, client-package, client-session, client-startup, credential, acl]"
    );
    expect(workflow).toContain("name: macOS native surfaces");
    expect(workflow).toContain("name: Windows preview client");
    expect(workflow).toContain("needs: windows_shards");
    expect(workflow).toContain("WINDOWS_RESULT: ${{ needs.windows_shards.result }}");
    expect(workflow).toContain(
      "SGW_WINDOWS_ACL_OPERATION_TIMEOUT_MS: ${{ matrix.group == 'acl' && '120000' || '' }}"
    );
    expect(workflow).toContain("SGW_WINDOWS_CREDENTIAL_HELPER_TIMEOUT_MS: 120000");
    expect(workflow).toContain(
      "SGW_WINDOWS_HELPER_OPERATION_TIMEOUT_MS: ${{ startsWith(matrix.group, 'client-') && '120000' || '' }}"
    );
    expect(workflow).toContain("SGW_WINDOWS_PROCESS_INSPECTION_TIMEOUT_MS: 120000");
    expect(workflow).toContain("SGW_WINDOWS_STARTUP_OPERATION_TIMEOUT_MS: 120000");
    expect(workflow).toContain("name: Desktop app (${{ matrix.name }})");
    expect(workflow).toContain("name: Windows x64 NSIS");
    expect(workflow).toContain("runner: windows-latest");
    expect(workflow).toContain("runtime_target: win32-x64");
    expect(workflow).toContain("artifact_name: s-gw-windows-x64-nsis");
    expect(workflow).toContain(
      "artifact_path: native/desktop-app/target/release/bundle/nsis/*.exe"
    );
    expect(workflow).toContain("name: Ubuntu 22.04 x64 deb");
    expect(workflow).toContain("runner: ubuntu-22.04");
    expect(workflow).toContain("runtime_target: linux-x64");
    expect(workflow).toContain("artifact_name: s-gw-linux-x64-deb");
    expect(workflow).toContain(
      "artifact_path: native/desktop-app/target/release/bundle/deb/*.deb"
    );
    expect(workflow).toContain("name: Verify Windows MSVC host");
    expect(workflow).toContain("name: Pin desktop npm");
    expect(workflow).toContain("npm install --global npm@10.9.8");
    expect(workflow).toContain("cargo audit --file native/desktop-app/Cargo.lock");
    expect(workflow).toContain("retention-days: 14");
  });

  it("keeps desktop packages native while retaining the browser fallback", async () => {
    const workflow = await readFile(path.resolve(".github/workflows/ci.yml"), "utf8");

    expect(workflow).not.toContain("libwebkit2gtk-4.1-dev");
    for (const dependency of [
      "libayatana-appindicator3-dev",
      "libgtk-3-dev",
      "libwayland-dev",
      "libx11-dev",
      "libxcb-render0-dev",
      "libxcb-shape0-dev",
      "libxcb-xfixes0-dev",
      "libxdo-dev",
      "libxkbcommon-dev"
    ]) {
      expect(workflow).toContain(dependency);
    }
    expect(workflow).toContain("name: Verify native Rust dependency graph (Linux)");
    expect(workflow).toContain("name: Verify native Rust dependency graph (Windows)");
    expect(workflow).toContain(
      "cargo metadata --locked --format-version 1"
    );
    expect(workflow).toContain("for required in eframe glow tray-icon");
    expect(workflow).toContain('grep -Fxq "$required" <<< "$package_list"');
    expect(workflow).not.toContain('| grep -Fxq "$required"');
    expect(workflow).toContain(
      'grep -Eq "(^|[[:space:]])${required_renderer} v[0-9]" <<< "$active_tree"'
    );
    expect(workflow).not.toContain('| grep -Eq "(^|[[:space:]])${required_renderer} v[0-9]"');
    expect(workflow).toContain("foreach ($required in @('eframe', 'wgpu', 'tray-icon'))");
    expect(workflow).toContain("egui-wgpu|gpu-allocator|wgpu");
    expect(workflow).toContain("foreach ($requiredRenderer in @('egui-wgpu', 'wgpu', 'wgpu-core', 'wgpu-hal', 'gpu-allocator'))");
    expect(workflow).toContain("foreach ($requiredFeature in @('dx12', 'std', 'wgsl'))");
    expect(workflow).toContain(
      "__TAURI__|tauri://|tauri-runtime|tauri_runtime|tauri-plugin|webview2|webkit2gtk|javascriptcore|github\\.com/tauri-apps/wry|wry::"
    );
    expect(workflow).toContain("ldd \"$unpacked/usr/bin/s-gw-desktop\"");
    expect(workflow).toContain("[IO.File]::ReadAllBytes($desktop.FullName)");
    expect(workflow).toContain("test -f \"$(dirname \"$cli_path\")/console-ui/index.html\"");
    expect(workflow).toContain(
      String.raw`[\\/]runtime[\\/]package[\\/]dist[\\/]console-ui[\\/]index\.html$`
    );
  });

  it("allows enough time to create the private Windows test root", async () => {
    const runner = await readFile(path.resolve("scripts/run-windows-tests.mjs"), "utf8");
    expect(runner).toContain("timeout: 60_000");
  });

  it("assigns every Windows client test to one shard", async () => {
    const source = await readFile(path.resolve("tests/windows-client.test.ts"), "utf8");
    const titles = [...source.matchAll(/^\s*it\("([^"]+)"/gmu)].map((match) => match[1]);
    const clientGroups = ["client-package", "client-session", "client-startup"];

    expect(titles.length).toBeGreaterThan(0);
    for (const title of titles) {
      const matches = clientGroups.filter((group) => {
        const pattern = testNamePatternForWindowsTestGroup(group);
        return pattern ? new RegExp(pattern, "u").test(title) : false;
      });
      expect(matches, title).toHaveLength(1);
    }
    expect(testNamePatternForWindowsTestGroup("core")).toBeUndefined();
    expect(() => testNamePatternForWindowsTestGroup("missing")).toThrow("Unknown Windows test group");
  });
});

async function discoverTests(directory: string, relativeDirectory = "tests"): Promise<string[]> {
  const found: string[] = [];
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    const relativePath = `${relativeDirectory}/${entry.name}`;
    if (entry.isDirectory()) {
      if (relativePath === "tests/fixtures") continue;
      found.push(...await discoverTests(path.join(directory, entry.name), relativePath));
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".test.ts")) found.push(relativePath);
  }
  return found.sort();
}
