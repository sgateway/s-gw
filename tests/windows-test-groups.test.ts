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
