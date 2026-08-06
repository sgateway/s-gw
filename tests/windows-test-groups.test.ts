import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  filesForWindowsTestGroup,
  parseWindowsTestGroup,
  windowsTestGroups
} from "../scripts/windows-test-groups.mjs";

describe("Windows test groups", () => {
  it("partitions every test file exactly once", async () => {
    const allFiles = await discoverTests(path.resolve("tests"));
    const shardFiles = windowsTestGroups
      .filter((group) => group !== "all")
      .flatMap((group) => filesForWindowsTestGroup(group, allFiles));

    expect([...new Set(shardFiles)].sort()).toEqual(allFiles);
    expect(shardFiles).toHaveLength(allFiles.length);
    expect(filesForWindowsTestGroup("all", allFiles)).toEqual(allFiles);
    expect(allFiles).not.toContain("tests/fixtures/fully-skipped.test.ts");
  });

  it("accepts only the supported command line", () => {
    expect(parseWindowsTestGroup([])).toBe("all");
    expect(parseWindowsTestGroup(["--group", "client"])).toBe("client");
    expect(() => parseWindowsTestGroup(["--group", "missing"])).toThrow("Unknown Windows test group");
    expect(() => parseWindowsTestGroup(["--pool", "threads"])).toThrow("Usage:");
  });

  it("fails when a dedicated test disappears", () => {
    expect(() => filesForWindowsTestGroup("core", ["tests/example.test.ts"]))
      .toThrow("Windows test group references a missing file");
  });

  it("keeps the stable aggregate CI check over every shard", async () => {
    const workflow = await readFile(path.resolve(".github/workflows/ci.yml"), "utf8");
    expect(workflow).toContain("group: [core, store, client, credential, acl]");
    expect(workflow).toContain("name: macOS native surfaces");
    expect(workflow).toContain("name: Windows preview client");
    expect(workflow).toContain("needs: windows_shards");
    expect(workflow).toContain("WINDOWS_RESULT: ${{ needs.windows_shards.result }}");
    expect(workflow).toContain("SGW_WINDOWS_CREDENTIAL_HELPER_TIMEOUT_MS: 120000");
    expect(workflow).toContain("SGW_WINDOWS_PROCESS_INSPECTION_TIMEOUT_MS: 120000");
    expect(workflow).toContain("SGW_WINDOWS_STARTUP_OPERATION_TIMEOUT_MS: 120000");
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
