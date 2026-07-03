import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "../native/macos-app/Sources/SgwMac");

describe("native readiness UI contract", () => {
  it("keeps the Overview readiness banner visible and accessible", async () => {
    const [overview, components] = await Promise.all([
      readFile(path.join(appRoot, "Views/OverviewView.swift"), "utf8"),
      readFile(path.join(appRoot, "Views/Components.swift"), "utf8")
    ]);

    expect(overview).toContain("if !appState.isReady");
    expect(overview).toContain("ReadinessBanner(");
    expect(overview).toContain("onRunSetup: { appState.runSetup() }");

    expect(components).toContain("struct ReadinessBanner");
    expect(components).toContain('Button("Run Setup"');
    expect(components).toContain('.accessibilityIdentifier("s-gw-readiness-banner")');
    expect(components).toContain('.accessibilityLabel("s-gw readiness")');
    expect(components).toContain('.accessibilityIdentifier("s-gw-readiness-run-setup")');
  });
});
