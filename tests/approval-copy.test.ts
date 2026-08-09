import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const approvalCopy = "This only approves local credential use; host-agent command prompts are separate.";

describe("approval surface copy", () => {
  it("distinguishes s-gw credential approval from host-agent command prompts", async () => {
    const files = [
      "native/macos-app/Sources/SgwMac/Views/ApprovalsView.swift",
      "native/menu-bar-helper/Sources/HelperDashboard.swift",
      "docs/ui/local-console.html"
    ];

    for (const file of files) {
      const text = await readFile(path.join(repoRoot, file), "utf8");
      expect(text).toContain(approvalCopy);
    }
  });

  it("shows the pinned executable on native and web approval surfaces", async () => {
    const [nativeModel, nativeView, webView] = await Promise.all([
      readFile(path.join(repoRoot, "native/macos-app/Sources/SgwMac/Models/Models.swift"), "utf8"),
      readFile(path.join(repoRoot, "native/macos-app/Sources/SgwMac/Views/ApprovalsView.swift"), "utf8"),
      readFile(path.join(repoRoot, "src/console-ui/src/App.tsx"), "utf8")
    ]);

    expect(nativeModel).toContain("var resolvedCommand: String?");
    expect(nativeView).toContain("request.action.resolvedCommand");
    expect(nativeView).toContain("Not pinned (legacy request)");
    expect(webView).toContain('["Executable", request.action.kind === "env_command"');
    expect(webView).toContain("Not pinned (legacy request)");
  });
});
