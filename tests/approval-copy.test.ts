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
});
