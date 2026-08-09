import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();

describe("platform support documentation", () => {
  it("describes Linux Secret Service and preview support consistently", async () => {
    const [readme, deployment, index, community] = await Promise.all([
      readFile(path.join(root, "README.md"), "utf8"),
      readFile(path.join(root, "docs/deployment.md"), "utf8"),
      readFile(path.join(root, "docs/README.md"), "utf8"),
      readFile(path.join(root, "docs/community-launch.md"), "utf8")
    ]);

    expect(readme).toContain("| Linux | Preview | Secret Service; explicit environment fallback |");
    expect(deployment).toContain("| Linux x64/arm64 | Preview | Secret Service through trusted `secret-tool`;");
    expect(index).toContain(
      "[macOS Keychain, Linux Secret Service, and Windows Credential Manager](keychain.md)"
    );
    expect(community).toContain("Windows and Linux are preview");
    expect(community).not.toContain("Linux is experimental");
  });
});
