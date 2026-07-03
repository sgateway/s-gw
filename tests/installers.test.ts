import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();

describe("platform installers", () => {
  it("builds versioned Mac and Windows artifacts from the package tarball", async () => {
    const [pkgRaw, builder] = await Promise.all([
      readFile(path.join(root, "package.json"), "utf8"),
      readFile(path.join(root, "scripts/build-installers.mjs"), "utf8")
    ]);
    const pkg = JSON.parse(pkgRaw);

    expect(pkg.scripts["build:installers"]).toBe("npm run build && node scripts/build-installers.mjs");
    expect(pkg.files).toContain("native/installers");
    expect(pkg.files).toContain("!dist/installers");
    expect(builder).toContain("hdiutil");
    expect(builder).toContain("s-gw-${version}-macos.dmg");
    expect(builder).toContain("s-gw-${version}-windows.zip");
    expect(builder).toContain("SHA256SUMS.txt");
  });

  it("keeps installer setup local and does not embed credential material", async () => {
    const [mac, windows] = await Promise.all([
      readFile(path.join(root, "native/installers/macos/Install s-gw.command"), "utf8"),
      readFile(path.join(root, "native/installers/windows/Install-s-gw.ps1"), "utf8")
    ]);
    const combined = `${mac}\n${windows}`;

    expect(mac).toContain('"$sgw_bin" setup --port 8718');
    expect(windows).toContain('$setupArgs = @("setup", "--port", [string]$Port)');
    expect(combined).toContain("npm");
    expect(combined).not.toContain("SGW_MASTER_PASSPHRASE");
    expect(combined).not.toContain("op read");
  });
});
