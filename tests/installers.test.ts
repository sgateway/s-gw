import { execFileSync } from "node:child_process";
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

    expect(pkg.name).toBe("@s-gw/s-gw");
    expect(pkg.publishConfig.access).toBe("public");
    expect(pkg.scripts["build:installers"]).toBe("npm run build && node scripts/build-installers.mjs");
    expect(pkg.scripts["build:rust-core"]).toBe("node scripts/build-rust-core.mjs");
    expect(pkg.files).toContain("dist");
    expect(pkg.files).toContain("!dist/installers");
    expect(pkg.files).toContain("!dist/**/*.map");
    expect(pkg.files).not.toContain("scripts");
    expect(pkg.files).not.toContain("native/macos-app/Sources");
    expect(pkg.files).not.toContain("native/menu-bar-helper/Sources");
    expect(builder).toContain("hdiutil");
    expect(builder).toContain("s-gw-${version}-macos.dmg");
    expect(builder).toContain("s-gw-${version}-windows.zip");
    expect(builder).toContain('const packageFile = `s-gw-${version}.tgz`');
    expect(builder).toContain("SHA256SUMS.txt");
  });

  it("ships runtime artifacts without development source or source maps", () => {
    const npmCli = process.env.npm_execpath;
    if (!npmCli) {
      throw new Error("npm_execpath is required for the package manifest test.");
    }

    const raw = execFileSync(process.execPath, [npmCli, "pack", "--dry-run", "--json", "--ignore-scripts"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });
    const manifest = JSON.parse(raw)[0] as { files: Array<{ path: string }> };
    const files = manifest.files.map((item) => item.path);
    const coreName = process.platform === "win32" ? "dist/native/s-gw-core.exe" : "dist/native/s-gw-core";

    expect(files).toContain(coreName);
    expect(files.some((file) => file.endsWith(".map"))).toBe(false);
    expect(files.some((file) => file.startsWith("native/"))).toBe(false);
    expect(files.some((file) => file.startsWith("scripts/"))).toBe(false);
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

  it("resolves the Windows command from npm without requiring a restart", async () => {
    const installerPath = path.join(root, "native/installers/windows/Install-s-gw.ps1");
    const windows = await readFile(installerPath, "utf8");

    expect(windows).toContain("prefix --global");
    expect(windows).toContain('$sgwCommandPath = Join-Path $npmPrefix "s-gw.cmd"');
    expect(windows).toContain('$env:Path = "$env:Path;$npmPrefix"');
    expect(windows).toContain('[Environment]::SetEnvironmentVariable("Path", $nextUserPath, "User")');
    expect(windows).toContain("& $sgwCommandPath @setupArgs");
    expect(windows).not.toContain("Restart Windows and run s-gw setup");

    if (process.platform === "win32") {
      const escapedPath = installerPath.replaceAll("'", "''");
      const parseCommand = [
        "$tokens = $null",
        "$errors = $null",
        `[System.Management.Automation.Language.Parser]::ParseFile('${escapedPath}', [ref]$tokens, [ref]$errors) | Out-Null`,
        "if ($errors.Count -gt 0) { $errors | ForEach-Object { Write-Error $_ }; exit 1 }"
      ].join("; ");
      execFileSync("powershell.exe", ["-NoProfile", "-Command", parseCommand], { stdio: "pipe" });
    }
  });
});
