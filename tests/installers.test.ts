import { execFileSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

const root = process.cwd();

describe("platform installers", () => {
  it("builds versioned Mac and Windows artifacts from the package tarball", async () => {
    const [pkgRaw, builder, inspectorSource] = await Promise.all([
      readFile(path.join(root, "package.json"), "utf8"),
      readFile(path.join(root, "scripts/build-installers.mjs"), "utf8"),
      readFile(path.join(root, "native/macos-keychain/SgwKeychainInspector.swift"), "utf8")
    ]);
    const pkg = JSON.parse(pkgRaw);

    expect(pkg.name).toBe("@s-gw/s-gw");
    expect(pkg.publishConfig.access).toBe("public");
    expect(pkg.scripts["build:installers"]).toContain("node scripts/build-installers.mjs");
    expect(pkg.scripts["build:installers"]).toContain("npm run validate:release-assets");
    expect(pkg.scripts["validate:release-assets"]).toBe("node scripts/validate-release-assets.mjs dist/installers");
    expect(pkg.scripts["validate:npm-package"]).toBe("node scripts/validate-npm-package.mjs");
    expect(pkg.scripts["build:rust-core"]).toBe("node scripts/build-rust-core.mjs");
    expect(pkg.files).toContain("dist");
    expect(pkg.files).toContain("!dist/installers");
    expect(pkg.files).toContain("!dist/native/s-gw-core");
    expect(pkg.files).toContain("!dist/native/s-gw-core.exe");
    expect(pkg.files).toContain("!dist/native/s-gw-keychain-helper");
    expect(pkg.files).toContain("!dist/**/*.map");
    expect(pkg.scripts.prepublishOnly).toBe("npm run validate:npm-package");
    expect(pkg.files).not.toContain("scripts");
    expect(pkg.files).not.toContain("native/macos-app/Sources");
    expect(pkg.files).not.toContain("native/menu-bar-helper/Sources");
    expect(builder).toContain("hdiutil");
    expect(builder).toContain("s-gw-${version}-macos.dmg");
    expect(builder).toContain("s-gw-${version}-windows.zip");
    expect(builder).toContain('const packageFile = `s-gw-${version}.tgz`');
    expect(builder).toContain("SHA256SUMS.txt");
    expect(inspectorSource).toContain("validateTrustedApplication");
    expect(inspectorSource).not.toContain("kSecReturnData");
    const validator = await readFile(path.join(root, "scripts/validate-release-assets.mjs"), "utf8");
    expect(validator).toContain("validateReleaseDirectory");
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
    const manifest = JSON.parse(raw)[0] as { files: Array<{ path: string; mode: number }> };
    const files = manifest.files.map((item) => item.path);
    const target = `${process.platform}-${process.arch}`;
    const coreName = process.platform === "win32"
      ? `dist/native/${target}/s-gw-core.exe`
      : `dist/native/${target}/s-gw-core`;

    expect(files).toContain(coreName);
    expect(files).not.toContain("dist/native/s-gw-core");
    expect(files).not.toContain("dist/native/s-gw-core.exe");
    if (process.platform === "darwin") {
      expect(files).toContain(`dist/native/${target}/s-gw-keychain-helper`);
      expect(files).toContain(`dist/native/${target}/s-gw-keychain-inspector`);
      expect(files).toContain("dist/s-gw.app/Contents/MacOS/s-gw");
      expect(files).toContain("dist/s-gw Menu Bar.app/Contents/MacOS/s-gw-menu-bar-helper");
    }
    const nativeCore = manifest.files.find((item) => item.path === coreName);
    if (process.platform !== "win32") {
      expect((nativeCore?.mode || 0) & 0o111).not.toBe(0);
    }
    expect(files.some((file) => file.endsWith(".map"))).toBe(false);
    expect(files.some((file) => file.startsWith("native/"))).toBe(false);
    expect(files.some((file) => file.startsWith("scripts/"))).toBe(false);
  }, 20_000);

  it("keeps installer setup local and does not embed credential material", async () => {
    const [mac, windows] = await Promise.all([
      readFile(path.join(root, "native/installers/macos/Install s-gw.command"), "utf8"),
      readFile(path.join(root, "native/installers/windows/Install-s-gw.ps1"), "utf8")
    ]);
    const combined = `${mac}\n${windows}`;

    expect(mac).toContain('"$sgw_bin" setup --port 8718');
    expect(mac).toContain('PATH="$npm_prefix/bin:$PATH" "$sgw_bin" setup');
    expect(mac).toContain('persistent_helper="$sgw_home/native/$keychain_target/s-gw-keychain-helper"');
    expect(mac).toContain('The existing Keychain helper could not be preserved before upgrade.');
    expect(mac).toContain('archive_keychain_helper "$candidate"');
    expect(mac).toContain('archive_keychain_helper "$installed_helper"');
    expect(mac).toContain('/usr/bin/shasum -a 256');
    expect(mac).toContain('installed_helper="$npm_root/@s-gw/s-gw/dist/native/$keychain_target/s-gw-keychain-helper"');
    expect(mac).toContain('The stable Keychain helper could not be activated after upgrade.');
    expect(windows).toContain('$setupArgs = @("setup", "--port", [string]$Port)');
    expect(combined).toContain("npm");
    expect(combined).not.toContain("SGW_MASTER_PASSPHRASE");
    expect(combined).not.toContain("op read");
  });

  it("removes the legacy package before install and clears a partial scoped package only during rollback", async () => {
    const [mac, windows] = await Promise.all([
      readFile(path.join(root, "native/installers/macos/Install s-gw.command"), "utf8"),
      readFile(path.join(root, "native/installers/windows/Install-s-gw.ps1"), "utf8")
    ]);

    for (const installer of [mac, windows]) {
      expect(installer).toContain("pack --dry-run --ignore-scripts --json");
      expect(installer).toContain("pack --ignore-scripts --json --pack-destination");
      expect(installer).toContain("uninstall --global --prefix");
      expect(installer).toContain("rollback");
      expect(installer).toContain("~/.s-gw");
      const restoreAt = installer.indexOf("Restoring legacy s-gw");
      const scopedRemovalAt = installer.search(/uninstall[^\n]+@s-gw\/s-gw/);
      expect(restoreAt).toBeGreaterThan(0);
      expect(scopedRemovalAt).toBeGreaterThan(restoreAt);
    }

    expect(mac).toContain("-- s-gw");
    expect(mac).toContain("item.version === process.argv[1]");
    expect(windows).toContain('-- "s-gw"');
    expect(windows).toContain("$rollbackMetadata.version -ne $legacyVersion");
    if (process.platform === "darwin") {
      execFileSync("zsh", ["-n", path.join(root, "native/installers/macos/Install s-gw.command")]);
    }
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

  it("builds and verifies updater assets independently from npm publishing", async () => {
    const [workflow, builder, validator] = await Promise.all([
      readFile(path.join(root, ".github/workflows/publish.yml"), "utf8"),
      readFile(path.join(root, "scripts/build-installers.mjs"), "utf8"),
      readFile(path.join(root, "scripts/validate-release-assets.mjs"), "utf8")
    ]);
    const assetJob = workflow.slice(workflow.indexOf("  release-assets:"));

    expect(assetJob).toContain("runs-on: macos-15");
    expect(workflow).toContain("release_tag:");
    expect(assetJob).toContain("inputs.release_tag != ''");
    expect(assetJob).toContain("ref: ${{ env.RELEASE_TAG }}");
    expect(assetJob).toContain("npm run verify");
    expect(assetJob).toContain("npm run build:installers");
    expect(assetJob).toContain("first_tgz");
    expect(assetJob).not.toContain("needs: publish");
    expect(builder).toContain("buildLegacyBridge");
    expect(builder).toContain("0-s-gw-legacy-${version}.tgz");
    expect(validator).toContain('bridgeMetadata.name !== "s-gw"');
  });

  it("publishes the native npm package on Apple Silicon and keeps Registry publishing on Linux", async () => {
    const workflow = await readFile(path.join(root, ".github/workflows/publish.yml"), "utf8");
    const npmJob = workflow.slice(
      workflow.indexOf("  publish-npm:"),
      workflow.indexOf("  publish-registry:")
    );
    const registryJob = workflow.slice(
      workflow.indexOf("  publish-registry:"),
      workflow.indexOf("  release-assets:")
    );

    expect(npmJob).toContain("runs-on: macos-15");
    expect(npmJob).toContain("npm run validate:npm-package");
    expect(npmJob).toContain("npm publish --access public --ignore-scripts");
    expect(npmJob).toContain("-verify_arch arm64");
    expect(npmJob).toContain('npm install --global --prefix "$prefix"');
    expect(npmJob).toContain('"@s-gw/s-gw@${package_version}"');
    expect(npmJob).toContain('s-gw-core" --version');
    expect(npmJob).toContain('test ! -e "$package_root/dist/native/s-gw-core"');
    expect(registryJob).toContain("needs: publish-npm");
    expect(registryJob).toContain("runs-on: ubuntu-latest");
    expect(registryJob).toContain("mcp-publisher_linux_amd64.tar.gz");
    expect(registryJob).not.toContain("npm publish --access public");
  });
});
