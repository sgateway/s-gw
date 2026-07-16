import { execFileSync } from "node:child_process";
import { access, readFile } from "node:fs/promises";
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
    const publishWorkflow = await readFile(path.join(root, ".github/workflows/publish.yml"), "utf8");
    expect(publishWorkflow).toContain("dist/native/darwin-arm64/s-gw-keychain-inspector");
    const validator = await readFile(path.join(root, "scripts/validate-release-assets.mjs"), "utf8");
    expect(validator).toContain("validateReleaseDirectory");
  });

  it("ships runtime artifacts without development source or source maps", async () => {
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

    const hasCore = await fileExists(path.join(root, coreName));
    if (process.env.SGW_REQUIRE_RUST_CORE === "1" || hasCore) {
      expect(files).toContain(coreName);
      const nativeCore = manifest.files.find((item) => item.path === coreName);
      if (process.platform !== "win32") {
        expect((nativeCore?.mode || 0) & 0o111).not.toBe(0);
      }
    }
    expect(files).not.toContain("dist/native/s-gw-core");
    expect(files).not.toContain("dist/native/s-gw-core.exe");
    if (process.platform === "darwin") {
      expect(files).toContain(`dist/native/${target}/s-gw-keychain-helper`);
      expect(files).toContain(`dist/native/${target}/s-gw-keychain-inspector`);
      expect(files).toContain("dist/s-gw.app/Contents/MacOS/s-gw");
      expect(files).toContain("dist/s-gw Menu Bar.app/Contents/MacOS/s-gw-menu-bar-helper");
    }
    expect(files.some((file) => file.endsWith(".map"))).toBe(false);
    expect(files.some((file) => file.startsWith("native/"))).toBe(false);
    expect(files.some((file) => file.startsWith("scripts/"))).toBe(false);
  }, 20_000);

  it("builds a self-contained macOS app with an Applications shortcut", async () => {
    const [builder, runtimeConfig, nodeEntitlements, verifier, windows] = await Promise.all([
      readFile(path.join(root, "scripts/build-installers.mjs"), "utf8"),
      readFile(path.join(root, "native/macos-app/runtime.json"), "utf8"),
      readFile(path.join(root, "native/macos-app/NodeRuntime.entitlements"), "utf8"),
      readFile(path.join(root, "scripts/verify-macos-dmg.mjs"), "utf8"),
      readFile(path.join(root, "native/installers/windows/Install-s-gw.ps1"), "utf8")
    ]);
    const runtime = JSON.parse(runtimeConfig) as { node: { version: string; url: string; sha256: string } };

    expect(builder).toContain('resolve(stageRoot, "s-gw.app")');
    expect(builder).toContain('symlinkSync("/Applications"');
    expect(builder).toContain('Contents/Resources/s-gw-runtime');
    expect(builder).toContain('npm", ["ci", "--omit=dev", "--ignore-scripts"');
    expect(builder).toContain('Contents/Library/LoginItems/s-gw Menu Bar.app');
    expect(builder).toContain('writeLauncher(resolve(binDir, "s-gw")');
    expect(builder).toContain('writeLauncher(resolve(binDir, "s-gw-mcp")');
    expect(builder).toContain("SGW_REQUIRE_NOTARIZATION");
    expect(builder).toContain("notarytool");
    expect(builder).toContain("NodeRuntime.entitlements");
    expect(builder).toContain("com.apple.security.cs.allow-jit");
    expect(builder).toContain('"--options", "runtime"');
    expect(builder).toContain('for (const command of ["corepack", "npm", "npx"])');
    expect(builder).not.toContain("Install s-gw.command");
    expect(nodeEntitlements).toContain("com.apple.security.cs.allow-jit");
    expect(verifier).toContain('path.join(runtimeRoot, "bin", "s-gw")');
    expect(verifier).toContain("runMcpSmoke");
    expect(verifier).toContain("SGW_TEST_HOME_ROOT");
    expect(runtime.node.version).toMatch(/^24\./);
    expect(runtime.node.url).toContain(`v${runtime.node.version}/node-v${runtime.node.version}-darwin-arm64.tar.gz`);
    expect(runtime.node.sha256).toMatch(/^[a-f0-9]{64}$/);

    expect(windows).toContain('$setupArgs = @("setup", "--port", [string]$Port)');
    expect(windows).not.toContain("SGW_MASTER_PASSPHRASE");
    expect(windows).not.toContain("op read");
  });

  it("keeps the Windows npm installer rollback-safe", async () => {
    const windows = await readFile(path.join(root, "native/installers/windows/Install-s-gw.ps1"), "utf8");

    expect(windows).toContain("pack --dry-run --ignore-scripts --json");
    expect(windows).toContain("pack --ignore-scripts --json --pack-destination");
    expect(windows).toContain("uninstall --global --prefix");
    expect(windows).toContain("rollback");
    expect(windows).toContain("~/.s-gw");
    const restoreAt = windows.indexOf("Restoring legacy s-gw");
    const scopedRemovalAt = windows.search(/uninstall[^\n]+@s-gw\/s-gw/);
    expect(restoreAt).toBeGreaterThan(0);
    expect(scopedRemovalAt).toBeGreaterThan(restoreAt);
    expect(windows).toContain('-- "s-gw"');
    expect(windows).toContain("$rollbackMetadata.version -ne $legacyVersion");
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
    const assetJob = workflow.slice(
      workflow.indexOf("  release-assets:"),
      workflow.indexOf("  publish-release:")
    );

    expect(assetJob).toContain("runs-on: macos-15");
    expect(workflow).toContain("workflow_dispatch:");
    expect(workflow).not.toContain("  release:");
    expect(workflow).toContain("release_tag:");
    expect(workflow).toContain("publish_release:");
    expect(assetJob).toContain("ref: ${{ inputs.release_tag }}");
    expect(assetJob).toContain('SGW_REQUIRE_RUST_CORE: "1"');
    expect(assetJob).toContain("SGW_RUST_CORE_DIR: ${{ github.workspace }}/.private/sgw-core");
    expect(assetJob).toContain("repository: barryqy/s-gw-rust-core");
    expect(assetJob).toContain("path: .private/sgw-core");
    expect(assetJob).toContain("npm run build");
    expect(assetJob).toContain("npm run check:rust");
    expect(assetJob).toContain("npx vitest run --testTimeout 15000");
    expect(assetJob).toContain("npm audit --audit-level=high");
    expect(assetJob).toContain("npm run package:dry-run");
    expect(assetJob).toContain("npm run validate:npm-package");
    expect(assetJob).toContain("npm run build:installers");
    expect(assetJob).toContain("Configure macOS distribution signing");
    expect(assetJob).toContain("APPLE_DEVELOPER_ID_P12_BASE64");
    expect(assetJob).toContain("APPLE_NOTARY_KEY_P8_BASE64");
    expect(assetJob).toContain("SGW_MACOS_SIGN_IDENTITY=$identity");
    expect(assetJob).toContain("SGW_REQUIRE_NOTARIZATION=1");
    expect(assetJob).toContain("spctl --assess");
    expect(assetJob).toContain("Create or verify a draft release");
    expect(assetJob).toContain("gh release create \"$RELEASE_TAG\" --draft --verify-tag --generate-notes");
    expect(assetJob).toContain('select(.state == "uploaded")');
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
      workflow.length
    );
    const releaseJob = workflow.slice(
      workflow.indexOf("  publish-release:"),
      workflow.indexOf("  publish-npm:")
    );

    expect(releaseJob).toContain("needs: release-assets");
    expect(releaseJob).toContain("gh release edit \"$RELEASE_TAG\" --draft=false");
    expect(npmJob).toContain("runs-on: macos-15");
    expect(npmJob).toContain("needs: publish-release");
    expect(npmJob).toContain('SGW_REQUIRE_RUST_CORE: "1"');
    expect(npmJob).toContain("repository: barryqy/s-gw-rust-core");
    expect(npmJob).toContain("ref: ${{ inputs.release_tag }}");
    expect(npmJob).not.toContain("github.event.release");
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

async function fileExists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}
