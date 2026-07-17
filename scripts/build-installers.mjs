import {
  chmodSync,
  copyFileSync,
  cpSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { basename, dirname, extname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildLegacyBridge } from "./build-legacy-bridge.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageInfo = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
const macRuntime = JSON.parse(readFileSync(resolve(root, "native/macos-app/runtime.json"), "utf8"));
const nodeRuntimeEntitlements = resolve(root, "native/macos-app/NodeRuntime.entitlements");
const version = packageInfo.version;
const packedFile = `${packageInfo.name.replace(/^@/, "").replaceAll("/", "-")}-${version}.tgz`;
const packageFile = `s-gw-${version}.tgz`;
const legacyBridgeFile = `0-s-gw-legacy-${version}.tgz`;
const macInstallerFile = "s-gw.dmg";
const versionedMacInstallerFile = `s-gw-${version}-macos.dmg`;
const outputDir = resolve(root, "dist/installers");
const workDir = mkdtempSync(resolve(tmpdir(), "s-gw-installers-"));

if (!version) {
  throw new Error("package.json does not define a version.");
}

if (process.platform !== "darwin") {
  throw new Error("Installer packaging currently runs on macOS because the DMG build requires hdiutil.");
}

try {
  rmSync(outputDir, { recursive: true, force: true });
  mkdirSync(outputDir, { recursive: true });

  run("npm", ["pack", "--ignore-scripts", "--pack-destination", workDir], root);
  const packed = resolve(workDir, packedFile);
  requireFile(packed);

  const macArtifact = buildMacInstaller(packed);
  const windowsArtifact = buildWindowsInstaller(packed);
  copyFileSync(packed, resolve(outputDir, packageFile));
  buildLegacyBridge(packed, resolve(outputDir, legacyBridgeFile), version);

  const artifacts = [legacyBridgeFile, packageFile, ...macArtifact.paths.map((file) => basename(file)), basename(windowsArtifact)];
  const checksumLines = artifacts.map((name) => `${sha256(resolve(outputDir, name))}  ${name}`);
  writeFileSync(resolve(outputDir, "SHA256SUMS.txt"), `${checksumLines.join("\n")}\n`);

  for (const name of artifacts) {
    writeFileSync(resolve(outputDir, `${name}.sha256`), `${sha256(resolve(outputDir, name))}  ${name}\n`);
  }

  writeFileSync(resolve(outputDir, "RELEASE.json"), `${JSON.stringify({
    name: packageInfo.name,
    version,
    generatedAt: new Date().toISOString(),
    releaseTag: macArtifact.releaseTag,
    macosDistribution: macArtifact.distribution,
    notarized: macArtifact.notarized,
    artifacts
  }, null, 2)}\n`);

  console.log(`Built release installers in ${outputDir}`);
} finally {
  rmSync(workDir, { recursive: true, force: true });
}

function buildMacInstaller(packed) {
  const stageRoot = resolve(workDir, "macos", "dmg-root");
  const appRoot = resolve(stageRoot, "s-gw.app");
  const signing = signingConfiguration();
  mkdirSync(stageRoot, { recursive: true });
  buildSelfContainedMacApp(packed, appRoot);
  symlinkSync("/Applications", resolve(stageRoot, "Applications"));
  writeFileSync(resolve(stageRoot, "README.txt"), macInstallReadme(signing));

  signMacApp(appRoot, signing);
  const target = resolve(outputDir, macInstallerFile);
  run("hdiutil", ["create", "-volname", `s-gw ${version}`, "-srcfolder", stageRoot, "-ov", "-format", "UDZO", target], root);
  signMacDmg(target, signing);
  notarizeMacDmg(target, signing);
  const compatibilityTarget = resolve(outputDir, versionedMacInstallerFile);
  copyFileSync(target, compatibilityTarget);
  return {
    paths: [target, compatibilityTarget],
    releaseTag: releaseTagFor(signing),
    distribution: signing.distribution,
    notarized: signing.requireNotarization
  };
}

function macInstallReadme(signing) {
  const trustNotice = signing.distribution === "unsigned"
    ? [
      "This macOS release is not signed with an Apple Developer ID or notarized.",
      "macOS will require an explicit Gatekeeper override before it opens."
    ]
    : signing.distribution === "notarized"
      ? ["This installer is Developer ID signed and notarized by Apple."]
      : ["This is a local ad-hoc build. It is not intended for public distribution."];

  return `${[
    `s-gw ${version} for Apple silicon`,
    "",
    "Recommended installation (Node.js 20+):",
    "npm install -g @s-gw/s-gw",
    "s-gw setup",
    "",
    "Self-contained desktop alternative:",
    "1. Drag s-gw.app to Applications.",
    "2. Open s-gw from Applications and complete setup.",
    "",
    ...trustNotice,
    signing.distribution === "unsigned"
      ? "Use the npm installation above if you do not want to use a macOS security override."
      : ""
  ].join("\n")}\n`;
}

function releaseTagFor(signing) {
  const expected = `v${version}`;
  const configured = process.env.SGW_RELEASE_TAG?.trim();
  if (configured && configured !== expected) {
    throw new Error(`SGW_RELEASE_TAG must be ${expected} for this distribution.`);
  }
  return expected;
}

function buildSelfContainedMacApp(packed, appRoot) {
  const thinApp = resolve(root, "dist/s-gw.app");
  const menuBarApp = resolve(root, "dist/s-gw Menu Bar.app");
  requireFile(resolve(thinApp, "Contents/MacOS/s-gw"));
  requireFile(resolve(menuBarApp, "Contents/MacOS/s-gw-menu-bar-helper"));

  cpSync(thinApp, appRoot, { recursive: true });
  const resources = resolve(appRoot, "Contents/Resources");
  const loginItems = resolve(appRoot, "Contents/Library/LoginItems");
  const runtimeRoot = resolve(resources, "s-gw-runtime");
  const packageRoot = resolve(runtimeRoot, "package");
  mkdirSync(resources, { recursive: true });
  mkdirSync(loginItems, { recursive: true });
  mkdirSync(runtimeRoot, { recursive: true });

  cpSync(menuBarApp, resolve(loginItems, "s-gw Menu Bar.app"), { recursive: true });
  unpackRuntimePackage(packed, packageRoot);
  stageNodeRuntime(resolve(runtimeRoot, "node"));
  stageRuntimeLaunchers(runtimeRoot);

  writeFileSync(resolve(runtimeRoot, "runtime.json"), `${JSON.stringify({
    kind: "s-gw-self-contained-runtime",
    version,
    nodeVersion: macRuntime.node.version
  }, null, 2)}\n`);

  verifySelfContainedRuntime(appRoot, runtimeRoot, packageRoot);
}

function unpackRuntimePackage(packed, packageRoot) {
  mkdirSync(packageRoot, { recursive: true });
  run("tar", ["-xzf", packed, "--strip-components=1", "-C", packageRoot], root);
  copyFileSync(resolve(root, "package-lock.json"), resolve(packageRoot, "package-lock.json"));
  run("npm", ["ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"], packageRoot);
  rmSync(resolve(packageRoot, "package-lock.json"), { force: true });

  // The outer app is the only GUI bundle in this distribution. Keeping the thin
  // npm copies here would waste space and make it easy to launch the wrong runtime.
  rmSync(resolve(packageRoot, "dist/s-gw.app"), { recursive: true, force: true });
  rmSync(resolve(packageRoot, "dist/s-gw Menu Bar.app"), { recursive: true, force: true });
}

function stageNodeRuntime(target) {
  const archive = resolve(workDir, macRuntime.node.archive);
  const suppliedArchive = process.env.SGW_NODE_RUNTIME_ARCHIVE?.trim();
  if (suppliedArchive) {
    copyFileSync(resolve(suppliedArchive), archive);
  } else {
    run("curl", ["--fail", "--location", "--retry", "3", "--output", archive, macRuntime.node.url], root);
  }

  const digest = sha256(archive);
  if (digest !== macRuntime.node.sha256) {
    throw new Error(`Embedded Node archive checksum mismatch. Expected ${macRuntime.node.sha256}, got ${digest}.`);
  }

  const extractRoot = resolve(workDir, "node-runtime");
  mkdirSync(extractRoot, { recursive: true });
  run("tar", ["-xzf", archive, "-C", extractRoot], root);
  const source = resolve(extractRoot, `node-v${macRuntime.node.version}-darwin-arm64`);
  requireFile(resolve(source, "bin/node"));
  cpSync(source, target, { recursive: true });

  // The packaged app invokes Node directly. The package-manager launchers are
  // symlinks that code signing rejects inside a sealed app bundle.
  for (const command of ["corepack", "npm", "npx"]) {
    rmSync(resolve(target, "bin", command), { force: true });
  }
}

function stageRuntimeLaunchers(runtimeRoot) {
  const binDir = resolve(runtimeRoot, "bin");
  mkdirSync(binDir, { recursive: true });
  writeLauncher(resolve(binDir, "s-gw"), "cli.js");
  writeLauncher(resolve(binDir, "sgw"), "cli.js");
  writeLauncher(resolve(binDir, "s-gw-mcp"), "mcp-server.js");
  writeLauncher(resolve(binDir, "secret-gateway-mcp"), "mcp-server.js");
}

function writeLauncher(target, entrypoint) {
  writeFileSync(target, `#!/bin/sh
set -eu

script=$0
while [ -h "$script" ]; do
  script_dir=$(CDPATH= cd -P "$(dirname "$script")" && pwd)
  link=$(readlink "$script")
  case $link in
    /*) script=$link ;;
    *) script=$script_dir/$link ;;
  esac
done

script_dir=$(CDPATH= cd -P "$(dirname "$script")" && pwd)
runtime_dir=$(CDPATH= cd -P "$script_dir/.." && pwd)
exec "$runtime_dir/node/bin/node" "$runtime_dir/package/dist/${entrypoint}" "$@"
`);
  chmodSync(target, 0o755);
}

function verifySelfContainedRuntime(appRoot, runtimeRoot, packageRoot) {
  const nativeTarget = "darwin-arm64";
  const expected = [
    resolve(appRoot, "Contents/MacOS/s-gw"),
    resolve(appRoot, "Contents/Library/LoginItems/s-gw Menu Bar.app/Contents/MacOS/s-gw-menu-bar-helper"),
    resolve(runtimeRoot, "node/bin/node"),
    resolve(runtimeRoot, "bin/s-gw"),
    resolve(runtimeRoot, "bin/s-gw-mcp"),
    resolve(packageRoot, "package.json"),
    resolve(packageRoot, "dist/cli.js"),
    resolve(packageRoot, "dist/mcp-server.js"),
    resolve(packageRoot, "dist/native", nativeTarget, "s-gw-core"),
    resolve(packageRoot, "dist/native", nativeTarget, "s-gw-keychain-helper"),
    resolve(packageRoot, "dist/native", nativeTarget, "s-gw-keychain-inspector"),
    resolve(packageRoot, "node_modules"),
    resolve(packageRoot, "skills/s-gw/SKILL.md")
  ];
  for (const item of expected) requireFile(item);

  if (existsSync(resolve(packageRoot, "dist/s-gw.app")) || existsSync(resolve(packageRoot, "dist/s-gw Menu Bar.app"))) {
    throw new Error("The embedded runtime must not contain thin app bundles.");
  }

  const nodeDeps = runOutput("otool", ["-L", resolve(runtimeRoot, "node/bin/node")], root);
  if (nodeDeps.includes("/opt/homebrew/") || nodeDeps.includes("/usr/local/Cellar/")) {
    throw new Error("The embedded Node runtime links to a local package manager path.");
  }
}

function signMacApp(appRoot, signing) {
  const runtimeRoot = resolve(appRoot, "Contents/Resources/s-gw-runtime");
  const packageRoot = resolve(runtimeRoot, "package");
  const menuApp = resolve(appRoot, "Contents/Library/LoginItems/s-gw Menu Bar.app");
  const menuBinary = resolve(menuApp, "Contents/MacOS/s-gw-menu-bar-helper");
  const mainBinary = resolve(appRoot, "Contents/MacOS/s-gw");
  requireFile(nodeRuntimeEntitlements);

  for (const dylib of collectFiles(resolve(runtimeRoot, "node/lib"), (file) => extname(file) === ".dylib")) {
    signCode(dylib, signing);
  }
  const nodeBinary = resolve(runtimeRoot, "node/bin/node");
  signCode(nodeBinary, signing, { entitlements: nodeRuntimeEntitlements });

  for (const binary of collectFiles(resolve(packageRoot, "dist/native/darwin-arm64"), isExecutableFile)) {
    signCode(binary, signing);
  }

  signCode(menuBinary, signing);
  signCode(menuApp, signing);
  signCode(mainBinary, signing);
  signCode(appRoot, signing);
  run("codesign", ["--verify", "--deep", "--strict", "--verbose=2", appRoot], root);
  const nodeEntitlements = runOutput("codesign", ["-d", "--entitlements", ":-", nodeBinary], root);
  if (!nodeEntitlements.includes("com.apple.security.cs.allow-jit")) {
    throw new Error("The embedded Node runtime must retain its hardened-runtime JIT entitlement.");
  }
}

function signingConfiguration() {
  const identity = process.env.SGW_MACOS_SIGN_IDENTITY?.trim() || "-";
  const requireNotarization = process.env.SGW_REQUIRE_NOTARIZATION === "1";
  const notaryProfile = process.env.SGW_NOTARY_PROFILE?.trim();
  const distribution = process.env.SGW_MACOS_DISTRIBUTION?.trim() || "local";

  if (!["local", "notarized", "unsigned"].includes(distribution)) {
    throw new Error("SGW_MACOS_DISTRIBUTION must be local, notarized, or unsigned.");
  }
  if (distribution === "notarized" && !requireNotarization) {
    throw new Error("A notarized distribution requires SGW_REQUIRE_NOTARIZATION=1.");
  }
  if (distribution === "unsigned" && (identity !== "-" || requireNotarization)) {
    throw new Error("An unsigned distribution must use the ad-hoc signing identity and no notarization.");
  }

  if (requireNotarization && identity === "-") {
    throw new Error("SGW_REQUIRE_NOTARIZATION=1 requires SGW_MACOS_SIGN_IDENTITY.");
  }
  if (requireNotarization && !identity.includes("Developer ID Application")) {
    throw new Error("Notarized distribution requires a Developer ID Application signing identity.");
  }
  if (requireNotarization && !notaryProfile) {
    throw new Error("SGW_REQUIRE_NOTARIZATION=1 requires SGW_NOTARY_PROFILE.");
  }

  return { identity, requireNotarization, notaryProfile, distribution };
}

function signCode(target, signing, options = {}) {
  const args = ["--force", "--sign", signing.identity];
  args.push("--options", "runtime");
  if (signing.identity !== "-") {
    args.push("--timestamp");
  }
  if (options.entitlements) {
    args.push("--entitlements", options.entitlements);
  }
  args.push(target);
  run("codesign", args, root);
}

function signMacDmg(target, signing) {
  if (signing.identity === "-") return;
  run("codesign", ["--force", "--timestamp", "--sign", signing.identity, target], root);
}

function notarizeMacDmg(target, signing) {
  if (!signing.requireNotarization) return;
  run("xcrun", ["notarytool", "submit", target, "--keychain-profile", signing.notaryProfile, "--wait"], root);
  run("xcrun", ["stapler", "staple", target], root);
  run("xcrun", ["stapler", "validate", target], root);
}

function collectFiles(directory, matches) {
  if (!existsSync(directory)) return [];
  const files = [];
  for (const name of readdirSync(directory)) {
    const candidate = resolve(directory, name);
    const info = lstatSync(candidate);
    if (info.isSymbolicLink()) continue;
    if (info.isDirectory()) {
      files.push(...collectFiles(candidate, matches));
    } else if (info.isFile() && matches(candidate)) {
      files.push(candidate);
    }
  }
  return files;
}

function isExecutableFile(filePath) {
  return (statSync(filePath).mode & 0o111) !== 0;
}

function buildWindowsInstaller(packed) {
  const folderName = `s-gw-${version}-windows`;
  const stageRoot = resolve(workDir, "windows", folderName);
  mkdirSync(stageRoot, { recursive: true });
  copyFileSync(packed, resolve(stageRoot, packageFile));

  const templates = [
    ["Install-s-gw.ps1", "Install-s-gw.ps1"],
    ["Install-s-gw.cmd", "Install-s-gw.cmd"],
    ["README.txt", "README.txt"]
  ];
  for (const [source, target] of templates) {
    renderTemplate(resolve(root, "native/installers/windows", source), resolve(stageRoot, target));
  }

  const target = resolve(outputDir, `s-gw-${version}-windows.zip`);
  run("ditto", ["-c", "-k", "--norsrc", "--keepParent", stageRoot, target], root);
  return target;
}

function renderTemplate(source, target) {
  requireFile(source);
  const rendered = readFileSync(source, "utf8")
    .replaceAll("__PACKAGE_FILE__", packageFile)
    .replaceAll("__VERSION__", version);
  writeFileSync(target, rendered);
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status === 0) return;

  const output = `${result.stdout || ""}\n${result.stderr || ""}`.trim();
  throw new Error(`${command} failed${output ? `:\n${output}` : "."}`);
}

function runOutput(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status === 0) return `${result.stdout || ""}\n${result.stderr || ""}`;

  const output = `${result.stdout || ""}\n${result.stderr || ""}`.trim();
  throw new Error(`${command} failed${output ? `:\n${output}` : "."}`);
}

function requireFile(filePath) {
  if (!existsSync(filePath)) {
    throw new Error(`Missing installer input: ${filePath}`);
  }
}

function sha256(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}
