import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { buildLegacyBridge } from "./build-legacy-bridge.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packageInfo = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
const version = packageInfo.version;
const packedFile = `${packageInfo.name.replace(/^@/, "").replaceAll("/", "-")}-${version}.tgz`;
const packageFile = `s-gw-${version}.tgz`;
const legacyBridgeFile = `0-s-gw-legacy-${version}.tgz`;
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

  const artifacts = [legacyBridgeFile, packageFile, basename(macArtifact), basename(windowsArtifact)];
  const checksumLines = artifacts.map((name) => `${sha256(resolve(outputDir, name))}  ${name}`);
  writeFileSync(resolve(outputDir, "SHA256SUMS.txt"), `${checksumLines.join("\n")}\n`);

  for (const name of artifacts) {
    writeFileSync(resolve(outputDir, `${name}.sha256`), `${sha256(resolve(outputDir, name))}  ${name}\n`);
  }

  writeFileSync(resolve(outputDir, "RELEASE.json"), `${JSON.stringify({
    name: packageInfo.name,
    version,
    generatedAt: new Date().toISOString(),
    artifacts
  }, null, 2)}\n`);

  console.log(`Built release installers in ${outputDir}`);
} finally {
  rmSync(workDir, { recursive: true, force: true });
}

function buildMacInstaller(packed) {
  const folderName = `s-gw ${version} Installer`;
  const stageRoot = resolve(workDir, "macos", folderName);
  mkdirSync(stageRoot, { recursive: true });
  copyFileSync(packed, resolve(stageRoot, packageFile));
  renderTemplate(
    resolve(root, "native/installers/macos/Install s-gw.command"),
    resolve(stageRoot, "Install s-gw.command")
  );
  chmodSync(resolve(stageRoot, "Install s-gw.command"), 0o755);
  renderTemplate(resolve(root, "native/installers/macos/README.txt"), resolve(stageRoot, "README.txt"));

  const target = resolve(outputDir, `s-gw-${version}-macos.dmg`);
  run("hdiutil", ["create", "-volname", `s-gw ${version}`, "-srcfolder", stageRoot, "-ov", "-format", "UDZO", target], root);
  return target;
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

function requireFile(path) {
  if (!existsSync(path)) {
    throw new Error(`Missing installer input: ${path}`);
  }
}

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}
