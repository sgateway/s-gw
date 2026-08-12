import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { packageApp } from "@crabnebula/packager";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const appRoot = resolve(root, "native/desktop-app");
const packageInfo = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
process.chdir(root);
const targetName = process.env.SGW_DESKTOP_TARGET?.trim() || `${process.platform}-${process.arch}`;
const hostTarget = `${process.platform}-${process.arch}`;

if (targetName !== hostTarget) {
  throw new Error(`Desktop packaging must run on ${targetName}; current host is ${hostTarget}.`);
}

const target = packagingTarget(targetName);
const cargoTargetDir = resolve(appRoot, "target");
const binaryDir = resolve(cargoTargetDir, target.rustTriple, "release");
const packageDir = resolve(cargoTargetDir, "release", "bundle", target.format);

run("cargo", [
  "build",
  "--release",
  "--locked",
  "--target",
  target.rustTriple,
  "--manifest-path",
  resolve(appRoot, "Cargo.toml")
]);

const binaryPath = resolve(binaryDir, process.platform === "win32" ? "s-gw-desktop.exe" : "s-gw-desktop");
if (!existsSync(binaryPath)) {
  throw new Error(`Desktop build did not create ${binaryPath}.`);
}

rmSync(packageDir, { recursive: true, force: true });
mkdirSync(packageDir, { recursive: true });

await packageApp({
  productName: "s-gw",
  version: packageInfo.version,
  identifier: "com.s-gw.sgw.desktop",
  binaries: [{ path: "s-gw-desktop", main: true }],
  binariesDir: binaryDir,
  outDir: packageDir,
  targetTriple: target.rustTriple,
  formats: target.formats,
  publisher: "s-gw",
  authors: ["Barry Yuan"],
  category: "DeveloperTool",
  description: packageInfo.description,
  longDescription: "s-gw keeps credential approval and execution local in a native desktop application.",
  homepage: packageInfo.homepage,
  licenseFile: resolve(root, "LICENSE"),
  icons: target.icons,
  resources: target.resources,
  nsis: target.nsis,
  deb: target.deb
});

const generatedPackage = resolve(packageDir, target.generatedName(packageInfo.version));
const finalPackage = resolve(packageDir, target.outputName(packageInfo.version));
if (!existsSync(generatedPackage)) {
  throw new Error(`Desktop packager did not create ${generatedPackage}.`);
}
renameSync(generatedPackage, finalPackage);
console.log(`Packaged ${targetName} desktop installer at ${finalPackage}`);

function packagingTarget(name) {
  if (name === "win32-x64") {
    return {
      format: "nsis",
      formats: ["nsis"],
      rustTriple: "x86_64-pc-windows-msvc",
      icons: [resolve(appRoot, "icons/icon.ico")],
      resources: [{ src: resolve(appRoot, "runtime"), target: "runtime" }],
      nsis: { installMode: "currentUser" },
      generatedName: (version) => `s-gw-desktop_${version}_x64-setup.exe`,
      outputName: (version) => `s-gw_${version}_x64-setup.exe`
    };
  }
  if (name === "linux-x64") {
    const files = {
      [resolve(appRoot, "runtime")]: "/usr/lib/s-gw/runtime",
      [resolve(appRoot, "s-gw.desktop")]: "/usr/share/applications/s-gw.desktop"
    };
    return {
      format: "deb",
      formats: ["deb"],
      rustTriple: "x86_64-unknown-linux-gnu",
      icons: [
        resolve(appRoot, "icons/32x32.png"),
        resolve(appRoot, "icons/128x128.png"),
        resolve(appRoot, "icons/128x128@2x.png"),
        resolve(appRoot, "icons/icon.png")
      ],
      resources: [],
      deb: {
        depends: [
          "libayatana-appindicator3-1",
          "libgl1",
          "libgtk-3-0",
          "libsecret-tools",
          "libxdo3",
          "libxkbcommon-x11-0"
        ],
        section: "utils",
        desktopTemplate: resolve(appRoot, "s-gw-desktop.hidden.desktop"),
        files
      },
      generatedName: (version) => `s-gw-desktop_${version}_amd64.deb`,
      outputName: (version) => `s-gw_${version}_amd64.deb`
    };
  }
  throw new Error(`Desktop packaging target ${name} is not supported.`);
}

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, CARGO_TARGET_DIR: cargoTargetDir },
    stdio: "inherit"
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${command} failed with exit code ${result.status}.`);
  }
}
