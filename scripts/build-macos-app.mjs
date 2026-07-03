import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const appSourceRoot = resolve(root, "native/macos-app");
const appRoot = resolve(root, "dist/s-gw.app");
const legacyAppRoot = resolve(root, "dist/Secret-GateWay.app");
const macosDir = resolve(appRoot, "Contents/MacOS");
const resourcesDir = resolve(appRoot, "Contents/Resources");
const executableName = "s-gw";
const builtExecutable = resolve(appSourceRoot, ".build/release", executableName);
const stagedExecutable = resolve(macosDir, executableName);
const iconPath = resolve(resourcesDir, "AppIcon.icns");
const builtIcon = resolve(root, "dist/assets/icons/AppIcon.icns");
const menuBarTemplate = resolve(root, "assets/icons/s-gw-menu-bar-template.png");
const menuBarTemplatePath = resolve(resourcesDir, "MenuBarTemplate.png");
const packageInfo = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
const appVersion = packageInfo.version || "0.1.0";

if (process.platform !== "darwin") {
  console.log("Skipping native macOS app build on non-macOS platform.");
  process.exit(0);
}

if (!existsSync(resolve(appSourceRoot, "Package.swift"))) {
  console.error(`Missing macOS app package: ${appSourceRoot}`);
  process.exit(1);
}

const swiftVersion = spawnSync("swift", ["--version"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});

if (swiftVersion.status !== 0) {
  console.error("swift is required to build the native macOS app.");
  console.error(swiftVersion.stderr || swiftVersion.stdout);
  process.exit(swiftVersion.status || 1);
}

const result = spawnSync("swift", ["build", "-c", "release", "--product", executableName], {
  cwd: appSourceRoot,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});

if (result.status !== 0) {
  console.error(result.stderr || result.stdout);
  process.exit(result.status || 1);
}

rmSync(appRoot, { recursive: true, force: true });
rmSync(legacyAppRoot, { recursive: true, force: true });
mkdirSync(macosDir, { recursive: true });
mkdirSync(resourcesDir, { recursive: true });
cpSync(builtExecutable, stagedExecutable);
chmodSync(stagedExecutable, 0o755);

const iconGen = spawnSync(process.execPath, [resolve(root, "scripts/build-icon-assets.mjs")], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});
if (iconGen.status !== 0) {
  console.error(iconGen.stderr || iconGen.stdout);
  process.exit(iconGen.status || 1);
}

cpSync(builtIcon, iconPath);
if (!existsSync(menuBarTemplate)) {
  console.error(`Missing menu bar template icon: ${menuBarTemplate}`);
  process.exit(1);
}
cpSync(menuBarTemplate, menuBarTemplatePath);

writeFileSync(resolve(appRoot, "Contents/Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>${executableName}</string>
  <key>CFBundleIdentifier</key>
  <string>com.s-gw.sgw.app</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleName</key>
  <string>s-gw</string>
  <key>CFBundleDisplayName</key>
  <string>s-gw</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${appVersion}</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>14.0</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>NSSupportsAutomaticGraphicsSwitching</key>
  <true/>
</dict>
</plist>
`);

const codesign = spawnSync("codesign", ["--force", "--sign", "-", appRoot], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});

if (codesign.status !== 0) {
  console.warn("Ad-hoc codesign failed; continuing with unsigned local app.");
  console.warn(codesign.stderr || codesign.stdout);
}

console.log(`Built native macOS app: ${appRoot}`);
