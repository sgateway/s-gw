import { chmodSync, cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const helperRoot = resolve(root, "native/menu-bar-helper");
const appRoot = resolve(root, "dist/s-gw Menu Bar.app");
const legacyAppRoot = resolve(root, "dist/Secret-GateWay Menu Bar.app");
const macosDir = resolve(appRoot, "Contents/MacOS");
const resourcesDir = resolve(appRoot, "Contents/Resources");
const executableName = "s-gw-menu-bar-helper";
const builtExecutable = resolve(helperRoot, ".build/release", executableName);
const stagedExecutable = resolve(macosDir, executableName);
const iconPath = resolve(resourcesDir, "AppIcon.icns");
const builtIcon = resolve(root, "dist/assets/icons/AppIcon.icns");
const menuBarTemplate = resolve(root, "assets/icons/s-gw-menu-bar-template.png");
const menuBarTemplatePath = resolve(resourcesDir, "MenuBarTemplate.png");
const awsEc2Icon = resolve(root, "assets/icons/aws-ec2.png");
const awsEc2IconPath = resolve(resourcesDir, "AwsEc2.png");
const lucideIcons = ["bot", "terminal", "server", "monitor"];
const packageInfo = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
const appVersion = packageInfo.version || "0.1.0";

if (process.platform !== "darwin") {
  console.log("Skipping native menu bar helper build on non-macOS platform.");
  process.exit(0);
}

if (!existsSync(resolve(helperRoot, "Package.swift"))) {
  console.error(`Missing menu bar helper package: ${helperRoot}`);
  process.exit(1);
}

const swiftVersion = spawnSync("swift", ["--version"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});

if (swiftVersion.status !== 0) {
  console.error("swift is required to build the native macOS menu bar helper.");
  console.error(swiftVersion.stderr || swiftVersion.stdout);
  process.exit(swiftVersion.status || 1);
}

const result = spawnSync("swift", ["build", "-c", "release", "--product", executableName], {
  cwd: helperRoot,
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
if (!existsSync(awsEc2Icon)) {
  console.error(`Missing AWS EC2 icon: ${awsEc2Icon}`);
  process.exit(1);
}
cpSync(awsEc2Icon, awsEc2IconPath);
for (const name of lucideIcons) {
  const source = resolve(root, `assets/icons/lucide/${name}.svg`);
  if (!existsSync(source)) {
    console.error(`Missing Lucide icon: ${source}`);
    process.exit(1);
  }
  cpSync(source, resolve(resourcesDir, `Lucide-${name}.svg`));
}

writeFileSync(resolve(appRoot, "Contents/Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>${executableName}</string>
  <key>CFBundleIdentifier</key>
  <string>com.s-gw.sgw.menu-bar</string>
  <key>CFBundleIconFile</key>
  <string>AppIcon</string>
  <key>CFBundleName</key>
  <string>s-gw Menu Bar</string>
  <key>CFBundleDisplayName</key>
  <string>s-gw</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
  <key>CFBundleShortVersionString</key>
  <string>${appVersion}</string>
  <key>CFBundleVersion</key>
  <string>1</string>
  <key>LSMinimumSystemVersion</key>
  <string>13.0</string>
  <key>LSUIElement</key>
  <true/>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
</dict>
</plist>
`);

const codesign = spawnSync("codesign", ["--force", "--sign", "-", appRoot], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});

if (codesign.status !== 0) {
  console.warn("Ad-hoc codesign failed; continuing with unsigned local helper.");
  console.warn(codesign.stderr || codesign.stdout);
}

console.log(`Built native macOS menu bar helper: ${appRoot}`);
