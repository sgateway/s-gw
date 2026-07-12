import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const expectedPlatform = "darwin";
const expectedArch = "arm64";
const target = `${expectedPlatform}-${expectedArch}`;

if (process.platform !== expectedPlatform || process.arch !== expectedArch) {
  throw new Error(
    `The public npm package must be published from macOS arm64; current target is ${process.platform}-${process.arch}.`
  );
}

const packageInfo = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
if (packageInfo.name !== "@s-gw/s-gw" || !packageInfo.version) {
  throw new Error("Unexpected npm package identity.");
}

const packed = npmPackManifest();
if (packed.name !== packageInfo.name || packed.version !== packageInfo.version) {
  throw new Error("npm pack metadata does not match package.json.");
}

const files = new Map(packed.files.map((entry) => [entry.path, entry]));
const requiredExecutables = [
  `dist/native/${target}/s-gw-core`,
  `dist/native/${target}/s-gw-keychain-helper`,
  "dist/s-gw.app/Contents/MacOS/s-gw",
  "dist/s-gw Menu Bar.app/Contents/MacOS/s-gw-menu-bar-helper"
];

for (const filePath of requiredExecutables) {
  const entry = files.get(filePath);
  if (!entry) {
    throw new Error(`npm package is missing required native executable: ${filePath}`);
  }
  if ((entry.mode & 0o111) === 0) {
    throw new Error(`npm package native executable is not executable: ${filePath}`);
  }
}

const coreSmoke = spawnSync(resolve(root, requiredExecutables[0]), ["--version"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});
if (coreSmoke.status !== 0 || coreSmoke.stdout.trim() !== `sgw-core ${packageInfo.version}`) {
  throw new Error(coreSmoke.stderr.trim() || "Packaged Rust core version does not match package.json.");
}

const forbidden = [
  "dist/native/s-gw-core",
  "dist/native/s-gw-core.exe",
  "dist/native/s-gw-keychain-helper",
  "dist/native/sgw-keychain-helper"
];
for (const filePath of forbidden) {
  if (files.has(filePath)) {
    throw new Error(`npm package contains a legacy unscoped native executable: ${filePath}`);
  }
}

const targetExecutables = [...files.keys()].filter((filePath) => (
  /^dist\/native\/[^/]+\/s-gw-core(?:\.exe)?$/.test(filePath)
  || /^dist\/native\/[^/]+\/(?:s-gw-keychain-helper|sgw-keychain-helper)$/.test(filePath)
));
for (const filePath of targetExecutables) {
  if (!filePath.startsWith(`dist/native/${target}/`)) {
    throw new Error(`npm package contains a native executable for another target: ${filePath}`);
  }
}

console.log(`Validated ${packageInfo.name}@${packageInfo.version} for ${target}.`);

function npmPackManifest() {
  const args = ["pack", "--dry-run", "--json", "--ignore-scripts"];
  const npmCli = process.env.npm_execpath;
  const result = npmCli
    ? spawnSync(process.execPath, [npmCli, ...args], packOptions())
    : spawnSync("npm", args, packOptions());

  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || "npm pack validation failed.");
  }

  let parsed;
  try {
    parsed = JSON.parse(result.stdout);
  } catch {
    throw new Error("npm pack returned invalid JSON.");
  }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !Array.isArray(parsed[0]?.files)) {
    throw new Error("npm pack returned an unexpected manifest.");
  }
  return parsed[0];
}

function packOptions() {
  return {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  };
}
