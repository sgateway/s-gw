import { chmodSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "native/macos-keychain/SgwKeychain.swift");
const inspectorSource = resolve(root, "native/macos-keychain/SgwKeychainInspector.swift");
const target = `${process.platform}-${process.arch}`;
const output = resolve(root, "dist/native", target, "s-gw-keychain-helper");
const inspectorOutput = resolve(root, "dist/native", target, "s-gw-keychain-inspector");
const legacyOutputs = [
  resolve(root, "dist/native/s-gw-keychain-helper"),
  resolve(root, "dist/native/sgw-keychain-helper")
];

if (process.platform !== "darwin") {
  console.log("Skipping native Keychain helper build on non-macOS platform.");
  process.exit(0);
}

if (!existsSync(source) || !existsSync(inspectorSource)) {
  console.error(`Missing native Keychain source: ${!existsSync(source) ? source : inspectorSource}`);
  process.exit(1);
}

const swiftVersion = spawnSync("swiftc", ["--version"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});

if (swiftVersion.status !== 0) {
  console.error("swiftc is required to build the native macOS Keychain helper.");
  console.error(swiftVersion.stderr || swiftVersion.stdout);
  process.exit(swiftVersion.status || 1);
}

mkdirSync(dirname(output), { recursive: true });
for (const legacyOutput of legacyOutputs) {
  rmSync(legacyOutput, { force: true });
}

const result = spawnSync("swiftc", [source, "-O", "-o", output], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});

if (result.status !== 0) {
  console.error(result.stderr || result.stdout);
  process.exit(result.status || 1);
}

chmodSync(output, 0o755);
console.log(`Built native macOS Keychain helper: ${output}`);

const inspectorResult = spawnSync("swiftc", [inspectorSource, "-O", "-o", inspectorOutput], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});

if (inspectorResult.status !== 0) {
  console.error(inspectorResult.stderr || inspectorResult.stdout);
  process.exit(inspectorResult.status || 1);
}

chmodSync(inspectorOutput, 0o755);
console.log(`Built native macOS Keychain inspector: ${inspectorOutput}`);
