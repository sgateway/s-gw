import { chmodSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "native/macos-keychain/SgwKeychain.swift");
const output = resolve(root, "dist/native/s-gw-keychain-helper");
const legacyOutput = resolve(root, "dist/native/sgw-keychain-helper");

if (process.platform !== "darwin") {
  console.log("Skipping native Keychain helper build on non-macOS platform.");
  process.exit(0);
}

if (!existsSync(source)) {
  console.error(`Missing native Keychain helper source: ${source}`);
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
rmSync(legacyOutput, { force: true });

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
