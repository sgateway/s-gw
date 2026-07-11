import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

export function buildLegacyBridge(packagePath, outputPath, expectedVersion) {
  const workDir = mkdtempSync(path.join(os.tmpdir(), "s-gw-legacy-bridge-"));
  try {
    mkdirSync(path.join(workDir, "unpacked"), { recursive: true });
    run("tar", ["-xzf", path.resolve(packagePath), "-C", path.join(workDir, "unpacked")]);

    const packageDir = path.join(workDir, "unpacked", "package");
    const manifestPath = path.join(packageDir, "package.json");
    const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
    if (manifest.name !== "@s-gw/s-gw" || manifest.version !== expectedVersion) {
      throw new Error(`Expected @s-gw/s-gw@${expectedVersion}, got ${manifest.name}@${manifest.version}.`);
    }

    manifest.name = "s-gw";
    writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
    run("npm", ["pack", "--ignore-scripts", "--pack-destination", workDir, packageDir]);

    const packed = path.join(workDir, `s-gw-${expectedVersion}.tgz`);
    cpSync(packed, path.resolve(outputPath));
  } finally {
    rmSync(workDir, { recursive: true, force: true });
  }
}

function run(command, args) {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status === 0) return;
  const details = `${result.stdout || ""}\n${result.stderr || ""}`.trim();
  throw new Error(`${command} failed${details ? `:\n${details}` : "."}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [, , packagePath, outputPath, expectedVersion] = process.argv;
  if (!packagePath || !outputPath || !expectedVersion) {
    throw new Error("Usage: node scripts/build-legacy-bridge.mjs PACKAGE_TGZ OUTPUT_TGZ VERSION");
  }
  buildLegacyBridge(packagePath, outputPath, expectedVersion);
}
