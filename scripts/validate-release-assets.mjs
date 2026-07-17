import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateReleaseDirectory, verifyReleasePackageChecksum } from "../dist/package-update.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageInfo = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const directory = path.resolve(process.argv[2] || path.join(root, "dist", "installers"));
const selected = await validateReleaseDirectory(directory, packageInfo.version);
const releaseMetadata = JSON.parse(await readFile(path.join(directory, "RELEASE.json"), "utf8"));
const distributions = new Set(["local", "notarized", "unsigned"]);
if (!distributions.has(releaseMetadata.macosDistribution) || typeof releaseMetadata.notarized !== "boolean" || typeof releaseMetadata.releaseTag !== "string") {
  throw new Error("RELEASE.json must declare the macOS distribution and notarization state.");
}
if (releaseMetadata.macosDistribution === "unsigned" && releaseMetadata.notarized) {
  throw new Error("An unsigned macOS distribution cannot claim notarization.");
}
const legacyBridgeName = `0-s-gw-legacy-${packageInfo.version}.tgz`;
const legacyBridgePath = path.join(directory, legacyBridgeName);
const bridgeMetadata = inspectPackage(legacyBridgePath);
if (bridgeMetadata.name !== "s-gw" || bridgeMetadata.version !== packageInfo.version) {
  throw new Error(`Invalid legacy bridge metadata: ${bridgeMetadata.name}@${bridgeMetadata.version}.`);
}

await verifyReleasePackageChecksum(
  legacyBridgePath,
  await readFile(path.join(directory, "SHA256SUMS.txt"), "utf8"),
  "sha256sums"
);
await verifyReleasePackageChecksum(
  legacyBridgePath,
  await readFile(path.join(directory, `${legacyBridgeName}.sha256`), "utf8"),
  "per-file"
);

const macDmgName = "s-gw.dmg";
const compatibilityDmgName = `s-gw-${packageInfo.version}-macos.dmg`;
const expectedReleaseTag = `v${packageInfo.version}`;
if (releaseMetadata.releaseTag !== expectedReleaseTag) {
  throw new Error(`RELEASE.json must use ${expectedReleaseTag} for this distribution.`);
}
if (!Array.isArray(releaseMetadata.artifacts) || !releaseMetadata.artifacts.includes(macDmgName) || !releaseMetadata.artifacts.includes(compatibilityDmgName)) {
  throw new Error(`RELEASE.json must list ${macDmgName} and ${compatibilityDmgName}.`);
}
const macDmg = path.join(directory, macDmgName);
await verifyReleasePackageChecksum(
  macDmg,
  await readFile(path.join(directory, "SHA256SUMS.txt"), "utf8"),
  "sha256sums"
);
await verifyReleasePackageChecksum(
  macDmg,
  await readFile(path.join(directory, `${macDmgName}.sha256`), "utf8"),
  "per-file"
);
const compatibilityDmg = path.join(directory, compatibilityDmgName);
await verifyReleasePackageChecksum(
  compatibilityDmg,
  await readFile(path.join(directory, "SHA256SUMS.txt"), "utf8"),
  "sha256sums"
);
await verifyReleasePackageChecksum(
  compatibilityDmg,
  await readFile(path.join(directory, `${compatibilityDmgName}.sha256`), "utf8"),
  "per-file"
);
if (process.platform === "darwin" && existsSync(macDmg)) {
  const verification = spawnSync(process.execPath, [path.join(root, "scripts/verify-macos-dmg.mjs"), macDmg], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (verification.status !== 0) {
    throw new Error(verification.stderr.trim() || verification.stdout.trim() || "macOS DMG verification failed.");
  }
  process.stdout.write(verification.stdout);
}

process.stdout.write(
  `Validated ${selected.packageAsset.name}, ${legacyBridgeName}, and their checksums.\n`
);

function inspectPackage(packagePath) {
  const result = spawnSync("npm", ["pack", "--dry-run", "--ignore-scripts", "--json", "--", packagePath], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `Could not inspect ${path.basename(packagePath)}.`);
  }
  const metadata = JSON.parse(result.stdout)[0];
  if (!metadata || typeof metadata.name !== "string" || typeof metadata.version !== "string") {
    throw new Error(`npm returned invalid metadata for ${path.basename(packagePath)}.`);
  }
  return metadata;
}
