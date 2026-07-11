import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { validateReleaseDirectory, verifyReleasePackageChecksum } from "../dist/package-update.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const packageInfo = JSON.parse(await readFile(path.join(root, "package.json"), "utf8"));
const directory = path.resolve(process.argv[2] || path.join(root, "dist", "installers"));
const selected = await validateReleaseDirectory(directory, packageInfo.version);
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
