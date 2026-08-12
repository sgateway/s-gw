import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const allowedNames = ["@crabnebula/packager", "extract-zip"];
const packagerIntegrity =
  "sha512-kuJ2PZl6U04KdC5+pLrdAppDTTSKHxgSU1U5hC+8ZnoiG6wIVvK8a+T01fg6oxeUPYAPhxGFEbG+7DEaKPNvlA==";
const extractZipIntegrity =
  "sha512-GDhU9ntwuKyGXdZBUgTIe+vXnWj0fppUEtMDL0+idd5Sta8TGpHssn/eusA9mrPr9qNDym6SxAYZjNvCn/9RBg==";

export function validateAudit(report, packageInfo, lock) {
  const vulnerabilities = report?.vulnerabilities;
  if (!vulnerabilities || typeof vulnerabilities !== "object") {
    throw new Error("npm audit did not return a vulnerability report");
  }

  const blocking = Object.entries(vulnerabilities)
    .filter(([, item]) => item?.severity === "high" || item?.severity === "critical")
    .map(([name]) => name)
    .sort();

  const metadata = report?.metadata?.vulnerabilities;
  requireCondition(Number.isInteger(metadata?.high) && Number.isInteger(metadata?.critical));
  const reportedBlocking = metadata.high + metadata.critical;
  requireCondition(reportedBlocking === blocking.length);

  if (blocking.length === 0) return { allowedBuildOnlyAdvisory: false };
  if (JSON.stringify(blocking) !== JSON.stringify(allowedNames)) {
    throw new Error(`npm audit found blocking vulnerabilities: ${blocking.join(", ")}`);
  }

  const rootLock = lock?.packages?.[""];
  const packagerLock = lock?.packages?.["node_modules/@crabnebula/packager"];
  const extractLock = lock?.packages?.["node_modules/extract-zip"];
  const hasElectron = Object.keys(lock?.packages || {}).some(
    (name) => name === "node_modules/electron" || name.endsWith("/node_modules/electron")
  );

  requireCondition(packageInfo?.dependencies?.["@crabnebula/packager"] === undefined);
  requireCondition(packageInfo?.devDependencies?.["@crabnebula/packager"] === "0.11.2");
  requireCondition(rootLock?.devDependencies?.["@crabnebula/packager"] === "0.11.2");
  requireCondition(!hasElectron);
  requireCondition(packagerLock?.version === "0.11.2" && packagerLock?.dev === true);
  requireCondition(packagerLock?.integrity === packagerIntegrity);
  requireCondition(packagerLock?.dependencies?.["extract-zip"] === "^2.0.1");
  requireCondition(extractLock?.version === "2.0.1" && extractLock?.dev === true);
  requireCondition(extractLock?.integrity === extractZipIntegrity);

  const packagerFinding = vulnerabilities["@crabnebula/packager"];
  const extractFinding = vulnerabilities["extract-zip"];
  requireCondition(
    packagerFinding?.isDirect === true &&
      packagerFinding?.fixAvailable === false &&
      JSON.stringify(packagerFinding?.via) === JSON.stringify(["extract-zip"])
  );
  requireCondition(
    JSON.stringify(packagerFinding?.nodes) ===
      JSON.stringify(["node_modules/@crabnebula/packager"])
  );
  requireCondition(
    extractFinding?.isDirect === false &&
      extractFinding?.fixAvailable === false &&
      JSON.stringify(extractFinding?.effects) === JSON.stringify(["@crabnebula/packager"])
  );
  requireCondition(JSON.stringify(extractFinding?.nodes) === JSON.stringify(["node_modules/extract-zip"]));
  requireCondition(Array.isArray(extractFinding?.via) && extractFinding.via.length === 1);

  const advisory = extractFinding.via[0];
  requireCondition(advisory?.source === 1139346);
  requireCondition(advisory?.url === "https://github.com/advisories/GHSA-jmr9-qjv8-65gv");
  requireCondition(advisory?.severity === "high" && advisory?.range === "<=2.0.1");
  requireCondition(metadata.high === 2);
  requireCondition(metadata.critical === 0);

  // This extractor is only reached by the packager's Electron plugin; s-gw does not ship Electron.
  return { allowedBuildOnlyAdvisory: true };
}

function requireCondition(condition) {
  if (!condition) throw new Error("The build-only audit exception no longer matches its pinned contract");
}

function main() {
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const result = spawnSync(npm, ["audit", "--json"], {
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024
  });
  if (result.error) throw result.error;
  if (result.status !== 0 && result.status !== 1) {
    throw new Error(`npm audit failed with exit code ${result.status}`);
  }

  let report;
  try {
    report = JSON.parse(result.stdout);
  } catch {
    throw new Error("npm audit returned invalid JSON");
  }

  const packageInfo = JSON.parse(readFileSync("package.json", "utf8"));
  const lock = JSON.parse(readFileSync("package-lock.json", "utf8"));
  const outcome = validateAudit(report, packageInfo, lock);
  if (outcome.allowedBuildOnlyAdvisory) {
    console.log("Dependency audit passed with the pinned, unreachable Electron extractor advisory.");
  } else {
    console.log("Dependency audit passed with no high or critical vulnerabilities.");
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) main();
