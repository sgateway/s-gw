import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { validateAudit } from "../scripts/audit-dependencies.mjs";

const packageInfo = JSON.parse(await readFile("package.json", "utf8"));
const lock = JSON.parse(await readFile("package-lock.json", "utf8"));

function allowedReport() {
  return {
    metadata: { vulnerabilities: { high: 2, critical: 0 } },
    vulnerabilities: {
      "@crabnebula/packager": {
        severity: "high",
        isDirect: true,
        via: ["extract-zip"],
        nodes: ["node_modules/@crabnebula/packager"],
        fixAvailable: false
      },
      "extract-zip": {
        severity: "high",
        isDirect: false,
        via: [
          {
            source: 1139346,
            url: "https://github.com/advisories/GHSA-jmr9-qjv8-65gv",
            severity: "high",
            range: "<=2.0.1"
          }
        ],
        effects: ["@crabnebula/packager"],
        nodes: ["node_modules/extract-zip"],
        fixAvailable: false
      }
    }
  };
}

describe("release dependency audit", () => {
  it("allows only the pinned build-only Electron extractor advisory", () => {
    expect(validateAudit(allowedReport(), packageInfo, lock)).toEqual({
      allowedBuildOnlyAdvisory: true
    });
  });

  it("fails when another high-severity advisory appears", () => {
    const report = allowedReport();
    report.vulnerabilities["another-package"] = { severity: "high" };
    report.metadata.vulnerabilities.high = 3;
    expect(() => validateAudit(report, packageInfo, lock)).toThrow(
      "npm audit found blocking vulnerabilities"
    );
  });

  it("fails when Electron enters the dependency graph", () => {
    const changedLock = structuredClone(lock);
    changedLock.packages["node_modules/electron"] = { version: "1.0.0", dev: true };
    expect(() => validateAudit(allowedReport(), packageInfo, changedLock)).toThrow(
      "build-only audit exception"
    );
  });

  it("fails when npm publishes a fix", () => {
    const report = allowedReport();
    report.vulnerabilities["extract-zip"].fixAvailable = true;
    expect(() => validateAudit(report, packageInfo, lock)).toThrow("build-only audit exception");
  });

  it("fails when audit metadata and findings disagree", () => {
    const report = allowedReport();
    report.metadata.vulnerabilities.high = 3;
    expect(() => validateAudit(report, packageInfo, lock)).toThrow("build-only audit exception");
  });
});
