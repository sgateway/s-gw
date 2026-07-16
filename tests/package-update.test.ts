import { createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  PackageUpdateError,
  inspectGlobalSgwInstall,
  installPackageUpdate,
  planPackageUpdate,
  selectReleasePackageAssets,
  validateReleaseDirectory,
  verifyReleasePackageChecksum,
  type NpmCommandResult
} from "../src/package-update.js";
import { CURRENT_VERSION } from "../src/version.js";

const execFileAsync = promisify(execFile);
const tmpDirs: string[] = [];

afterEach(async () => {
  for (const dir of tmpDirs.splice(0)) {
    await rm(dir, { recursive: true, force: true });
  }
});

describe("scoped package migration", () => {
  it("replaces a previous unscoped package without mutating the real npm prefix or s-gw home", async () => {
    const tmp = await tempDir("sgw-package-migration-");
    const npmPrefix = path.join(tmp, "npm-prefix");
    const sgwHome = path.join(tmp, "sgw-home");
    const tarballs = path.join(tmp, "tarballs");
    await mkdir(tarballs, { recursive: true });
    await mkdir(sgwHome, { recursive: true });
    await writeFile(path.join(sgwHome, "store.json"), "keep-this-ledger\n", { mode: 0o600 });

    const legacyTarball = await packageFixture(tmp, tarballs, "legacy", "s-gw", "0.1.0");
    const scopedTarball = await packageFixture(tmp, tarballs, "scoped", "@s-gw/s-gw", CURRENT_VERSION);
    await npm(["install", "--global", "--prefix", npmPrefix, "--ignore-scripts", "--", legacyTarball]);

    const before = await inspectGlobalSgwInstall({ npmPrefix });
    expect(before.legacy?.version).toBe("0.1.0");
    expect(before.scoped).toBeNull();

    const plan = await planPackageUpdate({ target: scopedTarball, npmPrefix, sgwHome });
    expect(plan.migrationRequired).toBe(true);
    expect(plan.steps.map((step) => step.id)).toEqual([
      "stop-services",
      "remove-legacy",
      "install-scoped"
    ]);
    expect(plan.rollback).toMatchObject({
      packageName: "s-gw",
      version: "0.1.0",
      strategy: "temporary-backup"
    });

    const dryRun = await installPackageUpdate({ target: scopedTarball, npmPrefix, sgwHome, dryRun: true });
    expect(dryRun.changed).toBe(false);
    expect((await inspectGlobalSgwInstall({ npmPrefix })).legacy?.version).toBe("0.1.0");

    let stopped = 0;
    let restarted = 0;
    const result = await installPackageUpdate({
      target: scopedTarball,
      npmPrefix,
      sgwHome,
      stopServices: async () => { stopped += 1; },
      restartServices: async () => { restarted += 1; }
    });

    expect(stopped).toBe(1);
    expect(restarted).toBe(1);
    expect(result.installed.legacy).toBeNull();
    expect(result.installed.scoped?.version).toBe(CURRENT_VERSION);
    expect(result.dataHomePreserved).toBe(true);
    expect(await readFile(path.join(sgwHome, "store.json"), "utf8")).toBe("keep-this-ledger\n");

    const command = process.platform === "win32"
      ? path.join(npmPrefix, "s-gw.cmd")
      : path.join(npmPrefix, "bin", "s-gw");
    const env = {
      ...process.env,
      SGW_HOME: sgwHome,
      SGW_RECOVERY_HOME: `${sgwHome}-recovery`
    };
    const output = process.platform === "win32"
      ? await execFileAsync(process.env.ComSpec || "cmd.exe", ["/d", "/s", "/c", `"${command}"`], { env })
      : await execFileAsync(command, [], { env });
    expect(output.stdout.trim()).toBe(`@s-gw/s-gw ${CURRENT_VERSION}`);
  }, 30_000);

  it("preserves the installed macOS helper before replacing a scoped package", async () => {
    if (process.platform !== "darwin") {
      return;
    }

    const tmp = await tempDir("sgw-helper-upgrade-");
    const npmPrefix = path.join(tmp, "npm-prefix");
    const sgwHome = path.join(tmp, "sgw-home");
    const tarballs = path.join(tmp, "tarballs");
    await mkdir(tarballs, { recursive: true });
    const oldTarball = await packageFixture(tmp, tarballs, "old-scoped", "@s-gw/s-gw", "0.1.8");
    const nextHelperIdentity = "new helper identity\n";
    const nextTarball = await packageFixture(
      tmp,
      tarballs,
      "next-scoped",
      "@s-gw/s-gw",
      CURRENT_VERSION,
      nextHelperIdentity
    );
    await npm(["install", "--global", "--prefix", npmPrefix, "--ignore-scripts", "--", oldTarball]);

    const before = await inspectGlobalSgwInstall({ npmPrefix });
    const oldHelper = path.join(
      before.scoped?.packageRoot || "",
      "dist",
      "native",
      `${process.platform}-${process.arch}`,
      "s-gw-keychain-helper"
    );
    await mkdir(path.dirname(oldHelper), { recursive: true });
    await writeFile(oldHelper, "trusted helper identity\n");
    await chmod(oldHelper, 0o755);

    const result = await installPackageUpdate({
      target: nextTarball,
      npmPrefix,
      sgwHome,
      stopServices: async () => undefined,
      restartServices: async () => undefined
    });

    const persistent = path.join(
      sgwHome,
      "native",
      `${process.platform}-${process.arch}`,
      "s-gw-keychain-helper"
    );
    expect(await readFile(persistent, "utf8")).toBe("trusted helper identity\n");
    expect((await stat(persistent)).mode & 0o777).toBe(0o700);
    const installedHelper = path.join(
      result.installed.scoped?.packageRoot || "",
      "dist",
      "native",
      `${process.platform}-${process.arch}`,
      "s-gw-keychain-helper"
    );
    expect(result.keychainCompatibility?.packagePath).toBe(installedHelper);
    expect(await readFile(installedHelper, "utf8")).toBe("trusted helper identity\n");
    const nextHash = createHash("sha256").update(nextHelperIdentity).digest("hex");
    const archivedHelper = path.join(
      sgwHome,
      "native",
      "legacy",
      nextHash,
      "s-gw-keychain-helper"
    );
    expect(await readFile(archivedHelper, "utf8")).toBe(nextHelperIdentity);
    expect((await stat(archivedHelper)).mode & 0o777).toBe(0o700);
  }, 30_000);

  it("exposes the migration plan and top-level install result through the CLI", async () => {
    const tmp = await tempDir("sgw-package-cli-");
    const npmPrefix = path.join(tmp, "npm-prefix");
    const sgwHome = path.join(tmp, "sgw-home");
    const tarballs = path.join(tmp, "tarballs");
    await mkdir(tarballs, { recursive: true });
    await mkdir(sgwHome, { recursive: true });
    const legacyTarball = await packageFixture(tmp, tarballs, "legacy", "s-gw", "0.1.0");
    const scopedTarball = await packageFixture(tmp, tarballs, "scoped", "@s-gw/s-gw", CURRENT_VERSION);
    await npm(["install", "--global", "--prefix", npmPrefix, "--ignore-scripts", "--", legacyTarball]);

    const tsx = path.join(process.cwd(), "node_modules", ".bin", process.platform === "win32" ? "tsx.cmd" : "tsx");
    const env = {
      ...process.env,
      HOME: tmp,
      USERPROFILE: tmp,
      SGW_HOME: sgwHome,
      SGW_RECOVERY_HOME: `${sgwHome}-recovery`,
      SGW_DISABLE_UPDATE_CHECK: "1",
      SGW_SKIP_APP_STOP: "1"
    };
    const runCli = async (args: string[]) => execFileAsync(tsx, ["src/cli.ts", ...args], {
      cwd: process.cwd(),
      env,
      shell: process.platform === "win32"
    });

    const planned = JSON.parse((await runCli([
      "update", "plan", "--package", scopedTarball, "--npm-prefix", npmPrefix
    ])).stdout);
    expect(planned.migrationRequired).toBe(true);
    expect(planned.target).toMatchObject({ name: "@s-gw/s-gw", version: CURRENT_VERSION });

    const installed = JSON.parse((await runCli([
      "update", "install", "--package", scopedTarball, "--npm-prefix", npmPrefix
    ])).stdout);
    expect(installed).toMatchObject({ changed: true, dryRun: false, dataHomePreserved: true });
    expect(installed.installed.binDir).toBe(process.platform === "win32" ? npmPrefix : path.join(npmPrefix, "bin"));
    expect(installed.installed.legacy).toBeNull();
    expect(installed.installed.scoped.version).toBe(CURRENT_VERSION);
  }, 40_000);

  it("builds a release bridge that upgrades the legacy package without a bin collision", async () => {
    const tmp = await tempDir("sgw-legacy-bridge-");
    const npmPrefix = path.join(tmp, "npm-prefix");
    const tarballs = path.join(tmp, "tarballs");
    await mkdir(tarballs, { recursive: true });
    const legacyTarball = await packageFixture(tmp, tarballs, "legacy", "s-gw", "0.1.0");
    const scopedTarball = await packageFixture(tmp, tarballs, "scoped", "@s-gw/s-gw", CURRENT_VERSION);
    const bridge = path.join(tarballs, `0-s-gw-legacy-${CURRENT_VERSION}.tgz`);

    await execFileAsync(process.execPath, [
      path.join(process.cwd(), "scripts", "build-legacy-bridge.mjs"),
      scopedTarball,
      bridge,
      CURRENT_VERSION
    ]);
    const metadata = JSON.parse((await npm([
      "pack", "--dry-run", "--ignore-scripts", "--json", "--", bridge
    ])).stdout)[0];
    expect(metadata).toMatchObject({ name: "s-gw", version: CURRENT_VERSION });

    await npm(["install", "--global", "--prefix", npmPrefix, "--ignore-scripts", "--", legacyTarball]);
    await npm(["install", "--global", "--prefix", npmPrefix, "--ignore-scripts", "--", bridge]);
    const installed = await inspectGlobalSgwInstall({ npmPrefix });
    expect(installed.legacy?.version).toBe(CURRENT_VERSION);
    expect(installed.scoped).toBeNull();
  }, 40_000);

  it("reports a concrete legacy rollback when scoped installation fails", async () => {
    const tmp = await tempDir("sgw-package-rollback-");
    const prefix = path.join(tmp, "prefix");
    const replacedResolvedArtifact = path.join(tmp, "not-the-installed-legacy.tgz");
    await writeFile(replacedResolvedArtifact, "untrusted old resolved file");
    let legacyInstalled = true;
    const calls: string[][] = [];
    const runNpm = async (args: string[]): Promise<NpmCommandResult> => {
      calls.push(args);
      if (args[0] === "root") {
        return ok(path.join(prefix, "lib", "node_modules"));
      }
      if (args[0] === "pack" && args.includes("--dry-run")) {
        return ok(JSON.stringify([{ name: "@s-gw/s-gw", version: CURRENT_VERSION }]));
      }
      if (args[0] === "pack") {
        const backupDir = args[args.indexOf("--pack-destination") + 1];
        await writeFile(path.join(backupDir, "s-gw-0.1.0.tgz"), "rollback copy");
        return ok(JSON.stringify([{ name: "s-gw", version: "0.1.0", filename: "s-gw-0.1.0.tgz" }]));
      }
      if (args[0] === "list") {
        return ok(JSON.stringify({
          dependencies: legacyInstalled ? {
            "s-gw": { version: "0.1.0", resolved: `file:${replacedResolvedArtifact}` }
          } : {}
        }));
      }
      if (args[0] === "uninstall") {
        legacyInstalled = false;
        return ok("");
      }
      return { status: 1, stdout: "", stderr: "simulated install failure" };
    };

    let thrown: unknown;
    try {
      await installPackageUpdate({
        npmPrefix: prefix,
        runNpm,
        servicesAlreadyStopped: true,
        sgwHome: path.join(tmp, "home")
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(PackageUpdateError);
    expect(thrown).toMatchObject({ phase: "install-scoped" });
    expect((thrown as PackageUpdateError).message).toContain("Your s-gw data");
    expect((thrown as PackageUpdateError).message).toContain("simulated install failure");
    expect((thrown as PackageUpdateError).recoveryCommands.join("\n")).not.toContain("s-gw@0.1.0");
    expect((thrown as PackageUpdateError).recoveryCommands[0]).toContain("@s-gw/s-gw");
    const rollbackTarget = (thrown as PackageUpdateError).recoveryCommands[1]
      .split(" -- ").at(-1)?.replace(/^'|'$/g, "");
    expect(rollbackTarget).toContain("sgw-legacy-rollback-");
    expect(rollbackTarget).not.toBe(replacedResolvedArtifact);
    expect(await readFile(rollbackTarget || "", "utf8")).toBe("rollback copy");
    await rm(path.dirname(rollbackTarget || ""), { recursive: true, force: true });
    const uninstall = calls.find((args) => args[0] === "uninstall");
    expect(uninstall?.at(-1)).toBe("s-gw");
    expect(calls.some((args) => args[0] === "uninstall" && args.includes("@s-gw/s-gw"))).toBe(true);
  });

  it("restores the legacy package before restarting services when post-remove inspection fails", async () => {
    const tmp = await tempDir("sgw-package-post-remove-");
    const prefix = path.join(tmp, "prefix");
    let listCalls = 0;
    const calls: string[][] = [];
    const runNpm = async (args: string[]): Promise<NpmCommandResult> => {
      calls.push(args);
      if (args[0] === "root") return ok(path.join(prefix, "lib", "node_modules"));
      if (args[0] === "list") {
        listCalls += 1;
        if (listCalls === 1) {
          return ok(JSON.stringify({ dependencies: { "s-gw": { version: "0.1.0" } } }));
        }
        return { status: 1, stdout: "", stderr: "simulated post-remove inspection failure" };
      }
      if (args[0] === "pack" && args.includes("--dry-run")) {
        return ok(JSON.stringify([{ name: "@s-gw/s-gw", version: CURRENT_VERSION }]));
      }
      if (args[0] === "pack") {
        const backupDir = args[args.indexOf("--pack-destination") + 1];
        await writeFile(path.join(backupDir, "s-gw-0.1.0.tgz"), "rollback copy");
        return ok(JSON.stringify([{ name: "s-gw", version: "0.1.0", filename: "s-gw-0.1.0.tgz" }]));
      }
      if (args[0] === "uninstall") return ok("");
      if (args[0] === "install") {
        const packageRoot = path.join(prefix, "lib", "node_modules", "s-gw");
        await mkdir(path.join(packageRoot, "dist"), { recursive: true });
        await writeFile(path.join(packageRoot, "package.json"), JSON.stringify({ name: "s-gw", version: "0.1.0" }));
        await writeFile(path.join(packageRoot, "dist", "cli.js"), "restored CLI");
        return ok("");
      }
      return ok("");
    };
    let restarted = 0;

    let thrown: unknown;
    try {
      await installPackageUpdate({
        npmPrefix: prefix,
        runNpm,
        stopServices: async () => undefined,
        restartServices: async () => { restarted += 1; }
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(PackageUpdateError);
    expect(thrown).toMatchObject({ phase: "inspect" });
    expect((thrown as PackageUpdateError).message).toContain("simulated post-remove inspection failure");
    expect((thrown as PackageUpdateError).message).toContain("previous s-gw@0.1.0 package was restored");
    expect((thrown as PackageUpdateError).recoveryCommands).toEqual([]);
    const restore = calls.find((args) => args[0] === "install");
    const rollbackTarget = restore?.at(-1) || "";
    expect(rollbackTarget).toContain("sgw-legacy-rollback-");
    await expect(readFile(rollbackTarget, "utf8")).rejects.toThrow();
    expect(restarted).toBe(1);
  });

  it("never suggests setup when missing data still needs to be restored", async () => {
    const tmp = await tempDir("sgw-package-missing-data-");
    const prefix = path.join(tmp, "prefix");
    const sgwHome = path.join(tmp, "home");
    await mkdir(sgwHome, { recursive: true });
    await writeFile(path.join(sgwHome, "store.json"), "existing data");
    let listCalls = 0;
    const runNpm = async (args: string[]): Promise<NpmCommandResult> => {
      if (args[0] === "root") return ok(path.join(prefix, "lib", "node_modules"));
      if (args[0] === "list") {
        listCalls += 1;
        if (listCalls === 1) return ok(JSON.stringify({ dependencies: { "s-gw": { version: "0.1.0" } } }));
        if (listCalls === 2) return ok(JSON.stringify({ dependencies: {} }));
        return ok(JSON.stringify({ dependencies: { "@s-gw/s-gw": { version: CURRENT_VERSION } } }));
      }
      if (args[0] === "pack" && args.includes("--dry-run")) {
        return ok(JSON.stringify([{ name: "@s-gw/s-gw", version: CURRENT_VERSION }]));
      }
      if (args[0] === "pack") {
        const backupDir = args[args.indexOf("--pack-destination") + 1];
        await writeFile(path.join(backupDir, "s-gw-0.1.0.tgz"), "rollback copy");
        return ok(JSON.stringify([{ name: "s-gw", version: "0.1.0", filename: "s-gw-0.1.0.tgz" }]));
      }
      if (args[0] === "uninstall") return ok("");
      if (args[0] === "install" && args.at(-1) === `@s-gw/s-gw@${CURRENT_VERSION}`) {
        await rm(sgwHome, { recursive: true, force: true });
        return ok("");
      }
      if (args[0] === "install") {
        return { status: 1, stdout: "", stderr: "simulated rollback failure" };
      }
      return ok("");
    };
    let restarted = 0;

    let thrown: unknown;
    try {
      await installPackageUpdate({
        npmPrefix: prefix,
        sgwHome,
        runNpm,
        stopServices: async () => undefined,
        restartServices: async () => { restarted += 1; }
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({ phase: "verify-data" });
    expect((thrown as Error).message).toContain("Do not run setup until the data is restored");
    expect((thrown as Error).message).toContain("Services remain stopped");
    expect((thrown as Error).message).toContain("Automatic rollback failed");
    expect((thrown as PackageUpdateError).recoveryCommands).toHaveLength(2);
    expect((thrown as PackageUpdateError).recoveryCommands.join("\n")).not.toContain("s-gw setup");
    expect((thrown as PackageUpdateError).recoveryCommands.join("\n")).not.toContain("s-gw start");
    expect(restarted).toBe(0);
    const rollbackTarget = (thrown as PackageUpdateError).recoveryCommands[1]
      .split(" -- ").at(-1)?.replace(/^'|'$/g, "");
    await rm(path.dirname(rollbackTarget || ""), { recursive: true, force: true });
  });

  it("restarts services after stop, rollback preparation, and install failures", async () => {
    const scenarios = ["stop", "backup", "install"] as const;

    for (const scenario of scenarios) {
      const tmp = await tempDir(`sgw-package-restart-${scenario}-`);
      const prefix = path.join(tmp, "prefix");
      let restarted = 0;
      const runNpm = async (args: string[]): Promise<NpmCommandResult> => {
        if (args[0] === "root") return ok(path.join(prefix, "lib", "node_modules"));
        if (args[0] === "list") {
          const dependencies = scenario === "backup" ? { "s-gw": { version: "0.1.0" } } : {};
          return ok(JSON.stringify({ dependencies }));
        }
        if (args[0] === "pack" && args.includes("--dry-run")) {
          return ok(JSON.stringify([{ name: "@s-gw/s-gw", version: CURRENT_VERSION }]));
        }
        if (args[0] === "pack") {
          return { status: 1, stdout: "", stderr: "simulated backup failure" };
        }
        if (args[0] === "install") {
          return { status: 1, stdout: "", stderr: "simulated install failure" };
        }
        return ok("");
      };

      await expect(installPackageUpdate({
        npmPrefix: prefix,
        runNpm,
        stopServices: async () => {
          if (scenario === "stop") throw new Error("simulated partial stop failure");
        },
        restartServices: async () => { restarted += 1; }
      })).rejects.toBeInstanceOf(PackageUpdateError);
      expect(restarted, scenario).toBe(1);
    }
  });

  it("reports a successful install that cannot restart without retrying the restart", async () => {
    const tmp = await tempDir("sgw-package-success-restart-failure-");
    const prefix = path.join(tmp, "prefix");
    const sgwHome = path.join(tmp, "home");
    await mkdir(sgwHome, { recursive: true });

    let listCalls = 0;
    const runNpm = async (args: string[]): Promise<NpmCommandResult> => {
      if (args[0] === "root") return ok(path.join(prefix, "lib", "node_modules"));
      if (args[0] === "list") {
        listCalls += 1;
        const version = listCalls === 1 ? "0.1.6" : CURRENT_VERSION;
        return ok(JSON.stringify({ dependencies: { "@s-gw/s-gw": { version } } }));
      }
      if (args[0] === "pack") {
        return ok(JSON.stringify([{ name: "@s-gw/s-gw", version: CURRENT_VERSION }]));
      }
      if (args[0] === "install") return ok("");
      return ok("");
    };
    let restarted = 0;

    let thrown: unknown;
    try {
      await installPackageUpdate({
        npmPrefix: prefix,
        sgwHome,
        runNpm,
        stopServices: async () => undefined,
        restartServices: async () => {
          restarted += 1;
          throw new Error("simulated restart failure");
        }
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({ phase: "restart-services" });
    expect((thrown as Error).message).toContain("installed, but s-gw could not restart");
    expect((thrown as Error).message).toContain("simulated restart failure");
    expect((thrown as PackageUpdateError).recoveryCommands).toEqual([
      "s-gw setup",
      "s-gw doctor",
      "s-gw app open"
    ]);
    expect(restarted).toBe(1);
  });

  it("preserves the update failure when restarting services also fails", async () => {
    const prefix = "/tmp/sgw-restart-failure";
    const runNpm = async (args: string[]): Promise<NpmCommandResult> => {
      if (args[0] === "root") return ok(`${prefix}/lib/node_modules`);
      if (args[0] === "list") return ok(JSON.stringify({ dependencies: {} }));
      if (args[0] === "pack") return ok(JSON.stringify([{ name: "@s-gw/s-gw", version: CURRENT_VERSION }]));
      if (args[0] === "install") return { status: 1, stdout: "", stderr: "original install failure" };
      return ok("");
    };

    let thrown: unknown;
    try {
      await installPackageUpdate({
        npmPrefix: prefix,
        runNpm,
        stopServices: async () => undefined,
        restartServices: async () => { throw new Error("restart also failed"); }
      });
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toMatchObject({ phase: "install-scoped" });
    expect((thrown as Error).message).toContain("original install failure");
    expect((thrown as Error).message).toContain("restart also failed");
    expect((thrown as PackageUpdateError).recoveryCommands).toContain("s-gw start --no-open-app");
  });

  it("wires CLI update failures back to the previously loaded local services", async () => {
    const cli = await readFile(path.join(process.cwd(), "src", "cli.ts"), "utf8");
    expect(cli).toContain("restartServices: services.restart");
    expect(cli).toContain("serviceBefore.installed && serviceBefore.loaded");
    expect(cli).toContain("menuBarBefore.installed && menuBarBefore.loaded");
    expect(cli).toContain('restartLaunchAgent("console", serviceWasLoaded');
    expect(cli).toContain('restartLaunchAgent("menubar", menuBarWasLoaded');
    expect(cli).toContain("verifyRestoredLaunchAgents(serviceWasLoaded, menuBarWasLoaded");
    expect(cli).toContain("await restartWindowsSurfaces(windowsStopped)");
  });

  it("refuses an unrelated target before removing the legacy package", async () => {
    const calls: string[][] = [];
    const runNpm = async (args: string[]): Promise<NpmCommandResult> => {
      calls.push(args);
      if (args[0] === "root") return ok("/tmp/sgw-prefix/lib/node_modules");
      if (args[0] === "list") {
        return ok(JSON.stringify({ dependencies: { "s-gw": { version: "0.1.0" } } }));
      }
      if (args[0] === "pack") return ok(JSON.stringify([{ name: "not-s-gw", version: "9.9.9" }]));
      return ok("");
    };

    await expect(planPackageUpdate({
      target: "./wrong.tgz",
      npmPrefix: "/tmp/sgw-prefix",
      runNpm
    })).rejects.toThrow("Refusing to install");
    expect(calls.some((args) => args[0] === "uninstall")).toBe(false);
  });

  it("stops when npm cannot provide a trustworthy global package list", async () => {
    const calls: string[][] = [];
    const runNpm = async (args: string[]): Promise<NpmCommandResult> => {
      calls.push(args);
      if (args[0] === "root") return ok("/tmp/sgw-prefix/lib/node_modules");
      if (args[0] === "list") {
        return {
          status: 1,
          stdout: JSON.stringify({ dependencies: { "s-gw": { version: "0.1.0" } } }),
          stderr: "npm list failed"
        };
      }
      return ok("");
    };

    await expect(planPackageUpdate({ npmPrefix: "/tmp/sgw-prefix", runNpm }))
      .rejects.toMatchObject({ phase: "inspect" });
    expect(calls.some((args) => args[0] === "pack")).toBe(false);
    expect(calls.some((args) => args[0] === "install" || args[0] === "uninstall")).toBe(false);
  });

  it("pins registry installs and rejects a different final version", async () => {
    let listCalls = 0;
    const calls: string[][] = [];
    const runNpm = async (args: string[]): Promise<NpmCommandResult> => {
      calls.push(args);
      if (args[0] === "root") return ok("/tmp/sgw-prefix/lib/node_modules");
      if (args[0] === "list") {
        listCalls += 1;
        return ok(JSON.stringify({
          dependencies: listCalls === 1 ? {} : { "@s-gw/s-gw": { version: "9.9.9" } }
        }));
      }
      if (args[0] === "pack") {
        return ok(JSON.stringify([{ name: "@s-gw/s-gw", version: CURRENT_VERSION }]));
      }
      if (args[0] === "install") return ok("");
      return ok("");
    };

    await expect(installPackageUpdate({
      npmPrefix: "/tmp/sgw-prefix",
      runNpm,
      servicesAlreadyStopped: true
    })).rejects.toMatchObject({ phase: "verify-install" });
    expect(calls.find((args) => args[0] === "install")?.at(-1)).toBe(`@s-gw/s-gw@${CURRENT_VERSION}`);
  });

  it("runs the macOS release installer through the legacy binary collision in an isolated prefix", async () => {
    if (process.platform !== "darwin") return;

    const tmp = await tempDir("sgw-macos-installer-");
    const npmPrefix = path.join(tmp, "npm-prefix");
    const tarballs = path.join(tmp, "installer");
    const home = path.join(tmp, "home");
    await mkdir(tarballs, { recursive: true });
    await mkdir(home, { recursive: true });
    const legacyTarball = await packageFixture(tmp, tarballs, "legacy", "s-gw", "0.1.0");
    const scopedTarball = await packageFixture(tmp, tarballs, "scoped", "@s-gw/s-gw", CURRENT_VERSION);
    await npm(["install", "--global", "--prefix", npmPrefix, "--ignore-scripts", "--", legacyTarball]);

    const template = await readFile(path.join(
      process.cwd(),
      "native",
      "installers",
      "macos",
      "Install s-gw.command"
    ), "utf8");
    const installer = path.join(tarballs, "Install s-gw.command");
    await writeFile(
      installer,
      template
        .replaceAll("__PACKAGE_FILE__", path.basename(scopedTarball))
        .replaceAll("__VERSION__", CURRENT_VERSION)
    );
    await chmod(installer, 0o755);

    const binDir = path.join(npmPrefix, "bin");
    const output = await execFileAsync("zsh", [installer], {
      env: {
        ...process.env,
        HOME: home,
        NPM_CONFIG_PREFIX: npmPrefix,
        SGW_HOME: path.join(home, ".s-gw"),
        SGW_RECOVERY_HOME: path.join(home, ".s-gw-recovery"),
        SGW_SKIP_APP_STOP: "1",
        PATH: `${binDir}:${path.dirname(process.execPath)}:${process.env.PATH || ""}`
      },
      timeout: 30_000
    });

    expect(output.stdout).toContain("Migrating legacy s-gw 0.1.0");
    expect(output.stdout).toContain("Existing ~/.s-gw data was preserved");
    const installed = await inspectGlobalSgwInstall({ npmPrefix });
    expect(installed.legacy).toBeNull();
    expect(installed.scoped?.version).toBe(CURRENT_VERSION);
  }, 40_000);
});

describe("release package assets", () => {
  it("accepts and verifies a matching SHA256SUMS entry", async () => {
    const tmp = await tempDir("sgw-release-assets-");
    const fileName = `s-gw-${CURRENT_VERSION}.tgz`;
    const packagePath = path.join(tmp, fileName);
    await writeFile(packagePath, "release package bytes");
    const digest = createHash("sha256").update("release package bytes").digest("hex");
    await writeFile(path.join(tmp, "SHA256SUMS.txt"), `${digest}  ${fileName}\n`);

    const selected = await validateReleaseDirectory(tmp, CURRENT_VERSION);
    expect(selected.packageAsset.name).toBe(fileName);
    expect(selected.checksumAsset.name).toBe("SHA256SUMS.txt");
    expect(selected.checksumKind).toBe("sha256sums");
  });

  it("prefers a per-file checksum and accepts a raw digest", async () => {
    const tmp = await tempDir("sgw-release-per-file-");
    const fileName = "s-gw-0.1.2.tgz";
    const packagePath = path.join(tmp, fileName);
    await writeFile(packagePath, "next release");
    const digest = createHash("sha256").update("next release").digest("hex");
    await writeFile(path.join(tmp, `${fileName}.sha256`), `${digest}\n`);
    await writeFile(path.join(tmp, "SHA256SUMS.txt"), `${"0".repeat(64)}  ${fileName}\n`);

    const assets = selectReleasePackageAssets([
      { name: fileName },
      { name: "SHA256SUMS.txt" },
      { name: `${fileName}.sha256` }
    ], "v0.1.2");
    expect(assets.checksumKind).toBe("per-file");
    await expect(verifyReleasePackageChecksum(packagePath, digest, "per-file")).resolves.toBe(digest);
  });

  it("rejects missing, mismatched, and unrelated checksums", async () => {
    const fileName = `s-gw-${CURRENT_VERSION}.tgz`;
    expect(() => selectReleasePackageAssets([{ name: fileName }], CURRENT_VERSION))
      .toThrow(`requires ${fileName}.sha256 or SHA256SUMS.txt`);

    const tmp = await tempDir("sgw-release-invalid-");
    const packagePath = path.join(tmp, fileName);
    await writeFile(packagePath, "package");
    await expect(verifyReleasePackageChecksum(
      packagePath,
      `${"a".repeat(64)}  another-package.tgz\n`,
      "sha256sums"
    )).rejects.toThrow("does not contain");
    await expect(verifyReleasePackageChecksum(
      packagePath,
      `${"a".repeat(64)}  ${fileName}\n`,
      "sha256sums"
    )).rejects.toThrow("mismatch");
  });
});

async function packageFixture(
  root: string,
  outputDir: string,
  folder: string,
  name: string,
  version: string,
  nativeHelper?: string
): Promise<string> {
  const packageDir = path.join(root, folder);
  await mkdir(packageDir, { recursive: true });
  await writeFile(path.join(packageDir, "package.json"), `${JSON.stringify({
    name,
    version,
    bin: { "s-gw": "cli.js" }
  }, null, 2)}\n`);
  await writeFile(path.join(packageDir, "cli.js"), `#!/usr/bin/env node\nconsole.log(${JSON.stringify(`${name} ${version}`)});\n`);
  await chmod(path.join(packageDir, "cli.js"), 0o755);
  if (nativeHelper !== undefined) {
    const helperPath = path.join(
      packageDir,
      "dist",
      "native",
      `${process.platform}-${process.arch}`,
      "s-gw-keychain-helper"
    );
    await mkdir(path.dirname(helperPath), { recursive: true });
    await writeFile(helperPath, nativeHelper);
    await chmod(helperPath, 0o755);
  }
  const packed = await npm(["pack", "--ignore-scripts", "--json", "--pack-destination", outputDir], packageDir);
  const manifest = JSON.parse(packed.stdout) as Array<{ filename: string }>;
  return path.join(outputDir, manifest[0].filename);
}

async function npm(args: string[], cwd?: string): Promise<{ stdout: string; stderr: string }> {
  const npmExec = process.env.npm_execpath;
  if (npmExec && /\.js$/i.test(npmExec)) {
    return execFileAsync(process.execPath, [npmExec, ...args], { cwd });
  }
  return execFileAsync(process.platform === "win32" ? "npm.cmd" : "npm", args, { cwd, shell: process.platform === "win32" });
}

async function tempDir(prefix: string): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), prefix));
  tmpDirs.push(dir);
  return dir;
}

function ok(stdout: string): NpmCommandResult {
  return { status: 0, stdout: stdout.endsWith("\n") ? stdout : `${stdout}\n`, stderr: "" };
}
