import os from "node:os";
import path from "node:path";
import { lstatSync, realpathSync } from "node:fs";
import { mkdir } from "node:fs/promises";

export function expandHome(inputPath: string): string {
  if (inputPath === "~") {
    return os.homedir();
  }

  if (inputPath.startsWith("~/")) {
    return path.join(os.homedir(), inputPath.slice(2));
  }

  return inputPath;
}

export function getSgwHome(): string {
  const configuredHome = process.env.SGW_HOME?.trim();
  if (isTestMode() && !configuredHome) {
    throw new Error("Refusing to use s-gw while tests are running without an explicit SGW_HOME.");
  }

  const home = path.resolve(expandHome(configuredHome || "~/.s-gw"));
  assertIsolatedTestHome(home);
  return home;
}

export function getSgwRecoveryHome(home = getSgwHome()): string {
  assertIsolatedTestHome(home);
  const configuredRecoveryHome = process.env.SGW_RECOVERY_HOME?.trim();
  if (isTestMode() && !configuredRecoveryHome) {
    throw new Error("Refusing to use s-gw while tests are running without an explicit SGW_RECOVERY_HOME.");
  }

  const recoveryHome = path.resolve(expandHome(configuredRecoveryHome || `${home}-recovery`));
  assertIsolatedTestRecoveryHome(recoveryHome);
  if (pathsOverlap(home, recoveryHome)) {
    throw new Error(`s-gw recovery home must be outside the primary ledger home: ${recoveryHome}`);
  }
  return recoveryHome;
}

function pathsOverlap(left: string, right: string): boolean {
  const normalizedLeft = canonicalPath(left);
  const normalizedRight = canonicalPath(right);
  if (normalizedLeft === normalizedRight) {
    return true;
  }
  return normalizedLeft.startsWith(`${normalizedRight}${path.sep}`)
    || normalizedRight.startsWith(`${normalizedLeft}${path.sep}`);
}

export function getStorePath(home = getSgwHome()): string {
  assertIsolatedTestHome(home);
  return path.join(home, "store.json");
}

export async function ensureSgwHome(home = getSgwHome()): Promise<void> {
  assertIsolatedTestHome(home);
  await mkdir(home, { recursive: true, mode: 0o700 });
}

function isTestMode(): boolean {
  return process.env.SGW_TEST_MODE === "1";
}

function assertIsolatedTestHome(home: string): void {
  if (!isTestMode()) return;
  requireTestEnvironmentPath("SGW_HOME");
  assertIsolatedTestPath(home, "s-gw home");
}

function assertIsolatedTestRecoveryHome(recoveryHome: string): void {
  if (!isTestMode()) return;
  requireTestEnvironmentPath("SGW_RECOVERY_HOME");
  assertIsolatedTestPath(recoveryHome, "s-gw recovery home");
}

function requireTestEnvironmentPath(name: "SGW_HOME" | "SGW_RECOVERY_HOME"): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`Refusing to use s-gw while tests are running without an explicit ${name}.`);
  }
  return value;
}

function assertIsolatedTestPath(inputPath: string, label: string): void {
  const testRoot = canonicalTestRoot();
  const candidate = canonicalPath(inputPath);
  if (!isInside(candidate, testRoot)) {
    throw new Error(`Refusing to use a ${label} outside SGW_TEST_HOME_ROOT while tests are running: ${inputPath}`);
  }

  for (const protectedPath of protectedTestPaths()) {
    if (pathsOverlap(candidate, protectedPath)) {
      throw new Error(`Refusing to use the live ${label} while tests are running: ${inputPath}`);
    }
  }
}

function canonicalTestRoot(): string {
  const configuredRoot = process.env.SGW_TEST_HOME_ROOT?.trim();
  if (!configuredRoot) {
    throw new Error("Refusing to use s-gw while tests are running without SGW_TEST_HOME_ROOT.");
  }

  const root = canonicalPath(configuredRoot);
  const systemTemp = canonicalPath(os.tmpdir());
  if (!isInside(root, systemTemp)) {
    throw new Error(`Refusing to use an SGW_TEST_HOME_ROOT outside the system temporary directory: ${configuredRoot}`);
  }
  return root;
}

function protectedTestPaths(): string[] {
  const configuredLiveHome = process.env.SGW_TEST_LIVE_HOME?.trim();
  const defaultLiveHome = configuredLiveHome || path.join(os.homedir(), ".s-gw");
  const configuredLiveRecoveryHome = process.env.SGW_TEST_LIVE_RECOVERY_HOME?.trim();
  const paths = [
    defaultLiveHome,
    `${defaultLiveHome}-recovery`,
    configuredLiveRecoveryHome
  ].filter((value): value is string => Boolean(value));
  return [...new Set(paths.map(canonicalPath))];
}

function canonicalPath(inputPath: string): string {
  const absolute = path.resolve(expandHome(inputPath));
  const missing: string[] = [];
  let current = absolute;

  while (true) {
    try {
      const resolved = realpathSync.native(current);
      return missing.length === 0 ? resolved : path.join(resolved, ...missing.reverse());
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "ENOENT" && code !== "ENOTDIR") {
        throw new Error(`Cannot verify s-gw test path isolation for ${absolute}.`);
      }

      if (isDanglingSymlink(current)) {
        throw new Error(`Refusing to use a symlinked s-gw test path: ${absolute}`);
      }

      const parent = path.dirname(current);
      if (parent === current) {
        throw new Error(`Cannot verify s-gw test path isolation for ${absolute}.`);
      }
      missing.push(path.basename(current));
      current = parent;
    }
  }
}

function isDanglingSymlink(inputPath: string): boolean {
  try {
    return lstatSync(inputPath).isSymbolicLink();
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code === "ENOENT" || code === "ENOTDIR") {
      return false;
    }
    throw new Error(`Cannot verify s-gw test path isolation for ${inputPath}.`);
  }
}

function isInside(candidate: string, root: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}
