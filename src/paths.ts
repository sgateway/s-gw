import os from "node:os";
import path from "node:path";
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
  const home = path.resolve(expandHome(process.env.SGW_HOME || "~/.s-gw"));
  if (process.env.SGW_TEST_MODE === "1") {
    const liveHome = path.resolve(process.env.SGW_TEST_LIVE_HOME || path.join(os.homedir(), ".s-gw"));
    if (home === liveHome) {
      throw new Error(`Refusing to use the live s-gw home while tests are running: ${home}`);
    }
  }
  return home;
}

export function getSgwRecoveryHome(home = getSgwHome()): string {
  const recoveryHome = path.resolve(expandHome(process.env.SGW_RECOVERY_HOME || `${home}-recovery`));
  if (process.env.SGW_TEST_MODE === "1") {
    const liveHome = path.resolve(process.env.SGW_TEST_LIVE_HOME || path.join(os.homedir(), ".s-gw"));
    const liveRecoveryHome = path.resolve(process.env.SGW_TEST_LIVE_RECOVERY_HOME || `${liveHome}-recovery`);
    if (recoveryHome === liveRecoveryHome) {
      throw new Error(`Refusing to use the live s-gw recovery home while tests are running: ${recoveryHome}`);
    }
  }
  return recoveryHome;
}

export function getStorePath(home = getSgwHome()): string {
  return path.join(home, "store.json");
}

export async function ensureSgwHome(home = getSgwHome()): Promise<void> {
  await mkdir(home, { recursive: true, mode: 0o700 });
}
