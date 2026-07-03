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
  return path.resolve(expandHome(process.env.SGW_HOME || "~/.s-gw"));
}

export function getStorePath(home = getSgwHome()): string {
  return path.join(home, "store.json");
}

export async function ensureSgwHome(home = getSgwHome()): Promise<void> {
  await mkdir(home, { recursive: true, mode: 0o700 });
}
