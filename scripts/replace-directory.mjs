import { existsSync } from "node:fs";
import { rename, rm } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { setTimeout as waitFor } from "node:timers/promises";

const windowsRetryCodes = new Set(["EACCES", "EBUSY", "EPERM"]);
const windowsRenameAttempts = 20;
const windowsRetryDelayMs = 250;

export async function replaceDirectory(stagedPath, destination, options = {}) {
  const platform = options.platform ?? process.platform;
  const renamePath = options.renamePath ?? rename;
  const wait = options.wait ?? waitFor;
  const backup = options.backupPath ?? resolve(
    dirname(destination),
    `.runtime-backup-${process.pid}-${Date.now()}`
  );
  let movedExisting = false;
  let published = false;

  try {
    if (existsSync(destination)) {
      await moveWithRetry(destination, backup, platform, renamePath, wait);
      movedExisting = true;
    }
    await moveWithRetry(stagedPath, destination, platform, renamePath, wait);
    published = true;
  } catch (error) {
    if (movedExisting && existsSync(backup)) {
      if (!existsSync(destination)) {
        try {
          await moveWithRetry(backup, destination, platform, renamePath, wait);
        } catch (rollbackError) {
          throw new AggregateError(
            [error, rollbackError],
            `Could not publish the desktop runtime or restore the previous runtime. Backup: ${backup}`
          );
        }
      } else {
        throw new AggregateError(
          [error],
          `Could not publish the desktop runtime because the destination reappeared. Previous runtime: ${backup}`
        );
      }
    }
    throw error;
  } finally {
    if (published && movedExisting) {
      await rm(backup, { recursive: true, force: true, maxRetries: 8, retryDelay: 250 });
    }
  }
}

async function moveWithRetry(source, destination, platform, renamePath, wait) {
  const attempts = platform === "win32" ? windowsRenameAttempts : 1;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      await renamePath(source, destination);
      return;
    } catch (error) {
      if (attempt === attempts || !canRetryWindowsRename(platform, error)) {
        throw error;
      }
      await wait(windowsRetryDelayMs);
    }
  }
}

function canRetryWindowsRename(platform, error) {
  return platform === "win32" && error instanceof Error &&
    "code" in error && windowsRetryCodes.has(error.code);
}
