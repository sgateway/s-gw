import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { installMacAppBundle } from "../src/install.js";

describe("macOS app installation", () => {
  it.skipIf(process.platform !== "darwin")("installs the app bundle once and replaces a changed copy", async () => {
    const applicationsDir = await mkdtemp(path.join(os.tmpdir(), "sgw-app-install-"));

    try {
      const first = installMacAppBundle({ applicationsDir, registerCliPath: false });
      expect(first.changed).toBe(true);
      expect(first.appPath).toBe(path.join(applicationsDir, "s-gw.app"));

      const second = installMacAppBundle({ applicationsDir, registerCliPath: false });
      expect(second.changed).toBe(false);

      const installedInfo = path.join(first.appPath, "Contents", "Info.plist");
      const originalInfo = await readFile(installedInfo);
      await writeFile(installedInfo, "outdated app bundle");

      const replaced = installMacAppBundle({ applicationsDir, registerCliPath: false });
      expect(replaced.changed).toBe(true);
      expect(await readFile(installedInfo)).toEqual(originalInfo);
    } finally {
      await rm(applicationsDir, { recursive: true, force: true });
    }
  });
});
