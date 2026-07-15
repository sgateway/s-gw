import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeEach } from "vitest";

const suiteHome = mkdtempSync(path.join(os.tmpdir(), "sgw-vitest-"));
function useDisposableHomes(): void {
  process.env.SGW_HOME = suiteHome;
  delete process.env.SGW_RECOVERY_HOME;
}

useDisposableHomes();
beforeEach(useDisposableHomes);

afterAll(() => {
  rmSync(suiteHome, { recursive: true, force: true });
  rmSync(`${suiteHome}-recovery`, { recursive: true, force: true });
});
