import { mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeEach } from "vitest";

const suiteHome = mkdtempSync(path.join(os.tmpdir(), "sgw-vitest-"));
const suiteRecoveryHome = `${suiteHome}-recovery`;
const testHomeRoot = path.resolve(os.tmpdir());

function useDisposableHomes(): void {
  process.env.SGW_TEST_MODE = "1";
  process.env.SGW_TEST_HOME_ROOT = testHomeRoot;
  process.env.SGW_HOME = suiteHome;
  process.env.SGW_RECOVERY_HOME = suiteRecoveryHome;
}

useDisposableHomes();
beforeEach(useDisposableHomes);

afterAll(() => {
  rmSync(suiteHome, { recursive: true, force: true });
  rmSync(suiteRecoveryHome, { recursive: true, force: true });
});
