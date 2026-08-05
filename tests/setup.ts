import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeEach } from "vitest";

const originalEnvironment = {
  TEMP: process.env.TEMP,
  TMP: process.env.TMP,
  SGW_TEST_HOME_ROOT: process.env.SGW_TEST_HOME_ROOT,
  SGW_HOME: process.env.SGW_HOME,
  SGW_RECOVERY_HOME: process.env.SGW_RECOVERY_HOME,
  SGW_LOGIN_SESSION_ID: process.env.SGW_LOGIN_SESSION_ID
};
const windowsTestRoot = makeWindowsTestRoot();
const testHomeRoot = windowsTestRoot || path.resolve(os.tmpdir());
if (windowsTestRoot) {
  process.env.TEMP = windowsTestRoot;
  process.env.TMP = windowsTestRoot;
}
const suiteHome = mkdtempSync(path.join(testHomeRoot, "sgw-vitest-"));
const suiteRecoveryHome = `${suiteHome}-recovery`;

function useDisposableHomes(): void {
  process.env.SGW_TEST_MODE = "1";
  process.env.SGW_TEST_HOME_ROOT = testHomeRoot;
  process.env.SGW_HOME = suiteHome;
  process.env.SGW_RECOVERY_HOME = suiteRecoveryHome;
  process.env.SGW_LOGIN_SESSION_ID = "vitest-login-session";
}

useDisposableHomes();
beforeEach(useDisposableHomes);

afterAll(() => {
  rmSync(suiteHome, { recursive: true, force: true });
  rmSync(suiteRecoveryHome, { recursive: true, force: true });
  if (windowsTestRoot) {
    rmSync(windowsTestRoot, { recursive: true, force: true });
  }
  for (const [name, value] of Object.entries(originalEnvironment)) {
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }
});

function makeWindowsTestRoot(): string | undefined {
  if (process.platform !== "win32") return undefined;

  const localAppData = process.env.LOCALAPPDATA?.trim()
    || path.join(os.homedir(), "AppData", "Local");
  const tempParent = path.join(localAppData, "Temp");
  mkdirSync(tempParent, { recursive: true });
  return mkdtempSync(path.join(tempParent, "sgw-vitest-root-"));
}
