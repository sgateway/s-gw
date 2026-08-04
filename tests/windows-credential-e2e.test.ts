import { execFileSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { getPackageLayout, stopWindowsSurfaces } from "../src/install.js";

const repoRoot = process.cwd();

describe("Windows credential protection", () => {
  it.skipIf(process.platform !== "win32")(
    "stores a synthetic credential, requires approval, and sanitizes execution output",
    async () => {
      const id = randomUUID();
      const home = await mkdtemp(path.join(os.tmpdir(), "sgw-windows-credential-"));
      const secretValue = `windows-credential-e2e-${id}`;
      const masterService = `com.s-gw.test.master.${id}`;
      const masterAccount = `sgw-test-${id}`;
      const secretService = `com.s-gw.test.secret.${id}`;
      const testEnv: NodeJS.ProcessEnv = {
        ...process.env,
        SGW_HOME: home,
        SGW_RECOVERY_HOME: `${home}-recovery`,
        SGW_KEYCHAIN_SERVICE: masterService,
        SGW_KEYCHAIN_ACCOUNT: masterAccount,
        SGW_SECRET_KEYCHAIN_SERVICE: secretService,
        SGW_DISABLE_UPDATE_CHECK: "1",
        SGW_EXECUTION_ENGINE: "typescript"
      };
      delete testEnv.SGW_DISABLE_KEYCHAIN;
      delete testEnv.SGW_MASTER_PASSPHRASE;

      let handle = "";
      try {
        const setup = JSON.parse(runCli([
          "setup",
          "--no-open-app",
          "--no-service",
          "--no-menubar",
          "--no-agents"
        ], testEnv));
        expect(setup.ok).toBe(true);
        expect(setup.unlock).toBe("generated-keychain-passphrase");

        const unlock = JSON.parse(runCli(["unlock", "status"], testEnv));
        expect(unlock.activeSource).toBe("windows-credential-manager");
        expect(unlock.keychain.provider).toBe("windows-helper");

        const added = JSON.parse(runCli([
          "secret",
          "add-keychain",
          "--name",
          "windows-e2e-token",
          "--type",
          "api-token",
          "--value-stdin",
          "--inject-env",
          "SGW_WINDOWS_E2E_TOKEN",
          "--allow-command",
          process.execPath
        ], testEnv, secretValue));
        handle = added.handle;
        expect(added.provider).toBe("windows-credential-manager");

        const listed = JSON.parse(runCli(["secret", "list"], testEnv));
        const summary = listed.find((item: { handle: string }) => item.handle === handle);
        expect(summary.provider).toBe("windows-credential-manager");
        expect(summary.source).toBe("windows-credential-manager");

        const request = JSON.parse(runCli([
          "request",
          "env-command",
          handle,
          "--command",
          process.execPath,
          "--inject-env",
          "SGW_WINDOWS_E2E_TOKEN",
          "--arg",
          "-e",
          "--arg",
          "process.stdout.write(process.env.SGW_WINDOWS_E2E_TOKEN || '')",
          "--reason",
          "Windows synthetic credential acceptance"
        ], testEnv));
        expect(request.state).toBe("pending");
        expect(() => runCli(["execute", request.id], testEnv)).toThrow(/approved|approval/i);

        runCli(["approve", request.id], testEnv);
        const executed = JSON.parse(runCli(["execute", request.id], testEnv));
        expect(executed.exitCode).toBe(0);
        expect(executed.stdout).toContain(`<<SGW_SECRET:${handle}>>`);
        expect(executed.stdout).not.toContain(secretValue);

        const deleted = JSON.parse(runCli(["secret", "delete", handle], testEnv));
        expect(deleted.deleted).toBe(true);
        handle = "";
        expect(JSON.parse(runCli(["unlock", "keychain", "delete"], testEnv)).deleted).toBe(true);
        expect(JSON.parse(runCli(["unlock", "status"], testEnv)).activeSource).toBe("none");
      } finally {
        try {
          stopWindowsSurfaces();
        } catch {
          // Credential cleanup must still run if process discovery is unavailable.
        }
        if (handle) deleteCredential(secretService, handle);
        deleteCredential(masterService, masterAccount);
        await rm(home, { recursive: true, force: true });
        await rm(`${home}-recovery`, { recursive: true, force: true });
      }
    },
    45_000
  );
});

function runCli(args: string[], env: NodeJS.ProcessEnv, input?: string): string {
  const layout = getPackageLayout();
  return execFileSync(process.execPath, [layout.cliPath, ...args], {
    cwd: repoRoot,
    env,
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"]
  });
}

function deleteCredential(service: string, account: string): void {
  const helper = getPackageLayout().windowsCredentialHelperPath;
  try {
    execFileSync("powershell.exe", [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-File",
      helper,
      "delete",
      "-Service",
      service,
      "-Account",
      account
    ], { stdio: "ignore" });
  } catch {
    // The primary assertions preserve the failure; cleanup remains best effort.
  }
}
