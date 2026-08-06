import { fileURLToPath } from "node:url";
import path from "node:path";
import { defineConfig } from "vitest/config";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

export default defineConfig({
  root: repoRoot,
  test: {
    environment: "node",
    include: ["tests/fixtures/fully-skipped.test.ts"],
    setupFiles: ["tests/setup.ts"],
    env: {
      SGW_DISABLE_UPDATE_CHECK: "1",
      SGW_DISABLE_KEYCHAIN: "1",
      SGW_DISABLE_ONEPASSWORD_BACKUP: "1",
      SGW_TEST_MODE: "1"
    }
  }
});
