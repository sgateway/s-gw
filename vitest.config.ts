import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["tests/**/*.test.ts"],
    restoreMocks: true,
    env: {
      SGW_DISABLE_UPDATE_CHECK: "1"
    }
  }
});
