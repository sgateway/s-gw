import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { CURRENT_VERSION } from "../src/version.js";

const root = process.cwd();

describe("release version alignment", () => {
  it("keeps every shipped product surface on the package version", async () => {
    const coreRoot = path.resolve(
      process.env.SGW_RUST_CORE_DIR || path.join(root, "..", "s-gw-rust-core")
    );
    const coreManifest = path.join(coreRoot, "Cargo.toml");
    const hasPrivateCore = existsSync(coreManifest);
    if (process.env.SGW_REQUIRE_RUST_CORE === "1" && !hasPrivateCore) {
      throw new Error(`Private s-gw Rust core checkout is required: ${coreRoot}`);
    }

    const [packageRaw, lockRaw, serverRaw, pluginRaw] = await Promise.all([
      readFile(path.join(root, "package.json"), "utf8"),
      readFile(path.join(root, "package-lock.json"), "utf8"),
      readFile(path.join(root, "server.json"), "utf8"),
      readFile(path.join(root, ".codex-plugin", "plugin.json"), "utf8")
    ]);

    const pkg = JSON.parse(packageRaw);
    const lock = JSON.parse(lockRaw);
    const server = JSON.parse(serverRaw);
    const plugin = JSON.parse(pluginRaw);

    expect(CURRENT_VERSION).toBe(pkg.version);
    expect(lock.version).toBe(pkg.version);
    expect(lock.packages[""].version).toBe(pkg.version);
    expect(server.version).toBe(pkg.version);
    expect(server.packages[0].version).toBe(pkg.version);
    expect(plugin.version).toBe(pkg.version);
    if (hasPrivateCore) {
      const [cargoRaw, cargoLockRaw] = await Promise.all([
        readFile(coreManifest, "utf8"),
        readFile(path.join(coreRoot, "Cargo.lock"), "utf8")
      ]);
      const cargoVersion = cargoRaw.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
      const cargoLockVersion = cargoLockRaw.match(/\[\[package\]\]\nname = "sgw-core"\nversion = "([^"]+)"/)?.[1];
      expect(cargoVersion).toBe(pkg.version);
      expect(cargoLockVersion).toBe(pkg.version);
    }
  });
});
