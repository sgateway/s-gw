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

    const [packageRaw, lockRaw, serverRaw, pluginRaw, desktopCargoRaw, desktopLockRaw, desktopConfigRaw] = await Promise.all([
      readFile(path.join(root, "package.json"), "utf8"),
      readFile(path.join(root, "package-lock.json"), "utf8"),
      readFile(path.join(root, "server.json"), "utf8"),
      readFile(path.join(root, ".codex-plugin", "plugin.json"), "utf8"),
      readFile(path.join(root, "native/desktop-app/Cargo.toml"), "utf8"),
      readFile(path.join(root, "native/desktop-app/Cargo.lock"), "utf8"),
      readFile(path.join(root, "native/desktop-app/tauri.conf.json"), "utf8")
    ]);

    const pkg = JSON.parse(packageRaw);
    const lock = JSON.parse(lockRaw);
    const server = JSON.parse(serverRaw);
    const plugin = JSON.parse(pluginRaw);
    const desktopConfig = JSON.parse(desktopConfigRaw);

    expect(CURRENT_VERSION).toBe(pkg.version);
    expect(lock.version).toBe(pkg.version);
    expect(lock.packages[""].version).toBe(pkg.version);
    expect(server.version).toBe(pkg.version);
    expect(server.packages[0].version).toBe(pkg.version);
    expect(plugin.version).toBe(pkg.version);
    expect(desktopCargoRaw.match(/^version\s*=\s*"([^"]+)"/m)?.[1]).toBe(pkg.version);
    const desktopLockPattern = /\[\[package\]\]\r?\nname = "s-gw-desktop"\r?\nversion = "([^"]+)"/;
    expect(desktopLockRaw.match(desktopLockPattern)?.[1]).toBe(pkg.version);
    // Git may check lockfiles out as CRLF on Windows.
    expect(desktopLockRaw.replace(/\r?\n/g, "\r\n").match(desktopLockPattern)?.[1]).toBe(pkg.version);
    expect(desktopConfig.version).toBe("../../package.json");
    if (hasPrivateCore) {
      const [cargoRaw, cargoLockRaw] = await Promise.all([
        readFile(coreManifest, "utf8"),
        readFile(path.join(coreRoot, "Cargo.lock"), "utf8")
      ]);
      const cargoVersion = cargoRaw.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
      const cargoLockVersion = cargoLockRaw.match(/\[\[package\]\]\r?\nname = "sgw-core"\r?\nversion = "([^"]+)"/)?.[1];
      expect(cargoVersion).toBe(pkg.version);
      expect(cargoLockVersion).toBe(pkg.version);
    }
  });
});
