import { readFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { CURRENT_VERSION } from "../src/version.js";

const root = process.cwd();

describe("release version alignment", () => {
  it("keeps every shipped product surface on the package version", async () => {
    const [packageRaw, lockRaw, serverRaw, pluginRaw, cargoRaw, cargoLockRaw] = await Promise.all([
      readFile(path.join(root, "package.json"), "utf8"),
      readFile(path.join(root, "package-lock.json"), "utf8"),
      readFile(path.join(root, "server.json"), "utf8"),
      readFile(path.join(root, ".codex-plugin", "plugin.json"), "utf8"),
      readFile(path.join(root, "Cargo.toml"), "utf8"),
      readFile(path.join(root, "Cargo.lock"), "utf8")
    ]);

    const pkg = JSON.parse(packageRaw);
    const lock = JSON.parse(lockRaw);
    const server = JSON.parse(serverRaw);
    const plugin = JSON.parse(pluginRaw);
    const cargoVersion = cargoRaw.match(/\[workspace\.package\][\s\S]*?^version\s*=\s*"([^"]+)"/m)?.[1];
    const cargoLockVersion = cargoLockRaw.match(/\[\[package\]\]\nname = "sgw-core"\nversion = "([^"]+)"/)?.[1];

    expect(CURRENT_VERSION).toBe(pkg.version);
    expect(lock.version).toBe(pkg.version);
    expect(lock.packages[""].version).toBe(pkg.version);
    expect(server.version).toBe(pkg.version);
    expect(server.packages[0].version).toBe(pkg.version);
    expect(plugin.version).toBe(pkg.version);
    expect(cargoVersion).toBe(pkg.version);
    expect(cargoLockVersion).toBe(pkg.version);
  });
});
