import { chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  isInstalledMacAppLocation,
  isSelfContainedMacApp,
  isTransientMacAppLocation,
  resolveSelfContainedMacRuntime
} from "../src/self-contained-runtime.js";

const tmpDirs: string[] = [];

afterEach(async () => {
  await Promise.all(tmpDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
});

describe("self-contained macOS runtime", () => {
  it.skipIf(process.platform !== "darwin")("resolves only a complete app-bundled Node and CLI runtime", async () => {
    const root = await mkdtemp(path.join(os.tmpdir(), "sgw-runtime-layout-"));
    tmpDirs.push(root);
    const app = path.join(root, "s-gw.app");
    const runtime = path.join(app, "Contents", "Resources", "s-gw-runtime");
    const packageRoot = path.join(runtime, "package");

    await writeExecutable(path.join(app, "Contents", "MacOS", "s-gw"), "main");
    await mkdir(runtime, { recursive: true });
    await writeFile(path.join(runtime, "runtime.json"), '{"kind":"s-gw-self-contained-runtime"}\n');
    await writeExecutable(path.join(runtime, "node", "bin", "node"), "node");
    await mkdir(path.join(packageRoot, "dist"), { recursive: true });
    await writeFile(path.join(packageRoot, "dist", "cli.js"), "export {};\n");
    await writeFile(path.join(packageRoot, "dist", "mcp-server.js"), "export {};\n");

    const resolved = resolveSelfContainedMacRuntime(packageRoot);
    expect(resolved).toMatchObject({
      appPath: app,
      runtimePath: runtime,
      packageRoot,
      nodePath: path.join(runtime, "node", "bin", "node"),
      cliPath: path.join(packageRoot, "dist", "cli.js"),
      mcpPath: path.join(packageRoot, "dist", "mcp-server.js"),
      menuBarAppPath: path.join(app, "Contents", "Library", "LoginItems", "s-gw Menu Bar.app")
    });
    expect(isSelfContainedMacApp(app)).toBe(true);

    await rm(path.join(runtime, "node", "bin", "node"));
    expect(resolveSelfContainedMacRuntime(packageRoot)).toBeUndefined();
    expect(isSelfContainedMacApp(app)).toBe(false);
  });

  it("rejects mounted and translocated app paths for setup", () => {
    expect(isTransientMacAppLocation("/Volumes/s-gw/s-gw.app")).toBe(true);
    expect(isTransientMacAppLocation("/private/var/folders/a/AppTranslocation/b/d/s-gw.app")).toBe(true);
    expect(isTransientMacAppLocation("/Applications/s-gw.app")).toBe(false);
    expect(isTransientMacAppLocation("/Users/test/Applications/s-gw.app")).toBe(false);
  });

  it("allows only durable Applications directories for a managed app", () => {
    const locations = ["/Applications", "/Users/test/Applications"];

    expect(isInstalledMacAppLocation("/Applications/s-gw.app", locations)).toBe(true);
    expect(isInstalledMacAppLocation("/Users/test/Applications/s-gw.app", locations)).toBe(true);
    expect(isInstalledMacAppLocation("/Volumes/s-gw/s-gw.app", locations)).toBe(false);
    expect(isInstalledMacAppLocation("/Users/test/Downloads/s-gw.app", locations)).toBe(false);
  });
});

async function writeExecutable(filePath: string, contents: string): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, contents, { mode: 0o755 });
  await chmod(filePath, 0o755);
}
