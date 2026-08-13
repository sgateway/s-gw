import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const root = process.cwd();
const productionSource = path.join(root, "native/macos-app/Sources/SgwMac/Views/ConsoleWebAppView.swift");
const testSource = path.join(root, "native/macos-app/Tests/WindowDragTests.swift");

function hasSwift(): boolean {
  if (process.platform !== "darwin") return false;
  return spawnSync("swiftc", ["--version"], { stdio: "ignore" }).status === 0;
}

const describeNative = hasSwift() && existsSync(productionSource) && existsSync(testSource)
  ? describe
  : describe.skip;

let workDir = "";
let binary = "";

describeNative("native macOS window dragging (real WebKit surface)", () => {
  beforeAll(async () => {
    workDir = await mkdtemp(path.join(os.tmpdir(), "sgw-window-drag-test-"));
    binary = path.join(workDir, "window-drag-tests");
    const compile = spawnSync(
      "swiftc",
      ["-O", "-parse-as-library", productionSource, testSource, "-o", binary],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
    );
    if (compile.status !== 0) {
      throw new Error(`swiftc failed:\n${compile.stderr || compile.stdout}`);
    }
  }, 180_000);

  afterAll(async () => {
    if (workDir) await rm(workDir, { recursive: true, force: true });
  });

  it("drags blank title chrome without stealing interactive clicks", () => {
    const run = spawnSync(binary, [], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 30_000
    });
    const output = `${run.stdout || ""}${run.stderr || ""}`;
    expect(output, output).toContain("WINDOW_DRAG_TESTS_OK");
    expect(run.status).toBe(0);
  }, 30_000);
});
