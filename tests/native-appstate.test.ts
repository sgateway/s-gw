import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

// Native macOS app coverage for the approve/deny in-flight guard and the
// readiness derivation. These live in SwiftUI/@MainActor AppState, so the
// TypeScript console-server / CLI suites can't reach them. Earlier overnight
// iterations could only verify them via `swift build` + `nm` symbol checks or a
// hand-rolled logic probe that re-implemented the guard.
//
// This compiles the REAL production AppState/Models/CLIRunner sources together
// with Tests/AppStateGuardTests.swift and runs the result, so the shipping guard
// is the thing under test. The harness drives AppState.decide through CLIRunner's
// real Process path (a fake CLI pointed at via the sgwBinaryPath override) and
// asserts a double-fire collapses to one decision call.
//
// Skips cleanly off-macOS or when `swift` isn't installed so other environments
// stay green — same pattern as the headless-Chrome console E2E.

const here = path.dirname(fileURLToPath(import.meta.url));
const appRoot = path.resolve(here, "../native/macos-app");
const updateStateSource = path.resolve(here, "../native/update-state/Sources/SgwUpdateState/UpdateNoticeState.swift");
const sources = [
  "Sources/SgwMac/App/AppState.swift",
  "Sources/SgwMac/Models/Models.swift",
  "Sources/SgwMac/Services/CLIRunner.swift",
  "Sources/SgwMac/Services/CommandActivityStore.swift",
  "Sources/SgwMac/Services/CommandRegistry.swift",
  "Sources/SgwMac/Stores/StoreReader.swift",
  "Sources/SgwMac/Services/UpdateChecker.swift",
  "Tests/AppStateGuardTests.swift"
].map((rel) => path.join(appRoot, rel));

function hasSwift(): boolean {
  if (process.platform !== "darwin") return false;
  const probe = spawnSync("swift", ["--version"], { stdio: ["ignore", "pipe", "pipe"] });
  return probe.status === 0;
}

const enabled = hasSwift() && existsSync(updateStateSource) && sources.every((p) => existsSync(p));
const describeNative = enabled ? describe : describe.skip;

let workDir = "";
let binary = "";

describeNative("native macOS AppState (real Swift sources)", () => {
  beforeAll(async () => {
    workDir = await mkdtemp(path.join(os.tmpdir(), "sgw-native-test-"));
    binary = path.join(workDir, "appstate-tests");
    const updateStateModule = path.join(workDir, "SgwUpdateState.swiftmodule");
    const updateStateLibrary = path.join(workDir, "libSgwUpdateState.dylib");
    const compileUpdateState = spawnSync(
      "swiftc",
      [
        "-O",
        "-parse-as-library",
        "-emit-library",
        "-emit-module",
        "-module-name", "SgwUpdateState",
        "-emit-module-path", updateStateModule,
        updateStateSource,
        "-o", updateStateLibrary
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
    );
    if (compileUpdateState.status !== 0) {
      throw new Error(`swiftc shared update state failed:\n${compileUpdateState.stderr || compileUpdateState.stdout}`);
    }
    const compile = spawnSync(
      "swiftc",
      [
        "-O",
        "-parse-as-library",
        "-I", workDir,
        "-L", workDir,
        "-lSgwUpdateState",
        "-Xlinker", "-rpath",
        "-Xlinker", "@executable_path",
        ...sources,
        "-o", binary
      ],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }
    );
    if (compile.status !== 0) {
      throw new Error(`swiftc failed:\n${compile.stderr || compile.stdout}`);
    }
  }, 180_000);

  afterAll(async () => {
    if (workDir) await rm(workDir, { recursive: true, force: true });
  });

  it("enforces the approve/deny in-flight guard and readiness derivation", () => {
    const run = spawnSync(binary, [], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      env: {
        ...process.env,
        DYLD_LIBRARY_PATH: workDir,
        SGW_UPDATE_NOTICE_STATE_PATH: path.join(workDir, "update-notice-state.json")
      }
    });
    const output = `${run.stdout ?? ""}${run.stderr ?? ""}`;
    expect(output, output).toContain("ALL_NATIVE_TESTS_OK");
    expect(run.status).toBe(0);
  }, 30_000);
});
