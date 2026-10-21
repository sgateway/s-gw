import { mkdirSync, renameSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "win32") {
  console.log("Skipping Windows peer-pipe helper on this platform.");
  process.exit(0);
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "native/windows-peer-identity/one-shot.c");
const output = resolve(root, "dist/native", `win32-${process.arch}`, "s-gw-windows-peer-identity.exe");
const temporary = resolve(dirname(output), `.windows-peer-identity-${process.pid}`);
const built = resolve(temporary, "s-gw-windows-peer-identity.exe");
mkdirSync(temporary, { recursive: true });

const result = spawnSync("cl", [
  "/nologo", "/std:c11", "/W4", "/WX", "/O2", "/GS", "/sdl", "/DUNICODE", "/D_UNICODE",
  `/Fo${resolve(temporary, "one-shot.obj")}`, `/Fe${built}`, source,
  "/link", "/INCREMENTAL:NO", "/DYNAMICBASE", "/NXCOMPAT", "advapi32.lib"
], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

if (result.error?.code === "ENOENT" && process.argv.includes("--optional")) {
  rmSync(temporary, { recursive: true, force: true });
  rmSync(output, { force: true });
  console.log("Skipping optional Windows peer-pipe helper; MSVC cl is unavailable.");
  process.exit(0);
}
if (result.error || result.status !== 0) {
  rmSync(temporary, { recursive: true, force: true });
  console.error(result.error?.message || result.stderr || result.stdout || "Could not build Windows peer-pipe helper.");
  process.exit(result.status || 1);
}

rmSync(output, { force: true });
renameSync(built, output);
rmSync(temporary, { recursive: true, force: true });
console.log(`Built Windows peer-pipe helper: ${output}`);
