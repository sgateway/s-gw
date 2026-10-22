import { chmodSync, mkdirSync, renameSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "darwin") {
  console.log("Skipping launchd console activator on non-macOS platform.");
  process.exit(0);
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "native/macos-console-activate/activate.c");
const output = resolve(root, "dist/native", `${process.platform}-${process.arch}`, "s-gw-console-activate");
const tmpOutput = `${output}.${process.pid}`;
mkdirSync(dirname(output), { recursive: true });

const result = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", source, "-o", tmpOutput], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});
if (result.error || result.status !== 0) {
  rmSync(tmpOutput, { force: true });
  console.error(result.error?.message || result.stderr || result.stdout || "Could not build launchd console activator.");
  process.exit(result.status || 1);
}
chmodSync(tmpOutput, 0o755);
renameSync(tmpOutput, output);
console.log(`Built launchd console activator: ${output}`);
