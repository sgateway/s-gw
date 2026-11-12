import { chmodSync, mkdirSync, renameSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux") {
  console.log("Skipping managed Linux network namespace helper on this platform.");
  process.exit(0);
}
if (!["x64", "arm64"].includes(process.arch)) {
  if (process.argv.includes("--optional")) {
    console.log(`Skipping optional managed Linux network namespace helper on ${process.arch}.`);
    process.exit(0);
  }
  throw new Error(`Managed Linux namespace helper has no reviewed build for ${process.arch}.`);
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "native/linux-managed-netns/netns.c");
const output = resolve(root, "dist/native", `${process.platform}-${process.arch}`, "s-gw-linux-netns");
const temporary = `${output}.${process.pid}`;
mkdirSync(dirname(output), { recursive: true });
const result = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
  source, "-o", temporary], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
if (result.error || result.status !== 0) {
  rmSync(temporary, { force: true });
  if (result.error?.code === "ENOENT" && process.argv.includes("--optional")) {
    rmSync(output, { force: true });
    console.log("Skipping optional managed Linux network namespace helper; cc is unavailable.");
    process.exit(0);
  }
  throw new Error(result.error?.message || result.stderr || result.stdout || "Managed namespace build failed.");
}
chmodSync(temporary, 0o755);
renameSync(temporary, output);
console.log(`Built managed Linux namespace helper: ${output}`);
