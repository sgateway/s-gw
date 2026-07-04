import { chmodSync, copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const extension = process.platform === "win32" ? ".exe" : "";
const built = resolve(root, "target", "release", `sgw-core${extension}`);
const output = resolve(root, "dist", "native", `s-gw-core${extension}`);

const cargo = spawnSync("cargo", ["build", "--release", "--locked", "-p", "sgw-core"], {
  cwd: root,
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});

if (cargo.error?.code === "ENOENT") {
  console.error("cargo is required to build the s-gw Rust core.");
  process.exit(1);
}
if (cargo.status !== 0) {
  console.error(cargo.stderr || cargo.stdout);
  process.exit(cargo.status || 1);
}
if (!existsSync(built)) {
  console.error(`Missing Rust core build output: ${built}`);
  process.exit(1);
}

mkdirSync(dirname(output), { recursive: true });
copyFileSync(built, output);
chmodSync(output, 0o755);

const smoke = spawnSync(output, ["--version"], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});
if (smoke.status !== 0 || !smoke.stdout.startsWith("sgw-core ")) {
  console.error(smoke.stderr || smoke.stdout || "Rust core smoke check failed.");
  process.exit(smoke.status || 1);
}

console.log(`Built Rust core: ${output}`);
