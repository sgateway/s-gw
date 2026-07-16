import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const coreRoot = resolve(
  process.env.SGW_RUST_CORE_DIR || resolve(root, "..", "s-gw-rust-core")
);
const manifest = resolve(coreRoot, "Cargo.toml");
const extension = process.platform === "win32" ? ".exe" : "";
const target = `${process.platform}-${process.arch}`;
const cargoTargetDir = process.env.CARGO_TARGET_DIR
  ? resolve(coreRoot, process.env.CARGO_TARGET_DIR)
  : resolve(coreRoot, "target");
const built = resolve(cargoTargetDir, "release", `sgw-core${extension}`);
const output = resolve(root, "dist", "native", target, `s-gw-core${extension}`);
const legacyOutputs = [
  resolve(root, "dist", "native", "s-gw-core"),
  resolve(root, "dist", "native", "s-gw-core.exe")
];

if (!existsSync(manifest)) {
  rmSync(output, { force: true });
  for (const legacyOutput of legacyOutputs) {
    rmSync(legacyOutput, { force: true });
  }
  if (process.env.SGW_REQUIRE_RUST_CORE === "1") {
    console.error(`Private s-gw Rust core checkout is required: ${coreRoot}`);
    process.exit(1);
  }
  console.log(`Skipping private Rust core build; checkout not found: ${coreRoot}`);
  process.exit(0);
}

const cargo = spawnSync("cargo", ["build", "--release", "--locked"], {
  cwd: coreRoot,
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
for (const legacyOutput of legacyOutputs) {
  rmSync(legacyOutput, { force: true });
}
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
