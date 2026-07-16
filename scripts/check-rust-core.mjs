import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const coreRoot = resolve(
  process.env.SGW_RUST_CORE_DIR || resolve(root, "..", "s-gw-rust-core")
);

if (!existsSync(resolve(coreRoot, "Cargo.toml"))) {
  if (process.env.SGW_REQUIRE_RUST_CORE === "1") {
    console.error(`Private s-gw Rust core checkout is required: ${coreRoot}`);
    process.exit(1);
  }
  console.log(`Skipping private Rust core checks; checkout not found: ${coreRoot}`);
  process.exit(0);
}

run(["fmt", "--all", "--", "--check"]);
run(["clippy", "--locked", "--all-targets", "--", "-D", "warnings"]);
run(["test", "--locked"]);

function run(args) {
  const result = spawnSync("cargo", args, {
    cwd: coreRoot,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.error?.code === "ENOENT") {
    console.error("cargo is required to check the private s-gw Rust core.");
    process.exit(1);
  }
  if (result.status !== 0) {
    console.error(result.stderr || result.stdout);
    process.exit(result.status || 1);
  }
}
