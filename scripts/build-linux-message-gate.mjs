import { chmodSync, mkdirSync, renameSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux") {
  console.log("Skipping Linux MCP message gate on this platform.");
  process.exit(0);
}
if (!["x64", "arm64"].includes(process.arch)) {
  if (process.argv.includes("--optional")) {
    console.log(`Skipping optional Linux MCP message gate on ${process.arch}.`);
    process.exit(0);
  }
  console.error(`Linux MCP message gate needs a reviewed socket option for ${process.arch}.`);
  process.exit(1);
}

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "native/linux-message-gate/gate.c");
const output = resolve(root, "dist/native", `${process.platform}-${process.arch}`, "s-gw-linux-message-gate");
const tmpOutput = `${output}.${process.pid}`;
mkdirSync(dirname(output), { recursive: true });

const result = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", source, "-o", tmpOutput], {
  encoding: "utf8", stdio: ["ignore", "pipe", "pipe"]
});
if (result.error || result.status !== 0) {
  rmSync(tmpOutput, { force: true });
  if (result.error?.code === "ENOENT" && process.argv.includes("--optional")) {
    rmSync(output, { force: true });
    console.log("Skipping optional Linux MCP message gate; cc is unavailable.");
    process.exit(0);
  }
  console.error(result.error?.message || result.stderr || result.stdout || "Could not build Linux MCP message gate.");
  process.exit(result.status || 1);
}
chmodSync(tmpOutput, 0o755);
renameSync(tmpOutput, output);
console.log(`Built Linux MCP message gate: ${output}`);
