import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";

// User command bytes reach spawn as arguments, never the runtime's shell-string API.
const manifest = JSON.parse(readFileSync(process.argv[2], "utf8"));
if (typeof manifest.command !== "string" || !Array.isArray(manifest.args) || manifest.args.some((arg: unknown) => typeof arg !== "string")) {
  throw new Error("Invalid sandbox launch manifest.");
}
if (typeof manifest.tmpdir !== "string") throw new Error("Invalid sandbox temporary directory.");
// The runtime's wrapper overrides TMPDIR before it reaches this trusted entry point.
process.env.TMPDIR = manifest.tmpdir;
const child = spawn(manifest.command, manifest.args, { stdio: "inherit", shell: false });
let launchFailed = false;
child.once("error", error => { launchFailed = true; process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
child.once("close", (code, signal) => {
  if (launchFailed) return;
  if (signal) { process.kill(process.pid, signal); return; }
  process.exitCode = code ?? 1;
});
