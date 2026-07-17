import { existsSync, lstatSync, mkdtempSync, readFileSync, readlinkSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const inputPath = process.argv[2];
if (!inputPath) {
  throw new Error("Usage: node scripts/verify-macos-dmg.mjs PATH_TO_DMG");
}
const dmgPath = path.resolve(inputPath);
if (!existsSync(dmgPath)) throw new Error(`Missing DMG: ${dmgPath}`);

if (process.platform !== "darwin") {
  throw new Error("macOS DMG verification must run on macOS.");
}

const mountPoint = mkdtempSync(path.join(tmpdir(), "s-gw-dmg-"));
const testHomeRoot = mkdtempSync(path.join(tmpdir(), "s-gw-dmg-home-"));
let attached = false;

try {
  run("hdiutil", ["attach", "-readonly", "-nobrowse", "-mountpoint", mountPoint, dmgPath]);
  attached = true;

  const appPath = path.join(mountPoint, "s-gw.app");
  const applicationsLink = path.join(mountPoint, "Applications");
  const readmePath = path.join(mountPoint, "README.txt");
  const runtimeRoot = path.join(appPath, "Contents", "Resources", "s-gw-runtime");
  const packageRoot = path.join(runtimeRoot, "package");
  const expected = [
    path.join(appPath, "Contents", "MacOS", "s-gw"),
    path.join(appPath, "Contents", "Library", "LoginItems", "s-gw Menu Bar.app", "Contents", "MacOS", "s-gw-menu-bar-helper"),
    path.join(runtimeRoot, "runtime.json"),
    path.join(runtimeRoot, "node", "bin", "node"),
    path.join(runtimeRoot, "bin", "s-gw"),
    path.join(runtimeRoot, "bin", "s-gw-mcp"),
    path.join(packageRoot, "package.json"),
    path.join(packageRoot, "dist", "cli.js"),
    path.join(packageRoot, "dist", "mcp-server.js"),
    path.join(packageRoot, "dist", "native", "darwin-arm64", "s-gw-core"),
    path.join(packageRoot, "dist", "native", "darwin-arm64", "s-gw-keychain-helper"),
    path.join(packageRoot, "dist", "native", "darwin-arm64", "s-gw-keychain-inspector"),
    path.join(packageRoot, "node_modules"),
    path.join(packageRoot, "skills", "s-gw", "SKILL.md")
  ];
  for (const item of expected) {
    if (!existsSync(item)) throw new Error(`Missing self-contained macOS runtime item: ${item}`);
  }

  if (!lstatSync(applicationsLink).isSymbolicLink() || readlinkSync(applicationsLink) !== "/Applications") {
    throw new Error("The DMG must include an Applications shortcut.");
  }
  if (existsSync(path.join(mountPoint, "Install s-gw.command"))) {
    throw new Error("The DMG must not include a clickable shell installer.");
  }
  if (!existsSync(readmePath)) {
    throw new Error("The DMG must include installation guidance.");
  }
  const readme = readFileSync(readmePath, "utf8");
  const packageVersion = JSON.parse(readFileSync(path.join(packageRoot, "package.json"), "utf8")).version;
  const npmInstall = packageVersion.includes("-unsigned.")
    ? `npm install -g https://github.com/sgateway/s-gw/releases/download/unsigned-macos-preview-v${packageVersion}/s-gw-${packageVersion}.tgz`
    : "npm install -g @s-gw/s-gw";
  if (!readme.includes(npmInstall) || !readme.includes("s-gw setup")) {
    throw new Error("The DMG installation guidance must include the matching npm alternative.");
  }

  run("codesign", ["--verify", "--deep", "--strict", "--verbose=2", appPath]);
  const node = path.join(runtimeRoot, "node", "bin", "node");
  const command = path.join(runtimeRoot, "bin", "s-gw");
  const env = {
    PATH: "/usr/bin:/bin",
    SGW_HOME: path.join(testHomeRoot, "home"),
    SGW_RECOVERY_HOME: path.join(testHomeRoot, "recovery"),
    SGW_DISABLE_KEYCHAIN: "1",
    SGW_MASTER_PASSPHRASE: "installer-test-passphrase",
    SGW_TEST_MODE: "1",
    SGW_TEST_HOME_ROOT: testHomeRoot
  };
  run(command, ["help"], packageRoot, env);
  runMcpSmoke(path.join(runtimeRoot, "bin", "s-gw-mcp"), packageRoot, env);
  run(node, ["-e", "let total = 0; for (let i = 0; i < 200000; i += 1) total += i; if (total < 1) process.exit(1)"], packageRoot, env);

  process.stdout.write(`Verified self-contained macOS DMG: ${path.basename(dmgPath)}\n`);
} finally {
  if (attached) {
    spawnSync("hdiutil", ["detach", mountPoint], { stdio: "ignore" });
  }
  rmSync(mountPoint, { recursive: true, force: true });
  rmSync(testHomeRoot, { recursive: true, force: true });
}

function run(command, args, cwd = process.cwd(), env = {}) {
  const result = spawnSync(command, args, {
    cwd,
    env: { ...process.env, ...env },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status === 0) return;

  const output = `${result.stdout || ""}\n${result.stderr || ""}`.trim();
  throw new Error(`${command} failed${output ? `:\n${output}` : "."}`);
}

function runMcpSmoke(command, cwd, env) {
  const input = `${JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion: "2025-11-25",
      capabilities: {},
      clientInfo: { name: "s-gw-installer-smoke", version: "1" }
    }
  })}\n`;
  const result = spawnSync(command, [], {
    cwd,
    env: { ...process.env, ...env },
    input,
    timeout: 10_000,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"]
  });
  if (result.status === 0 && result.stdout.includes('"result"')) return;

  const output = `${result.stdout || ""}\n${result.stderr || ""}`.trim();
  throw new Error(`${command} MCP smoke test failed${output ? `:\n${output}` : "."}`);
}
