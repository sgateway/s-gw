import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { basename, dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const appRoot = resolve(root, "native/desktop-app");
const runtimeRoot = resolve(appRoot, "runtime");
const runtimeConfig = JSON.parse(readFileSync(resolve(appRoot, "runtime.json"), "utf8"));
const packageInfo = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));
const targetName = process.env.SGW_DESKTOP_TARGET?.trim() || `${process.platform}-${process.arch}`;
const hostTarget = `${process.platform}-${process.arch}`;
const target = runtimeConfig.targets[targetName];
const npmCli = npmCliPath();

if (!target) {
  throw new Error(`Desktop runtime target ${targetName} is not configured.`);
}
if (targetName !== hostTarget) {
  throw new Error(`Desktop runtime staging must run on ${targetName}; current host is ${hostTarget}.`);
}

requireFile(resolve(root, "dist/cli.js"));
requireFile(resolve(root, "dist/console-ui/index.html"));

const workDir = mkdtempSync(resolve(tmpdir(), "s-gw-desktop-runtime-"));
const stagedRoot = mkdtempSync(resolve(appRoot, ".runtime-staging-"));
const packageRoot = resolve(stagedRoot, "package");
const nodeRoot = resolve(stagedRoot, "node");

try {
  const packOutput = runOutput(
    process.execPath,
    [npmCli, "pack", "--ignore-scripts", "--json", "--pack-destination", workDir],
    root
  );
  const packed = resolve(workDir, JSON.parse(packOutput)[0].filename);
  requireFile(packed);

  mkdirSync(packageRoot, { recursive: true });
  run("tar", ["-xzf", packed, "--strip-components=1", "-C", packageRoot], root);
  copyFileSync(resolve(root, "package-lock.json"), resolve(packageRoot, "package-lock.json"));
  run(
    process.execPath,
    [npmCli, "ci", "--omit=dev", "--ignore-scripts", "--no-audit", "--no-fund"],
    packageRoot
  );
  rmSync(resolve(packageRoot, "package-lock.json"), { force: true });
  rmSync(resolve(packageRoot, "dist/installers"), { recursive: true, force: true });
  rmSync(resolve(packageRoot, "dist/s-gw.app"), { recursive: true, force: true });
  rmSync(resolve(packageRoot, "dist/s-gw Menu Bar.app"), { recursive: true, force: true });

  const archive = resolve(workDir, target.archive);
  const suppliedArchive = process.env.SGW_NODE_RUNTIME_ARCHIVE?.trim();
  if (suppliedArchive) {
    copyFileSync(resolve(suppliedArchive), archive);
  } else {
    await download(target.url, archive);
  }

  const digest = sha256(archive);
  if (digest !== target.sha256) {
    throw new Error(`Embedded Node archive checksum mismatch. Expected ${target.sha256}, got ${digest}.`);
  }

  const extractRoot = resolve(workDir, "node-runtime");
  mkdirSync(extractRoot, { recursive: true });
  run("tar", ["-xf", archive, "-C", extractRoot], root);
  const sourceDir = resolve(extractRoot, archiveDirectory(target.archive));
  const sourceNode = nodeBinary(sourceDir);
  requireFile(sourceNode);
  mkdirSync(dirname(nodeBinary(nodeRoot)), { recursive: true });
  copyFileSync(sourceNode, nodeBinary(nodeRoot));
  copyFileSync(resolve(sourceDir, "LICENSE"), resolve(nodeRoot, "LICENSE"));

  if (process.platform !== "win32") {
    chmodSync(nodeBinary(nodeRoot), 0o755);
  }

  requireFile(resolve(packageRoot, "package.json"));
  requireFile(resolve(packageRoot, "dist/cli.js"));
  requireFile(resolve(packageRoot, "dist/mcp-server.js"));
  requireFile(resolve(packageRoot, "dist/console-ui/index.html"));
  requireFile(resolve(packageRoot, "node_modules"));
  requireFile(resolve(nodeRoot, "LICENSE"));
  requireFile(nodeBinary(nodeRoot));

  const nodeVersion = runOutput(nodeBinary(nodeRoot), ["--version"], root).trim();
  if (nodeVersion !== `v${runtimeConfig.nodeVersion}`) {
    throw new Error(`Embedded Node version mismatch. Expected v${runtimeConfig.nodeVersion}, got ${nodeVersion}.`);
  }
  run(nodeBinary(nodeRoot), [resolve(packageRoot, "dist/cli.js"), "help"], root);

  writeFileSync(resolve(stagedRoot, ".gitkeep"), "");
  writeFileSync(resolve(stagedRoot, "metadata.json"), `${JSON.stringify({
    kind: "s-gw-desktop-runtime",
    package: packageInfo.name,
    version: packageInfo.version,
    nodeVersion: runtimeConfig.nodeVersion,
    target: targetName
  }, null, 2)}\n`);

  replaceRuntime(stagedRoot, runtimeRoot);
  console.log(`Staged ${targetName} desktop runtime in ${runtimeRoot}`);
} finally {
  rmSync(workDir, { recursive: true, force: true });
  rmSync(stagedRoot, { recursive: true, force: true });
}

function replaceRuntime(stagedPath, destination) {
  const backup = resolve(appRoot, `.runtime-backup-${process.pid}-${Date.now()}`);
  let movedExisting = false;
  try {
    if (existsSync(destination)) {
      renameSync(destination, backup);
      movedExisting = true;
    }
    renameSync(stagedPath, destination);
  } catch (error) {
    if (movedExisting && !existsSync(destination) && existsSync(backup)) {
      renameSync(backup, destination);
    }
    throw error;
  } finally {
    rmSync(backup, { recursive: true, force: true });
  }
}

async function download(url, targetPath) {
  const response = await fetch(url, { redirect: "follow" });
  if (!response.ok) {
    throw new Error(`Could not download ${url}: HTTP ${response.status}`);
  }
  writeFileSync(targetPath, Buffer.from(await response.arrayBuffer()));
}

function archiveDirectory(archive) {
  return basename(archive).replace(/\.tar\.xz$|\.zip$/u, "");
}

function nodeBinary(base) {
  return process.platform === "win32"
    ? resolve(base, "node.exe")
    : resolve(base, "bin/node");
}

function npmCliPath() {
  const candidates = [
    process.env.npm_execpath,
    resolve(dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"),
    resolve(dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js")
  ].filter(Boolean);
  const npmCli = candidates.find((candidate) => /\.(?:c?m?js)$/iu.test(candidate) && existsSync(candidate));
  if (!npmCli) {
    throw new Error("Could not locate npm-cli.js for desktop runtime staging.");
  }
  return npmCli;
}

function sha256(filePath) {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

function requireFile(filePath) {
  if (!existsSync(filePath)) {
    throw new Error(`Missing desktop runtime input: ${filePath}`);
  }
}

function run(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || `${command} failed.`);
  }
}

function runOutput(command, args, cwd) {
  const result = spawnSync(command, args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || result.stdout.trim() || `${command} failed.`);
  }
  return result.stdout;
}
