import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { bundledPackages, seccompHelpers, stageAnthropicRuntime } from "./stage-anthropic-runtime.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const runtimeName = "@anthropic-ai/sandbox-runtime";

export function validatePackedConsumer(tarballFile) {
  if (!tarballFile) stageAnthropicRuntime();
  const workDir = mkdtempSync(join(tmpdir(), "sgw-packed-consumer-"));
  const consumer = join(workDir, "consumer");
  const home = join(workDir, "home");
  mkdirSync(consumer);
  mkdirSync(home);
  writeFileSync(join(consumer, "package.json"), '{"name":"sgw-packed-consumer","private":true}\n');
  writeFileSync(join(workDir, "user.npmrc"), "");
  writeFileSync(join(workDir, "global.npmrc"), "");
  const env = {
    PATH: process.env.PATH,
    HOME: home,
    ...(process.platform === "win32" ? {
      SystemRoot: process.env.SystemRoot,
      ComSpec: process.env.ComSpec,
      USERPROFILE: home,
      TEMP: workDir,
      TMP: workDir
    } : {}),
    npm_config_userconfig: join(workDir, "user.npmrc"),
    npm_config_globalconfig: join(workDir, "global.npmrc"),
    npm_config_cache: join(workDir, "npm-cache"),
    npm_config_registry: "https://registry.npmjs.org/"
  };

  let passed = false;
  try {
    const packArgs = tarballFile
      ? ["pack", "--dry-run", "--json", "--ignore-scripts", "--", tarballFile]
      : ["pack", "--json", "--ignore-scripts", "--pack-destination", workDir];
    const pack = JSON.parse(runNpm(packArgs, tarballFile ? workDir : root, env, workDir, "pack"));
    if (pack.length !== 1 || !pack[0]?.filename || !Array.isArray(pack[0].files)) {
      throw new Error("npm pack returned an unexpected result.");
    }
    validateBundledFiles(pack[0].files);
    const tarball = tarballFile || join(workDir, pack[0].filename);
    runNpm(["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], consumer, env, workDir, "install");

    const installed = join(consumer, "node_modules", "@s-gw", "s-gw");
    const runtime = readJson(join(installed, "node_modules", runtimeName, "package.json"));
    if (runtime.version !== "0.0.50" || runtime.dependencies?.zod !== "^4.6.7") {
      throw new Error("The packed Anthropic runtime manifest was not patched for Zod 4.6.7.");
    }
    const zod = readJson(join(installed, "node_modules", "zod", "package.json"));
    if (zod.version !== "4.6.7") throw new Error(`The packed package installed Zod ${zod.version}.`);
    if (existsSync(join(installed, "node_modules", runtimeName, "node_modules", "zod"))) {
      throw new Error("The packed Anthropic runtime installed a nested Zod copy.");
    }
    for (const [arch, hashes] of seccompHelpers) {
      for (const prefix of ["vendor", "dist/vendor"]) {
        const binary = join(installed, "node_modules", runtimeName, prefix, "seccomp", arch, "apply-seccomp");
        if (sha256(binary) !== hashes.patched) {
          throw new Error(`The packed Anthropic ${arch} seccomp helper is not patched.`);
        }
      }
    }

    const tree = JSON.parse(runNpm(["ls", runtimeName, "zod", "--all", "--json"], consumer, env, workDir, "npm-ls"));
    checkZodVersions(tree);
    const audit = JSON.parse(runNpm(["audit", "--json", "--omit=dev"], consumer, env, workDir, "audit", [0, 1]));
    if (audit.metadata?.vulnerabilities?.total !== 0) {
      throw new Error(`The packed consumer has ${audit.metadata?.vulnerabilities?.total ?? "unknown"} npm audit advisories.`);
    }

    passed = true;
    console.log("Packed consumer resolved Anthropic runtime 0.0.50 with Zod 4.6.7; npm ls and npm audit passed.");
  } catch (error) {
    throw new Error(`${error.message} Logs and consumer are at ${workDir}.`, { cause: error });
  } finally {
    if (passed) rmSync(workDir, { recursive: true, force: true });
  }
}

export function validateBundledFiles(files) {
  const bundled = new Set();
  const paths = new Set(files.map((entry) => entry.path));
  for (const name of ["LICENSE", "README.md", "apply-seccomp.c", "unix-block-bpf.h",
    "x64/apply-seccomp", "arm64/apply-seccomp"]) {
    if (!paths.has(`vendor/anthropic-seccomp/${name}`)) {
      throw new Error(`npm package is missing the Anthropic seccomp source or helper: ${name}`);
    }
  }
  for (const filePath of paths) {
    if (!filePath.startsWith("node_modules/")) continue;
    const match = /^node_modules\/((?:@[^/]+\/)?[^/]+)\//.exec(filePath);
    const nestedPath = match && filePath.slice(match[0].length);
    if (!match || nestedPath.startsWith("node_modules/") || nestedPath.includes("/node_modules/")) {
      throw new Error(`npm package contains an unexpected bundled path: ${filePath}`);
    }
    if (!bundledPackages.has(match[1])) {
      throw new Error(`npm package contains an unexpected bundled dependency: ${match[1]}`);
    }
    bundled.add(match[1]);
  }
  for (const name of bundledPackages.keys()) {
    if (!bundled.has(name) || !paths.has(`node_modules/${name}/package.json`)) {
      throw new Error(`npm package is missing bundled dependency: ${name}`);
    }
  }
}

function sha256(file) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

function runNpm(args, cwd, env, logs, name, allowed = [0]) {
  const npmCli = process.env.npm_execpath;
  const command = npmCli ? process.execPath : process.platform === "win32" ? "npm.cmd" : "npm";
  const npmArgs = npmCli ? [npmCli, ...args] : args;
  const result = spawnSync(command, npmArgs, {
    cwd, env, encoding: "utf8", timeout: 300_000, maxBuffer: 16 * 1024 * 1024
  });
  writeFileSync(join(logs, `${name}.stdout.log`), result.stdout || "");
  writeFileSync(join(logs, `${name}.stderr.log`), result.stderr || "");
  if (result.error) throw new Error(`${name} failed: ${result.error.message}`);
  if (!allowed.includes(result.status)) throw new Error(`${name} exited with status ${result.status}.`);
  return result.stdout;
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`Could not read ${file}: ${error.message}`, { cause: error });
  }
}

function checkZodVersions(node) {
  for (const [name, dependency] of Object.entries(node.dependencies || {})) {
    if (name === "zod" && dependency.version !== "4.6.7") {
      throw new Error(`npm ls found Zod ${dependency.version}.`);
    }
    checkZodVersions(dependency);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length > 0 && (args.length !== 2 || args[0] !== "--tarball")) {
    throw new Error("Usage: node scripts/validate-packed-consumer.mjs [--tarball FILE]");
  }
  validatePackedConsumer(args.length ? resolve(args[1]) : undefined);
}
