import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync, copyFileSync, existsSync, linkSync, mkdirSync, mkdtempSync,
  lstatSync, realpathSync, rmSync, symlinkSync, writeFileSync
} from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux" || process.getuid?.() !== 0) {
  console.log("Skipping Linux broker runtime verifier self-test; Linux root is required.");
  process.exit(0);
}

const repo = resolve(fileURLToPath(new URL("..", import.meta.url)));
const work = mkdtempSync("/run/s-gw-runtime-verify-");
const runtime = join(work, "runtime");
const nodePath = join(runtime, "node");
const entry = join(runtime, "entry.mjs");
const config = join(work, "config.json");
const ca = join(work, "ca.pem");
const envFile = join(work, "broker.env");
const verifier = join(work, "verify");
let preloadDir;

function run(args = ["verify", runtime, nodePath, entry, config, ca, envFile], env = {}) {
  const childEnv = { PATH: "/usr/bin:/bin", NODE_ENV: "production", NODE_EXTRA_CA_CERTS: ca, ...env };
  for (const key of Object.keys(childEnv)) {
    if (childEnv[key] === undefined) delete childEnv[key];
  }
  return spawnSync(verifier, args, {
    env: childEnv,
    encoding: "utf8"
  });
}

function passes(name) {
  const result = run();
  assert.equal(result.error, undefined, `${name}: ${result.error?.message}`);
  assert.equal(result.status, 0, `${name}: exit ${result.status}, ${result.stderr}\n` +
    ["/", "/run", work, runtime, nodePath].map(pathState).join("\n"));
}

function rejects(name, args, env) {
  const result = run(args, env);
  assert.equal(result.error, undefined, `${name}: ${result.error?.message}`);
  assert.notEqual(result.status, 0, `${name}: unsafe runtime accepted`);
}

function pathState(filename) {
  try {
    const info = lstatSync(filename);
    return `${filename}: uid=${info.uid} mode=${(info.mode & 0o777).toString(8)} ` +
      `links=${info.nlink} file=${info.isFile()} dir=${info.isDirectory()} ` +
      `canonical=${realpathSync(filename) === filename}`;
  } catch (error) {
    return `${filename}: ${error.message}`;
  }
}

try {
  mkdirSync(runtime);
  writeFileSync(nodePath, "fake node\n", { mode: 0o755 });
  writeFileSync(entry, "fake entry\n", { mode: 0o644 });
  writeFileSync(config, "{}\n", { mode: 0o640 });
  writeFileSync(ca, "fake CA\n", { mode: 0o644 });
  writeFileSync(envFile, "CI=true\n", { mode: 0o600 });

  const build = spawnSync("cc", [
    "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror", "-static",
    join(repo, "native/linux-broker-runtime/verify.c"), "-o", verifier
  ], { encoding: "utf8", env: { PATH: "/usr/bin:/bin" } });
  assert.equal(build.error, undefined, build.error?.message);
  assert.equal(build.status, 0, build.stderr);

  passes("root-owned baseline");
  rejects("Node preload", undefined, { NODE_OPTIONS: "--require=/tmp/evil.js" });
  rejects("Node import path", undefined, { NODE_PATH: "/tmp" });
  rejects("TLS disable", undefined, { NODE_TLS_REJECT_UNAUTHORIZED: "0" });
  rejects("dynamic loader preload", undefined, { LD_PRELOAD: "/tmp/evil.so" });
  rejects("dynamic loader tunables", undefined, { GLIBC_TUNABLES: "glibc.malloc.check=3" });
  rejects("OpenSSL config", undefined, { OPENSSL_CONF: "/tmp/evil.cnf" });
  rejects("certificate override", undefined, { SSL_CERT_FILE: "/tmp/evil.pem" });
  rejects("CA mismatch", undefined, { NODE_EXTRA_CA_CERTS: "/tmp/evil.pem" });
  rejects("CA omitted from environment", undefined, { NODE_EXTRA_CA_CERTS: undefined });
  rejects("CA omitted from arguments", ["verify", runtime, nodePath, entry, config, "-", envFile]);
  chmodSync(envFile, 0o644);
  rejects("public broker environment file");
  chmodSync(envFile, 0o600);

  symlinkSync("entry.mjs", join(runtime, "entry-link"));
  passes("safe in-tree symlink");
  symlinkSync("entry-link", join(runtime, "entry-link-chain"));
  passes("safe in-tree symlink chain");
  symlinkSync(entry, join(runtime, "absolute-link"));
  rejects("absolute in-tree symlink");
  rmSync(join(runtime, "absolute-link"));
  symlinkSync(config, join(runtime, "outside-link"));
  rejects("symlink escape");
  rmSync(join(runtime, "outside-link"));

  symlinkSync(".", join(runtime, "loop"));
  rejects("symlink cycle");
  rmSync(join(runtime, "loop"));

  mkdirSync(join(runtime, "x"));
  mkdirSync(join(runtime, "deep"));
  mkdirSync(join(runtime, "deep/child"));
  writeFileSync(join(runtime, "deep/outside.js"), "safe decoy\n");
  writeFileSync(join(work, "outside.js"), "writable outside import\n", { mode: 0o666 });
  chmodSync(join(work, "outside.js"), 0o666);
  symlinkSync("../../x", join(runtime, "deep/child/a"));
  symlinkSync("a/../../outside.js", join(runtime, "deep/child/b"));
  rejects("symlink alias plus dot-dot escapes trusted tree");
  rmSync(join(runtime, "deep/child/b"));
  mkdirSync(join(work, "agent"), { mode: 0o777 });
  chmodSync(join(work, "agent"), 0o777);
  writeFileSync(join(runtime, "x/module.js"), "trusted module\n");
  symlinkSync(join(runtime, "x"), join(work, "agent/bridge"));
  symlinkSync("a/../../agent/bridge/module.js", join(runtime, "deep/child/b"));
  rejects("symlink traversal leaves and reenters trusted tree");
  rmSync(join(runtime, "deep"), { recursive: true });
  rmSync(join(runtime, "x"), { recursive: true });

  linkSync(entry, join(runtime, "hardlink"));
  rejects("hardlinked runtime file");
  rmSync(join(runtime, "hardlink"));

  mkdirSync(join(runtime, "mutable"), { mode: 0o777 });
  chmodSync(join(runtime, "mutable"), 0o777);
  rejects("writable import directory");
  rmSync(join(runtime, "mutable"), { recursive: true });

  writeFileSync(join(runtime, "mutable.mjs"), "fake import\n", { mode: 0o666 });
  chmodSync(join(runtime, "mutable.mjs"), 0o666);
  rejects("writable import file");
  rmSync(join(runtime, "mutable.mjs"));

  const fifo = join(runtime, "unexpected.fifo");
  const mkfifo = spawnSync("mkfifo", [fifo], { env: { PATH: "/usr/bin:/bin" } });
  assert.equal(mkfifo.status, 0, mkfifo.error?.message);
  rejects("nonregular runtime node");
  rmSync(fifo);

  symlinkSync(runtime, join(work, "runtime-alias"));
  rejects("noncanonical trusted root", [
    "verify", join(work, "runtime-alias"), nodePath, entry, config, ca, envFile
  ]);

  const mutableConfigDir = join(work, "mutable-config-parent");
  mkdirSync(mutableConfigDir);
  chmodSync(mutableConfigDir, 0o777);
  const unsafeConfig = join(mutableConfigDir, "config.json");
  writeFileSync(unsafeConfig, "{}\n", { mode: 0o640 });
  rejects("writable config ancestor", ["verify", runtime, nodePath, entry, unsafeConfig, ca, envFile]);
  const unsafeEnv = join(mutableConfigDir, "broker.env");
  writeFileSync(unsafeEnv, "CI=true\n", { mode: 0o600 });
  rejects("writable environment-file ancestor", ["verify", runtime, nodePath, entry, config, ca, unsafeEnv]);
  rmSync(mutableConfigDir, { recursive: true });

  preloadDir = mkdtempSync("/tmp/s-gw-runtime-preload-");
  chmodSync(preloadDir, 0o777);
  const evil = join(preloadDir, "evil.cjs");
  const marker = join(preloadDir, "executed.marker");
  writeFileSync(evil, `require("node:fs").writeFileSync(${JSON.stringify(marker)}, "executed")\n`, {
    mode: 0o666
  });
  chmodSync(evil, 0o666);
  const proof = spawnSync(process.execPath, ["-e", "0"], {
    env: { PATH: "/usr/bin:/bin", NODE_OPTIONS: `--require=${evil}` }, encoding: "utf8"
  });
  assert.equal(proof.status, 0, proof.stderr);
  assert.equal(existsSync(marker), true, "the synthetic preload did not execute");
  rmSync(marker);

  rejects("preload marker must not run", undefined, {
    NODE_OPTIONS: `--require=${evil}`
  });
  assert.equal(existsSync(marker), false);

  rmSync(nodePath);
  copyFileSync(process.execPath, nodePath);
  chmodSync(nodePath, 0o755);
  writeFileSync(entry, 'import { writeFileSync } from "node:fs"; writeFileSync(process.argv[2], "executed")\n');
  passes("copied Node baseline");
  const execArgs = ["verify-exec", runtime, nodePath, entry, config, ca, envFile, "--", marker];
  const cleanExec = run(execArgs);
  assert.equal(cleanExec.status, 0, `${cleanExec.stderr}\n` +
    ["/", "/run", work, runtime, nodePath].map(pathState).join("\n"));
  assert.equal(existsSync(marker), true, "verified Node did not execute");
  rmSync(marker);
  rejects("verify-exec preload marker must not run", execArgs, { NODE_OPTIONS: `--require=${evil}` });
  assert.equal(existsSync(marker), false);
  chmodSync(entry, 0o777);
  rejects("verify-exec writable entry must not run", execArgs);
  assert.equal(existsSync(marker), false);
  chmodSync(entry, 0o644);
  console.log("Linux broker runtime verifier self-test passed.");
} finally {
  if (preloadDir) rmSync(preloadDir, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });
}
