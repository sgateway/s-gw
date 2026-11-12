import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { stageAnthropicRuntime } from "../scripts/stage-anthropic-runtime.mjs";

const root = process.cwd();
const runtime = "node_modules/@anthropic-ai/sandbox-runtime";
const patched = {
  x64: "c8364995249b76accbc29253aef3f22bf972bb536436af436b4714e493a7252c",
  arm64: "29f717c1b0ee79b5ddda69beef52d759a0dc238ed8389300f7b7875b291cb639"
};
const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) rmSync(dir, { recursive: true, force: true });
});

function fixture() {
  const dir = mkdtempSync(path.join(tmpdir(), "sgw-anthropic-stage-"));
  dirs.push(dir);
  for (const name of ["package.json", "package-lock.json"]) copy(name);
  for (const name of ["zod", "@pondwader/socks5-server", "commander", "shell-quote"]) {
    copy(`node_modules/${name}/package.json`);
  }
  copy(`${runtime}/package.json`);
  const manifestFile = path.join(dir, runtime, "package.json");
  const manifest = JSON.parse(readFileSync(manifestFile, "utf8"));
  manifest.dependencies.zod = "^3.24.1";
  writeFileSync(manifestFile, `${JSON.stringify(manifest, null, 2)}\n`);
  copy(`${runtime}/vendor/seccomp-src/apply-seccomp.c`);
  for (const prefix of ["vendor", "dist/vendor"]) {
    for (const arch of ["x64", "arm64"]) copy(`${runtime}/${prefix}/seccomp/${arch}/apply-seccomp`);
  }
  for (const arch of ["x64", "arm64"]) copy(`vendor/anthropic-seccomp/${arch}/apply-seccomp`);
  return dir;

  function copy(name: string) {
    const target = path.join(dir, name);
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(path.join(root, name), target);
  }
}

function sha256(file: string) {
  return createHash("sha256").update(readFileSync(file)).digest("hex");
}

describe("Anthropic runtime staging", () => {
  it("bundles both Linux seccomp helpers and stays idempotent", () => {
    const dir = fixture();
    stageAnthropicRuntime(dir);
    for (const prefix of ["vendor", "dist/vendor"]) {
      for (const arch of ["x64", "arm64"] as const) {
        expect(sha256(path.join(dir, runtime, prefix, "seccomp", arch, "apply-seccomp"))).toBe(patched[arch]);
      }
    }
    const manifest = JSON.parse(readFileSync(path.join(dir, runtime, "package.json"), "utf8"));
    expect(manifest.dependencies.zod).toBe("^4.6.7");
    expect(() => stageAnthropicRuntime(dir)).not.toThrow();
  });

  it("refuses an unreviewed helper before changing the runtime", () => {
    const dir = fixture();
    const file = path.join(dir, runtime, "vendor/seccomp/x64/apply-seccomp");
    writeFileSync(file, "unexpected helper");
    expect(() => stageAnthropicRuntime(dir)).toThrow("installed Anthropic x64 seccomp helper changed");
    const manifest = JSON.parse(readFileSync(path.join(dir, runtime, "package.json"), "utf8"));
    expect(manifest.dependencies.zod).toBe("^3.24.1");
  });
});
