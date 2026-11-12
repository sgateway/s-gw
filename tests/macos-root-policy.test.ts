import { spawnSync } from "node:child_process";
import { chmodSync, cpSync, mkdirSync, mkdtempSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const macWithCompiler = process.platform === "darwin" &&
  spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;

describe.skipIf(!macWithCompiler)("macOS root policy source", () => {
  const sources = fileURLToPath(new URL("../native/macos-root-policy/", import.meta.url));

  it("rejects malformed frames and missing provider evidence for two distinct UIDs", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-policy-core-"));
    try {
      const binary = path.join(tmp, "test-policy");
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        path.join(sources, "policy-core.c"), path.join(sources, "test-policy.c"), "-o", binary],
      { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      const run = spawnSync(binary, [], { encoding: "utf8" });
      expect(run.status, run.stderr).toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("builds the IPC service and refuses an unprivileged caller", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-policy-service-"));
    try {
      const binary = path.join(tmp, "policy-service");
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        path.join(sources, "policy-core.c"), path.join(sources, "policy-service.c"),
        "-framework", "Security", "-framework", "CoreFoundation", "-lbsm", "-o", binary],
      { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      if (process.getuid?.() === 0) return;
      const run = spawnSync(binary, [], { encoding: "utf8" });
      expect(run.status).not.toBe(0);
      expect(run.stderr).toContain("requires root");
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("returns DENIED for a registered UID while provider attestation is absent", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-policy-denial-"));
    try {
      const binary = path.join(tmp, "test-service");
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        path.join(sources, "policy-core.c"), path.join(sources, "test-service.c"),
        "-framework", "Security", "-framework", "CoreFoundation", "-lbsm", "-o", binary],
      { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      const run = spawnSync(binary, [], { encoding: "utf8" });
      expect(run.status, run.stderr).toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("rejects an ad-hoc provider even if it carries the requested entitlement", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-policy-signing-"));
    try {
      const source = path.join(tmp, "provider.c");
      const candidate = path.join(tmp, "provider");
      const entitlements = path.join(tmp, "entitlements.plist");
      const verifier = path.join(tmp, "test-service");
      writeFileSync(source, "int main(void) { return 0; }\n");
      writeFileSync(entitlements, `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>com.apple.developer.networking.networkextension</key>
<array><string>content-filter-provider-systemextension</string></array>
</dict></plist>\n`);
      const buildProvider = spawnSync("cc", [source, "-o", candidate], { encoding: "utf8" });
      expect(buildProvider.status, buildProvider.stderr).toBe(0);
      const buildVerifier = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        path.join(sources, "policy-core.c"), path.join(sources, "test-service.c"),
        "-framework", "Security", "-framework", "CoreFoundation", "-lbsm", "-o", verifier],
      { encoding: "utf8" });
      expect(buildVerifier.status, buildVerifier.stderr).toBe(0);
      const unsigned = spawnSync(verifier, [candidate], { encoding: "utf8" });
      expect(unsigned.status, unsigned.stderr).toBe(0);
      const sign = spawnSync("codesign", ["--force", "--sign", "-", "--identifier", "com.sgw.test-provider",
        "--entitlements", entitlements, candidate], { encoding: "utf8" });
      expect(sign.status, sign.stderr).toBe(0);
      const verify = spawnSync("codesign", ["--verify", "--strict", candidate], { encoding: "utf8" });
      expect(verify.status, verify.stderr).toBe(0);
      const adHoc = spawnSync(verifier, [candidate], { encoding: "utf8" });
      expect(adHoc.status, adHoc.stderr).toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("binds a signed live .systemextension peer to its pinned bundle path", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-policy-peer-path-"));
    try {
      const bundle = path.join(tmp, "Provider.systemextension");
      const copied = path.join(tmp, "Copied.systemextension");
      const verifier = path.join(bundle, "Contents", "MacOS", "test-service");
      const copiedVerifier = path.join(copied, "Contents", "MacOS", "test-service");
      mkdirSync(path.dirname(verifier), { recursive: true });
      writeFileSync(path.join(bundle, "Contents", "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.sgw.test-service</string>
<key>CFBundleExecutable</key><string>test-service</string>
<key>CFBundlePackageType</key><string>XPC!</string>
<key>CFBundleVersion</key><string>1</string>
</dict></plist>\n`);
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        path.join(sources, "policy-core.c"), path.join(sources, "test-service.c"),
        "-framework", "Security", "-framework", "CoreFoundation", "-lbsm", "-o", verifier],
      { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);
      const sign = spawnSync("codesign", ["--force", "--sign", "-", "--identifier",
        "com.sgw.test-service", bundle], { encoding: "utf8" });
      expect(sign.status, sign.stderr).toBe(0);
      cpSync(bundle, copied, { recursive: true });
      const matching = spawnSync(verifier, ["--live-path", bundle], { encoding: "utf8" });
      expect(matching.status, matching.stderr).toBe(0);
      expect(spawnSync(copiedVerifier, ["--live-path", copied], { encoding: "utf8" }).status).toBe(0);
      expect(spawnSync(verifier, ["--live-path", copied], { encoding: "utf8" }).status).not.toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });

  it("rejects mutable or linked content inside a provider bundle", () => {
    const tmp = mkdtempSync(path.join(os.tmpdir(), "sgw-policy-tree-"));
    try {
      const verifier = path.join(tmp, "test-service");
      const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        path.join(sources, "policy-core.c"), path.join(sources, "test-service.c"),
        "-framework", "Security", "-framework", "CoreFoundation", "-lbsm", "-o", verifier],
      { encoding: "utf8" });
      expect(build.status, build.stderr).toBe(0);

      const bundle = path.join(tmp, "Provider.systemextension");
      const contents = path.join(bundle, "Contents");
      const macos = path.join(contents, "MacOS");
      const executable = path.join(macos, "provider");
      mkdirSync(macos, { recursive: true });
      writeFileSync(executable, "signed bytes\n");
      const check = () => spawnSync(verifier, ["--tree", bundle], { encoding: "utf8" });
      expect(check().status).toBe(0);

      chmodSync(executable, 0o775);
      expect(check().status).not.toBe(0);
      chmodSync(executable, 0o644);
      chmodSync(macos, 0o775);
      expect(check().status).not.toBe(0);
      chmodSync(macos, 0o755);
      expect(check().status).toBe(0);

      const acl = `${os.userInfo().username} allow write`;
      const allow = spawnSync("chmod", ["+a", acl, contents], { encoding: "utf8" });
      expect(allow.status, allow.stderr).toBe(0);
      expect(statSync(contents).mode & 0o022).toBe(0);
      expect(check().status).not.toBe(0);
      const clear = spawnSync("chmod", ["-N", contents], { encoding: "utf8" });
      expect(clear.status, clear.stderr).toBe(0);
      expect(check().status).toBe(0);

      symlinkSync(executable, path.join(contents, "redirect"));
      expect(check().status).not.toBe(0);
    } finally { rmSync(tmp, { recursive: true, force: true }); }
  });
});
