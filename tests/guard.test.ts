import { execFileSync } from "node:child_process";
import { mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { prepareGuardedRun, resolveGuardLauncher } from "../src/guard.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";
const repoRoot = process.cwd();
const tsxCli = path.join(repoRoot, "node_modules", "tsx", "dist", "cli.mjs");

function fakeGithubToken(): string {
  return ["gh", "p_", "abcdefghijklmnopqrstuvwxyz0123456789ABCD"].join("");
}

function fakeOpenAiToken(suffix: string): string {
  return ["sk", "-proj-", "abcdefghijklmnopqrstuvwxyz1234567890", suffix].join("");
}

beforeEach(async () => {
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-guard-test-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_RECOVERY_HOME = `${tmpHome}-recovery`;
  process.env.SGW_MASTER_PASSPHRASE = "guard test passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
});

afterEach(async () => {
  delete process.env.SGW_HOME;
  delete process.env.SGW_RECOVERY_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
  }
});

describe("guard mode", () => {
  it("replaces credential-looking environment values with SGW handles before launch", async () => {
    const store = new SecretStore(tmpHome);
    await store.init();
    const raw = fakeOpenAiToken("_guard");

    const prepared = await prepareGuardedRun(store, {
      agent: "codex",
      command: process.execPath,
      args: ["-e", "console.log(process.env.OPENAI_API_KEY)"],
      env: {
        OPENAI_API_KEY: raw,
        PATH: "/usr/bin:/bin"
      },
      persist: true
    });

    expect(prepared.env.OPENAI_API_KEY).toMatch(/^<<SGW_SECRET:s-gw:api-token:/);
    expect(prepared.env.OPENAI_API_KEY).not.toContain(raw);
    expect(prepared.plan.scrubbedEnv).toHaveLength(1);
    expect(prepared.plan.scrubbedEnv[0].name).toBe("OPENAI_API_KEY");
    expect(prepared.env.PATH).toBe("/usr/bin:/bin");

    const handles = await store.listHandles();
    expect(handles).toHaveLength(1);
    expect(handles[0].source).toBe("guard-env:codex:OPENAI_API_KEY");
    expect(handles[0].policy.injectEnv).toBe("OPENAI_API_KEY");
  });

  it("dry-run uses preview handles and does not persist the environment secret", async () => {
    const store = new SecretStore(tmpHome);
    await store.init();
    const raw = fakeGithubToken();

    const prepared = await prepareGuardedRun(store, {
      agent: "claude-code",
      command: process.execPath,
      env: {
        GITHUB_TOKEN: raw,
        PATH: "/usr/bin:/bin"
      },
      persist: false
    });

    expect(JSON.stringify(prepared.plan)).not.toContain(raw);
    expect(prepared.env.GITHUB_TOKEN).toMatch(/^<<SGW_SECRET:s-gw:preview:api-token:/);
    expect(await store.listHandles()).toHaveLength(0);
  });

  it("scans credential-like npm environment values by default", async () => {
    const store = new SecretStore(tmpHome);
    await store.init();
    const raw = fakeGithubToken();

    const prepared = await prepareGuardedRun(store, {
      agent: "codex",
      command: process.execPath,
      env: { npm_config_password: raw },
      persist: false
    });

    expect(prepared.env.npm_config_password).toMatch(/^<<SGW_SECRET:/);
    expect(prepared.plan.scrubbedEnv.map(item => item.name)).toContain("npm_config_password");
    expect(JSON.stringify(prepared)).not.toContain(raw);
  });

  it("keeps raw npm values only in the explicit compatibility mode", async () => {
    const store = new SecretStore(tmpHome);
    await store.init();
    const raw = fakeGithubToken();
    const prepared = await prepareGuardedRun(store, {
      agent: "codex", command: process.execPath, env: { npm_config_password: raw },
      strictNpmEnv: false, persist: false
    });
    expect(prepared.env.npm_config_password).toBe(raw);
    expect(prepared.plan.warnings).toContain("Legacy npm environment compatibility passes npm-prefixed credentials to the agent unchanged.");
  });

  it("scans npm values and tokenizes short auth fields in strict npm mode", async () => {
    const store = new SecretStore(tmpHome);
    await store.init();
    const raw = fakeGithubToken();
    const env = {
      npm_config_custom_setting: raw,
      npm_config_password: "p4",
      "NPM_CONFIG_//registry.example.test/:_authToken": "q7",
      npm_config_registry: "https://registry.example.test/",
      npm_config_user_agent: "npm/10 node/v22",
      npm_config_always_auth: "true"
    };

    const prepared = await prepareGuardedRun(store, {
      agent: "codex",
      command: process.execPath,
      env,
      strictNpmEnv: true,
      persist: true
    });

    expect(prepared.env.npm_config_custom_setting).toMatch(/^<<SGW_SECRET:/);
    expect(prepared.env.npm_config_password).toMatch(/^<<SGW_SECRET:/);
    expect(prepared.env["NPM_CONFIG_//registry.example.test/:_authToken"]).toMatch(/^<<SGW_SECRET:/);
    expect(prepared.env.npm_config_registry).toBe(env.npm_config_registry);
    expect(prepared.env.npm_config_user_agent).toBe(env.npm_config_user_agent);
    expect(prepared.env.npm_config_always_auth).toBe(env.npm_config_always_auth);
    expect(JSON.stringify(prepared)).not.toContain(raw);
    const handles = await store.listHandles();
    expect(handles).toHaveLength(3);
    expect(handles.find((item) => item.source.includes("/_authToken"))?.policy.injectEnv).toBeUndefined();
  });

  it("tokenizes npm registry URLs carrying credentials in strict npm mode", async () => {
    const store = new SecretStore(tmpHome);
    await store.init();
    const env = {
      npm_config_registry: "https://user:tiny@registry.example.test/",
      npm_config_cache: "https://registry.example.test/cache?access_token=x2"
    };

    const prepared = await prepareGuardedRun(store, {
      agent: "codex",
      command: process.execPath,
      env,
      strictNpmEnv: true,
      persist: true
    });

    expect(prepared.env.npm_config_registry).toMatch(/^<<SGW_SECRET:/);
    expect(prepared.env.npm_config_cache).toMatch(/^<<SGW_SECRET:/);
    expect(JSON.stringify(prepared)).not.toContain("tiny");
    expect(JSON.stringify(prepared)).not.toContain("access_token=x2");
    const handles = await store.listHandles();
    expect(handles).toHaveLength(2);
    expect(handles.every((item) => item.source.startsWith("guard-env:codex:npm_config_"))).toBe(true);
  });

  it("tokenizes short npm credentials in custom URL parameters and fragments", async () => {
    const store = new SecretStore(tmpHome);
    await store.init();
    const env = {
      npm_config_registry: "https://registry.example.test/?custom_auth=x2",
      npm_config_disturl: "https://registry.example.test/#_authToken=q7",
      npm_config_cache: "registry.example.test/cache?access_token=y8",
      npm_config_user_agent: "npm/10 node/v22"
    };

    const prepared = await prepareGuardedRun(store, {
      agent: "codex", command: process.execPath, env,
      strictNpmEnv: true, persist: true
    });

    for (const name of ["npm_config_registry", "npm_config_disturl", "npm_config_cache"] as const) {
      expect(prepared.env[name]).toMatch(/^<<SGW_SECRET:/);
    }
    expect(prepared.env.npm_config_user_agent).toBe(env.npm_config_user_agent);
    expect(JSON.stringify(prepared)).not.toContain("custom_auth=x2");
    expect(JSON.stringify(prepared)).not.toContain("_authToken=q7");
    expect(JSON.stringify(prepared)).not.toContain("access_token=y8");
  });

  it("requires environment scrubbing when strict npm mode is selected", async () => {
    const store = new SecretStore(tmpHome);
    await store.init();
    await expect(prepareGuardedRun(store, {
      agent: "codex",
      command: process.execPath,
      env: { npm_config_password: "p4" },
      strictNpmEnv: true,
      scrubEnv: false
    })).rejects.toThrow("requires credential environment scrubbing");
  });

  it("drops the s-gw master passphrase before launching a guarded agent", async () => {
    const store = new SecretStore(tmpHome);
    await store.init();

    const prepared = await prepareGuardedRun(store, {
      agent: "codex",
      command: process.execPath,
      env: {
        SGW_MASTER_PASSPHRASE: "guard-master-should-not-leak",
        SGW_GUARD_INSTRUCTIONS: "stale instructions",
        PATH: "/usr/bin:/bin"
      },
      persist: false
    });

    expect(prepared.env.SGW_MASTER_PASSPHRASE).toBeUndefined();
    expect(prepared.env.SGW_GUARD_INSTRUCTIONS).not.toContain("stale instructions");
    expect(prepared.env.SGW_GUARD_INSTRUCTIONS).toContain("s-gw guard mode is active");
    expect(JSON.stringify(prepared)).not.toContain("guard-master-should-not-leak");
  });

  it("CLI dry-run keeps raw secrets out of stdout", () => {
    const raw = fakeOpenAiToken("_cli");
    const out = execFileSync(
      process.execPath,
      [
        tsxCli,
        "src/cli.ts",
        "guard",
        "run",
        "codex",
        "--dry-run",
        "--command",
        process.execPath,
        "--",
        "-v"
      ],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          SGW_HOME: tmpHome,
          SGW_RECOVERY_HOME: `${tmpHome}-recovery`,
          SGW_MASTER_PASSPHRASE: "guard cli passphrase",
          SGW_DISABLE_KEYCHAIN: "1",
          OPENAI_API_KEY: raw
        },
        encoding: "utf8"
      }
    );

    expect(out).not.toContain(raw);
    const plan = JSON.parse(out);
    expect(plan.agent.id).toBe("codex");
    expect(plan.scrubbedEnv.some((item: { name: string }) => item.name === "OPENAI_API_KEY")).toBe(true);
    expect(plan.args).toEqual(["-v"]);
    expect(plan.dryRun).toBe(true);
  });

  it("CLI dry-run replaces npm authentication values by default", () => {
    const out = execFileSync(
      process.execPath,
      [tsxCli, "src/cli.ts", "guard", "run", "codex", "--dry-run", "--command", process.execPath],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          SGW_HOME: tmpHome,
          SGW_RECOVERY_HOME: `${tmpHome}-recovery`,
          SGW_MASTER_PASSPHRASE: "guard cli passphrase",
          SGW_DISABLE_KEYCHAIN: "1",
          npm_config_password: "short-private-registry-password"
        },
        encoding: "utf8"
      }
    );

    expect(out).not.toContain("short-private-registry-password");
    const plan = JSON.parse(out);
    expect(plan.scrubbedEnv.some((item: { name: string }) => item.name === "npm_config_password")).toBe(true);
  });

  it("passes a handle to a launched child in the default npm mode", () => {
    const raw = "short-private-registry-password";
    const out = execFileSync(
      process.execPath,
      [
        tsxCli, "src/cli.ts", "guard", "run", "codex", "--command", process.execPath,
        "--", "-e", "process.stdout.write(process.env.npm_config_password || '')"
      ],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          SGW_HOME: tmpHome,
          SGW_RECOVERY_HOME: `${tmpHome}-recovery`,
          SGW_MASTER_PASSPHRASE: "guard cli passphrase",
          SGW_DISABLE_KEYCHAIN: "1",
          npm_config_password: raw
        },
        encoding: "utf8"
      }
    );

    expect(out).toMatch(/^<<SGW_SECRET:s-gw:password:/);
    expect(out).not.toContain(raw);
  });

  it("keeps the CLI raw npm compatibility path explicit", () => {
    const raw = "short-private-registry-password";
    const out = execFileSync(process.execPath, [
      tsxCli, "src/cli.ts", "guard", "run", "codex", "--allow-raw-npm-env",
      "--command", process.execPath, "--", "-e", "process.stdout.write(process.env.npm_config_password || '')"
    ], { cwd: repoRoot, env: {
      ...process.env, SGW_HOME: tmpHome, SGW_RECOVERY_HOME: `${tmpHome}-recovery`,
      SGW_MASTER_PASSPHRASE: "guard cli passphrase", SGW_DISABLE_KEYCHAIN: "1",
      npm_config_password: raw
    }, encoding: "utf8" });
    expect(out).toBe(raw);
  });

  it("launches canonical npm cmd shims without a command shell", async () => {
    const binDir = path.join(tmpHome, "npm bin");
    const target = path.join(binDir, "node_modules", "guard-fixture", "run.js");
    const shim = path.join(binDir, "guard-fixture.cmd");
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, "process.stdout.write(JSON.stringify(process.argv.slice(2)));\n", "utf8");
    await writeFile(shim, npmNodeCmdShim("node_modules\\guard-fixture\\run.js"), "utf8");

    const hostileArgs = [
      "plain",
      "& echo injected",
      "| whoami",
      "%PATH%",
      "!PROMPT!",
      "^&",
      "$(touch should-not-run)",
      "quote\"and\\slash"
    ];
    const launcher = resolveGuardLauncher("guard-fixture", hostileArgs, {
      platform: "win32",
      cwd: tmpHome,
      env: { Path: binDir, PATHEXT: ".EXE;.CMD" }
    });

    expect(launcher.command).toBe(process.execPath);
    expect(launcher.args[0]).toBe(await realpath(target));
    expect(JSON.parse(execFileSync(launcher.command, launcher.args, { encoding: "utf8" }))).toEqual(hostileArgs);
  });

  it("accepts canonical project-local npm cmd shims within node_modules", async () => {
    const modules = path.join(tmpHome, "node_modules");
    const binDir = path.join(modules, ".bin");
    const target = path.join(modules, "guard-fixture", "run.cjs");
    const shim = path.join(binDir, "guard-fixture.cmd");
    await mkdir(path.dirname(target), { recursive: true });
    await mkdir(binDir, { recursive: true });
    await writeFile(target, "process.stdout.write('local');\n", "utf8");
    await writeFile(shim, npmNodeCmdShim("..\\guard-fixture\\run.cjs"), "utf8");

    const launcher = resolveGuardLauncher(shim, [], { platform: "win32" });
    expect(execFileSync(launcher.command, launcher.args, { encoding: "utf8" })).toBe("local");
  });

  it("refuses arbitrary Windows script launchers", async () => {
    const cmd = path.join(tmpHome, "unsafe.cmd");
    const bat = path.join(tmpHome, "unsafe.bat");
    const ps1 = path.join(tmpHome, "unsafe.ps1");
    const py = path.join(tmpHome, "unsafe.py");
    await writeFile(cmd, "@echo off\r\necho unsafe %*\r\n", "utf8");
    await writeFile(bat, "@echo off\r\necho unsafe %*\r\n", "utf8");
    await writeFile(ps1, "Write-Output unsafe\r\n", "utf8");
    await writeFile(py, "print('unsafe')\n", "utf8");

    expect(() => resolveGuardLauncher(cmd, ["& whoami"], { platform: "win32" }))
      .toThrow("not a canonical npm Node.js .cmd shim");
    expect(() => resolveGuardLauncher(bat, ["& whoami"], { platform: "win32" }))
      .toThrow("will not launch script");
    expect(() => resolveGuardLauncher(ps1, [], { platform: "win32" }))
      .toThrow("will not launch script");
    expect(() => resolveGuardLauncher(py, [], { platform: "win32" }))
      .toThrow("will not launch non-native executable");
  });

  it("fails closed for unresolved Windows commands and scripts", () => {
    const missing = path.join(tmpHome, "missing-agent.cmd");
    expect(() => resolveGuardLauncher(missing, [], { platform: "win32", env: { PATH: "" } }))
      .toThrow(/will not launch unresolved script/i);
    expect(() => resolveGuardLauncher("missing-agent", [], { platform: "win32", env: { PATH: "" } }))
      .toThrow(/could not resolve executable/i);
    expect(() => resolveGuardLauncher("missing-agent.ps1", [], { platform: "win32", env: { PATH: "" } }))
      .toThrow(/will not launch unresolved script/i);
  });

  it("keeps explicit Windows executables shell-free", async () => {
    const executable = path.join(tmpHome, "agent.exe");
    const args = ["& whoami", "%PATH%", "quoted value"];
    await writeFile(executable, "fixture", "utf8");

    expect(resolveGuardLauncher(executable, args, { platform: "win32" })).toEqual({
      command: executable,
      args
    });
  });
});

function npmNodeCmdShim(relativeTarget: string): string {
  return [
    "@ECHO off",
    "GOTO start",
    ":find_dp0",
    "SET dp0=%~dp0",
    "EXIT /b",
    ":start",
    "SETLOCAL",
    "CALL :find_dp0",
    "",
    'IF EXIST "%dp0%\\node.exe" (',
    '  SET "_prog=%dp0%\\node.exe"',
    ") ELSE (",
    '  SET "_prog=node"',
    "  SET PATHEXT=%PATHEXT:;.JS;=;%",
    ")",
    "",
    `endLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & "%_prog%"  "%dp0%\\${relativeTarget}" %*`,
    ""
  ].join("\r\n");
}
