import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { prepareGuardedRun } from "../src/guard.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";
const repoRoot = process.cwd();
const tsxBin = path.join(repoRoot, "node_modules", ".bin", process.platform === "win32" ? "tsx.cmd" : "tsx");

function fakeGithubToken(): string {
  return ["gh", "p_", "abcdefghijklmnopqrstuvwxyz0123456789ABCD"].join("");
}

function fakeOpenAiToken(suffix: string): string {
  return ["sk", "-proj-", "abcdefghijklmnopqrstuvwxyz1234567890", suffix].join("");
}

beforeEach(async () => {
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-guard-test-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_MASTER_PASSPHRASE = "guard test passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
});

afterEach(async () => {
  delete process.env.SGW_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true });
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
      tsxBin,
      [
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
});
