import { execFileSync } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { KNOWN_COMMANDS, suggestCommands, unknownCommandMessage } from "../src/command-suggest.js";
import { CURRENT_VERSION } from "../src/version.js";

const repoRoot = process.cwd();
const tsxBin = path.join(repoRoot, "node_modules", ".bin", process.platform === "win32" ? "tsx.cmd" : "tsx");

function fakeAwsAccessKey(): string {
  return ["A", "KIA", "IOSFODNN7EXAMPLE"].join("");
}

describe("command suggestions", () => {
  it("maps a one-letter status typo to status", () => {
    expect(suggestCommands(["statu"])).toContain("status");
  });

  it("maps a pluralized secrets list to secret list", () => {
    expect(suggestCommands(["secrets", "list"])).toContain("secret list");
  });

  it("maps an update typo to the release check", () => {
    expect(suggestCommands(["updat", "check"])).toContain("update check");
  });

  it("lists subcommands when the noun is right but the verb is missing", () => {
    const out = suggestCommands(["secret"]);
    expect(out).toContain("secret add");
    expect(out).toContain("secret list");
  });

  it("matches the verb even when a positional arg is typed after it", () => {
    expect(suggestCommands(["aproove", "abc123"])).toContain("approve");
    expect(suggestCommands(["deni", "req-1"])).toContain("deny");
    expect(suggestCommands(["exicute", "req-1"])).toContain("execute");
  });

  it("disambiguates request (singular) toward requests", () => {
    expect(suggestCommands(["request"])).toContain("requests");
  });

  it("returns nothing for total nonsense so the message falls back to help", () => {
    expect(suggestCommands(["totalnonsense"])).toEqual([]);
    expect(unknownCommandMessage(["totalnonsense"])).toContain("Run `s-gw help`");
  });

  it("never suggests a command that is not in the known set", () => {
    for (const candidate of suggestCommands(["secret"])) {
      expect(KNOWN_COMMANDS).toContain(candidate);
    }
  });

  it("builds an actionable unknown-command message", () => {
    const msg = unknownCommandMessage(["statu"]);
    expect(msg).toMatch(/^Unknown command: statu\./);
    expect(msg).toContain("s-gw status");
    expect(msg).toContain("s-gw help");
  });
});

describe("CLI unknown-command behavior (end to end)", () => {
  it("reports update status without requiring local store setup", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-update-"));
    try {
      const result = JSON.parse(execFileSync(tsxBin, ["src/cli.ts", "update", "check"], {
        cwd: repoRoot,
        env: {
          ...process.env,
          SGW_HOME: home,
          SGW_RECOVERY_HOME: `${home}-recovery`,
          SGW_DISABLE_UPDATE_CHECK: "1"
        },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      }));

      expect(result).toMatchObject({
        checked: false,
        currentVersion: CURRENT_VERSION,
        available: false
      });
    } finally {
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  });

  it("updates and auto-arranges approval policies, and documents both commands", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-policy-"));
    const recoveryHome = `${home}-recovery`;
    const cargoTarget = `${home}-cargo`;
    const env = {
      ...process.env,
      SGW_HOME: home,
      SGW_RECOVERY_HOME: recoveryHome,
      CARGO_TARGET_DIR: cargoTarget,
      SGW_MASTER_PASSPHRASE: "cli-policy-test-passphrase",
      SGW_DISABLE_KEYCHAIN: "1",
      SGW_DISABLE_ONEPASSWORD_BACKUP: "1"
    };
    const run = (args: string[]) => execFileSync(tsxBin, ["src/cli.ts", ...args], {
      cwd: repoRoot,
      env,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });

    try {
      const broad = JSON.parse(run([
        "approval",
        "policy",
        "add",
        "--name",
        "Codex broad ask",
        "--decision",
        "ask",
        "--priority",
        "10",
        "--agent",
        "Codex"
      ]));
      const specific = JSON.parse(run([
        "approval",
        "policy",
        "add",
        "--name",
        "Codex AWS allow",
        "--decision",
        "allow",
        "--priority",
        "20",
        "--agent",
        "Codex",
        "--binding",
        "SGW_CLI_POLICY=s-gw:api-token:cli",
        "--expires-at",
        "2030-01-01T00:00:00.000Z"
      ]));

      let emptyUpdateError: { stderr?: string } | undefined;
      try {
        run(["approval", "policy", "update", "--id", specific.id]);
      } catch (error) {
        emptyUpdateError = error as { stderr?: string };
      }
      expect(emptyUpdateError?.stderr).toContain("at least one change");

      const updated = JSON.parse(run([
        "approval",
        "policy",
        "update",
        "--id",
        specific.id,
        "--name",
        "Codex AWS deny",
        "--decision",
        "deny",
        "--command",
        "aws",
        "--clear-expiry"
      ]));
      expect(updated).toMatchObject({
        id: specific.id,
        name: "Codex AWS deny",
        decision: "deny"
      });
      expect(updated.conditions).toMatchObject({
        agents: ["codex"],
        commands: ["aws"],
        envBindings: [{ handle: "s-gw:api-token:cli", injectEnv: "SGW_CLI_POLICY" }]
      });
      expect(updated.expiresAt).toBeUndefined();

      const arranged = JSON.parse(run(["approval", "policy", "arrange"]));
      expect(arranged.reordered).toBeGreaterThan(0);
      expect(arranged.rules.map((rule: { id: string }) => rule.id)).toEqual([specific.id, broad.id]);

      const listed = JSON.parse(run(["approval", "policy", "list"]));
      expect(listed.map((rule: { id: string }) => rule.id)).toEqual([specific.id, broad.id]);

      const help = run(["help"]);
      expect(help).toContain("s-gw approval policy update --id POLICY_ID");
      expect(help).toContain("s-gw approval policy arrange");
    } finally {
      await rm(home, { recursive: true, force: true });
      await rm(recoveryHome, { recursive: true, force: true });
      await rm(cargoTarget, { recursive: true, force: true });
    }
  });

  it("exits non-zero and prints a suggestion to stderr for a typo", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-typo-"));
    let stderr = "";
    let code = 0;
    try {
      execFileSync(tsxBin, ["src/cli.ts", "statu"], {
        cwd: repoRoot,
        env: {
          ...process.env,
          SGW_HOME: home,
          SGW_RECOVERY_HOME: `${home}-recovery`,
          SGW_DISABLE_KEYCHAIN: "1"
        },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (error) {
      const err = error as { status?: number; stderr?: string };
      code = err.status ?? 0;
      stderr = err.stderr ?? "";
    } finally {
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }

    expect(code).toBe(1);
    expect(stderr).toContain("s-gw error: Unknown command: statu");
    expect(stderr).toContain("Did you mean: s-gw status");
  });

  it("explains an already-in-use console port instead of dumping a raw listen error", async () => {
    // Occupy a port so `s-gw console` can't bind it — mirrors a fresh user who
    // ran `s-gw setup`/`s-gw start` (which leave a console daemon) and then
    // tries the foreground `s-gw console`.
    const occupier = createServer((_req, res) => res.end("busy"));
    const port = await new Promise<number>((resolve) => {
      occupier.listen(0, "127.0.0.1", () => resolve((occupier.address() as AddressInfo).port));
    });
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-port-"));

    let stderr = "";
    let code = 0;
    try {
      execFileSync(tsxBin, ["src/cli.ts", "console", "--port", String(port), "--no-open"], {
        cwd: repoRoot,
        env: {
          ...process.env,
          SGW_HOME: home,
          SGW_RECOVERY_HOME: `${home}-recovery`,
          SGW_DISABLE_KEYCHAIN: "1",
          SGW_MASTER_PASSPHRASE: "throwaway-eaddr-test"
        },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (error) {
      const err = error as { status?: number; stderr?: string };
      code = err.status ?? 0;
      stderr = err.stderr ?? "";
    } finally {
      await new Promise<void>((resolve) => occupier.close(() => resolve()));
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }

    expect(code).toBe(1);
    expect(stderr).toContain(`Port ${port} on 127.0.0.1 is already in use`);
    expect(stderr).toContain("already running");
    expect(stderr).toContain("s-gw stop");
    // The friendly message must replace, not include, the raw Node listen error.
    expect(stderr).not.toContain("EADDRINUSE");
  });

  it("preserves hyphenated --arg values and secondary env bindings in env-command requests", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-args-"));
    const env = {
      ...process.env,
      SGW_HOME: home,
      SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_MASTER_PASSPHRASE: "cli-arg-test-passphrase",
      SGW_DISABLE_KEYCHAIN: "1"
    };

    try {
      const secret = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "secret",
        "add",
        "--name",
        "aws secret",
        "--type",
        "credential",
        "--value-stdin",
        "--inject-env",
        "AWS_SECRET_ACCESS_KEY",
        "--allow-command",
        process.execPath
      ], {
        cwd: repoRoot,
        env,
        input: "aws-secret-cli-value-123456789",
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"]
      }));

      const access = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "secret",
        "add",
        "--name",
        "aws access",
        "--type",
        "access-key",
        "--value-stdin",
        "--inject-env",
        "AWS_ACCESS_KEY_ID",
        "--allow-command",
        process.execPath
      ], {
        cwd: repoRoot,
        env,
        input: fakeAwsAccessKey(),
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"]
      }));

      const request = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "request",
        "env-command",
        secret.handle,
        "--command",
        process.execPath,
        "--inject-env",
        "AWS_SECRET_ACCESS_KEY",
        "--with-env",
        `AWS_ACCESS_KEY_ID=${access.handle}`,
        "--arg",
        "ec2",
        "--arg",
        "describe-instances",
        "--arg",
        "--region",
        "--arg",
        "us-west-2",
        "--arg=--output",
        "--arg",
        "json",
        "--timeout-ms",
        "1800000"
      ], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      }));

      expect(request.action.args).toEqual([
        "ec2",
        "describe-instances",
        "--region",
        "us-west-2",
        "--output",
        "json"
      ]);
      expect(request.action.env).toEqual([{ handle: access.handle, injectEnv: "AWS_ACCESS_KEY_ID" }]);
      expect(request.action.timeoutMs).toBe(1_800_000);
    } finally {
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  });

  it("executes the next approved request through a stable command shape", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-next-"));
    const env = {
      ...process.env,
      SGW_HOME: home,
      SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_MASTER_PASSPHRASE: "cli-next-test-passphrase",
      SGW_DISABLE_KEYCHAIN: "1"
    };

    try {
      const secretValue = "execute-next-secret-value-123456789";
      const secret = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "secret",
        "add",
        "--name",
        "execute next",
        "--type",
        "credential",
        "--value-stdin",
        "--inject-env",
        "SGW_NEXT_TOKEN",
        "--allow-command",
        process.execPath
      ], {
        cwd: repoRoot,
        env,
        input: secretValue,
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"]
      }));

      const request = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "request",
        "env-command",
        secret.handle,
        "--command",
        process.execPath,
        "--inject-env",
        "SGW_NEXT_TOKEN",
        "--arg",
        "-e",
        "--arg",
        "console.log(process.env.SGW_NEXT_TOKEN)"
      ], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      }));

      execFileSync(tsxBin, ["src/cli.ts", "approve", request.id], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      });

      const executed = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "execute-next",
        "--handle",
        secret.handle
      ], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      }));

      expect(executed.requestId).toBe(request.id);
      expect(executed.summary.stdout).not.toContain(secretValue);
      expect(executed.summary.stdout).toContain(`<<SGW_SECRET:${secret.handle}>>`);
    } finally {
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  });

  it("wraps the AWS-dev handle pair behind a first-class request/run shortcut", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-aws-"));
    const wrapper = path.join(home, "aws-wrapper");
    const env = {
      ...process.env,
      SGW_HOME: home,
      SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_MASTER_PASSPHRASE: "cli-aws-test-passphrase",
      SGW_DISABLE_KEYCHAIN: "1"
    };

    await writeFile(wrapper, [
      "#!/bin/sh",
      "printf 'access=%s\\n' \"$SGW_AWS_DEV_ACCESS_KEY_ID\"",
      "printf 'secret=%s\\n' \"$SGW_AWS_DEV_CREDENTIAL\"",
      "printf 'args=%s\\n' \"$*\""
    ].join("\n"));
    await chmod(wrapper, 0o700);

    try {
      const secret = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "secret",
        "add",
        "--name",
        "AWS-dev",
        "--type",
        "credential",
        "--value-stdin",
        "--inject-env",
        "SGW_AWS_DEV_CREDENTIAL",
        "--allow-command",
        wrapper
      ], {
        cwd: repoRoot,
        env,
        input: "aws-secret-shortcut-value-123456789",
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"]
      }));

      const access = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "secret",
        "add",
        "--name",
        "AWS-dev-access-key-id",
        "--type",
        "credential",
        "--value-stdin",
        "--inject-env",
        "SGW_AWS_DEV_ACCESS_KEY_ID",
        "--allow-command",
        wrapper
      ], {
        cwd: repoRoot,
        env,
        input: fakeAwsAccessKey(),
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"]
      }));

      const plan = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "aws",
        "plan",
        "--wrapper",
        wrapper
      ], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      }));
      expect(plan.secretHandle).toBe(secret.handle);
      expect(plan.accessKeyHandle).toBe(access.handle);
      expect(plan.wrapper).toBe(wrapper);
      expect(plan.sampleRunCommand).toBe(`s-gw aws run --wrapper ${wrapper} -- sts get-caller-identity`);

      expect(() => execFileSync(tsxBin, ["src/cli.ts", "aws", "--version"], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      })).toThrow(/does not run the AWS CLI/);

      const request = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "aws",
        "request",
        "--wrapper",
        wrapper,
        "--",
        "sts",
        "get-caller-identity"
      ], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      }));

      expect(request.approvalRequired).toBe(true);
      expect(request.localApprovalCommand).toContain("--duration 8h");
      expect(request.localRunCommand).toBe(`s-gw execute ${request.request.id}`);
      expect(request.repeatCommand).toBe(`s-gw aws run --wrapper ${wrapper} -- sts get-caller-identity`);
      expect(request.request.handle).toBe(secret.handle);
      expect(request.request.action.env).toEqual([{ handle: access.handle, injectEnv: "SGW_AWS_DEV_ACCESS_KEY_ID" }]);
      expect(request.request.action.command).toBe(wrapper);
      expect(request.request.action.args).toEqual(["sts", "get-caller-identity"]);

      execFileSync(tsxBin, [
        "src/cli.ts",
        "approve",
        request.request.id,
        "--mode",
        "timed-session",
        "--duration",
        "8h",
        "--agent-scope",
        "any-agent"
      ], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      });

      const beforeRun = await readFile(path.join(home, "store.json"), "utf8");
      const run = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts",
        "aws",
        "run",
        "--wrapper",
        wrapper,
        "--",
        "ec2",
        "describe-instances",
        "--region",
        "us-west-2"
      ], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      }));

      expect(run.approvalRequired).toBe(false);
      expect(run.reusableAuthorization).toMatchObject({ kind: "grant" });
      expect(run.summary.stdout).toContain(`<<SGW_SECRET:${secret.handle}>>`);
      expect(run.summary.stdout).toContain(`<<SGW_SECRET:${access.handle}>>`);
      expect(run.summary.stdout).not.toContain("aws-secret-shortcut-value-123456789");
      expect(run.summary.stdout).not.toContain(fakeAwsAccessKey());
      expect(run.summary.stdout).toContain("args=ec2 describe-instances --region us-west-2");
      expect(await readFile(path.join(home, "store.json"), "utf8")).toBe(beforeRun);

      const raw = execFileSync(tsxBin, [
        "src/cli.ts",
        "aws",
        "run",
        "--raw",
        "--wrapper",
        wrapper,
        "--",
        "sts",
        "get-caller-identity"
      ], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      });

      expect(raw).toContain(`<<SGW_SECRET:${secret.handle}>>`);
      expect(raw).toContain(`<<SGW_SECRET:${access.handle}>>`);
      expect(raw).toContain("args=sts get-caller-identity");
      expect(raw).not.toContain("aws-secret-shortcut-value-123456789");
      expect(raw).not.toContain(fakeAwsAccessKey());
    } finally {
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 15_000);

  it("requires an explicit AWS wrapper when credential policies share more than one", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-aws-wrapper-"));
    const firstWrapper = path.join(home, "project-a-aws");
    const secondWrapper = path.join(home, "project-b-aws");
    const env = {
      ...process.env,
      SGW_HOME: home,
      SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_MASTER_PASSPHRASE: "cli-aws-wrapper-test-passphrase",
      SGW_DISABLE_KEYCHAIN: "1"
    };

    try {
      for (const wrapperPath of [firstWrapper, secondWrapper]) {
        await writeFile(wrapperPath, "#!/bin/sh\nexit 0\n");
        await chmod(wrapperPath, 0o700);
      }

      const secret = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts", "secret", "add",
        "--name", "AWS secret",
        "--type", "credential",
        "--value-stdin",
        "--inject-env", "AWS_SECRET_ACCESS_KEY",
        "--allow-command", firstWrapper,
        "--allow-command", secondWrapper
      ], {
        cwd: repoRoot,
        env,
        input: "aws-secret-value-123456789",
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"]
      }));

      const access = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts", "secret", "add",
        "--name", "AWS access key id",
        "--type", "credential",
        "--value-stdin",
        "--inject-env", "AWS_ACCESS_KEY_ID",
        "--allow-command", firstWrapper,
        "--allow-command", secondWrapper
      ], {
        cwd: repoRoot,
        env,
        input: fakeAwsAccessKey(),
        encoding: "utf8",
        stdio: ["pipe", "pipe", "pipe"]
      }));

      expect(() => execFileSync(tsxBin, [
        "src/cli.ts", "aws", "plan",
        "--secret-handle", secret.handle,
        "--access-handle", access.handle
      ], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      })).toThrow(/Multiple AWS wrappers/);

      const plan = JSON.parse(execFileSync(tsxBin, [
        "src/cli.ts", "aws", "plan",
        "--secret-handle", secret.handle,
        "--access-handle", access.handle,
        "--wrapper", secondWrapper
      ], {
        cwd: repoRoot,
        env,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      }));

      expect(plan.wrapper).toBe(secondWrapper);
      expect(plan.sampleRunCommand).toContain(`--wrapper ${secondWrapper}`);
    } finally {
      await rm(home, { recursive: true, force: true });
      await rm(`${home}-recovery`, { recursive: true, force: true });
    }
  }, 15_000);
});
