import { execFileSync } from "node:child_process";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
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
  it("reports update status without requiring local store setup", () => {
    const result = JSON.parse(execFileSync(tsxBin, ["src/cli.ts", "update", "check"], {
      cwd: repoRoot,
      env: { ...process.env, SGW_DISABLE_UPDATE_CHECK: "1" },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    }));

    expect(result).toMatchObject({
      checked: false,
      currentVersion: CURRENT_VERSION,
      available: false
    });
  });

  it("exits non-zero and prints a suggestion to stderr for a typo", () => {
    let stderr = "";
    let code = 0;
    try {
      execFileSync(tsxBin, ["src/cli.ts", "statu"], {
        cwd: repoRoot,
        env: { ...process.env, SGW_DISABLE_KEYCHAIN: "1" },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (error) {
      const err = error as { status?: number; stderr?: string };
      code = err.status ?? 0;
      stderr = err.stderr ?? "";
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

    let stderr = "";
    let code = 0;
    try {
      execFileSync(tsxBin, ["src/cli.ts", "console", "--port", String(port), "--no-open"], {
        cwd: repoRoot,
        env: { ...process.env, SGW_DISABLE_KEYCHAIN: "1", SGW_MASTER_PASSPHRASE: "throwaway-eaddr-test" },
        encoding: "utf8",
        stdio: ["ignore", "pipe", "pipe"]
      });
    } catch (error) {
      const err = error as { status?: number; stderr?: string };
      code = err.status ?? 0;
      stderr = err.stderr ?? "";
    } finally {
      await new Promise<void>((resolve) => occupier.close(() => resolve()));
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
    }
  });

  it("executes the next approved request through a stable command shape", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-next-"));
    const env = {
      ...process.env,
      SGW_HOME: home,
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
    }
  });

  it("wraps the AWS-dev handle pair behind a first-class request/run shortcut", async () => {
    const home = await mkdtemp(path.join(os.tmpdir(), "sgw-cli-aws-"));
    const wrapper = path.join(home, "aws-wrapper");
    const env = {
      ...process.env,
      SGW_HOME: home,
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
      expect(plan.sampleRunCommand).toBe("s-gw aws run -- sts get-caller-identity");
      expect(plan.sampleRunCommand).not.toContain(wrapper);

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
      expect(request.repeatCommand).toBe("s-gw aws run -- sts get-caller-identity");
      expect(request.repeatCommand).not.toContain(wrapper);
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
      expect(run.summary.stdout).toContain(`<<SGW_SECRET:${secret.handle}>>`);
      expect(run.summary.stdout).toContain(`<<SGW_SECRET:${access.handle}>>`);
      expect(run.summary.stdout).not.toContain("aws-secret-shortcut-value-123456789");
      expect(run.summary.stdout).not.toContain(fakeAwsAccessKey());
      expect(run.summary.stdout).toContain("args=ec2 describe-instances --region us-west-2");

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
    }
  }, 15_000);
});
