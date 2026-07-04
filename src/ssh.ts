import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { access, chmod, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { getSgwHome } from "./paths.js";
import { sanitizeKnownSecrets } from "./scanner.js";
import type { CommandAction, ExecutionSummary, RequestRecord, SecretRecord } from "./types.js";

export const SGW_SSH_SESSION_COMMAND = "s-gw:ssh-session";

export interface SshSessionInput {
  target: string;
  port?: number;
  args?: string[];
  injectEnv?: string;
  workingDir?: string;
  timeoutMs?: number;
}

interface ProcessResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

export function buildSshSessionAction(input: SshSessionInput): CommandAction {
  const target = normalizeSshTarget(input.target);
  const port = normalizeSshPort(input.port);
  return {
    kind: "ssh_session",
    command: SGW_SSH_SESSION_COMMAND,
    args: input.args || [],
    injectEnv: input.injectEnv || "SGW_SSH_CREDENTIAL",
    workingDir: input.workingDir,
    timeoutMs: input.timeoutMs ?? 30_000,
    ssh: { target, port }
  };
}

export function defaultSshInjectEnv(secret: SecretRecord): string {
  if (secret.policy.injectEnv) {
    return secret.policy.injectEnv;
  }
  if (secret.type === "ssh-key" || secret.type === "private-key") {
    return "SGW_SSH_PRIVATE_KEY";
  }
  return "SGW_SSH_PASSWORD";
}

export function normalizeSshTarget(target: string): string {
  const trimmed = String(target || "").trim();
  if (!trimmed || trimmed.includes("\0") || /[\r\n]/.test(trimmed)) {
    throw new Error("SSH target is required and cannot contain control characters.");
  }
  if (trimmed.startsWith("-") || /\s/.test(trimmed)) {
    throw new Error(`Invalid SSH target: ${trimmed}`);
  }
  return trimmed;
}

export function normalizeSshPort(port?: number): number {
  const value = port ?? 22;
  if (!Number.isInteger(value) || value < 1 || value > 65535) {
    throw new Error("SSH port must be an integer from 1 to 65535.");
  }
  return value;
}

export function sshSessionIdentity(action: CommandAction): string {
  const target = action.ssh?.target ? normalizeSshTarget(action.ssh.target) : "";
  const port = normalizeSshPort(action.ssh?.port);
  return `${target}:${port}`;
}

export async function runOwnedSshSession(
  request: RequestRecord,
  secretRecord: SecretRecord,
  secretValue: string,
  home = getSgwHome()
): Promise<ExecutionSummary> {
  if (request.action.kind !== "ssh_session") {
    throw new Error("runOwnedSshSession requires an ssh_session action.");
  }

  const target = normalizeSshTarget(request.action.ssh?.target || "");
  const port = normalizeSshPort(request.action.ssh?.port);
  const sshPath = process.env.SGW_SSH_CLI || "ssh";
  const maxOutput = secretRecord.policy.maxOutputBytes || 16_384;
  const captureCap = maxOutput + Math.max(secretValue.length, 0);
  const socketPath = await controlSocketPath(home, request.handle, target, port);
  const auth = await prepareSshAuth(secretRecord, secretValue);

  try {
    if (!(await controlMasterIsActive(sshPath, socketPath, target, port, request.action.timeoutMs, captureCap))) {
      await openControlMaster(sshPath, socketPath, target, port, request.action.timeoutMs, auth, captureCap);
    }

    const remoteArgs = request.action.args.length > 0 ? request.action.args : ["true"];
    const result = await runProcess(
      sshPath,
      [
        "-S", socketPath,
        "-o", "ControlMaster=no",
        "-o", "BatchMode=yes",
        "-p", String(port),
        target,
        ...remoteArgs
      ],
      { timeoutMs: request.action.timeoutMs, env: baseSshEnv(), maxOutputBytes: captureCap }
    );

    const cleanStdout = capBytes(sanitizeKnownSecrets(result.stdout, [{ handle: request.handle, value: secretValue }]), maxOutput);
    const cleanStderr = capBytes(sanitizeKnownSecrets(result.stderr, [{ handle: request.handle, value: secretValue }]), maxOutput);
    return {
      exitCode: result.timedOut ? 124 : result.exitCode,
      signal: result.signal,
      stdout: cleanStdout,
      stderr: cleanStderr,
      proof: proofFor(request, cleanStdout, cleanStderr),
      durationMs: result.durationMs,
      timeoutMs: request.action.timeoutMs,
      timedOut: result.timedOut,
      sanitized: cleanStdout !== result.stdout || cleanStderr !== result.stderr
    };
  } finally {
    await auth.cleanup();
  }
}

export async function closeOwnedSshSession(input: { handle: string; target: string; port?: number; home?: string }): Promise<ProcessResult> {
  const target = normalizeSshTarget(input.target);
  const port = normalizeSshPort(input.port);
  const socketPath = await controlSocketPath(input.home || getSgwHome(), input.handle, target, port);
  return runProcess(process.env.SGW_SSH_CLI || "ssh", ["-S", socketPath, "-O", "exit", "-p", String(port), target], {
    timeoutMs: 10_000,
    env: baseSshEnv(),
    maxOutputBytes: 16_384,
    rejectOnNonZero: false
  });
}

async function controlMasterIsActive(
  sshPath: string,
  socketPath: string,
  target: string,
  port: number,
  timeoutMs: number,
  maxOutputBytes: number
): Promise<boolean> {
  const exists = await fileExists(socketPath);
  if (!exists) {
    return false;
  }

  const result = await runProcess(sshPath, ["-S", socketPath, "-O", "check", "-p", String(port), target], {
    timeoutMs: timeoutMs > 0 ? Math.min(timeoutMs, 10_000) : 10_000,
    env: baseSshEnv(),
    maxOutputBytes,
    rejectOnNonZero: false
  });
  return result.exitCode === 0;
}

async function openControlMaster(
  sshPath: string,
  socketPath: string,
  target: string,
  port: number,
  timeoutMs: number,
  auth: PreparedSshAuth,
  maxOutputBytes: number
): Promise<void> {
  const result = await runProcess(
    sshPath,
    [
      "-M",
      "-N",
      "-f",
      "-o", "ControlMaster=yes",
      "-o", `ControlPath=${socketPath}`,
      "-o", "ControlPersist=10m",
      "-o", "ServerAliveInterval=30",
      "-o", "ServerAliveCountMax=2",
      "-o", "StrictHostKeyChecking=accept-new",
      "-o", "BatchMode=no",
      "-p", String(port),
      ...auth.args,
      target
    ],
    { timeoutMs, env: auth.env, maxOutputBytes, rejectOnNonZero: false }
  );

  if (result.exitCode !== 0) {
    const detail = result.stderr || result.stdout || `ssh exited ${result.exitCode}`;
    throw new Error(`Could not open s-gw-owned SSH session to ${target}: ${detail.trim()}`);
  }
}

interface PreparedSshAuth {
  args: string[];
  env: NodeJS.ProcessEnv;
  cleanup: () => Promise<void>;
}

async function prepareSshAuth(secret: SecretRecord, value: string): Promise<PreparedSshAuth> {
  const env = baseSshEnv();
  const tmpDir = await mkdtemp(path.join(os.tmpdir(), "sgw-ssh-"));
  let cleaned = false;
  const cleanup = async () => {
    if (cleaned) {
      return;
    }
    cleaned = true;
    await rm(tmpDir, { recursive: true, force: true });
  };

  if (secret.type === "ssh-key" || secret.type === "private-key" || looksLikePrivateKey(value)) {
    const keyPath = path.join(tmpDir, "identity");
    await writeFile(keyPath, value.endsWith("\n") ? value : `${value}\n`, { mode: 0o600 });
    await chmod(keyPath, 0o600);
    return {
      args: ["-i", keyPath, "-o", "IdentitiesOnly=yes"],
      env,
      cleanup
    };
  }

  const passPath = path.join(tmpDir, "password");
  const askpassPath = path.join(tmpDir, "askpass.sh");
  await writeFile(passPath, value, { mode: 0o600 });
  await chmod(passPath, 0o600);
  await writeFile(askpassPath, '#!/bin/sh\ncat "$SGW_ASKPASS_FILE"\n', { mode: 0o700 });
  await chmod(askpassPath, 0o700);
  return {
    args: ["-o", "PreferredAuthentications=password,keyboard-interactive", "-o", "PubkeyAuthentication=no"],
    env: {
      ...env,
      DISPLAY: env.DISPLAY || "sgw-local",
      SSH_ASKPASS_REQUIRE: "force",
      SSH_ASKPASS: askpassPath,
      SGW_ASKPASS_FILE: passPath
    },
    cleanup
  };
}

function looksLikePrivateKey(value: string): boolean {
  return /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/.test(value);
}

async function controlSocketPath(home: string, handle: string, target: string, port: number): Promise<string> {
  const dir = process.env.SGW_SSH_CONTROL_DIR || path.join(home, "ssh-sessions");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  const digest = createHash("sha256")
    .update(handle)
    .update("\0")
    .update(target)
    .update("\0")
    .update(String(port))
    .digest("base64url")
    .slice(0, 32);
  return path.join(dir, `ctl-${digest}`);
}

function baseSshEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const key of ["HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME", "PATH", "SHELL", "TERM", "TMPDIR", "USER"]) {
    const value = process.env[key];
    if (value) {
      env[key] = value;
    }
  }
  env.PATH ||= "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin";
  return env;
}

async function runProcess(
  command: string,
  args: string[],
  options: {
    timeoutMs: number;
    env: NodeJS.ProcessEnv;
    maxOutputBytes: number;
    rejectOnNonZero?: boolean;
  }
): Promise<ProcessResult> {
  const started = Date.now();
  const child = spawn(command, args, {
    env: options.env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  let timedOut = false;
  let killTimer: NodeJS.Timeout | undefined;
  const timeout = options.timeoutMs > 0
    ? setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      killTimer = setTimeout(() => child.kill("SIGKILL"), 1_500);
    }, options.timeoutMs)
    : undefined;

  child.stdout.on("data", (chunk: Buffer) => {
    stdout = appendBounded(stdout, chunk.toString("utf8"), options.maxOutputBytes);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = appendBounded(stderr, chunk.toString("utf8"), options.maxOutputBytes);
  });

  const status = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code, signal }));
  });
  if (timeout) {
    clearTimeout(timeout);
  }
  if (killTimer) {
    clearTimeout(killTimer);
  }

  const result = {
    exitCode: timedOut ? 124 : status.code,
    signal: status.signal,
    stdout,
    stderr,
    durationMs: Date.now() - started,
    timedOut
  };

  if (options.rejectOnNonZero !== false && result.exitCode !== 0) {
    throw new Error(stderr || stdout || `Command exited ${result.exitCode}`);
  }

  return result;
}

function appendBounded(current: string, extra: string, maxBytes: number): string {
  const combined = current + extra;
  if (Buffer.byteLength(combined, "utf8") <= maxBytes) {
    return combined;
  }
  return capBytes(combined, maxBytes);
}

function capBytes(text: string, maxBytes: number): string {
  if (Buffer.byteLength(text, "utf8") <= maxBytes) {
    return text;
  }
  return text.slice(0, maxBytes) + "\n<<SGW_OUTPUT_TRUNCATED>>";
}

function proofFor(request: RequestRecord, stdout: string, stderr: string): string {
  const digest = createHash("sha256")
    .update(request.id)
    .update(request.handle)
    .update(stdout)
    .update(stderr)
    .digest("base64url")
    .slice(0, 24);
  return `s-gw-proof:${request.id}:${digest}`;
}

async function fileExists(filePath: string): Promise<boolean> {
  try {
    await access(filePath, constants.F_OK);
    return true;
  } catch {
    return false;
  }
}
