import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { assertActionAllowed, type SecretStore } from "./store.js";
import { sanitizeKnownSecrets } from "./scanner.js";
import { runOwnedSshSession } from "./ssh.js";
import type { ExecutionSummary, RequestRecord, SecretRecord } from "./types.js";

export interface ExecutionOptions {
  engine?: "auto" | "rust" | "typescript";
  coreBinary?: string;
}

export async function executeApprovedRequest(
  store: SecretStore,
  requestId: string,
  options: ExecutionOptions = {}
): Promise<ExecutionSummary> {
  const request = await store.claimApprovedRequest(requestId);
  try {
    const secretRecord = await store.getSecretRecord(request.handle);
    assertActionAllowed(secretRecord, request.action);
    const secretValue = await store.revealSecretForLocalUse(request.handle, request);
    const extraSecrets = await resolveExtraSecrets(store, request);
    const summary = request.action.kind === "ssh_session"
      ? await runOwnedSshSession(request, secretRecord, secretValue, store.home)
      : await runEnvCommand(request, secretRecord, secretValue, extraSecrets, options);
    await store.markExecuted(requestId, summary);
    return summary;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await store.markFailed(requestId, message);
    throw error;
  }
}

async function runEnvCommand(
  request: RequestRecord,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[],
  options: ExecutionOptions
): Promise<ExecutionSummary> {
  const engine = executionEngine(options.engine);
  const coreBinary = options.coreBinary || rustCoreBinary();
  if (engine !== "typescript" && existsSync(coreBinary)) {
    return runRustEnvCommand(coreBinary, request, secretRecord, secretValue, extraSecrets);
  }
  if (engine === "rust") {
    throw new Error(`Rust execution core is unavailable: ${coreBinary}`);
  }

  return runTypeScriptEnvCommand(request, secretRecord, secretValue, extraSecrets);
}

async function runRustEnvCommand(
  coreBinary: string,
  request: RequestRecord,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[]
): Promise<ExecutionSummary> {
  const maxOutput = secretRecord.policy.maxOutputBytes || 16_384;
  const child = spawn(coreBinary, ["execute"], {
    env: buildCoreEnv(),
    shell: false,
    stdio: ["pipe", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  const responseLimit = Math.max(1_048_576, maxOutput * 4);

  child.stdout.on("data", (chunk: Buffer) => {
    stdout = appendBounded(stdout, chunk.toString("utf8"), responseLimit);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = appendBounded(stderr, chunk.toString("utf8"), responseLimit);
  });

  const completion = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  child.stdin.end(JSON.stringify({
    version: 1,
    requestId: request.id,
    handle: request.handle,
    command: request.action.command,
    args: request.action.args,
    injectEnv: request.action.injectEnv,
    secretValue,
    env: extraSecrets.map((item) => ({
      handle: item.handle,
      injectEnv: item.injectEnv,
      value: item.value
    })),
    workingDir: request.action.workingDir,
    timeoutMs: request.action.timeoutMs,
    maxOutputBytes: maxOutput
  }));

  const status = await completion;
  if (status.code !== 0) {
    throw new Error(stderr.trim() || `Rust execution core exited ${status.code ?? status.signal ?? "unexpectedly"}.`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error("Rust execution core returned an invalid response.");
  }
  const summary = parseCoreSummary(parsed, request);
  const secretValues = [secretValue, ...extraSecrets.map((item) => item.value)];
  if (secretValues.some((value) => summary.stdout.includes(value) || summary.stderr.includes(value))) {
    throw new Error("Rust execution core returned unsanitized output.");
  }

  const expectedProof = proofFor(request, summary.stdout, summary.stderr);
  if (summary.proof !== expectedProof) {
    throw new Error("Rust execution core returned an invalid execution proof.");
  }
  return summary;
}

function parseCoreSummary(value: unknown, request: RequestRecord): ExecutionSummary {
  if (!value || typeof value !== "object") {
    throw new Error("Rust execution core returned an invalid summary.");
  }
  const summary = value as Record<string, unknown>;
  const validExit = summary.exitCode === null || Number.isInteger(summary.exitCode);
  const validSignal = summary.signal === null || typeof summary.signal === "string";
  if (
    !validExit
    || !validSignal
    || typeof summary.stdout !== "string"
    || typeof summary.stderr !== "string"
    || typeof summary.proof !== "string"
    || typeof summary.durationMs !== "number"
    || !Number.isFinite(summary.durationMs)
    || summary.durationMs < 0
    || summary.timeoutMs !== request.action.timeoutMs
    || typeof summary.timedOut !== "boolean"
    || typeof summary.sanitized !== "boolean"
  ) {
    throw new Error("Rust execution core returned an invalid summary.");
  }

  return summary as unknown as ExecutionSummary;
}

function executionEngine(override?: ExecutionOptions["engine"]): "auto" | "rust" | "typescript" {
  const configured = override || process.env.SGW_EXECUTION_ENGINE?.trim().toLowerCase() || "auto";
  if (configured === "auto" || configured === "rust" || configured === "typescript") {
    return configured;
  }
  throw new Error(`Unsupported SGW_EXECUTION_ENGINE value: ${configured}`);
}

function rustCoreBinary(): string {
  const extension = process.platform === "win32" ? ".exe" : "";
  return fileURLToPath(new URL(`../dist/native/s-gw-core${extension}`, import.meta.url));
}

function buildCoreEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const copyKeys = [
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LOGNAME",
    "NO_COLOR",
    "PATH",
    "SHELL",
    "SYSTEMROOT",
    "TERM",
    "TMPDIR",
    "USER",
    "USERPROFILE",
    "WINDIR"
  ];
  for (const key of copyKeys) {
    const value = process.env[key];
    if (value) {
      env[key] = value;
    }
  }
  env.PATH ||= process.platform === "win32"
    ? "C:\\Windows\\System32;C:\\Windows"
    : "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin";
  return env;
}

async function runTypeScriptEnvCommand(
  request: RequestRecord,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[]
): Promise<ExecutionSummary> {
  const started = Date.now();
  const maxOutput = secretRecord.policy.maxOutputBytes || 16_384;
  const secretPairs = [
    { handle: request.handle, value: secretValue },
    ...extraSecrets.map((item) => ({ handle: item.handle, value: item.value }))
  ];
  const longestSecretBytes = secretPairs.reduce((max, item) => Math.max(max, Buffer.byteLength(item.value, "utf8")), 0);
  // Capture slightly more than the display cap so a secret that straddles the
  // boundary is still present in full when we sanitize. Without this headroom,
  // truncating raw output first could cut a secret in half and leak the prefix.
  const captureCap = maxOutput + longestSecretBytes;
  const env = buildExecutionEnv(request.action.injectEnv, secretValue, extraSecrets);
  const child = spawn(request.action.command, request.action.args, {
    cwd: request.action.workingDir,
    env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"]
  });

  let stdout = "";
  let stderr = "";
  let timedOut = false;
  let killTimer: NodeJS.Timeout | undefined;
  const timeout = request.action.timeoutMs > 0
    ? setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      killTimer = setTimeout(() => {
        child.kill("SIGKILL");
      }, 1_500);
    }, request.action.timeoutMs)
    : undefined;

  child.stdout.on("data", (chunk: Buffer) => {
    stdout = appendBounded(stdout, chunk.toString("utf8"), captureCap);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = appendBounded(stderr, chunk.toString("utf8"), captureCap);
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

  // Sanitize the full captured output BEFORE applying the display cap. Sanitized
  // text no longer contains the raw secret, so the final byte-cap can never split
  // a credential and leak a partial value to the caller.
  const sanitizedStdout = sanitizeKnownSecrets(stdout, secretPairs);
  const sanitizedStderr = sanitizeKnownSecrets(stderr, secretPairs);
  const cleanStdout = capBytes(sanitizedStdout, maxOutput);
  const cleanStderr = capBytes(sanitizedStderr, maxOutput);
  const summary: ExecutionSummary = {
    exitCode: timedOut ? 124 : status.code,
    signal: status.signal,
    stdout: cleanStdout,
    stderr: cleanStderr,
    proof: proofFor(request, cleanStdout, cleanStderr),
    durationMs: Date.now() - started,
    timeoutMs: request.action.timeoutMs,
    timedOut,
    sanitized: sanitizedStdout !== stdout || sanitizedStderr !== stderr
  };

  return summary;
}

interface ResolvedEnvSecret {
  handle: string;
  injectEnv: string;
  value: string;
}

async function resolveExtraSecrets(store: SecretStore, request: RequestRecord): Promise<ResolvedEnvSecret[]> {
  const out: ResolvedEnvSecret[] = [];
  for (const binding of request.action.env || []) {
    const secret = await store.getSecretRecord(binding.handle);
    assertActionAllowed(secret, {
      ...request.action,
      injectEnv: binding.injectEnv,
      env: []
    });
    out.push({
      handle: binding.handle,
      injectEnv: binding.injectEnv,
      value: await store.revealSecretForLocalUse(binding.handle, request)
    });
  }

  return out;
}

function buildExecutionEnv(
  injectEnv: string,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[]
): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  const copyKeys = [
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LOGNAME",
    "NO_COLOR",
    "PATH",
    "SHELL",
    "TERM",
    "TMPDIR",
    "USER"
  ];

  for (const key of copyKeys) {
    const value = process.env[key];
    if (value) {
      env[key] = value;
    }
  }

  env.PATH ||= "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin";
  env[injectEnv] = secretValue;
  for (const item of extraSecrets) {
    env[item.injectEnv] = item.value;
  }
  return env;
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
