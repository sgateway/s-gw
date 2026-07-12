import { createHash } from "node:crypto";
import { accessSync, constants, existsSync, readFileSync } from "node:fs";
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
    if (!nativeCoreIsCompatible(coreBinary)) {
      if (engine === "rust") {
        throw new Error(`Rust execution core is not compatible with ${process.platform}-${process.arch}: ${coreBinary}`);
      }
      return runTypeScriptEnvCommand(request, secretRecord, secretValue, extraSecrets);
    }

    try {
      return await runRustEnvCommand(coreBinary, request, secretRecord, secretValue, extraSecrets);
    } catch (error) {
      if (engine === "auto" && isNativeLaunchError(error)) {
        return runTypeScriptEnvCommand(request, secretRecord, secretValue, extraSecrets);
      }
      if (engine === "rust" && isNativeLaunchError(error)) {
        throw new Error(`Rust execution core could not be launched: ${coreBinary}. ${errorMessage(error)}`);
      }
      throw error;
    }
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
  return fileURLToPath(new URL(
    `../dist/native/${process.platform}-${process.arch}/s-gw-core${extension}`,
    import.meta.url
  ));
}

function nativeCoreIsCompatible(coreBinary: string): boolean {
  try {
    if (process.platform !== "win32") accessSync(coreBinary, constants.X_OK);
    const header = readFileSync(coreBinary).subarray(0, 4096);
    if (header[0] === 0x23 && header[1] === 0x21) return true;
    if (process.platform === "darwin") return compatibleMachO(header);
    if (process.platform === "win32") return compatiblePe(header);
    return compatibleElf(header);
  } catch {
    return false;
  }
}

function compatibleElf(header: Buffer): boolean {
  if (header.length < 20 || !header.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))) {
    return false;
  }
  const littleEndian = header[5] === 1;
  if (!littleEndian && header[5] !== 2) return false;
  const machine = littleEndian ? header.readUInt16LE(18) : header.readUInt16BE(18);
  const expected: Partial<Record<NodeJS.Architecture, number>> = {
    arm: 40,
    arm64: 183,
    ia32: 3,
    x64: 62
  };
  return expected[process.arch] === machine;
}

function compatibleMachO(header: Buffer): boolean {
  if (header.length < 8) return false;
  const magic = header.subarray(0, 4).toString("hex");
  const thinLittle = magic === "cefaedfe" || magic === "cffaedfe";
  const thinBig = magic === "feedface" || magic === "feedfacf";
  if (thinLittle || thinBig) {
    const cpu = thinLittle ? header.readUInt32LE(4) : header.readUInt32BE(4);
    return cpu === machCpuType();
  }

  const fatBig = magic === "cafebabe" || magic === "cafebabf";
  const fatLittle = magic === "bebafeca" || magic === "bfbafeca";
  if (!fatBig && !fatLittle) return false;
  const read32 = fatLittle
    ? (offset: number) => header.readUInt32LE(offset)
    : (offset: number) => header.readUInt32BE(offset);
  const count = read32(4);
  const entrySize = magic === "cafebabf" || magic === "bfbafeca" ? 32 : 20;
  if (count > 64 || header.length < 8 + count * entrySize) return false;
  for (let index = 0; index < count; index += 1) {
    if (read32(8 + index * entrySize) === machCpuType()) return true;
  }
  return false;
}

function machCpuType(): number {
  if (process.arch === "arm64") return 0x0100000c;
  if (process.arch === "x64") return 0x01000007;
  if (process.arch === "arm") return 12;
  if (process.arch === "ia32") return 7;
  return -1;
}

function compatiblePe(header: Buffer): boolean {
  if (header.length < 64 || header[0] !== 0x4d || header[1] !== 0x5a) return false;
  const offset = header.readUInt32LE(0x3c);
  if (offset + 6 > header.length || header.subarray(offset, offset + 4).toString("hex") !== "50450000") {
    return false;
  }
  const expected: Partial<Record<NodeJS.Architecture, number>> = {
    arm64: 0xaa64,
    ia32: 0x014c,
    x64: 0x8664
  };
  return header.readUInt16LE(offset + 4) === expected[process.arch];
}

function isNativeLaunchError(error: unknown): boolean {
  const code = (error as NodeJS.ErrnoException | undefined)?.code;
  return code === "EACCES" || code === "ENOENT" || code === "ENOEXEC";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
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
