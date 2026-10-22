import { runOwnedHttpRequest, type OwnedHttpOptions } from "./http-executor.js";
import { createHash } from "node:crypto";
import { accessSync, constants, existsSync, readFileSync } from "node:fs";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { verifyPinnedCommand } from "./command-path.js";
import {
  assertActionAllowed,
  type ExecutionLaunch,
  type ReusableExecutionPermit,
  type SecretStore
} from "./store.js";
import { sanitizeKnownSecrets } from "./scanner.js";
import { assertSshCredentialSupported, runOwnedSshSession } from "./ssh.js";
import { killProcessTree, spawnIsolated } from "./process-tree.js";
import type { AgentIdentityContext } from "./agent-context.js";
import type { ExecutionSummary, RequestRecord, SecretRecord } from "./types.js";

export interface ExecutionOptions {
  engine?: "auto" | "rust" | "typescript";
  coreBinary?: string;
  http?: OwnedHttpOptions;
  operationsOnly?: boolean;
  strictLegacyRevocation?: boolean;
  caller?: AgentIdentityContext;
  agentSession?: { signal: AbortSignal; assertActive(): void };
}

export async function executeApprovedRequest(
  store: SecretStore,
  requestId: string,
  options: ExecutionOptions = {}
): Promise<ExecutionSummary> {
  options.agentSession?.assertActive();
  if (options.operationsOnly) {
    const pending = await store.getRequest(requestId);
    options.agentSession?.assertActive();
    if (!["http_request", "ssh_session"].includes(pending.action.kind)) throw new Error("Sandbox execution supports owned SSH and HTTPS operations only.");
  }
  const request = await store.claimApprovedRequest(requestId, options.caller, options.agentSession?.assertActive);
  const strictLegacy = options.strictLegacyRevocation === true &&
    (request.action.kind === "env_command" || request.action.kind === "ssh_session") && !request.action.owned;
  try {
    options.agentSession?.assertActive();
    const summary = await executeRequest(store, request, options);
    options.agentSession?.assertActive();
    if (strictLegacy) await store.assertLegacyRequestAuthorized(requestId);
    await store.markExecuted(requestId, summary);
    return summary;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    try {
      await store.markFailed(requestId, message);
    } catch (markError) {
      if (!strictLegacy || (await store.getRequest(requestId)).state !== "failed") throw markError;
    }
    throw error;
  }
}

export async function executeReusablePermit(
  store: SecretStore,
  permit: ReusableExecutionPermit,
  options: ExecutionOptions = {}
): Promise<ExecutionSummary> {
  const initialRequest = await store.validateReusableExecutionPermit(permit, options.caller);
  if (initialRequest.action.kind !== "env_command") {
    throw new Error("Reusable execution permits only support environment-command actions.");
  }

  const prepared = await prepareEnvExecution(store, initialRequest);
  const assertReusable = options.strictLegacyRevocation ? async () => {
    options.agentSession?.assertActive();
    await store.validateReusableExecutionPermit(permit, options.caller);
    options.agentSession?.assertActive();
  } : undefined;
  let nativeLaunch = false;
  try {
    const summary = await store.launchReusableExecution(permit, (request) => {
      const launch = launchReusableEnvCommand(
        request,
        prepared.command,
        prepared.secretRecord,
        prepared.secretValue,
        prepared.extraSecrets,
        options,
        assertReusable
      );
      nativeLaunch = launch.nativeLaunch;
      return launch;
    }, options.caller);
    await assertReusable?.();
    return summary;
  } catch (error) {
    if (!nativeLaunch || executionEngine(options.engine) !== "auto" || !isNativeLaunchError(error)) {
      throw error;
    }

    const summary = await store.launchReusableExecution(permit, (request) => {
      return startTypeScriptEnvCommand(
        request,
        prepared.command,
        prepared.secretRecord,
        prepared.secretValue,
        prepared.extraSecrets,
        assertReusable
      );
    }, options.caller);
    await assertReusable?.();
    return summary;
  }
}

function commandForExecution(request: RequestRecord): string {
  if (request.action.kind !== "env_command") {
    throw new Error("Pinned command validation only supports environment-command actions.");
  }
  return verifyPinnedCommand(request.action.command, request.action.resolvedCommand);
}

async function executeRequest(
  store: SecretStore,
  request: RequestRecord,
  options: ExecutionOptions,
  executionOptions: { cacheOnePassword?: boolean } = {}
): Promise<ExecutionSummary> {
  options.agentSession?.assertActive();
  const strictLegacy = options.strictLegacyRevocation === true &&
    (request.action.kind === "env_command" || request.action.kind === "ssh_session") && !request.action.owned;
  const assertLegacy = strictLegacy ? async () => {
    options.agentSession?.assertActive();
    await store.assertLegacyRequestAuthorized(request.id);
    options.agentSession?.assertActive();
  } : undefined;
  await assertLegacy?.();
  const command = request.action.kind === "env_command"
    ? commandForExecution(request)
    : undefined;
  const secretRecord = await store.getSecretRecord(request.handle, request.id);
  options.agentSession?.assertActive();
  assertActionAllowed(secretRecord, request.action);
  if (request.action.kind === "ssh_session") {
    assertSshCredentialSupported(secretRecord);
  }
  const secretValue = await store.revealSecretForLocalUse(request.handle, request, {
    cache: executionOptions.cacheOnePassword !== false
  });
  options.agentSession?.assertActive();
  if (request.action.kind === "http_request") {
    return runOwnedHttpRequest(store, request, secretRecord, secretValue, {
      ...options.http, signal: options.agentSession?.signal, assertActive: options.agentSession?.assertActive
    });
  }
  if (request.action.kind === "ssh_session") {
    const assertSshAuthorization = options.operationsOnly || request.action.owned ? async () => {
      options.agentSession?.assertActive();
      await store.assertOwnedRequestAuthorized(request.id);
      options.agentSession?.assertActive();
    } : assertLegacy;
    if (options.operationsOnly) await assertSshAuthorization?.();
    return runOwnedSshSession(request, secretRecord, secretValue, store.home, assertSshAuthorization, options.agentSession?.signal, strictLegacy);
  }
  const extraSecrets = await resolveExtraSecrets(store, request, executionOptions);
  await assertLegacy?.();
  return runEnvCommand(request, command!, secretRecord, secretValue, extraSecrets, options, assertLegacy);
}

interface PreparedEnvExecution {
  command: string;
  secretRecord: SecretRecord;
  secretValue: string;
  extraSecrets: ResolvedEnvSecret[];
}

async function prepareEnvExecution(store: SecretStore, request: RequestRecord): Promise<PreparedEnvExecution> {
  const command = commandForExecution(request);
  const secretRecord = await store.getSecretRecord(request.handle, request.id);
  assertActionAllowed(secretRecord, request.action);
  const secretValue = await store.revealSecretForLocalUse(request.handle, request);
  const extraSecrets = await resolveExtraSecrets(store, request);
  return { command, secretRecord, secretValue, extraSecrets };
}

async function runEnvCommand(
  request: RequestRecord,
  command: string,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[],
  options: ExecutionOptions,
  assertAuthorized?: () => Promise<void>
): Promise<ExecutionSummary> {
  await assertAuthorized?.();
  const engine = executionEngine(options.engine);
  const coreBinary = options.coreBinary || rustCoreBinary();
  if (engine !== "typescript" && existsSync(coreBinary)) {
    if (!nativeCoreIsCompatible(coreBinary)) {
      if (engine === "rust") {
        throw new Error(`Rust execution core is not compatible with ${process.platform}-${process.arch}: ${coreBinary}`);
      }
      return startTypeScriptEnvCommand(request, command, secretRecord, secretValue, extraSecrets, assertAuthorized).completion;
    }

    try {
      return await startRustEnvCommand(coreBinary, request, command, secretRecord, secretValue, extraSecrets, assertAuthorized).completion;
    } catch (error) {
      if (engine === "auto" && isNativeLaunchError(error)) {
        await assertAuthorized?.();
        return startTypeScriptEnvCommand(request, command, secretRecord, secretValue, extraSecrets, assertAuthorized).completion;
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

  return startTypeScriptEnvCommand(request, command, secretRecord, secretValue, extraSecrets, assertAuthorized).completion;
}

interface ReusableEnvLaunch extends ExecutionLaunch<ExecutionSummary> {
  nativeLaunch: boolean;
}

function launchReusableEnvCommand(
  request: RequestRecord,
  command: string,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[],
  options: ExecutionOptions,
  assertAuthorized?: () => Promise<void>
): ReusableEnvLaunch {
  const engine = executionEngine(options.engine);
  const coreBinary = options.coreBinary || rustCoreBinary();
  if (engine !== "typescript" && existsSync(coreBinary)) {
    if (!nativeCoreIsCompatible(coreBinary)) {
      if (engine === "rust") {
        throw new Error(`Rust execution core is not compatible with ${process.platform}-${process.arch}: ${coreBinary}`);
      }
      return { ...startTypeScriptEnvCommand(request, command, secretRecord, secretValue, extraSecrets, assertAuthorized), nativeLaunch: false };
    }

    const launch = startRustEnvCommand(coreBinary, request, command, secretRecord, secretValue, extraSecrets, assertAuthorized);
    if (engine !== "rust") {
      return { ...launch, nativeLaunch: true };
    }
    return {
      nativeLaunch: true,
      completion: launch.completion.catch((error) => {
        if (isNativeLaunchError(error)) {
          throw new Error(`Rust execution core could not be launched: ${coreBinary}. ${errorMessage(error)}`);
        }
        throw error;
      })
    };
  }
  if (engine === "rust") {
    throw new Error(`Rust execution core is unavailable: ${coreBinary}`);
  }

  return { ...startTypeScriptEnvCommand(request, command, secretRecord, secretValue, extraSecrets, assertAuthorized), nativeLaunch: false };
}

function startRustEnvCommand(
  coreBinary: string,
  request: RequestRecord,
  command: string,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[],
  assertAuthorized?: () => Promise<void>
): ExecutionLaunch<ExecutionSummary> {
  const maxOutput = secretRecord.policy.maxOutputBytes || 16_384;
  const launch = assertAuthorized ? spawnIsolated : spawn;
  const child = launch(coreBinary, ["execute"], {
    env: buildCoreEnv(),
    shell: false,
    stdio: ["pipe", "pipe", "pipe"]
  });
  if (!child.stdin || !child.stdout || !child.stderr) {
    killProcessTree(child, "SIGKILL");
    throw new Error("Rust execution core capture pipes unavailable.");
  }
  const stdin = child.stdin;
  const monitor = monitorLegacyAuthorization(child, assertAuthorized);
  let stdout = "";
  let stderr = "";
  const responseLimit = Math.max(1_048_576, maxOutput * 4);

  child.stdout.on("data", (chunk: Buffer) => {
    stdout = appendBounded(stdout, chunk.toString("utf8"), responseLimit);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = appendBounded(stderr, chunk.toString("utf8"), responseLimit);
  });

  const childCompletion = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  const input = new Promise<void>((resolve, reject) => {
    stdin.once("error", (error: NodeJS.ErrnoException) => {
      if (error.code === "EPIPE") {
        resolve();
        return;
      }
      reject(error);
    });
    stdin.end(JSON.stringify({
      version: 1,
      requestId: request.id,
      handle: request.handle,
      command,
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
    }), resolve);
  });

  const completion = Promise.all([childCompletion, input]).then(async ([status]) => {
    const revoked = await monitor?.stop();
    if (revoked) throw revoked;
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
  }).catch(async (error: unknown) => {
    const revoked = await monitor?.stop();
    throw revoked || error;
  });
  void completion.catch(() => undefined);
  return { completion };
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

function startTypeScriptEnvCommand(
  request: RequestRecord,
  command: string,
  secretRecord: SecretRecord,
  secretValue: string,
  extraSecrets: ResolvedEnvSecret[],
  assertAuthorized?: () => Promise<void>
): ExecutionLaunch<ExecutionSummary> {
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
  const launch = assertAuthorized ? spawnIsolated : spawn;
  const child = launch(command, request.action.args, {
    cwd: request.action.workingDir,
    env,
    shell: false,
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (!child.stdout || !child.stderr) {
    killProcessTree(child, "SIGKILL");
    throw new Error("Command capture pipes unavailable.");
  }
  const monitor = monitorLegacyAuthorization(child, assertAuthorized);

  let stdout = "";
  let stderr = "";
  let timedOut = false;
  let killTimer: NodeJS.Timeout | undefined;
  const timeout = request.action.timeoutMs > 0
    ? setTimeout(() => {
      timedOut = true;
      if (assertAuthorized) killProcessTree(child, "SIGTERM"); else child.kill("SIGTERM");
      killTimer = setTimeout(() => {
        if (assertAuthorized) killProcessTree(child, "SIGKILL"); else child.kill("SIGKILL");
      }, 1_500);
    }, request.action.timeoutMs)
    : undefined;

  child.stdout.on("data", (chunk: Buffer) => {
    stdout = appendBounded(stdout, chunk.toString("utf8"), captureCap);
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr = appendBounded(stderr, chunk.toString("utf8"), captureCap);
  });

  const completion = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    child.on("error", reject);
    child.on("close", (code, signal) => resolve({ code, signal }));
  }).then(async (status) => {
    if (timeout) {
      clearTimeout(timeout);
    }
    if (killTimer) {
      clearTimeout(killTimer);
    }
    const revoked = await monitor?.stop();
    if (revoked) throw revoked;

    const sanitizedStdout = sanitizeKnownSecrets(stdout, secretPairs);
    const sanitizedStderr = sanitizeKnownSecrets(stderr, secretPairs);
    const cleanStdout = capBytes(sanitizedStdout, maxOutput);
    const cleanStderr = capBytes(sanitizedStderr, maxOutput);
    return {
      exitCode: timedOut ? 124 : status.code,
      signal: status.signal,
      stdout: cleanStdout,
      stderr: cleanStderr,
      proof: proofFor(request, cleanStdout, cleanStderr),
      durationMs: Date.now() - started,
      timeoutMs: request.action.timeoutMs,
      timedOut,
      sanitized: sanitizedStdout !== stdout || sanitizedStderr !== stderr
    } satisfies ExecutionSummary;
  }).catch(async (error: unknown) => {
    if (timeout) clearTimeout(timeout);
    if (killTimer) clearTimeout(killTimer);
    const revoked = await monitor?.stop();
    throw revoked || error;
  });
  void completion.catch(() => undefined);
  return { completion };
}

function monitorLegacyAuthorization(child: ChildProcess, assertAuthorized?: () => Promise<void>):
  { stop(): Promise<Error | undefined> } | undefined {
  if (!assertAuthorized) return;
  let pending: Promise<void> | undefined;
  let revoked: Error | undefined;
  let closed = false;
  const timer = setInterval(() => {
    if (closed || pending || revoked) return;
    pending = assertAuthorized().catch((error: unknown) => {
      if (closed) return;
      revoked = error instanceof Error ? error : new Error("Legacy execution authorization was revoked.");
      try { killProcessTree(child, "SIGKILL"); }
      catch { child.kill("SIGKILL"); }
    }).finally(() => { pending = undefined; });
  }, 100);
  child.once("close", () => { closed = true; clearInterval(timer); });
  return {
    async stop() {
      closed = true;
      clearInterval(timer);
      await pending;
      return revoked;
    }
  };
}

interface ResolvedEnvSecret {
  handle: string;
  injectEnv: string;
  value: string;
}

async function resolveExtraSecrets(
  store: SecretStore,
  request: RequestRecord,
  executionOptions: { cacheOnePassword?: boolean } = {}
): Promise<ResolvedEnvSecret[]> {
  const out: ResolvedEnvSecret[] = [];
  for (const binding of request.action.env || []) {
    const secret = await store.getSecretRecord(binding.handle, request.id);
    assertActionAllowed(secret, {
      ...request.action,
      injectEnv: binding.injectEnv,
      env: []
    });
    out.push({
      handle: binding.handle,
      injectEnv: binding.injectEnv,
      value: await store.revealSecretForLocalUse(binding.handle, request, {
        cache: executionOptions.cacheOnePassword !== false
      })
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
