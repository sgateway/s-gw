import { spawn, type ChildProcess } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { executeApprovedRequest } from "../src/executor.js";
import { buildEnvCommandAction } from "../src/gateway.js";
import {
  encodedSecretForms,
  sanitizeCapturedOutput,
  sanitizeKnownSecretForms,
  SGW_OUTPUT_TRUNCATED
} from "../src/output-redaction.js";
import { listDescendantPids, signalPids } from "../src/process-descendants.js";
import { sanitizeKnownSecrets, tokenForHandle } from "../src/scanner.js";
import { SecretStore } from "../src/store.js";

let tmpHome = "";
const unixIt = process.platform === "win32" ? it.skip : it;
const windowsIt = process.platform === "win32" ? it : it.skip;
const spawned: ChildProcess[] = [];

beforeEach(async () => {
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-env-hardening-"));
  process.env.SGW_HOME = tmpHome;
  process.env.SGW_RECOVERY_HOME = `${tmpHome}-recovery`;
  process.env.SGW_MASTER_PASSPHRASE = "env hardening test passphrase";
  process.env.SGW_DISABLE_KEYCHAIN = "1";
});

afterEach(async () => {
  for (const child of spawned.splice(0)) child.kill("SIGKILL");
  delete process.env.SGW_HOME;
  delete process.env.SGW_RECOVERY_HOME;
  delete process.env.SGW_MASTER_PASSPHRASE;
  delete process.env.SGW_DISABLE_KEYCHAIN;
  await rm(tmpHome, { recursive: true, force: true });
  await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
});

describe("encoded secret forms", () => {
  it("lists base64, base64url, hex and URI forms of a secret", () => {
    const secret = "p@ss word/+value?";
    const raw = Buffer.from(secret, "utf8");

    expect(encodedSecretForms(secret)).toEqual([
      raw.toString("base64"),
      raw.toString("base64url"),
      raw.toString("hex"),
      raw.toString("hex").toUpperCase(),
      encodeURIComponent(secret)
    ]);
  });

  it("skips secrets shorter than eight characters", () => {
    expect(encodedSecretForms("")).toEqual([]);
    expect(encodedSecretForms("1234567")).toEqual([]);
    expect(encodedSecretForms("12345678")).not.toEqual([]);
  });

  it("drops duplicate forms and forms equal to the raw value", () => {
    // Nine digits: base64 needs no padding, hex has no letters, and URI encoding is a no-op.
    const secret = "123456789";
    expect(encodedSecretForms(secret)).toEqual(["MTIzNDU2Nzg5", "313233343536373839"]);
  });

  it("replaces the literal value and every encoded form", () => {
    const secret = "sgw test/opaque+complete value";
    const handle = "s-gw:credential:encoded";
    const raw = Buffer.from(secret, "utf8");
    const text = [
      secret,
      raw.toString("base64"),
      raw.toString("base64url"),
      raw.toString("hex"),
      raw.toString("hex").toUpperCase(),
      encodeURIComponent(secret)
    ].join(" | ");

    const clean = sanitizeKnownSecretForms(text, [{ handle, value: secret }]);
    expect(clean).toBe(Array(6).fill(tokenForHandle(handle)).join(" | "));
  });

  it("replaces padded base64 whole and the longest secret first", () => {
    const short = "sgw-test-opaque-pad";
    const long = `${short}-and-a-longer-tail`;
    const padded = Buffer.from(short, "utf8").toString("base64");
    expect(padded.endsWith("=")).toBe(true);
    const pairs = [
      { handle: "s-gw:credential:short", value: short },
      { handle: "s-gw:credential:long", value: long }
    ];

    expect(sanitizeKnownSecretForms(`${padded} ${long}`, pairs)).toBe(
      `${tokenForHandle("s-gw:credential:short")} ${tokenForHandle("s-gw:credential:long")}`
    );
  });

  it("only redacts the literal value of a short secret", () => {
    const secret = "abc1234";
    const encoded = Buffer.from(secret, "utf8").toString("base64");
    const pairs = [{ handle: "s-gw:credential:tiny", value: secret }];

    expect(sanitizeKnownSecretForms(`${secret} ${encoded}`, pairs))
      .toBe(`${tokenForHandle("s-gw:credential:tiny")} ${encoded}`);
  });

  it("keeps sanitizeKnownSecrets and the default capture sanitizer literal-only", () => {
    const secret = "literal-only-secret-value-123456789";
    const encoded = Buffer.from(secret, "utf8").toString("hex");
    const pairs = [{ handle: "s-gw:credential:literal", value: secret }];

    expect(sanitizeKnownSecrets(encoded, pairs)).toBe(encoded);
    expect(sanitizeCapturedOutput(encoded, pairs, 4096)).toEqual({ text: encoded, changed: false });
    expect(sanitizeCapturedOutput(encoded, pairs, 4096, { encodedForms: true }))
      .toEqual({ text: tokenForHandle("s-gw:credential:literal"), changed: true });
  });

  it("redacts a capture cut inside an encoded form", () => {
    const secret = "cut-inside-encoded-secret-value-123456789";
    const hex = Buffer.from(secret, "utf8").toString("hex");
    const pairs = [{ handle: "s-gw:credential:cut", value: secret }];

    const clean = sanitizeCapturedOutput(`head ${hex.slice(0, 30)}`, pairs, 4096, {
      rawTruncated: true, encodedForms: true
    });
    expect(clean.text).toBe(`head ${tokenForHandle("s-gw:credential:cut")}`);
  });

  it("does not leak a fragment at a multi-secret capture boundary", () => {
    const pad = "x".repeat(50);
    const first = "A".repeat(100);
    const second = "B".repeat(100);
    const pairs = [
      { handle: "s-gw:credential:first", value: first },
      { handle: "s-gw:credential:second", value: second }
    ];
    const captured = `${pad}${first}${second.slice(0, 50)}`;

    // Sanitize-then-cap alone is the leak this guards against.
    expect(sanitizeKnownSecrets(captured, pairs).slice(0, 100)).toContain(second.slice(0, 6));

    const clean = sanitizeCapturedOutput(captured, pairs, 100, { rawTruncated: true, encodedForms: true });
    expect(clean.changed).toBe(true);
    expect(clean.text).not.toContain(first.slice(0, 6));
    expect(clean.text).not.toContain(second.slice(0, 6));
    expect(clean.text).toContain(tokenForHandle("s-gw:credential:first"));
  });

  it("can leave a complete stream that ends in a secret prefix alone", () => {
    const pairs = [{ handle: "s-gw:credential:prefix", value: "opaque-prefix-secret-value-123456789" }];

    expect(sanitizeCapturedOutput("opaque", pairs, 4096).text).toBe(tokenForHandle("s-gw:credential:prefix"));
    expect(sanitizeCapturedOutput("opaque", pairs, 4096, { fragmentsOnlyWhenTruncated: true }))
      .toEqual({ text: "opaque", changed: false });
    expect(sanitizeCapturedOutput("opaque", pairs, 4096, { fragmentsOnlyWhenTruncated: true, rawTruncated: true }).text)
      .toBe(tokenForHandle("s-gw:credential:prefix"));
  });
});

describe("TypeScript environment command hardening", () => {
  it("tokenizes base64 and hex copies of the secret", async () => {
    const store = new SecretStore();
    const secret = "typescript-encoded-secret-value-123456789";
    const record = await addCredential(store, "encoded output", secret);
    const summary = await runNode(store, record.handle, "SGW_ENCODED", [
      "const raw = Buffer.from(process.env.SGW_ENCODED)",
      "console.log('b64=' + raw.toString('base64'))",
      "console.log('hex=' + raw.toString('hex'))",
      "console.error('url=' + raw.toString('base64url'))"
    ].join(";"));

    const token = tokenForHandle(record.handle);
    expect(summary.exitCode).toBe(0);
    expect(summary.stdout).toBe(`b64=${token}\nhex=${token}\n`);
    expect(summary.stderr).toBe(`url=${token}\n`);
    expect(summary.sanitized).toBe(true);
    expect(summary.proof).toMatch(new RegExp(`^s-gw-proof:`));
  });

  it("leaves complete output that only shares a prefix with the secret", async () => {
    const store = new SecretStore();
    const record = await addCredential(store, "shared prefix", "opaque-shared-prefix-secret-value-123456789");
    const summary = await runNode(store, record.handle, "SGW_PREFIX", "process.stdout.write('opaque')");

    expect(summary.stdout).toBe("opaque");
    expect(summary.sanitized).toBe(false);
  });

  it("redacts a second secret cut by the capture limit", async () => {
    const store = new SecretStore();
    const maxOutput = 512;
    const first = "A".repeat(300);
    const second = "B".repeat(300);
    const { primary, extra } = await addSecretPair(store, first, second, maxOutput);
    // Three copies of the first secret shrink to tokens, which pulls the cut
    // second secret well inside the visible window.
    const lead = "x".repeat(50) + first.repeat(3);
    const captureCap = maxOutput + first.length + second.length;
    const filler = "y".repeat(captureCap - second.length / 2 - lead.length);
    const summary = await runNode(store, primary.handle, "SGW_FIRST", [
      `process.stdout.write('x'.repeat(50) + process.env.SGW_FIRST.repeat(3) + 'y'.repeat(${filler.length}))`,
      "process.stdout.write(process.env.SGW_SECOND + 'z'.repeat(2000))"
    ].join(";"), [{ handle: extra.handle, injectEnv: "SGW_SECOND" }]);

    const firstToken = tokenForHandle(primary.handle);
    expect(summary.stdout).toBe(`${"x".repeat(50)}${firstToken.repeat(3)}${filler}${tokenForHandle(extra.handle)}`);
    expect(summary.stdout).not.toContain(SGW_OUTPUT_TRUNCATED);
    expect(summary.sanitized).toBe(true);
  });

  unixIt("kills a grandchild when the command times out", async () => {
    const store = new SecretStore();
    const pidFile = path.join(tmpHome, "grandchild.pid");
    const summary = await runShell(store, `sleep 30 & echo $! > "${pidFile}"; wait`, 400);

    expect(summary.timedOut).toBe(true);
    expect(summary.exitCode).toBe(124);
    expect(summary.durationMs).toBeLessThan(10_000);
    await expectGone(Number((await readFile(pidFile, "utf8")).trim()));
  }, 20_000);

  unixIt("force-kills an orphaned grandchild that ignored SIGTERM", async () => {
    const store = new SecretStore();
    const pidFile = path.join(tmpHome, "stubborn.pid");
    const script = `trap "" TERM; sleep 30 & echo $! > "${pidFile}"; trap - TERM; wait`;
    const summary = await runShell(store, script, 400);

    expect(summary.timedOut).toBe(true);
    expect(summary.exitCode).toBe(124);
    expect(summary.durationMs).toBeGreaterThanOrEqual(1_500);
    expect(summary.durationMs).toBeLessThan(10_000);
    await expectGone(Number((await readFile(pidFile, "utf8")).trim()));
  }, 20_000);

  windowsIt("kills a grandchild on Windows when the command times out", async () => {
    const store = new SecretStore();
    const pidFile = path.join(tmpHome, "grandchild.pid");
    // The grandchild holds none of the command's pipes, so only a tree kill can end it.
    const script = [
      "const idle = 'setInterval(() => {}, 1000)'",
      "const grandchild = require('node:child_process').spawn(process.execPath, ['-e', idle], { stdio: 'ignore' })",
      `require('node:fs').writeFileSync(${JSON.stringify(pidFile)}, String(grandchild.pid))`,
      "setInterval(() => {}, 1000)"
    ].join(";");
    const summary = await runNodeWithTimeout(store, script, 800);

    expect(summary.timedOut).toBe(true);
    expect(summary.exitCode).toBe(124);
    expect(summary.durationMs).toBeLessThan(10_000);
    await expectGone(Number((await readFile(pidFile, "utf8")).trim()));
  }, 20_000);
});

describe("Rust core response verification", () => {
  unixIt("rejects a core response containing an encoded credential", async () => {
    const fakeCore = path.join(tmpHome, "fake-core");
    await writeFile(fakeCore, [
      `#!${process.execPath}`,
      "let input = '';",
      "process.stdin.on('data', chunk => input += chunk);",
      "process.stdin.on('end', () => {",
      "  const request = JSON.parse(input);",
      "  console.log(JSON.stringify({",
      "    exitCode: 0, signal: null, stdout: '', proof: 'invalid', durationMs: 1,",
      "    stderr: Buffer.from(request.secretValue).toString('hex').toUpperCase(),",
      "    timeoutMs: request.timeoutMs, timedOut: false, sanitized: false",
      "  }));",
      "});"
    ].join("\n"), { mode: 0o700 });
    await chmod(fakeCore, 0o700);

    const store = new SecretStore();
    const secret = "encoded-core-secret-value-123456789";
    const record = await addCredential(store, "encoded core", secret);
    const request = await createNodeRequest(store, record.handle, "SGW_BAD_CORE", "console.log('should-not-run')");

    await expect(executeApprovedRequest(store, request.id, { engine: "rust", coreBinary: fakeCore }))
      .rejects.toThrow("Rust execution core returned unsanitized output.");
    expect((await store.getRequest(request.id)).state).toBe("failed");
  });
});

describe("process descendants", () => {
  unixIt("lists and kills descendants without touching the root", async () => {
    const child = spawn("/bin/sh", ["-c", "sleep 30 & echo $!; wait"], { stdio: ["ignore", "pipe", "ignore"] });
    spawned.push(child);
    const grandchild = Number(await firstLine(child));

    expect(listDescendantPids(child.pid!)).toEqual([grandchild]);
    expect(listDescendantPids(process.pid)).toEqual(expect.arrayContaining([child.pid, grandchild]));

    // pid 1 and the broker itself are never signalled, whatever the caller passes.
    signalPids([1, process.pid], "SIGKILL");
    expect(() => process.kill(grandchild, 0)).not.toThrow();
    expect(() => process.kill(child.pid!, 0)).not.toThrow();

    signalPids(listDescendantPids(child.pid!), "SIGKILL");
    await expectGone(grandchild);
  }, 20_000);

  it("returns nothing for an invalid or childless root", () => {
    expect(listDescendantPids(0)).toEqual([]);
    expect(listDescendantPids(-5)).toEqual([]);
    expect(listDescendantPids(1.5)).toEqual([]);
  });
});

async function addCredential(store: SecretStore, name: string, value: string, maxOutputBytes = 4096) {
  return store.addSecret({
    name,
    type: "credential",
    value,
    policy: { allowedCommands: [process.execPath], maxOutputBytes }
  });
}

async function addSecretPair(store: SecretStore, first: string, second: string, maxOutputBytes: number) {
  const primary = await addCredential(store, "boundary first", first, maxOutputBytes);
  const extra = await addCredential(store, "boundary second", second, maxOutputBytes);
  return { primary, extra };
}

async function createNodeRequest(
  store: SecretStore,
  handle: string,
  injectEnv: string,
  script: string,
  env?: Array<{ handle: string; injectEnv: string }>
) {
  const request = await store.createRequest(
    handle,
    buildEnvCommandAction({ command: process.execPath, args: ["-e", script], injectEnv, env }),
    "Environment command hardening test"
  );
  await store.approveRequest(request.id);
  return request;
}

async function runNode(
  store: SecretStore,
  handle: string,
  injectEnv: string,
  script: string,
  env?: Array<{ handle: string; injectEnv: string }>
) {
  const request = await createNodeRequest(store, handle, injectEnv, script, env);
  return executeApprovedRequest(store, request.id, { engine: "typescript" });
}

async function runShell(store: SecretStore, script: string, timeoutMs: number) {
  const record = await store.addSecret({
    name: "timeout shell token",
    type: "api-token",
    value: "timeout-shell-secret-value-123456789",
    policy: { allowedCommands: ["/bin/sh"], injectEnv: "SGW_TIMEOUT_TOKEN" }
  });
  const request = await store.createRequest(record.handle, buildEnvCommandAction({
    command: "/bin/sh", args: ["-c", script], injectEnv: "SGW_TIMEOUT_TOKEN", timeoutMs
  }), "Environment command timeout test");
  await store.approveRequest(request.id);
  return executeApprovedRequest(store, request.id, { engine: "typescript" });
}

async function runNodeWithTimeout(store: SecretStore, script: string, timeoutMs: number) {
  const record = await addCredential(store, "timeout node token", "timeout-node-secret-value-123456789");
  const request = await store.createRequest(record.handle, buildEnvCommandAction({
    command: process.execPath, args: ["-e", script], injectEnv: "SGW_TIMEOUT_TOKEN", timeoutMs
  }), "Environment command timeout test");
  await store.approveRequest(request.id);
  return executeApprovedRequest(store, request.id, { engine: "typescript" });
}

async function expectGone(pid: number): Promise<void> {
  expect(pid).toBeGreaterThan(1);
  await vi.waitFor(() => expect(() => process.kill(pid, 0)).toThrow(), { timeout: 5_000 });
}

function firstLine(child: ChildProcess): Promise<string> {
  return new Promise((resolve, reject) => {
    let text = "";
    child.once("error", reject);
    child.stdout!.on("data", (chunk: Buffer) => {
      text += chunk.toString("utf8");
      if (text.includes("\n")) resolve(text.split("\n")[0]);
    });
  });
}
