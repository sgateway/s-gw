import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { requestAgentIdentity } from "../src/agent-context.js";
import { WindowsAgentPipeRegistry, type WindowsAgentPipeIdentity } from "../src/windows-agent-pipe.js";

const oldTestMode = process.env.SGW_TEST_MODE;
beforeAll(() => { process.env.SGW_TEST_MODE = "1"; });
afterAll(() => {
  if (oldTestMode === undefined) delete process.env.SGW_TEST_MODE;
  else process.env.SGW_TEST_MODE = oldTestMode;
});

function identity(changes: Partial<WindowsAgentPipeIdentity> = {}): WindowsAgentPipeIdentity {
  return {
    brokerSid: "S-1-5-21-100-200-300-1001",
    userSid: "S-1-5-21-100-200-300-1001",
    appContainerSid: "S-1-15-2-111-222-333-444",
    logonLuid: "00000000000003e7",
    windowsSessionId: 3,
    sessionId: "windows-session-1",
    name: "Synthetic Windows agent",
    ...changes
  };
}

function fakeHelper(script: string) {
  const launches: string[][] = [];
  return {
    launches,
    start: (_path: string, args: string[]): ChildProcessWithoutNullStreams => {
      launches.push(args);
      return spawn(process.execPath, ["-e", script], { stdio: ["pipe", "pipe", "pipe"] });
    }
  };
}

const goodHelper = `
const body = Buffer.from(JSON.stringify({ principalId: 'win32:sid:forged', operation: 'synthetic' }));
const header = Buffer.alloc(5);
header[0] = 0x51;
header.writeUInt32LE(body.length, 1);
process.stdout.write(Buffer.concat([Buffer.from('R'), header, body]));
let response = Buffer.alloc(0);
process.stdin.on('data', chunk => {
  response = Buffer.concat([response, chunk]);
  if (response.length < 5) return;
  const size = response.readUInt32LE(1);
  if (response.length >= size + 5) process.exit(response[0] === 0x53 && size === 2 &&
    response.subarray(5).toString() === 'ok' ? 0 : 5);
});
`;

describe("Windows named-pipe session foundation", () => {
  it("refuses the native helper before installer ACL attestation exists", () => {
    expect(() => new WindowsAgentPipeRegistry(String.raw`C:\Program Files\s-gw\peer-identity.exe`))
      .toThrow("Native Windows agent pipes require installer-verified helper ACLs.");
  });

  it("binds a request to the registered SID, ignoring an agent-claimed principal", async () => {
    const helper = fakeHelper(goodHelper);
    const registry = new WindowsAgentPipeRegistry("ignored-test-helper", helper.start);
    const onRequest = vi.fn(async (request: Buffer, principal: Parameters<typeof requestAgentIdentity>[1]["managedPrincipal"]) => {
      expect(JSON.parse(request.toString()).principalId).toBe("win32:sid:forged");
      expect(requestAgentIdentity("claimed by someone else", { managedPrincipal: principal }).principalId)
        .toBe("win32:sid:s-1-15-2-111-222-333-444");
      return Buffer.from("ok");
    });
    const session = registry.register(identity());
    const exchange = await session.openOnce(onRequest);
    expect(exchange.pipeName).toMatch(/^\\\\\.\\pipe\\LOCAL\\s-gw-[a-f0-9]{32}$/);
    expect(helper.launches[0]).toEqual([
      exchange.pipeName, "S-1-5-21-100-200-300-1001", "S-1-5-21-100-200-300-1001",
      "S-1-15-2-111-222-333-444", "00000000000003e7", "3"
    ]);
    await exchange.completed;
    expect(onRequest).toHaveBeenCalledOnce();
    session.revoke();
  });

  it("rejects invalid launch identities before creating a pipe", () => {
    const helper = fakeHelper(goodHelper);
    const registry = new WindowsAgentPipeRegistry("ignored-test-helper", helper.start);
    expect(() => registry.register(identity({ appContainerSid: "S-1-15-2-01-222" }))).toThrow("numeric");
    expect(() => registry.register(identity({ appContainerSid: "S-1-5-21-123" }))).toThrow("package SID");
    expect(() => registry.register(identity({ appContainerSid: undefined }))).toThrow("must differ");
    expect(() => registry.register(identity({ logonLuid: "0000000000000000" }))).toThrow("logon LUID");
    expect(helper.launches).toHaveLength(0);
  });

  it("burns a SID and session ID even after revocation", () => {
    const registry = new WindowsAgentPipeRegistry("ignored-test-helper", fakeHelper(goodHelper).start);
    registry.register(identity()).revoke();
    expect(() => registry.register(identity({ sessionId: "new-session" }))).toThrow("already used");
    expect(() => registry.register(identity({ appContainerSid: "S-1-15-2-555-666", sessionId: "windows-session-1" })))
      .toThrow("already used");
    const dedicated = identity({ userSid: "S-1-5-21-100-200-300-5000", appContainerSid: undefined,
      sessionId: "dedicated" });
    registry.register(dedicated).revoke();
    expect(() => registry.register({ ...dedicated, logonLuid: "00000000000003e8", sessionId: "dedicated-next" }))
      .toThrow("already used");
  });

  it("never dispatches a request if the helper exits before token verification", async () => {
    const helper = fakeHelper("process.stdout.write('R'); setTimeout(() => process.exit(4), 10);");
    const onRequest = vi.fn(async () => Buffer.from("ok"));
    const session = new WindowsAgentPipeRegistry("ignored-test-helper", helper.start).register(identity());
    const exchange = await session.openOnce(onRequest);
    await expect(exchange.completed).rejects.toThrow("before a verified exchange");
    expect(onRequest).not.toHaveBeenCalled();
    session.revoke();
  });

  it("revokes an in-flight exchange before the callback may run", async () => {
    const helper = fakeHelper("process.stdout.write('R'); setInterval(() => {}, 1000);");
    const onRequest = vi.fn(async () => Buffer.from("ok"));
    const session = new WindowsAgentPipeRegistry("ignored-test-helper", helper.start).register(identity());
    const exchange = await session.openOnce(onRequest);
    session.revoke();
    await expect(exchange.completed).rejects.toThrow("session ended");
    expect(onRequest).not.toHaveBeenCalled();
    await expect(session.openOnce(onRequest)).rejects.toThrow("ended");
  });

  it("rejects a helper frame larger than the native request limit", async () => {
    const helper = fakeHelper(`
      process.stdout.write('R');
      const header = Buffer.alloc(5);
      header[0] = 0x51;
      header.writeUInt32LE(32769, 1);
      process.stdout.write(header);
      setInterval(() => {}, 1000);
    `);
    const onRequest = vi.fn(async () => Buffer.from("ok"));
    const session = new WindowsAgentPipeRegistry("ignored-test-helper", helper.start).register(identity());
    const exchange = await session.openOnce(onRequest);
    await expect(exchange.completed).rejects.toThrow("Invalid Windows pipe helper request frame");
    expect(onRequest).not.toHaveBeenCalled();
    session.revoke();
  });

  it("ends a stalled one-shot helper when its deadline expires", async () => {
    const helper = fakeHelper("process.stdout.write('R'); setInterval(() => {}, 1000);");
    const session = new WindowsAgentPipeRegistry("ignored-test-helper", helper.start).register(identity());
    const exchange = await session.openOnce(async () => Buffer.from("ok"), 1000);
    await expect(exchange.completed).rejects.toThrow("timed out");
    session.revoke();
  });

  it("holds a session slot until a canceled helper really exits", async () => {
    const children: Array<EventEmitter & { stdout: PassThrough }> = [];
    const start = (): ChildProcessWithoutNullStreams => {
      const child = Object.assign(new EventEmitter(), {
        stdout: new PassThrough(), stdin: new PassThrough(), stderr: new PassThrough(),
        kill: vi.fn(() => true)
      });
      children.push(child);
      queueMicrotask(() => child.stdout.write("R"));
      return child as unknown as ChildProcessWithoutNullStreams;
    };
    const session = new WindowsAgentPipeRegistry("ignored-test-helper", start).register(identity());
    for (let index = 0; index < 8; index++) {
      const exchange = await session.openOnce(async () => Buffer.from("ok"));
      exchange.close();
      await expect(exchange.completed).rejects.toThrow("closed");
    }
    await expect(session.openOnce(async () => Buffer.from("ok"))).rejects.toThrow("too many pending");
    expect(children).toHaveLength(8);
    for (const child of children) child.emit("close", null);
    const replacement = await session.openOnce(async () => Buffer.from("ok"));
    replacement.close();
    await expect(replacement.completed).rejects.toThrow("closed");
    children.at(-1)!.emit("close", null);
    session.revoke();
  });

  it("signals an active broker callback when its agent session ends", async () => {
    const helper = fakeHelper(goodHelper);
    let callbackStarted!: () => void;
    const started = new Promise<void>(resolve => { callbackStarted = resolve; });
    let callbackSignal: AbortSignal | undefined;
    const session = new WindowsAgentPipeRegistry("ignored-test-helper", helper.start).register(identity());
    const exchange = await session.openOnce(async (_request, _principal, signal) => {
      callbackSignal = signal;
      callbackStarted();
      await new Promise<void>((_resolve, reject) => signal.addEventListener("abort", () => reject(signal.reason)));
      return Buffer.from("ok");
    });
    await started;
    session.revoke();
    expect(callbackSignal?.aborted).toBe(true);
    await expect(exchange.completed).rejects.toThrow("session ended");
  });
});
