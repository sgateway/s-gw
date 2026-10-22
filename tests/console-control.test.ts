import { spawn } from "node:child_process";
import { chmodSync, existsSync, realpathSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createConnection } from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { requestConsoleCode, startConsoleControl } from "../src/console-control.js";

let home = "";
let control: Awaited<ReturnType<typeof startConsoleControl>> | undefined;

afterEach(async () => {
  await control?.close();
  control = undefined;
  if (home) await rm(home, { recursive: true, force: true });
  home = "";
});

describe.skipIf(process.platform !== "darwin")("background console control", () => {
  it("refuses a control socket directory readable by other OS identities", async () => {
    home = realpathSync(await mkdtemp(path.join(os.tmpdir(), "sgw-console-control-")));
    chmodSync(home, 0o755);
    await expect(startConsoleControl(path.join(home, "console-8718.sock"), () => "x".repeat(32)))
      .rejects.toThrow("private to the broker user");
  });

  it("does not replace an active control server", async () => {
    home = realpathSync(await mkdtemp(path.join(os.tmpdir(), "sgw-console-control-")));
    const socketPath = path.join(home, "console-8718.sock");
    control = await startConsoleControl(socketPath, () => "a".repeat(32));
    await expect(startConsoleControl(socketPath, () => "b".repeat(32)))
      .rejects.toThrow("already running");
    expect(await requestConsoleCode(socketPath)).toBe("a".repeat(32));
  });

  it("keeps serving after a client resets before code delivery", async () => {
    home = realpathSync(await mkdtemp(path.join(os.tmpdir(), "sgw-console-control-")));
    const socketPath = path.join(home, "console-8718.sock");
    control = await startConsoleControl(socketPath, () => "d".repeat(32));
    const client = createConnection(socketPath);
    await new Promise<void>((resolve, reject) => {
      client.once("connect", resolve);
      client.once("error", reject);
    });
    client.destroy();
    expect(await requestConsoleCode(socketPath)).toBe("d".repeat(32));
  });

  it("recovers a private socket left by a crashed daemon", async () => {
    home = realpathSync(await mkdtemp(path.join(os.tmpdir(), "sgw-console-control-")));
    const socketPath = path.join(home, "console-8718.sock");
    const script = `const fs=require('fs');const net=require('net');net.createServer().listen(process.argv[1],()=>{fs.chmodSync(process.argv[1],0o600);process.stdout.write('ready\\n')})`;
    const child = spawn(process.execPath, ["-e", script, socketPath], { stdio: ["ignore", "pipe", "pipe"] });
    try {
      await new Promise<void>((resolve, reject) => {
        child.stdout!.once("data", data => String(data).includes("ready") ? resolve() : reject(new Error("Socket was not ready.")));
        child.once("error", reject);
      });
    } finally {
      child.kill("SIGKILL");
      await new Promise(resolve => child.once("close", resolve));
    }
    expect(existsSync(socketPath)).toBe(true);
    control = await startConsoleControl(socketPath, () => "c".repeat(32));
    expect(await requestConsoleCode(socketPath)).toBe("c".repeat(32));
  });
});
