import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const native = process.platform === "darwin" && spawnSync("cc", ["--version"], { stdio: "ignore" }).status === 0;
const children: ChildProcess[] = [];
const listeners: net.Server[] = [];
const homes: string[] = [];

afterEach(async () => {
  for (const child of children.splice(0)) {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await new Promise<void>((resolve) => child.once("exit", () => resolve()));
    }
  }
  for (const listener of listeners.splice(0)) {
    if (listener.listening) await new Promise<void>((resolve) => listener.close(() => resolve()));
  }
  for (const home of homes.splice(0)) {
    await rm(home, { recursive: true, force: true });
    await rm(`${home}-recovery`, { recursive: true, force: true });
  }
});

async function boundListener(host: string): Promise<net.Server> {
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(0, host, resolve));
  listeners.push(server);
  return server;
}

async function runChild(listener: net.Server, port: number): Promise<{ child: ChildProcess; line: string }> {
  const home = await realpath(await mkdtemp("/private/tmp/sgw-ac-"));
  homes.push(home);
  const fd = (listener as net.Server & { _handle: { fd: number } })._handle.fd;
  const script = `
    import { startConsoleServer } from './src/console-server.ts';
    try {
      const running = await startConsoleServer({ host: '127.0.0.1', port: ${port},
        activatedFd: 3, operatorAuth: { background: true } });
      process.stdout.write('READY ' + running.url + '\\n');
      process.on('SIGTERM', () => { void running.close().finally(() => process.exit(0)); });
    } catch (error) {
      process.stderr.write(String(error) + '\\n');
      process.exitCode = 1;
    }
  `;
  const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", script], {
    cwd: root,
    env: { ...process.env, TMPDIR: "/private/tmp", SGW_TEST_HOME_ROOT: "/private/tmp",
      SGW_HOME: home, SGW_RECOVERY_HOME: `${home}-recovery`,
      SGW_DISABLE_KEYCHAIN: "1", SGW_SECRET_BACKEND: "local", SGW_MASTER_PASSPHRASE: "synthetic fixture" },
    stdio: ["ignore", "pipe", "pipe", fd]
  });
  children.push(child);
  return new Promise((resolve, reject) => {
    let output = "";
    let errors = "";
    const timer = setTimeout(() => reject(new Error("Activated console child did not report a result.")), 10_000);
    child.stdout!.on("data", (chunk) => {
      output += String(chunk);
      if (!output.includes("\n")) return;
      clearTimeout(timer);
      resolve({ child, line: output.trim() });
    });
    child.stderr!.on("data", (chunk) => { errors += String(chunk); });
    child.once("exit", (code) => {
      if (output.includes("\n")) return;
      clearTimeout(timer);
      reject(new Error(`Activated console child exited ${code}: ${errors}`));
    });
  });
}

describe.skipIf(!native)("launchd protected console listener", () => {
  it("serves a protected console from an inherited exact loopback socket", async () => {
    const listener = await boundListener("127.0.0.1");
    const port = (listener.address() as net.AddressInfo).port;
    const { line } = await runChild(listener, port);
    expect(line).toBe(`READY http://127.0.0.1:${port}/`);
    await new Promise<void>((resolve) => listener.close(() => resolve()));
    const response = await fetch(`http://127.0.0.1:${port}/`);
    expect(response.status).toBe(200);
    expect(await response.text()).toContain("s-gw operator sign-in");
  }, 20_000);

  it("rejects an inherited listener on another port or a wildcard address", async () => {
    const wrongPort = await boundListener("127.0.0.1");
    const port = (wrongPort.address() as net.AddressInfo).port;
    await expect(runChild(wrongPort, port === 65_535 ? port - 1 : port + 1))
      .rejects.toThrow("Inherited console listener does not match");

    const wildcard = await boundListener("0.0.0.0");
    const wildcardPort = (wildcard.address() as net.AddressInfo).port;
    await expect(runChild(wildcard, wildcardPort))
      .rejects.toThrow("Inherited console listener does not match");
  }, 25_000);

  it("refuses the native activator outside a launchd socket job", async () => {
    const temp = await mkdtemp(path.join(os.tmpdir(), "sgw-console-activate-"));
    homes.push(temp);
    const binary = path.join(temp, "activate");
    const source = path.join(root, "native/macos-console-activate/activate.c");
    const build = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", source, "-o", binary], { encoding: "utf8" });
    expect(build.status, build.stderr).toBe(0);
    const listener = await boundListener("127.0.0.1");
    const port = (listener.address() as net.AddressInfo).port;
    const fd = (listener as net.Server & { _handle: { fd: number } })._handle.fd;
    const run = spawnSync(binary, [process.execPath, path.join(root, "dist/cli.js"), "console", "--host",
      "127.0.0.1", "--port", String(port), "--no-open", "--operator-auth", "--background", "--launchd-socket"],
    { encoding: "utf8", stdio: ["ignore", "pipe", "pipe", fd] });
    expect(run.status).toBe(1);
    expect(run.stderr).toContain("launchd-owned IPv4 loopback listener");
  });
});
