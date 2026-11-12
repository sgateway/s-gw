import { spawn, spawnSync } from "node:child_process";
import { closeSync, openSync } from "node:fs";
import { chmod, mkdtemp, readFile, rename, rm, symlink, writeFile } from "node:fs/promises";
import { createConnection, createServer } from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

const source = fileURLToPath(new URL("../native/linux-agent-gate/launch-gate.c", import.meta.url));
const invocation = "0123456789abcdef0123456789abcdef";
let tmp = "";

afterEach(async () => {
  if (tmp) await rm(tmp, { recursive: true, force: true });
  tmp = "";
});

async function compiledGate(forceFdFallback = false, swapOn?: "fstat" | "read"): Promise<{ binary: string; marker: string }> {
  tmp = await mkdtemp(path.join(os.tmpdir(), "sgw-linux-gate-"));
  const marker = path.join(tmp, "release");
  const binary = path.join(tmp, "gate");
  const swapSource = path.join(tmp, "swap-marker.c");
  const swapFunction = swapOn === "fstat"
    ? `int gate_test_fstat(int fd, struct stat *info) {
  if (swap_marker() != 0) return -1;
  return fstat(fd, info);
}`
    : `ssize_t gate_test_read(int fd, void *buf, size_t size) {
  if (swap_marker() != 0) return -1;
  return read(fd, buf, size);
}`;
  if (swapOn) await writeFile(swapSource, `#undef ${swapOn}
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static int swap_marker(void) {
  static int swapped = 0;
  if (swapped) return 0;
  swapped = 1;
  return rename(getenv("SGW_GATE_TEST_REPLACEMENT"), SGW_GATE_RELEASE_FILE);
}

${swapFunction}
`);
  const result = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror",
    `-DSGW_GATE_RELEASE_FILE="${marker}"`, `-DSGW_GATE_OWNER_UID=${process.getuid?.() ?? 0}`,
    "-DGATE_WAIT_SECONDS=1", ...(forceFdFallback ? ["-DSGW_GATE_FORCE_FD_FALLBACK=1"] : []),
    ...(swapOn ? [`-D${swapOn}=gate_test_${swapOn}`] : []), source,
    ...(swapOn ? [swapSource] : []), "-o", binary], { encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || "Could not compile Linux launch gate test binary.");
  return { binary, marker };
}

function runGate(binary: string, args: string[], inheritedFd?: number) {
  const child = spawn(binary, ["--", ...args], {
    env: { INVOCATION_ID: invocation },
    ...(inheritedFd === undefined ? {} :
      { stdio: ["ignore", "ignore", "ignore", "ignore", "ignore", "ignore", "ignore", inheritedFd] })
  });
  const finished = new Promise<number>((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", code => resolve(code ?? -1));
  });
  return { child, finished };
}

describe.skipIf(process.platform === "win32")("native Linux launch gate protocol", () => {
  it("retries a WAIT inode unlinked between open and fstat", async () => {
    const { binary, marker } = await compiledGate(false, "fstat");
    await writeFile(marker, "WAIT\n", { mode: 0o444 });
    await chmod(marker, 0o444);
    const ready = path.join(tmp, "ready.tmp");
    const script = `set -e; printf 'GO %s %s\\n' "$INVOCATION_ID" "$$" > "$SGW_GATE_TEST_REPLACEMENT"; ` +
      `chmod 444 "$SGW_GATE_TEST_REPLACEMENT"; exec "$SGW_GATE_TEST_BINARY" -- /usr/bin/true`;
    const child = spawn("/bin/sh", ["-c", script], { env: {
      INVOCATION_ID: invocation, SGW_GATE_TEST_REPLACEMENT: ready, SGW_GATE_TEST_BINARY: binary
    } });
    const finished = new Promise<number>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", code => resolve(code ?? -1));
    });
    const exitCode = await finished;
    expect(await readFile(marker, "utf8")).toBe(`GO ${invocation} ${child.pid}\n`);
    await expect(readFile(ready)).rejects.toMatchObject({ code: "ENOENT" });
    expect(exitCode).toBe(0);
  });

  it("rejects an unlinked GO inode even when its invocation and PID match", async () => {
    const { binary, marker } = await compiledGate(false, "fstat");
    const ready = path.join(tmp, "ready.tmp");
    const script = `set -e; printf 'GO %s %s\\n' "$INVOCATION_ID" "$$" > "$SGW_GATE_TEST_MARKER"; ` +
      `chmod 444 "$SGW_GATE_TEST_MARKER"; ` +
      `printf 'GO %s %s\\n' "$INVOCATION_ID" "$$" > "$SGW_GATE_TEST_REPLACEMENT"; ` +
      `chmod 444 "$SGW_GATE_TEST_REPLACEMENT"; exec "$SGW_GATE_TEST_BINARY" -- /usr/bin/true`;
    const child = spawn("/bin/sh", ["-c", script], { env: {
      INVOCATION_ID: invocation, SGW_GATE_TEST_MARKER: marker,
      SGW_GATE_TEST_REPLACEMENT: ready, SGW_GATE_TEST_BINARY: binary
    } });
    const finished = new Promise<number>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", code => resolve(code ?? -1));
    });
    expect(await finished).toBe(70);
    await expect(readFile(ready)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it("rejects GO unlinked after its first fstat but before read", async () => {
    const { binary, marker } = await compiledGate(false, "read");
    const ready = path.join(tmp, "ready.tmp");
    const script = `set -e; printf 'GO %s %s\\n' "$INVOCATION_ID" "$$" > "$SGW_GATE_TEST_MARKER"; ` +
      `chmod 444 "$SGW_GATE_TEST_MARKER"; ` +
      `printf 'WAIT\\n' > "$SGW_GATE_TEST_REPLACEMENT"; ` +
      `chmod 444 "$SGW_GATE_TEST_REPLACEMENT"; exec "$SGW_GATE_TEST_BINARY" -- /usr/bin/true`;
    const child = spawn("/bin/sh", ["-c", script], { env: {
      INVOCATION_ID: invocation, SGW_GATE_TEST_MARKER: marker,
      SGW_GATE_TEST_REPLACEMENT: ready, SGW_GATE_TEST_BINARY: binary
    } });
    const finished = new Promise<number>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", code => resolve(code ?? -1));
    });
    const exitCode = await finished;
    expect(await readFile(marker, "utf8")).toBe("WAIT\n");
    await expect(readFile(ready)).rejects.toMatchObject({ code: "ENOENT" });
    expect(exitCode).toBe(70);
  });

  it("keeps the target stopped until the exact invocation and PID are released", async () => {
    const { binary, marker } = await compiledGate();
    await writeFile(marker, "WAIT\n", { mode: 0o444 });
    await chmod(marker, 0o444);
    const effect = path.join(tmp, "ran");
    const { child, finished } = runGate(binary, ["/bin/sh", "-c", `touch "${effect}"`]);
    await new Promise(resolve => setTimeout(resolve, 100));
    await expect(readFile(effect)).rejects.toMatchObject({ code: "ENOENT" });
    const ready = path.join(tmp, "ready.tmp");
    await writeFile(ready, `GO ${invocation} ${child.pid}\n`, { mode: 0o444 });
    await chmod(ready, 0o444);
    await rename(ready, marker);
    expect(await finished).toBe(0);
    expect(await readFile(effect, "utf8")).toBe("");
  });

  it("rejects a stale release marker without starting the target", async () => {
    const { binary, marker } = await compiledGate();
    await writeFile(marker, `GO ${invocation} 1\n`, { mode: 0o444 });
    const effect = path.join(tmp, "ran");
    const { finished } = runGate(binary, ["/bin/sh", "-c", `touch "${effect}"`]);
    expect(await finished).toBe(72);
    await expect(readFile(effect)).rejects.toMatchObject({ code: "ENOENT" });
  });

  it.skipIf(process.platform !== "linux")("closes inherited descriptors before starting the agent", async () => {
    const { binary, marker } = await compiledGate();
    await writeFile(marker, "WAIT\n", { mode: 0o444 });
    const probeSource = path.join(tmp, "probe.c");
    const probe = path.join(tmp, "probe");
    await writeFile(probeSource, `#include <errno.h>
#include <fcntl.h>
int main(void) {
  for (int fd = 0; fd < 3; fd++) if (fcntl(fd, F_GETFD) < 0) return 92;
  for (int fd = 3; fd <= 7; fd++) {
    if (fcntl(fd, F_GETFD) != -1 || errno != EBADF) return 91;
  }
  return 0;
}
`);
    const built = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", probeSource, "-o", probe],
      { encoding: "utf8" });
    if (built.status !== 0) throw new Error(built.stderr || "Could not compile inherited descriptor probe.");
    const peers = new Set<ReturnType<typeof createConnection>>();
    const server = createServer(socket => {
      peers.add(socket);
      socket.once("close", () => peers.delete(socket));
      socket.resume();
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => { server.off("error", reject); resolve(); });
    });
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test listener address.");
    const connected = createConnection({ host: "127.0.0.1", port: address.port });
    try {
      await new Promise<void>((resolve, reject) => {
        connected.once("connect", resolve);
        connected.once("error", reject);
      });
      const fd = (connected as typeof connected & { _handle?: { fd?: number } })._handle?.fd;
      if (!Number.isInteger(fd)) throw new Error("The test socket has no connected descriptor.");
      const inheritedFd = fd as number;
      const stdio = ["ignore", "ignore", "ignore", "ignore", "ignore", "ignore", "ignore", inheritedFd] as const;
      const control = spawnSync(probe, [], { stdio });
      expect(control.status).toBe(91);
      const { child, finished } = runGate(binary, [probe], inheritedFd);
      const ready = path.join(tmp, "ready.tmp");
      await writeFile(ready, `GO ${invocation} ${child.pid}\n`, { mode: 0o444 });
      await rename(ready, marker);
      expect(await finished).toBe(0);
    } finally {
      connected.destroy();
      for (const peer of peers) peer.destroy();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });

  it.skipIf(process.platform !== "linux")("closes descriptors above a lowered soft file limit in the fallback", async () => {
    const { binary, marker } = await compiledGate(true);
    await writeFile(marker, "WAIT\n", { mode: 0o444 });
    const wrapperSource = path.join(tmp, "lower-limit.c");
    const wrapper = path.join(tmp, "lower-limit");
    const probeSource = path.join(tmp, "high-fd-probe.c");
    const probe = path.join(tmp, "high-fd-probe");
    await writeFile(wrapperSource, `#include <sys/resource.h>
#include <unistd.h>
int main(int argc, char **argv) {
  if (argc < 2) return 64;
  if (dup2(7, 64) != 64) return 68;
  close(7);
  struct rlimit limit;
  if (getrlimit(RLIMIT_NOFILE, &limit) != 0) return 65;
  limit.rlim_cur = 32;
  if (setrlimit(RLIMIT_NOFILE, &limit) != 0) return 66;
  for (int fd = 3; fd < 32; fd++) close(fd);
  execv(argv[1], argv + 1);
  return 67;
}
`);
    await writeFile(probeSource, `#include <errno.h>
#include <fcntl.h>
int main(void) {
  if (fcntl(64, F_GETFD) >= 0) return 91;
  if (errno != EBADF) return 92;
  return 0;
}
`);
    for (const [src, binaryPath] of [[wrapperSource, wrapper], [probeSource, probe]]) {
      const built = spawnSync("cc", ["-std=c11", "-Wall", "-Wextra", "-Werror", src, "-o", binaryPath],
        { encoding: "utf8" });
      if (built.status !== 0) throw new Error(built.stderr || `Could not compile ${src}.`);
    }
    const heldFds: number[] = [];
    try {
      let inheritedFd = 0;
      do {
        inheritedFd = openSync("/dev/null", "r");
        heldFds.push(inheritedFd);
      } while (inheritedFd <= 7);
      const stdio = ["ignore", "ignore", "ignore", "ignore", "ignore", "ignore", "ignore", inheritedFd] as const;
      expect(spawnSync(wrapper, [probe], { stdio }).status).toBe(91);
      const child = spawn(wrapper, [binary, "--", probe], {
        env: { INVOCATION_ID: invocation }, stdio
      });
      const finished = new Promise<number>((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", code => resolve(code ?? -1));
      });
      const ready = path.join(tmp, "ready.tmp");
      await writeFile(ready, `GO ${invocation} ${child.pid}\n`, { mode: 0o444 });
      await rename(ready, marker);
      expect(await finished).toBe(0);
    } finally {
      for (const fd of heldFds) closeSync(fd);
    }
  });

  it("times out closed and rejects a symlinked marker", async () => {
    const { binary, marker } = await compiledGate();
    await writeFile(marker, "WAIT\n", { mode: 0o444 });
    expect(await runGate(binary, ["/bin/true"]).finished).toBe(73);
    await rm(marker);
    const target = path.join(tmp, "other");
    await writeFile(target, `GO ${invocation} 1\n`, { mode: 0o444 });
    await symlink(target, marker);
    expect(await runGate(binary, ["/bin/true"]).finished).toBe(70);
  });
});
