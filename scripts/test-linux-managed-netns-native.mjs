import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync } from "node:fs";
import { lstat, mkdir, rmdir, stat, unlink } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux" || process.getuid?.() !== 0 || process.geteuid?.() !== 0 ||
    process.env.CI !== "true" || process.argv.length !== 3 || process.argv[2] !== "--root") {
  throw new Error("Run this network namespace fixture as root on disposable Linux CI.");
}

const root = fileURLToPath(new URL("..", import.meta.url));
const helper = path.join(root, "dist/native", `linux-${process.arch}`, "s-gw-linux-netns");
const parent = "/run/s-gw/netns";
const name = `ci-netns-${randomBytes(7).toString("hex")}`;
const filename = `${parent}/${name}`;
const made = [];

function call(command, args, shouldPass = true) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 10_000,
    env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C" } });
  if (result.error || result.signal || result.status === null ||
      (shouldPass ? result.status !== 0 : result.status === 0)) {
    throw new Error(`${path.basename(command)} ${args[0]} failed: ` +
      (result.error?.message || result.stderr || result.stdout || result.status));
  }
  return result;
}

function routeMustFail() {
  const result = call(helper, ["check", filename], false);
  if (!result.stderr.includes("route invariant failed")) {
    throw new Error("Namespace check failed for a reason other than the injected route: " +
      (result.stderr || result.status));
  }
}

async function ensureDir(name, mode) {
  try { await lstat(name); }
  catch (error) {
    if (error.code !== "ENOENT") throw error;
    await mkdir(name, { mode });
    made.push(name);
  }
  const item = await lstat(name);
  if (!item.isDirectory() || item.uid !== 0 || (item.mode & 0o777) !== mode) {
    throw new Error(`Untrusted namespace fixture parent: ${name}`);
  }
}

try {
  await ensureDir("/run/s-gw", 0o755);
  await ensureDir(parent, 0o700);
  call(helper, ["create", filename]);
  const host = await stat("/proc/self/ns/net");
  const privateNs = await stat(filename);
  if (host.dev === privateNs.dev && host.ino === privateNs.ino) {
    throw new Error("Namespace helper pinned the host network namespace.");
  }
  call(helper, ["check", filename]);
  call(helper, ["create", filename], false);
  call(helper, ["check", `/run/s-gw/netns/../${name}`], false);
  const ip = ["/usr/sbin/ip", "/usr/bin/ip"].find(existsSync);
  if (!ip) throw new Error("Namespace fixture needs iproute2.");
  const inspected = spawnSync("/usr/bin/nsenter", [`--net=${filename}`, "--", ip,
    "-o", "link", "show"], { encoding: "utf8", timeout: 10_000 });
  if (inspected.status !== 0 || !/^\d+: lo:/m.test(inspected.stdout) ||
      inspected.stdout.trim().split("\n").length !== 1) {
    throw new Error("Pinned namespace has an unexpected network interface.");
  }
  call("/usr/bin/nsenter", [`--net=${filename}`, "--", ip, "route", "add", "default", "dev", "lo"]);
  routeMustFail();
  call("/usr/bin/nsenter", [`--net=${filename}`, "--", ip, "route", "del", "default", "dev", "lo"]);
  call(helper, ["check", filename]);
  call("/usr/bin/nsenter", [`--net=${filename}`, "--", ip, "route", "add",
    "198.51.100.1/32", "dev", "lo"]);
  routeMustFail();
  call("/usr/bin/nsenter", [`--net=${filename}`, "--", ip, "route", "del",
    "198.51.100.1/32", "dev", "lo"]);
  call("/usr/bin/nsenter", [`--net=${filename}`, "--", ip, "-6", "route", "add",
    "2001:db8::1/128", "dev", "lo"]);
  routeMustFail();
  call("/usr/bin/nsenter", [`--net=${filename}`, "--", ip, "-6", "route", "del",
    "2001:db8::1/128", "dev", "lo"]);
  call(helper, ["check", filename]);
  console.log("Managed Linux network namespace create/check and route-free loopback passed.");
} finally {
  try {
    const item = await lstat(filename);
    if (item.uid !== 0 || !item.isFile()) {
      throw new Error("Namespace fixture cannot prove ownership before cleanup.");
    }
    call("/usr/bin/umount", [filename]);
    await unlink(filename);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  for (const dir of made.reverse()) await rmdir(dir);
}
