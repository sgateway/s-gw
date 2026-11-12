import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createServer } from "node:net";
import { chown, lstat, mkdir, readFile, readlink, readdir, rm, unlink,
  writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "linux" || process.getuid?.() !== 0 || process.geteuid?.() !== 0 ||
    process.env.CI !== "true" || process.argv.length !== 3 || process.argv[2] !== "--root") {
  throw new Error("Run the agent census fixture as root on disposable Linux CI.");
}

const project = fileURLToPath(new URL("..", import.meta.url));
const id = randomBytes(5).toString("hex");
const base = `/var/lib/s-gw-census-${id}`;
const root = `${base}/root`;
const ready = `${root}/ready`;
const gate = `${root}/gate`;
const census = `${base}/agent-census`;
const username = `sgwc${id.slice(0, 7)}`;
const alias = `${root}/alias.sock`;
const units = [];
let uid;
let baseInode;
let server;
let groupCreated = false;
let userCreated = false;
let startUncertain = false;
let rootMount;

function call(command, args, allowFailure = false) {
  const result = spawnSync(command, args, { encoding: "utf8", timeout: 15_000,
    env: { PATH: "/usr/sbin:/usr/bin:/sbin:/bin", LANG: "C", CI: "true" } });
  if (!allowFailure && (result.error || result.signal || result.status !== 0)) {
    throw new Error(`${path.basename(command)} failed: ` +
      String(result.error?.message || result.stderr || result.stdout || result.status).slice(0, 4096));
  }
  return result;
}

function properties(unit) {
  const result = call("/usr/bin/systemctl", ["--system", "--no-pager", "show", unit,
    "-p", "Id", "-p", "Description", "-p", "LoadState", "-p", "ActiveState",
    "-p", "MainPID", "-p", "ControlGroup",
    "-p", "MountAPIVFS", "-p", "MountFlags", "-p", "Delegate", "-p", "User",
    "-p", "Group", "-p", "RootDirectory"]);
  const fields = new Map();
  for (const line of result.stdout.trim().split("\n")) {
    const at = line.indexOf("=");
    if (at < 1 || fields.has(line.slice(0, at))) throw new Error("Invalid census unit readback.");
    fields.set(line.slice(0, at), line.slice(at + 1));
  }
  return fields;
}

async function waitFor(test, label) {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await test()) return;
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error(`Timed out waiting for ${label}.`);
}

async function freeUid() {
  for (let n = 0; n < 100; n++) {
    const candidate = 280000 + randomBytes(2).readUInt16BE() + n;
    const account = call("/usr/bin/getent", ["passwd", String(candidate)], true);
    const group = call("/usr/bin/getent", ["group", String(candidate)], true);
    if (account.error || account.signal || group.error || group.signal ||
        ![0, 2].includes(account.status) || ![0, 2].includes(group.status)) {
      throw new Error("Census fixture identity lookup failed.");
    }
    if (account.status === 2 && group.status === 2) return candidate;
  }
  throw new Error("No dedicated census fixture UID is free.");
}

function decodeMountPath(value) {
  if (/\\(?![0-7]{3})/.test(value)) throw new Error("Malformed host mount path.");
  return value.replace(/\\([0-7]{3})/g, (_, code) => String.fromCharCode(parseInt(code, 8)));
}

async function hostMountFor(target) {
  const mountinfo = await readFile("/proc/self/mountinfo", "utf8");
  let selected;
  for (const line of mountinfo.trimEnd().split("\n")) {
    const fields = line.split(" ");
    const separator = fields.indexOf("-");
    if (separator < 6 || separator + 4 !== fields.length || !/^\d+:\d+$/.test(fields[2])) {
      throw new Error("Malformed host mountinfo.");
    }
    const mountpoint = decodeMountPath(fields[4]);
    if (target !== mountpoint && !target.startsWith(`${mountpoint === "/" ? "" : mountpoint}/`))
      continue;
    if (selected && mountpoint.length < selected.mountpoint.length) continue;
    if (selected && mountpoint.length === selected.mountpoint.length) {
      throw new Error("Ambiguous host mount for census root.");
    }
    selected = {
      mountpoint, root: decodeMountPath(fields[3]), device: fields[2],
      options: fields[5], type: fields[separator + 1], source: fields[separator + 2],
      superOptions: fields[separator + 3]
    };
  }
  if (!selected || !selected.root.startsWith("/")) {
    throw new Error("No host mount for census root.");
  }
  const relative = target.slice(selected.mountpoint.length).replace(/^\//, "");
  return {
    root: relative ? path.posix.resolve(selected.root, relative) : selected.root,
    device: selected.device, options: selected.options, type: selected.type,
    source: selected.source, superOptions: selected.superOptions
  };
}

async function checkCensus(pid, cgroup, shouldPass, mount = rootMount) {
  const args = ["--pid", String(pid), "--uid", String(uid), "--cgroup", cgroup,
    "--root", root, "--mount", "/", "--mount-root", mount.root,
    "--mount-device", mount.device, "--mount-options", mount.options,
    "--mount-type", mount.type, "--mount-source", mount.source,
    "--mount-super-options", mount.superOptions];
  const result = call(census, args, true);
  if (result.error || result.signal || (shouldPass ? result.status !== 0 : result.status !== 1)) {
    const mountinfo = await readFile(`/proc/${pid}/mountinfo`, "utf8").catch(() => "unavailable");
    throw new Error(`Agent census ${shouldPass ? "rejected clean state" : "accepted hostile state"}: ` +
      `status=${result.status} ${String(result.stderr || result.stdout).slice(0, 4096)}\n` +
      `mountinfo=${mountinfo.slice(0, 4096)}`);
  }
}

async function assertHeldFd(pid, mode) {
  const base = `/proc/${pid}/fd`;
  const fds = (await readdir(base)).filter(value => /^\d+$/.test(value))
    .map(Number).sort((a, b) => a - b);
  const extra = fds.filter(value => value > 2);
  const targets = new Map();
  for (const fd of fds.slice(0, 16)) {
    try { targets.set(fd, (await readlink(`${base}/${fd}`)).slice(0, 256)); }
    catch (error) { targets.set(fd, `<${error.code || "readlink-error"}>`); }
  }
  const detail = (`count=${fds.length}; fds=${fds.slice(0, 16).join(",")}` +
    `${fds.length > 16 ? ",..." : ""}; ` +
    `targets=${[...targets].map(([fd, target]) => `${fd}=${target}`).join(",")}`).slice(0, 2048);
  if (mode === "extra") {
    if (extra.length !== 1 || extra[0] !== 3 || !targets.get(3)?.endsWith("/ready")) {
      throw new Error(`Census extra-FD adversary did not hold its regular descriptor: ${detail}`);
    }
    return;
  }
  if (extra.length !== 2 || extra[0] !== 3 || extra[1] !== 4 ||
      !/^socket:\[\d+\]$/.test(targets.get(3) || "") ||
      !/^socket:\[\d+\]$/.test(targets.get(4) || "")) {
    throw new Error(`Census socket adversary did not hold its connected descriptors: ${detail}`);
  }
}

function assertOwnedUnit(owned, state, requireCgroup) {
  if (state.get("LoadState") === "not-found") return;
  const group = state.get("ControlGroup");
  const expectedGroup = owned.cgroup.slice("/sys/fs/cgroup".length);
  const emptyAfterStop = !requireCgroup && group === "" &&
    ["inactive", "failed"].includes(state.get("ActiveState"));
  if (state.get("Id") !== owned.unit || state.get("Description") !== owned.description ||
      state.get("User") !== String(uid) || state.get("Group") !== String(uid) ||
      state.get("RootDirectory") !== root ||
      (group !== expectedGroup && !emptyAfterStop)) {
    throw new Error("Census fixture unit ownership changed before teardown.");
  }
}

async function unitDrained(owned) {
  const state = properties(owned.unit);
  assertOwnedUnit(owned, state, false);
  if (state.get("ActiveState") !== "inactive" && state.get("LoadState") !== "not-found")
    return false;
  if (owned.pid && await lstat(`/proc/${owned.pid}`).then(() => true, error => {
    if (error.code === "ENOENT") return false;
    throw error;
  })) return false;
  let events;
  try { events = await readFile(`${owned.cgroup}/cgroup.events`, "utf8"); }
  catch (error) { if (error.code !== "ENOENT") throw error; }
  return !events || /^populated 0$/m.test(events);
}

async function stopUnit(owned) {
  const before = properties(owned.unit);
  const loaded = before.get("LoadState") !== "not-found";
  assertOwnedUnit(owned, before, true);
  const currentPid = Number(before.get("MainPID"));
  if (Number.isSafeInteger(currentPid) && currentPid > 0) owned.pid = currentPid;
  const errors = [];
  if (loaded) {
    const frozen = `${owned.cgroup}/cgroup.freeze`;
    try { await writeFile(frozen, "0\n"); }
    catch (error) { if (error.code !== "ENOENT") errors.push(`thaw: ${error.message}`); }
    if (before.get("ActiveState") !== "inactive") {
      try { call("/usr/bin/systemctl", ["--system", "stop", owned.unit]); }
      catch (error) { errors.push(`stop: ${error.message}`); }
    }
    try {
      const afterStop = properties(owned.unit);
      if (afterStop.get("LoadState") !== "not-found") {
        assertOwnedUnit(owned, afterStop, false);
        if (!["inactive", "failed"].includes(afterStop.get("ActiveState"))) {
          throw new Error("unit is still active");
        }
        try { call("/usr/bin/systemctl", ["--system", "reset-failed", owned.unit]); }
        catch (error) {
          const afterReset = properties(owned.unit);
          if (afterReset.get("LoadState") !== "not-found") {
            assertOwnedUnit(owned, afterReset, false);
            throw error;
          }
        }
      }
    } catch (error) { errors.push(`reset: ${error.message}`); }
  }
  try {
    await waitFor(() => unitDrained(owned), `unit teardown ${owned.unit}`);
  } catch (error) { errors.push(`drain: ${error.message}`); }
  if (errors.length) {
    throw new Error(`Census fixture teardown failed: ${errors.join("; ").slice(0, 4096)}`);
  }
  owned.drained = true;
}

async function assertNoUidProcesses() {
  const entries = await readdir("/proc");
  if (entries.length > 100000) throw new Error("Census fixture process inventory is too large.");
  for (const entry of entries) {
    if (!/^\d+$/.test(entry)) continue;
    let status;
    try { status = await readFile(`/proc/${entry}/status`, "utf8"); }
    catch (error) { if (error.code === "ENOENT") continue; throw error; }
    const ids = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/m.exec(status);
    if (!ids) throw new Error("Census fixture found malformed process identity.");
    if (ids.slice(1).some(value => Number(value) === uid)) {
      throw new Error("Census fixture dedicated UID still has a live process.");
    }
  }
}

function removeCreatedGroup() {
  const group = call("/usr/bin/getent", ["group", username], true);
  if (group.error || group.signal || ![0, 2].includes(group.status)) {
    throw new Error("Census fixture group lookup failed during cleanup.");
  }
  if (group.status === 2) return;
  const fields = group.stdout.trimEnd().split(":");
  if (fields.length !== 4 || fields[0] !== username ||
      fields[2] !== String(uid) || fields[3] !== "") {
    throw new Error("Census fixture group changed before cleanup.");
  }
  call("/usr/sbin/groupdel", [username]);
}

async function withUnit(mode, inspect) {
  const unit = `s-gw-agent-census-${id}-${mode}.service`;
  const description = `s-gw-agent-census-fixture:${id}:${mode}`;
  const owned = { unit, description, cgroup: `/sys/fs/cgroup/system.slice/${unit}`,
    pid: 0, drained: false };
  await writeFile(ready, "");
  units.push(owned);
  const result = call("/usr/bin/systemd-run", ["--system", "--no-ask-password", "--quiet",
    `--unit=${unit}`, `--description=${description}`, "--property=Type=exec",
    `--property=User=${uid}`,
    `--property=Group=${uid}`, `--property=RootDirectory=${root}`,
    "--property=WorkingDirectory=/", "--property=MountFlags=private",
    "--property=MountAPIVFS=no", "--property=BindLogSockets=no",
    "--property=StandardInput=null",
    "--property=StandardOutput=null", "--property=StandardError=null",
    "--property=NoNewPrivileges=yes", "--property=CapabilityBoundingSet=",
    "--property=AmbientCapabilities=", "--property=RestrictNamespaces=yes",
    "--property=KillMode=control-group", "--property=Delegate=no",
    "--", "/gate", mode], true);
  if (result.error || result.status !== 0) {
    startUncertain = true;
    throw new Error(`Census fixture unit failed to start: ${String(result.stderr || result.stdout ||
      result.error?.message || result.status).slice(0, 4096)}`);
  }
  let failure;
  try {
    await waitFor(async () => (await readFile(ready, "utf8")) === "READY\n", "gate readiness");
    const state = properties(unit);
    const pid = Number(state.get("MainPID"));
    const group = state.get("ControlGroup");
    if (state.get("Id") !== unit || state.get("Description") !== description ||
        state.get("ActiveState") !== "active" || state.get("MountAPIVFS") !== "no" ||
        state.get("MountFlags") !== "private" || state.get("Delegate") !== "no" ||
        state.get("User") !== String(uid) || state.get("Group") !== String(uid) ||
        state.get("RootDirectory") !== root ||
        !Number.isSafeInteger(pid) || pid < 1 ||
        !/^\/system\.slice\/s-gw-agent-census-[a-z0-9-]+\.service$/.test(group || "")) {
      throw new Error("Census fixture unit lost its live process identity.");
    }
    if (owned.cgroup !== `/sys/fs/cgroup${group}`) {
      throw new Error("Census fixture cgroup path changed.");
    }
    owned.pid = pid;
    // READY is written before the helper closes its temporary writer.
    const readyFd = mode === "clean" ? 3 : mode === "extra" ? 4 : 5;
    await waitFor(async () => {
      try { await readlink(`/proc/${pid}/fd/${readyFd}`); return false; }
      catch (error) { if (error.code === "ENOENT") return true; throw error; }
    }, "gate readiness descriptor close");
    await writeFile(`${owned.cgroup}/cgroup.freeze`, "1\n");
    await waitFor(async () => /^frozen 1$/m.test(await readFile(`${owned.cgroup}/cgroup.events`, "utf8")),
      "cgroup freeze");
    await inspect(pid, owned.cgroup);
  } catch (error) { failure = error; }
  let teardownError;
  try { await stopUnit(owned); }
  catch (error) { teardownError = error; }
  if (failure && teardownError) {
    throw new AggregateError([failure, teardownError],
      `Census fixture check failed: ${String(failure).slice(0, 2048)}; ` +
      `teardown failed: ${String(teardownError).slice(0, 2048)}`);
  }
  if (failure) throw failure;
  if (teardownError) throw teardownError;
}

let failure;
try {
  uid = await freeUid();
  call("/usr/sbin/groupadd", ["--gid", String(uid), username]);
  groupCreated = true;
  call("/usr/sbin/useradd", ["--system", "--uid", String(uid), "--gid", username,
    "--no-create-home", "--shell", "/usr/sbin/nologin", username]);
  userCreated = true;
  await mkdir(base, { mode: 0o755 });
  baseInode = await lstat(base);
  await mkdir(root, { mode: 0o755 });
  rootMount = await hostMountFor(root);
  call("/usr/bin/cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "native/linux-agent-isolation/agent-census.c"), "-o", census]);
  call("/usr/bin/cc", ["-static", "-O2", "-std=c11", "-Wall", "-Wextra", "-Werror",
    path.join(project, "scripts/fixtures/linux-agent-census-wait.c"), "-o", gate]);
  await writeFile(ready, "", { mode: 0o600 });
  await chown(ready, uid, uid);
  await withUnit("clean", async (pid, cgroup) => {
    await checkCensus(pid, cgroup, true);
    await checkCensus(pid, cgroup, false, { ...rootMount, source: "not-the-host-backing" });
    const readOnlyOptions = rootMount.options.replace(/(^|,)rw(?=,|$)/, "$1ro");
    if (readOnlyOptions === rootMount.options) {
      throw new Error("Census fixture root was not mounted read-write as expected.");
    }
    await checkCensus(pid, cgroup, false, { ...rootMount, options: readOnlyOptions });
    server = createServer();
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(alias, resolve);
    });
    if (!(await lstat(alias)).isSocket()) throw new Error("Census socket alias is absent.");
    await checkCensus(pid, cgroup, false);
    await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    server = undefined;
    if (await lstat(alias).then(() => true, () => false)) await unlink(alias);
    await checkCensus(pid, cgroup, true);
  });
  await withUnit("extra", async (pid, cgroup) => {
    await assertHeldFd(pid, "extra");
    await checkCensus(pid, cgroup, false);
  });
  await withUnit("socket", async (pid, cgroup) => {
    await assertHeldFd(pid, "socket");
    await checkCensus(pid, cgroup, false);
  });
  console.log("Native agent census accepted the frozen mount and refused mismatched mount metadata, socket aliases, and extra FDs.");
} catch (error) {
  failure = error;
} finally {
  let cleanupError;
  try {
    if (server) await new Promise(resolve => server.close(resolve));
    const teardownErrors = [];
    for (const owned of units.reverse()) {
      try {
        if (owned.drained) await waitFor(() => unitDrained(owned), `unit teardown ${owned.unit}`);
        else await stopUnit(owned);
      }
      catch (error) { teardownErrors.push(error.message); }
    }
    if (teardownErrors.length) {
      throw new Error(teardownErrors.join("; ").slice(0, 4096));
    }
    if (startUncertain) throw new Error("Census fixture start outcome is uncertain; preserving root and account.");
    if (userCreated) await assertNoUidProcesses();
    if (baseInode) {
      const item = await lstat(base);
      if (!item.isDirectory() || item.uid !== 0 || item.dev !== baseInode.dev ||
          item.ino !== baseInode.ino) throw new Error("Census fixture root changed before cleanup.");
      await rm(base, { recursive: true });
    }
    if (userCreated) call("/usr/sbin/userdel", [username]);
    if (groupCreated) removeCreatedGroup();
  } catch (error) { cleanupError = error; }
  if (cleanupError && failure) {
    throw new AggregateError([failure, cleanupError],
      `Census fixture check failed: ${String(failure).slice(0, 2048)}; ` +
      `cleanup failed: ${String(cleanupError).slice(0, 2048)}`);
  }
  if (cleanupError) throw new Error(`Census fixture cleanup failed: ${cleanupError.message}`, {
    cause: cleanupError
  });
}
if (failure) throw failure;
