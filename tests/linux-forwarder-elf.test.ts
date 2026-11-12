import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { Readable } from "node:stream";
import { createHash } from "node:crypto";
import { discoverLinuxForwarderElfClosure } from "../src/linux-forwarder-elf.js";

interface FakeItem {
  kind: "directory" | "file" | "link";
  content?: string;
  link?: string;
  uid: number;
  mode: number;
  ino: number;
  nlink: number;
}

const fake = vi.hoisted(() => ({
  items: new Map<string, FakeItem>(),
  readelf: new Map<string, string>(),
  realpaths: new Map<string, string>(),
  cache: "",
  calls: [] as Array<{ command: string; args: string[]; options: Record<string, unknown> }>
}));

vi.mock("node:child_process", async importOriginal => ({
  ...(await importOriginal<typeof import("node:child_process")>()),
  spawnSync: (command: string, args: string[], options: Record<string, unknown>) => {
    fake.calls.push({ command, args, options });
    const stdout = command === "/usr/sbin/ldconfig" ? fake.cache :
      fake.readelf.get(args[args.length - 1]);
    return stdout === undefined ? { status: 1, stdout: "", stderr: "missing fixture" } :
      { status: 0, stdout, stderr: "" };
  }
}));

vi.mock("node:fs/promises", async importOriginal => ({
  ...(await importOriginal<typeof import("node:fs/promises")>()),
  lstat: async (filename: string) => {
    const item = fake.items.get(filename);
    if (!item) throw new Error(`Missing fixture path: ${filename}`);
    return { uid: item.uid, mode: item.mode, nlink: item.nlink,
      dev: 1, ino: item.ino, size: item.content?.length ?? 0, mtimeMs: 1, ctimeMs: 1,
      isFile: () => item.kind === "file",
      isDirectory: () => item.kind === "directory",
      isSymbolicLink: () => item.kind === "link" };
  },
  readlink: async (filename: string) => {
    const item = fake.items.get(filename);
    if (item?.kind !== "link") throw new Error("Not a symlink");
    return item.link;
  },
  realpath: async (filename: string) => {
    if (fake.realpaths.has(filename)) return fake.realpaths.get(filename);
    if (filename === "/lib/ld-linux.so") return "/lib/ld-linux-real.so";
    if (filename === "/lib/libfoo.so.1") return "/lib/libfoo.so.1.2";
    return filename;
  }
}));

vi.mock("node:fs", async importOriginal => ({
  ...(await importOriginal<typeof import("node:fs")>()),
  createReadStream: (filename: string) => {
    const item = fake.items.get(filename);
    if (item?.kind !== "file") throw new Error("Missing fixture file");
    return Readable.from([Buffer.from(item.content || "")]);
  }
}));

const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
const matchingAbi = process.arch === "arm64" ? "AArch64" : "x86-64";
let inode = 10;

function add(filename: string, kind: FakeItem["kind"], value = "", mode?: number) {
  fake.items.set(filename, { kind, uid: 0, mode: mode ?? (kind === "directory" ? 0o755 : 0o644),
    ino: ++inode, nlink: 1,
    ...(kind === "link" ? { link: value } : { content: value }) });
}

function elf(needed: string[] = [], interpreter?: string, extra = "", wrongMachine = false): string {
  const machine = wrongMachine ? "RISC-V" : process.arch === "arm64" ? "AArch64" :
    "Advanced Micro Devices X86-64";
  const endian = process.arch === "s390x" || process.arch === "ppc64" ? "big endian" :
    "little endian";
  return `Class: ELF64\nData: 2's complement, ${endian}\nMachine: ${machine}\n` +
    (interpreter ? `[Requesting program interpreter: ${interpreter}]\n` : "") +
    needed.map(name => `0x00000001 (NEEDED) Shared library: [${name}]\n`).join("") + extra;
}

function setup() {
  for (const directory of ["/", "/run", "/run/s-gw", "/lib", "/usr", "/usr/bin",
    "/usr/sbin"]) add(directory, "directory");
  add("/usr/bin/readelf", "file", "readelf", 0o755);
  add("/usr/sbin/ldconfig", "file", "ldconfig", 0o755);
  add("/run/s-gw/node", "file", "node bytes", 0o755);
  add("/lib/ld-linux-real.so", "file", "loader bytes", 0o755);
  add("/lib/ld-linux.so", "link", "ld-linux-real.so");
  add("/lib/libfoo.so.1.2", "file", "foo bytes");
  add("/lib/libfoo.so.1", "link", "libfoo.so.1.2");
  add("/lib/libbar.so.2", "file", "bar bytes");
  fake.readelf.set("/run/s-gw/node", elf(["libfoo.so.1"], "/lib/ld-linux.so"));
  fake.readelf.set("/lib/ld-linux-real.so", elf());
  fake.readelf.set("/lib/libfoo.so.1.2", elf(["libbar.so.2"]));
  fake.readelf.set("/lib/libbar.so.2", elf());
  fake.cache = "3 libs found in cache `/etc/ld.so.cache'\n" +
    `  libfoo.so.1 (libc6,${matchingAbi}) => /lib/libfoo.so.1\n` +
    `  libbar.so.2 (libc6,${matchingAbi}) => /lib/libbar.so.2\n`;
}

describe.skipIf(process.platform === "win32")("Linux forwarder ELF closure", () => {
  beforeEach(() => {
    fake.items.clear();
    fake.readelf.clear();
    fake.realpaths.clear();
    fake.cache = "";
    fake.calls.length = 0;
    Object.defineProperty(process, "platform", { configurable: true, value: "linux" });
    vi.spyOn(process, "getuid").mockReturnValue(0);
    vi.spyOn(process, "geteuid").mockReturnValue(0);
    setup();
  });

  afterEach(() => {
    Object.defineProperty(process, "platform", platform);
    vi.restoreAllMocks();
  });

  it("discovers interpreter and recursive libraries at loader-visible names", async () => {
    const result = await discoverLinuxForwarderElfClosure("/run/s-gw/node");
    expect(result.interpreter).toBe("/lib/ld-linux.so");
    expect(result.files.map(file => [file.sourcePath, file.targetPath])).toEqual([
      ["/lib/ld-linux-real.so", "/lib/ld-linux.so"],
      ["/lib/libfoo.so.1.2", "/lib/libfoo.so.1"],
      ["/lib/libbar.so.2", "/lib/libbar.so.2"]
    ]);
    expect(result.files[1].sha256).toBe(createHash("sha256").update("foo bytes").digest("hex"));
    expect(fake.calls.map(call => call.command)).toContain("/usr/bin/readelf");
    expect(fake.calls.map(call => call.command)).toContain("/usr/sbin/ldconfig");
    expect(fake.calls.every(call => (call.options.env as Record<string, string>).LC_ALL === "C" &&
      typeof call.options.timeout === "number" && typeof call.options.maxBuffer === "number"))
      .toBe(true);
  });

  it("accepts executable glibc libc only when it names Node's interpreter", async () => {
    add("/lib/libc.so.6", "file", "libc bytes");
    fake.readelf.set("/run/s-gw/node", elf(["libc.so.6"], "/lib/ld-linux.so"));
    fake.readelf.set("/lib/libc.so.6", elf([], "/lib/ld-linux.so"));
    fake.cache = `  libc.so.6 (libc6,${matchingAbi}) => /lib/libc.so.6\n`;
    const result = await discoverLinuxForwarderElfClosure("/run/s-gw/node");
    expect(result.files.map(file => file.targetPath)).toEqual([
      "/lib/ld-linux.so", "/lib/libc.so.6"
    ]);

    fake.readelf.set("/lib/libc.so.6", elf([], "/lib/different-loader.so"));
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/interpreter mismatch.*libc.so.6/);
  });

  it("rejects PT_INTERP on another shared object even when it names Node's loader", async () => {
    fake.readelf.set("/lib/libfoo.so.1.2", elf([], "/lib/ld-linux.so"));
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/interpreter mismatch.*libfoo.so.1/);
  });

  it("rejects non-root discovery before inspecting the runtime", async () => {
    vi.mocked(process.geteuid).mockReturnValue(501);
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/root Linux operator/);
    expect(fake.calls).toEqual([]);
  });

  it("rejects unsafe loader directives and slash-containing sonames", async () => {
    fake.readelf.set("/run/s-gw/node", elf(["libfoo.so.1"], "/lib/ld-linux.so",
      "0x0000001d (RUNPATH) Library runpath: [/tmp]\n"));
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/loader directive/);
    fake.readelf.set("/run/s-gw/node", elf(["/tmp/libfoo.so"], "/lib/ld-linux.so"));
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/dependency name/);
  });

  it("rejects a wrong-machine library under the matching ABI", async () => {
    fake.readelf.set("/lib/libfoo.so.1.2", elf([], undefined, "", true));
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/machine does not match/);
  });

  it("skips a wrong-ABI cache duplicate before inspecting its /lib32 path", async () => {
    fake.cache += "  libfoo.so.1 (libc6) => /lib32/libfoo.so.1\n";
    const result = await discoverLinuxForwarderElfClosure("/run/s-gw/node");
    expect(result.files.find(file => file.targetPath === "/lib/libfoo.so.1")?.sourcePath)
      .toBe("/lib/libfoo.so.1.2");
  });

  it("rejects an ambiguous cache under the matching ABI", async () => {
    fake.readelf.set("/lib/libfoo.so.1.2", elf(["libbar.so.2"]));
    add("/lib/other", "directory");
    add("/lib/other/libfoo.so.1", "file", "other foo");
    fake.readelf.set("/lib/other/libfoo.so.1", elf());
    fake.cache += `  libfoo.so.1 (libc6,${matchingAbi}) => /lib/other/libfoo.so.1\n`;
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/ambiguous/);
  });

  it("rejects non-system and writable library paths", async () => {
    fake.cache = `  libfoo.so.1 (libc6,${matchingAbi}) => /tmp/libfoo.so.1\n`;
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/non-system lookup path/);
    setup();
    fake.items.get("/lib")!.mode = 0o777;
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/writable directory/);
  });

  it("rejects a library symlink that escapes to /tmp", async () => {
    fake.items.get("/lib/libfoo.so.1")!.link = "/tmp/libfoo.so.1";
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/untrusted directory/);
  });

  it("rejects an inspection tool redirected outside system binary directories", async () => {
    fake.items.get("/usr/bin/readelf")!.kind = "link";
    fake.items.get("/usr/bin/readelf")!.link = "/tmp/readelf";
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/untrusted directory/);
    expect(fake.calls).toEqual([]);
  });

  it("rejects a writable ancestor beneath a library directory", async () => {
    add("/lib/vendor", "directory", "", 0o777);
    add("/lib/vendor/libfoo.so.1", "file", "vendor foo");
    fake.cache = `  libfoo.so.1 (libc6,${matchingAbi}) => /lib/vendor/libfoo.so.1\n`;
    fake.readelf.set("/lib/vendor/libfoo.so.1", elf());
    await expect(discoverLinuxForwarderElfClosure("/run/s-gw/node"))
      .rejects.toThrow(/writable directory/);
  });

  it("keeps /lib lookup names when usr-merge resolves sources into /usr/lib", async () => {
    add("/usr/lib", "directory");
    fake.items.set("/lib", { kind: "link", uid: 0, mode: 0o777, ino: ++inode,
      nlink: 1, link: "usr/lib" });
    for (const name of ["ld-linux-real.so", "libfoo.so.1.2", "libbar.so.2"]) {
      const source = `/usr/lib/${name}`;
      const old = fake.items.get(`/lib/${name}`)!;
      fake.items.set(source, { ...old, ino: ++inode });
      fake.readelf.set(source, fake.readelf.get(`/lib/${name}`)!);
    }
    add("/usr/lib/ld-linux.so", "link", "ld-linux-real.so");
    add("/usr/lib/libfoo.so.1", "link", "libfoo.so.1.2");
    fake.realpaths.set("/lib/ld-linux.so", "/usr/lib/ld-linux-real.so");
    fake.realpaths.set("/lib/libfoo.so.1", "/usr/lib/libfoo.so.1.2");
    fake.realpaths.set("/lib/libbar.so.2", "/usr/lib/libbar.so.2");
    const result = await discoverLinuxForwarderElfClosure("/run/s-gw/node");
    expect(result.files.map(file => [file.sourcePath, file.targetPath])).toEqual([
      ["/usr/lib/ld-linux-real.so", "/lib/ld-linux.so"],
      ["/usr/lib/libfoo.so.1.2", "/lib/libfoo.so.1"],
      ["/usr/lib/libbar.so.2", "/lib/libbar.so.2"]
    ]);
  });
});
