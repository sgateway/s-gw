import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  observeLauncherChain,
  parseProcStat,
  parseWindowsLauncherJson,
  WINDOWS_LAUNCHER_SCRIPT
} from "../src/launcher-observation.js";

const realPlatform = process.platform;

afterEach(() => {
  Object.defineProperty(process, "platform", { value: realPlatform });
  delete process.env.SGW_DISABLE_LAUNCHER_ATTESTATION;
});

describe("Linux /proc stat parsing", () => {
  const tail = "S 4321 4400 4400 34816 4400 4194304 1200 0 0 0 5 2 0 0 20 0 1 0 987654 12345678 900";

  it("reads the parent pid and start time", () => {
    expect(parseProcStat(`4400 (bash) ${tail} 18446744073709551615\n`)).toEqual({ parentPid: 4321, startTime: "987654" });
  });

  it("ignores spaces and parens inside comm", () => {
    expect(parseProcStat(`4400 (tmux: server (1) R 7 8) ${tail}`)).toEqual({ parentPid: 4321, startTime: "987654" });
    expect(parseProcStat(`4400 (a) b) S 1 4400 4400`)).toEqual({ parentPid: 1, startTime: "" });
  });

  it("rejects lines without a usable parent pid", () => {
    expect(parseProcStat("")).toBeUndefined();
    expect(parseProcStat("4400 bash S 4321")).toBeUndefined();
    expect(parseProcStat("4400 (bash)")).toBeUndefined();
    expect(parseProcStat("4400 (bash) S")).toBeUndefined();
    expect(parseProcStat("4400 (bash) S -1 4400")).toBeUndefined();
    expect(parseProcStat("4400 (bash) S x1 4400")).toBeUndefined();
  });
});

describe("Windows launcher JSON parsing", () => {
  const code = { pid: 9120, path: "C:\\Program Files\\Microsoft VS Code\\Code.exe", status: "Valid", subject: "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" };
  const node = { pid: 7044, path: "C:\\Users\\dev\\tools\\node.exe", status: "NotSigned", subject: "" };

  it("uses the signer for validly signed files and the path for the rest", () => {
    expect(parseWindowsLauncherJson(JSON.stringify([node, code]))).toEqual([
      { kind: "exe", id: node.path, pid: 7044 },
      { kind: "authenticode", id: code.subject, pid: 9120 }
    ]);
  });

  it("falls back to the path when the signature is not valid or has no subject", () => {
    const tampered = { ...code, status: "HashMismatch" };
    const anonymous = { ...code, subject: "  " };
    expect(parseWindowsLauncherJson(JSON.stringify([tampered, anonymous]))).toEqual([
      { kind: "exe", id: code.path, pid: 9120 },
      { kind: "exe", id: code.path, pid: 9120 }
    ]);
  });

  it("accepts a single object and a leading byte order mark", () => {
    expect(parseWindowsLauncherJson(`\uFEFF${JSON.stringify(code)}\r\n`)).toEqual([
      { kind: "authenticode", id: code.subject, pid: 9120 }
    ]);
  });

  it("drops rows with missing fields or system pids", () => {
    const rows = [
      { pid: 7044 },
      { path: node.path, status: "NotSigned", subject: "" },
      { pid: "7044", path: node.path },
      { pid: 4, path: "C:\\Windows\\System32\\ntoskrnl.exe" },
      { pid: 0, path: "idle" },
      { pid: 7044.5, path: node.path },
      null,
      "text",
      { pid: 812, status: "Valid", subject: "CN=Example" },
      { pid: 816, path: node.path, status: null, subject: null }
    ];
    expect(parseWindowsLauncherJson(JSON.stringify(rows))).toEqual([
      { kind: "authenticode", id: "CN=Example", pid: 812 },
      { kind: "exe", id: node.path, pid: 816 }
    ]);
  });

  it("returns nothing for garbage", () => {
    for (const text of ["", "   ", "not json", "{", "null", "42", "\"text\"", "[]", "[[1,2]]"]) {
      expect(parseWindowsLauncherJson(text)).toEqual([]);
    }
  });

  it("keeps at most eight ancestors", () => {
    const rows = Array.from({ length: 12 }, (_, index) => ({ ...node, pid: 1000 + index * 4 }));
    const found = parseWindowsLauncherJson(JSON.stringify(rows));
    expect(found).toHaveLength(8);
    expect(found[0].pid).toBe(1000);
  });
});

describe("Windows launcher script", () => {
  it("stays free of double quotes so it survives as one -Command argument", () => {
    expect(WINDOWS_LAUNCHER_SCRIPT).not.toContain("\"");
  });

  it("walks parents once and reports the Authenticode signer", () => {
    expect(WINDOWS_LAUNCHER_SCRIPT).toContain("param([int]$StartPid)");
    expect(WINDOWS_LAUNCHER_SCRIPT).toContain("Get-CimInstance -ClassName Win32_Process");
    expect(WINDOWS_LAUNCHER_SCRIPT).toContain("Get-AuthenticodeSignature -LiteralPath");
    expect(WINDOWS_LAUNCHER_SCRIPT).toContain("ConvertTo-Json -InputObject @($found) -Compress");
    // Automatic and read-only in PowerShell. Assigning it would abort the script.
    expect(WINDOWS_LAUNCHER_SCRIPT).not.toMatch(/\$pid\b/i);
  });
});

describe("observeLauncherChain", () => {
  it("returns nothing on macOS", async () => {
    Object.defineProperty(process, "platform", { value: "darwin" });
    expect(await observeLauncherChain()).toEqual([]);
    expect(await observeLauncherChain(process.pid)).toEqual([]);
  });

  it("returns nothing when launcher attestation is disabled", async () => {
    process.env.SGW_DISABLE_LAUNCHER_ATTESTATION = "1";
    expect(await observeLauncherChain()).toEqual([]);
  });

  it("returns nothing for a start pid that cannot be a launcher", async () => {
    expect(await observeLauncherChain(0)).toEqual([]);
    expect(await observeLauncherChain(1)).toEqual([]);
    expect(await observeLauncherChain(Number.NaN)).toEqual([]);
  });

  it.skipIf(process.platform !== "linux")("lists the executables above this process on Linux", async () => {
    const chain = await observeLauncherChain(process.ppid);

    expect(chain.length).toBeGreaterThan(0);
    expect(chain.length).toBeLessThanOrEqual(8);
    for (const launcher of chain) {
      expect(launcher.kind).toBe("exe");
      expect(path.isAbsolute(launcher.id)).toBe(true);
      expect(launcher.pid).toBeGreaterThan(1);
    }
  });

  it.skipIf(process.platform !== "win32")("observes the ancestors of this process on Windows", async () => {
    const chain = await observeLauncherChain(process.ppid);

    expect(Array.isArray(chain)).toBe(true);
    expect(chain.length).toBeLessThanOrEqual(8);
    for (const launcher of chain) {
      expect(["exe", "authenticode"]).toContain(launcher.kind);
      expect(launcher.id.length).toBeGreaterThan(0);
      expect(launcher.pid).toBeGreaterThan(4);
    }
  }, 30_000);
});
