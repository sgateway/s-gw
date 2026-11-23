import { execFile } from "node:child_process";
import { readFile, readlink } from "node:fs/promises";

const MAX_ANCESTORS = 8;
const POWERSHELL_TIMEOUT_MS = 10_000;

export interface ObservedLauncher {
  kind: "exe" | "authenticode";
  id: string;
  pid: number;
}

// One invocation for the whole chain because PowerShell takes a second or so to start.
// No double quotes anywhere: the script travels as a single -Command argument, and that
// keeps it out of reach of Windows command-line quoting rules.
export const WINDOWS_LAUNCHER_SCRIPT = `& { param([int]$StartPid)
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; } catch { };
$found = @();
$seen = @{};
$childCreated = $null;
$next = $StartPid;
for ($depth = 0; $depth -lt ${MAX_ANCESTORS} -and $next -gt 4; $depth++) {
  if ($seen.ContainsKey($next)) { break; };
  $seen[$next] = $true;
  $proc = Get-CimInstance -ClassName Win32_Process -Filter ('ProcessId = ' + $next) -ErrorAction SilentlyContinue;
  if (-not $proc) { break; };
  if ($childCreated -and $proc.CreationDate -and $proc.CreationDate -gt $childCreated) { break; };
  $childCreated = $proc.CreationDate;
  if ($proc.ExecutablePath) {
    $status = '';
    $subject = '';
    try {
      $sig = Get-AuthenticodeSignature -LiteralPath $proc.ExecutablePath -ErrorAction Stop;
      $status = [string]$sig.Status;
      if ($sig.SignerCertificate) { $subject = [string]$sig.SignerCertificate.Subject; };
    } catch { };
    $found += [pscustomobject]@{ pid = [int]$proc.ProcessId; path = [string]$proc.ExecutablePath; status = $status; subject = $subject; };
  };
  $next = [int]$proc.ParentProcessId;
};
ConvertTo-Json -InputObject @($found) -Compress;
}`;

/**
 * Walks up from the process that launched this s-gw process and records what each ancestor
 * is running: the executable path on Linux, the Authenticode signer on Windows (or the path
 * when the file is not validly signed). macOS has its own code-signature attestation.
 *
 * This is evidence about the launching application. It is not an isolation boundary: a
 * process running as the same user can start s-gw from any binary it likes.
 */
export async function observeLauncherChain(startPid = process.ppid): Promise<ObservedLauncher[]> {
  if (process.env.SGW_DISABLE_LAUNCHER_ATTESTATION === "1" || !Number.isInteger(startPid)) {
    return [];
  }
  try {
    if (process.platform === "linux") return await linuxChain(startPid);
    if (process.platform === "win32") return await windowsChain(startPid);
  } catch {
    // Observation is best effort. No evidence is better than a failed MCP start.
  }
  return [];
}

export function parseProcStat(stat: string): { parentPid: number; startTime: string } | undefined {
  // comm may itself contain spaces and parens, so only trust what follows the last ")".
  const close = stat.lastIndexOf(")");
  if (close < 0) {
    return undefined;
  }
  const fields = stat.slice(close + 1).trim().split(/\s+/);
  if (!/^\d+$/.test(fields[1] || "")) {
    return undefined;
  }
  // starttime is field 22 of the line, which is index 19 once pid and comm are gone.
  return { parentPid: Number(fields[1]), startTime: fields[19] || "" };
}

export function parseWindowsLauncherJson(text: string): ObservedLauncher[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text.replace(/^\uFEFF/, "").trim());
  } catch {
    return [];
  }
  // Windows PowerShell unwraps a one-element array into a bare object in some paths.
  const rows: unknown[] = Array.isArray(parsed) ? parsed : [parsed];
  const found: ObservedLauncher[] = [];
  for (const row of rows) {
    if (found.length >= MAX_ANCESTORS) break;
    const launcher = launcherFromRow(row);
    if (launcher) found.push(launcher);
  }
  return found;
}

function launcherFromRow(row: unknown): ObservedLauncher | undefined {
  if (typeof row !== "object" || row === null) {
    return undefined;
  }
  const { pid, path, status, subject } = row as Record<string, unknown>;
  // 0 is the idle process and 4 is System. Neither is a launcher.
  if (typeof pid !== "number" || !Number.isInteger(pid) || pid <= 4) {
    return undefined;
  }
  if (status === "Valid" && typeof subject === "string" && subject.trim()) {
    return { kind: "authenticode", id: subject, pid };
  }
  if (typeof path !== "string" || !path.trim()) {
    return undefined;
  }
  return { kind: "exe", id: path, pid };
}

async function linuxChain(startPid: number): Promise<ObservedLauncher[]> {
  const found: ObservedLauncher[] = [];
  let pid = startPid;
  for (let depth = 0; depth < MAX_ANCESTORS && pid > 1; depth += 1) {
    const before = await procStat(pid);
    if (!before) break;
    const exe = await procExe(pid);
    const after = exe ? await procStat(pid) : undefined;
    // Same start time on both sides of the readlink, or the pid was reused meanwhile.
    if (exe && after && after.startTime === before.startTime) {
      found.push({ kind: "exe", id: exe, pid });
    }
    pid = before.parentPid;
  }
  return found;
}

async function procStat(pid: number): Promise<{ parentPid: number; startTime: string } | undefined> {
  try {
    return parseProcStat(await readFile(`/proc/${pid}/stat`, "utf8"));
  } catch {
    return undefined;
  }
}

async function procExe(pid: number): Promise<string | undefined> {
  try {
    // The kernel appends this when the binary was replaced or removed after exec.
    const exe = (await readlink(`/proc/${pid}/exe`)).replace(/ \(deleted\)$/, "");
    return exe.startsWith("/") ? exe : undefined;
  } catch {
    // Another user's process, or a kernel thread with no executable.
    return undefined;
  }
}

async function windowsChain(startPid: number): Promise<ObservedLauncher[]> {
  if (startPid <= 4) {
    return [];
  }
  return parseWindowsLauncherJson(await runPowerShell(`${WINDOWS_LAUNCHER_SCRIPT} ${startPid}`));
}

function runPowerShell(script: string): Promise<string> {
  // Absolute path on purpose: a PATH lookup could run a planted powershell.exe.
  const powershell = `${process.env.SystemRoot || "C:\\Windows"}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe`;
  const args = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script];
  return new Promise((resolve, reject) => {
    const child = execFile(powershell, args, {
      encoding: "utf8",
      maxBuffer: 1024 * 1024,
      timeout: POWERSHELL_TIMEOUT_MS,
      windowsHide: true
    }, (error, stdout) => (error ? reject(error) : resolve(stdout)));
    // PowerShell can sit waiting on an open stdin pipe even with -Command.
    child.stdin?.end();
  });
}
