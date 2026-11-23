import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";

// Absolute paths on purpose: a PATH lookup could run a planted codesign or ps.
const CODESIGN = "/usr/bin/codesign";
const PS = "/bin/ps";
const TOOL_TIMEOUT_MS = 3_000;
const MAX_ANCESTORS = 8;

export interface LauncherSignature {
  teamId: string;
  identifier: string;
  pid: number;
  startedAt: string;
}

export interface AttestedLauncherChain {
  /** Nearest ancestor first. Only ancestors with a valid team-signed code signature appear. */
  readonly signatures: readonly LauncherSignature[];
}

const attestedChains = new WeakSet<object>();

// Only code that has checked the running processes may call this. Agent input,
// MCP metadata, and environment variables must never be passed here.
export function launcherChainFromAttestation(signatures: LauncherSignature[]): AttestedLauncherChain {
  for (const signature of signatures) {
    if (!validTeamId(signature.teamId) || !validIdentifier(signature.identifier) ||
        !Number.isInteger(signature.pid) || signature.pid <= 1 || !signature.startedAt) {
      throw new Error("Launcher signature attestation is malformed.");
    }
  }
  const chain = Object.freeze({ signatures: Object.freeze(signatures.map((item) => Object.freeze({ ...item }))) });
  attestedChains.add(chain);
  return chain;
}

export function isAttestedLauncherChain(value: unknown): value is AttestedLauncherChain {
  return typeof value === "object" && value !== null && attestedChains.has(value);
}

export function launcherPrincipalId(signature: Pick<LauncherSignature, "teamId" | "identifier">): string {
  return `codesign:${signature.teamId}:${signature.identifier}`;
}

export function launcherSessionId(signature: Pick<LauncherSignature, "pid" | "startedAt">): string {
  const started = createHash("sha256").update(signature.startedAt).digest("hex").slice(0, 16);
  return `launcher:${signature.pid}:${started}`;
}

export function validTeamId(value: unknown): value is string {
  return typeof value === "string" && /^[A-Z0-9]{10}$/.test(value);
}

export function validIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(value);
}

/**
 * Walks up from the process that launched this s-gw process and records each ancestor whose
 * running code has a valid signature with a team identifier. macOS only.
 *
 * This identifies the launching application. It is not an isolation boundary: a process
 * running as the same user can start s-gw and then replace itself with a signed binary.
 */
export function attestLauncherChain(startPid = process.ppid): AttestedLauncherChain | undefined {
  if (process.platform !== "darwin" || process.env.SGW_DISABLE_LAUNCHER_ATTESTATION === "1") {
    return undefined;
  }

  const signatures: LauncherSignature[] = [];
  let pid = startPid;
  for (let depth = 0; depth < MAX_ANCESTORS && pid > 1; depth += 1) {
    const before = processRow(pid);
    if (!before) {
      break;
    }
    const signed = signedRunningCode(pid);
    const after = signed ? processRow(pid) : undefined;
    // Same pid and start time on both sides of the check, or the pid was reused meanwhile.
    if (signed && after && after.startedAt === before.startedAt) {
      signatures.push({ ...signed, pid, startedAt: before.startedAt });
    }
    pid = before.parentPid;
  }
  return launcherChainFromAttestation(signatures);
}

export function launcherChainIsLive(chain: AttestedLauncherChain): boolean {
  return chain.signatures.every((signature) => processRow(signature.pid)?.startedAt === signature.startedAt);
}

export function parseCodesignDetails(text: string): { teamId: string; identifier: string } | undefined {
  const identifier = /^Identifier=(.+)$/m.exec(text)?.[1]?.trim();
  const teamId = /^TeamIdentifier=(.+)$/m.exec(text)?.[1]?.trim();
  if (!validTeamId(teamId) || !validIdentifier(identifier)) {
    return undefined;
  }
  return { teamId, identifier };
}

export function parseProcessRow(text: string): { parentPid: number; startedAt: string } | undefined {
  const match = /^\s*(\d+)\s+(\S.*\S)\s*$/.exec(text.split("\n").find((line) => line.trim()) || "");
  if (!match) {
    return undefined;
  }
  return { parentPid: Number(match[1]), startedAt: match[2].replace(/\s+/g, " ") };
}

function signedRunningCode(pid: number): { teamId: string; identifier: string } | undefined {
  // A leading digit makes codesign validate the running process, not a file on disk.
  if (runTool(CODESIGN, ["--verify", "--strict", String(pid)]) === undefined) {
    return undefined;
  }
  const details = runTool(CODESIGN, ["-d", "--verbose=2", String(pid)]);
  return details === undefined ? undefined : parseCodesignDetails(details);
}

function processRow(pid: number): { parentPid: number; startedAt: string } | undefined {
  const output = runTool(PS, ["-o", "ppid=,lstart=", "-p", String(pid)]);
  return output === undefined ? undefined : parseProcessRow(output);
}

// codesign writes its report to stderr, so both streams are returned together.
function runTool(tool: string, args: string[]): string | undefined {
  const result = spawnSync(tool, args, {
    encoding: "utf8",
    env: { LC_ALL: "C" },
    stdio: ["ignore", "pipe", "pipe"],
    timeout: TOOL_TIMEOUT_MS
  });
  if (result.error || result.status !== 0) {
    return undefined;
  }
  return `${result.stdout}${result.stderr}`;
}
