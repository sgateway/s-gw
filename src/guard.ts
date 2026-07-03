import { spawn } from "node:child_process";
import process from "node:process";
import { resolveAgentProfile, type AgentProfile } from "./agents.js";
import { addLocalSecret, preferredLocalSecretBackend } from "./gateway.js";
import { previewHandle, scanText } from "./scanner.js";
import { SecretStore } from "./store.js";
import type { ScanCandidate } from "./types.js";

export interface GuardRunOptions {
  agent: string;
  command?: string;
  args?: string[];
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  extraEnv?: Record<string, string>;
  scrubEnv?: boolean;
  persist?: boolean;
  allowedCommands?: string[];
}

export interface GuardEnvFinding {
  name: string;
  handle: string;
  token: string;
  type: string;
  provider?: string;
  ruleId?: string;
  severity?: string;
}

export interface GuardRunPlan {
  agent: {
    id: string;
    displayName: string;
  };
  command: string;
  args: string[];
  cwd: string;
  mode: "guarded";
  scrubbedEnv: GuardEnvFinding[];
  keptEnvCount: number;
  scrubbedEnvCount: number;
  mcp: {
    serverName: string;
    command: string;
  };
  instructions: string;
  dryRun: boolean;
  warnings: string[];
}

export interface GuardRunPreparation {
  plan: GuardRunPlan;
  env: Record<string, string>;
}

const defaultAgentCommands: Record<string, string> = {
  codex: "codex",
  claudecode: "claude",
  opencode: "opencode",
  geminicli: "gemini",
  openclaw: "openclaw",
  zeptoclaw: "zeptoclaw",
  openhands: "openhands",
  antigravity: "agy"
};

export function guardStatus() {
  const agents = [
    "codex",
    "claudecode",
    "cursor",
    "opencode",
    "vscode",
    "openclaw",
    "zeptoclaw",
    "hermes",
    "windsurf",
    "geminicli",
    "copilot",
    "openhands",
    "antigravity",
    "omnigent"
  ].map((id) => {
    const profile = resolveAgentProfile(id);
    return {
      id: profile.id,
      displayName: profile.displayName,
      mcpStatus: profile.mcp.status,
      configPaths: profile.mcp.configPaths,
      defaultRunCommand: defaultAgentCommands[profile.id],
      directRunSupported: Boolean(defaultAgentCommands[profile.id])
    };
  });

  return {
    mode: "guarded-agent-launcher",
    envScrubbing: true,
    rawSecretPolicy: "credential-like environment values are replaced with stable SGW tokens before launch",
    configInstall: "planned",
    agents
  };
}

export async function prepareGuardedRun(store: SecretStore, options: GuardRunOptions): Promise<GuardRunPreparation> {
  const profile = resolveAgentProfile(options.agent);
  const command = options.command || defaultAgentCommands[profile.id];
  if (!command) {
    throw new Error(`Guard run for ${profile.displayName} needs --command because it has no safe default CLI launcher yet.`);
  }

  const cwd = options.cwd || process.cwd();
  const baseEnv = normalizeEnv(options.env || process.env);
  for (const [key, value] of Object.entries(options.extraEnv || {})) {
    baseEnv[key] = value;
  }

  const scrubbedEnv: GuardEnvFinding[] = [];
  let guardedEnv = { ...baseEnv };
  if (options.scrubEnv !== false) {
    const scrubbed = await scrubEnvironment(store, profile, guardedEnv, {
      persist: options.persist === true,
      allowedCommands: options.allowedCommands || []
    });
    guardedEnv = scrubbed.env;
    scrubbedEnv.push(...scrubbed.findings);
  }

  const instructions = guardInstructions(profile, scrubbedEnv);
  guardedEnv.SGW_GUARD_MODE = "1";
  guardedEnv.SGW_GUARD_AGENT = profile.id;
  guardedEnv.SGW_GUARD_INSTRUCTIONS = instructions;
  guardedEnv.SGW_GUARD_TOKENIZED_ENV = JSON.stringify(
    scrubbedEnv.map((item) => ({
      name: item.name,
      handle: item.handle,
      token: item.token,
      type: item.type,
      provider: item.provider,
      ruleId: item.ruleId,
      severity: item.severity
    }))
  );

  const args = options.args || [];
  const warnings: string[] = [];
  if (scrubbedEnv.length === 0) {
    warnings.push("No credential-like environment variables were detected.");
  }
  if (profile.mcp.status !== "supported") {
    warnings.push(`${profile.displayName} MCP setup is marked ${profile.mcp.status}; install/config may need manual review.`);
  }

  return {
    env: guardedEnv,
    plan: {
      agent: {
        id: profile.id,
        displayName: profile.displayName
      },
      command,
      args,
      cwd,
      mode: "guarded",
      scrubbedEnv,
      keptEnvCount: Object.keys(guardedEnv).length - scrubbedEnv.length,
      scrubbedEnvCount: scrubbedEnv.length,
      mcp: {
        serverName: "s-gw",
        command: "s-gw-mcp"
      },
      instructions,
      dryRun: options.persist !== true,
      warnings
    }
  };
}

export async function runGuardedAgent(store: SecretStore, options: GuardRunOptions): Promise<number> {
  const prepared = await prepareGuardedRun(store, {
    ...options,
    persist: true
  });

  process.stderr.write(
    `s-gw guard mode: launching ${prepared.plan.agent.displayName}; tokenized ${prepared.plan.scrubbedEnvCount} environment credential(s).\n`
  );

  const child = spawn(prepared.plan.command, prepared.plan.args, {
    cwd: prepared.plan.cwd,
    env: prepared.env,
    stdio: "inherit"
  });

  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (signal) {
        resolve(128 + signalToExitCode(signal));
        return;
      }
      resolve(code ?? 1);
    });
  });
}

async function scrubEnvironment(
  store: SecretStore,
  profile: AgentProfile,
  env: Record<string, string>,
  options: { persist: boolean; allowedCommands: string[] }
): Promise<{ env: Record<string, string>; findings: GuardEnvFinding[] }> {
  const out = { ...env };
  const findings: GuardEnvFinding[] = [];

  for (const [name, value] of Object.entries(env)) {
    if (shouldDropEnv(name)) {
      delete out[name];
      continue;
    }

    if (!value || shouldSkipEnv(name)) {
      continue;
    }

    const line = `${name}=${value}`;
    const result = await scanText(line, async (candidate: ScanCandidate) => {
      if (!options.persist) {
        return previewHandle(candidate);
      }

      const record = await addLocalSecret(store, {
        name: `${profile.id} env ${name}`,
        type: candidate.type,
        provider: candidate.provider,
        ruleId: candidate.ruleId,
        severity: candidate.severity,
        confidence: candidate.confidence,
        value: candidate.value,
        source: `guard-env:${profile.id}:${name}`,
        policy: {
          injectEnv: name,
          allowedCommands: options.allowedCommands,
          maxOutputBytes: 16_384
        }
      }, preferredLocalSecretBackend());
      return record.handle;
    });

    if (result.findings.length === 0) {
      continue;
    }

    const prefix = `${name}=`;
    out[name] = result.tokenizedText.startsWith(prefix)
      ? result.tokenizedText.slice(prefix.length)
      : result.findings.map((finding) => finding.token).join("\n");

    for (const finding of result.findings) {
      findings.push({
        name,
        handle: finding.handle,
        token: finding.token,
        type: finding.type,
        provider: finding.provider,
        ruleId: finding.ruleId,
        severity: finding.severity
      });
    }
  }

  return { env: out, findings };
}

function normalizeEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (typeof value === "string") {
      out[key] = value;
    }
  }
  return out;
}

function shouldDropEnv(name: string): boolean {
  return (
    name === "SGW_MASTER_PASSPHRASE" ||
    name === "SGW_GUARD_AGENT" ||
    name === "SGW_GUARD_INSTRUCTIONS" ||
    name === "SGW_GUARD_MODE" ||
    name === "SGW_GUARD_TOKENIZED_ENV"
  );
}

function shouldSkipEnv(name: string): boolean {
  const commonNonSecret = new Set([
    "HOME",
    "LANG",
    "LOGNAME",
    "OLDPWD",
    "PATH",
    "PWD",
    "SHELL",
    "SHLVL",
    "TERM",
    "TMPDIR",
    "USER",
    "_"
  ]);

  return (
    commonNonSecret.has(name) ||
    name.startsWith("npm_")
  );
}

function guardInstructions(profile: AgentProfile, scrubbedEnv: GuardEnvFinding[]): string {
  const names = scrubbedEnv.map((item) => `${item.name}=${item.token}`).join(", ") || "none";
  return [
    `s-gw guard mode is active for ${profile.displayName}.`,
    `Credential-like environment values were replaced with SGW handles: ${names}.`,
    "Treat SGW handles as unique secret representations, not redactions.",
    "Do not ask the user to paste raw credentials.",
    "Use s-gw MCP tools to scan files/text and request local approved execution when a credential-backed action is needed.",
    "Raw secret values must remain in the local s-gw store and local approved child processes."
  ].join(" ");
}

function signalToExitCode(signal: NodeJS.Signals): number {
  const known: Partial<Record<NodeJS.Signals, number>> = {
    SIGHUP: 1,
    SIGINT: 2,
    SIGQUIT: 3,
    SIGTERM: 15
  };

  return known[signal] ?? 1;
}
