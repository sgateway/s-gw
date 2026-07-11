import { createHash, randomUUID } from "node:crypto";
import {
  chmodSync,
  closeSync,
  copyFileSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  renameSync,
  rmdirSync,
  statSync,
  unlinkSync,
  writeFileSync
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { agentProfiles, renderAgentMcpSnippet, resolveAgentProfile, type AgentProfile } from "./agents.js";

export type AgentIntegrationState = "not-detected" | "manual" | "available" | "partial" | "installed" | "conflict";
export type AgentResourceState = "unsupported" | "missing" | "installed" | "existing" | "conflict";

export interface AgentResourceStatus {
  state: AgentResourceState;
  path?: string;
  owned: boolean;
  message?: string;
}

export interface AgentIntegrationStatus {
  agentId: string;
  displayName: string;
  detected: boolean;
  eligible: boolean;
  state: AgentIntegrationState;
  mcp: AgentResourceStatus;
  skill: AgentResourceStatus;
  reason?: string;
  plannedChanges: Array<"mcp" | "skill">;
}

export interface AgentIntegrationResult extends AgentIntegrationStatus {
  action: "install" | "uninstall";
  changed: boolean;
  dryRun: boolean;
  backups: string[];
}

export interface AgentIntegrationOptions {
  homeDir?: string;
  pathEnv?: string;
  sgwHome?: string;
  agentIds?: string[];
  dryRun?: boolean;
  skillSourcePath?: string;
}

type JsonContainer = "mcpServers";

interface AgentAdapter {
  id: string;
  commands: string[];
  configPath: (homeDir: string) => string;
  configKind: "json" | "toml";
  jsonContainer?: JsonContainer;
  skillPath?: (homeDir: string) => string;
}

interface OwnedResource {
  path: string;
  kind: "json-entry" | "toml-block" | "skill";
  fingerprint: string;
  parentCreated?: boolean;
}

interface AgentOwnership {
  mcp?: OwnedResource;
  skill?: OwnedResource;
  updatedAt: string;
}

interface AgentManifest {
  version: 1;
  agents: Record<string, AgentOwnership>;
}

interface WorkContext {
  homeDir: string;
  pathEnv: string;
  sgwHome: string;
  mcpCommand: string;
  skillSourcePath: string;
  manifestPath: string;
  manifest: AgentManifest;
  manifestError?: string;
}

interface JsonConfigInfo {
  state: AgentResourceState;
  entry?: Record<string, unknown>;
  document?: Record<string, unknown>;
  message?: string;
}

interface TomlSection {
  start: number;
  end: number;
  text: string;
  command?: string;
  args: string[];
  managed: boolean;
}

const managedStart = "# >>> s-gw managed MCP server";
const managedEnd = "# <<< s-gw managed MCP server";

const adapters: AgentAdapter[] = [
  {
    id: "claudecode",
    commands: ["claude"],
    configPath: (homeDir) => path.join(homeDir, ".claude.json"),
    configKind: "json",
    jsonContainer: "mcpServers",
    skillPath: (homeDir) => path.join(homeDir, ".claude", "skills", "s-gw", "SKILL.md")
  },
  {
    id: "codex",
    commands: ["codex"],
    configPath: (homeDir) => path.join(homeDir, ".codex", "config.toml"),
    configKind: "toml",
    skillPath: (homeDir) => path.join(homeDir, ".codex", "skills", "s-gw", "SKILL.md")
  },
  {
    id: "cursor",
    commands: ["cursor", "cursor-agent"],
    configPath: (homeDir) => path.join(homeDir, ".cursor", "mcp.json"),
    configKind: "json",
    jsonContainer: "mcpServers",
    skillPath: (homeDir) => path.join(homeDir, ".cursor", "skills", "s-gw", "SKILL.md")
  },
  {
    id: "geminicli",
    commands: ["gemini"],
    configPath: (homeDir) => path.join(homeDir, ".gemini", "settings.json"),
    configKind: "json",
    jsonContainer: "mcpServers",
    skillPath: (homeDir) => path.join(homeDir, ".gemini", "skills", "s-gw", "SKILL.md")
  },
  {
    id: "copilot",
    commands: ["copilot"],
    configPath: (homeDir) => path.join(homeDir, ".copilot", "mcp-config.json"),
    configKind: "json",
    jsonContainer: "mcpServers",
    skillPath: (homeDir) => path.join(homeDir, ".copilot", "skills", "s-gw", "SKILL.md")
  }
];

const commandNames: Record<string, string[]> = {
  openclaw: ["openclaw"],
  zeptoclaw: ["zeptoclaw"],
  claudecode: ["claude"],
  codex: ["codex"],
  hermes: ["hermes"],
  cursor: ["cursor", "cursor-agent"],
  windsurf: ["windsurf"],
  geminicli: ["gemini"],
  copilot: ["copilot"],
  openhands: ["openhands"],
  antigravity: ["agy", "antigravity"],
  opencode: ["opencode"],
  omnigent: ["omnigent"],
  vscode: ["code"]
};

export function agentIntegrationStatus(options: AgentIntegrationOptions = {}): AgentIntegrationStatus[] {
  const ctx = loadContext(options);
  const profiles = selectedProfiles(options.agentIds);
  return profiles.map((profile) => statusForProfile(profile, ctx));
}

export function installAgentIntegrations(options: AgentIntegrationOptions = {}): AgentIntegrationResult[] {
  const ctx = loadContext(options);
  const explicit = Boolean(options.agentIds?.length);
  const profiles = selectedProfiles(options.agentIds);
  const results: AgentIntegrationResult[] = [];

  for (const profile of profiles) {
    const status = statusForProfile(profile, ctx);
    if (!explicit && !status.detected) continue;

    if (!status.eligible || status.state === "conflict" || status.mcp.state === "conflict" ||
      status.skill.state === "conflict" || (!explicit && status.state === "not-detected")) {
      const blocked = status.state === "conflict" ||
        (status.mcp.state !== "conflict" && status.skill.state !== "conflict")
        ? status
        : {
            ...status,
            state: "conflict" as const,
            reason: status.mcp.message || status.skill.message || status.reason
          };
      results.push(asResult(blocked, "install", false, Boolean(options.dryRun), []));
      continue;
    }

    if (options.dryRun) {
      results.push(asResult(status, "install", false, true, []));
      continue;
    }

    results.push(installOne(profile, ctx));
  }

  return results;
}

export function uninstallAgentIntegrations(options: AgentIntegrationOptions = {}): AgentIntegrationResult[] {
  const ctx = loadContext(options);
  const ids = options.agentIds?.length
    ? options.agentIds
    : ctx.manifestError ? agentProfiles.map((profile) => profile.id) : Object.keys(ctx.manifest.agents);
  const profiles = selectedProfiles(ids);
  const results: AgentIntegrationResult[] = [];

  for (const profile of profiles) {
    const status = statusForProfile(profile, ctx);
    const owned = ctx.manifest.agents[profile.id];
    if (!owned) {
      results.push(asResult(status, "uninstall", false, Boolean(options.dryRun), []));
      continue;
    }

    const conflict = uninstallConflict(profile, ctx, owned);
    if (conflict) {
      results.push(asResult({ ...status, state: "conflict", reason: conflict }, "uninstall", false, Boolean(options.dryRun), []));
      continue;
    }

    if (options.dryRun) {
      const plannedChanges: Array<"mcp" | "skill"> = [];
      if (owned.mcp) plannedChanges.push("mcp");
      if (owned.skill) plannedChanges.push("skill");
      results.push(asResult({ ...status, plannedChanges }, "uninstall", false, true, []));
      continue;
    }

    results.push(uninstallOne(profile, ctx, owned));
  }

  return results;
}

function loadContext(options: AgentIntegrationOptions): WorkContext {
  const homeDir = path.resolve(options.homeDir || process.env.HOME || process.env.USERPROFILE || os.homedir());
  const pathEnv = options.pathEnv ?? process.env.PATH ?? "";
  const manifestPath = path.join(homeDir, ".s-gw", "agent-integrations.json");
  let manifest: AgentManifest = { version: 1, agents: {} };
  let manifestError: string | undefined;
  try {
    manifest = readManifest(manifestPath);
  } catch (error) {
    manifestError = error instanceof Error ? error.message : String(error);
  }
  return {
    homeDir,
    pathEnv,
    sgwHome: path.resolve(options.sgwHome || process.env.SGW_HOME || path.join(homeDir, ".s-gw")),
    mcpCommand: commandPath("s-gw-mcp", pathEnv) || "s-gw-mcp",
    skillSourcePath: options.skillSourcePath || fileURLToPath(new URL("../skills/s-gw/SKILL.md", import.meta.url)),
    manifestPath,
    manifest,
    manifestError
  };
}

function selectedProfiles(ids?: string[]): AgentProfile[] {
  if (!ids?.length) return agentProfiles;
  const profiles: AgentProfile[] = [];
  const seen = new Set<string>();
  for (const id of ids) {
    const profile = resolveAgentProfile(id);
    if (seen.has(profile.id)) continue;
    profiles.push(profile);
    seen.add(profile.id);
  }
  return profiles;
}

function statusForProfile(profile: AgentProfile, ctx: WorkContext): AgentIntegrationStatus {
  const adapter = adapters.find((candidate) => candidate.id === profile.id);
  const ownership = ctx.manifest.agents[profile.id];
  const detected = Boolean(ownership) || detectProfile(profile, adapter, ctx);

  if (!adapter) {
    const manualProfile = profile.mcp.status === "manual" || profile.mcp.writeMode === "manual";
    const reason = manualProfile
      ? "This profile remains snippet-only because s-gw does not have a safe automatic merge for its config format."
      : "This agent does not have a safe user-level automatic registration target. Use the generated MCP snippet.";
    return {
      agentId: profile.id,
      displayName: profile.displayName,
      detected,
      eligible: false,
      state: detected ? "manual" : "not-detected",
      mcp: { state: "unsupported", owned: false, message: reason },
      skill: { state: "unsupported", owned: false },
      reason,
      plannedChanges: []
    };
  }

  const mcp = mcpStatus(profile, adapter, ctx, ownership?.mcp);
  const skill = skillStatus(adapter, ctx, ownership?.skill);
  if (ctx.manifestError) {
    return {
      agentId: profile.id,
      displayName: profile.displayName,
      detected,
      eligible: true,
      state: "conflict",
      mcp,
      skill,
      reason: ctx.manifestError,
      plannedChanges: []
    };
  }
  const plannedChanges: Array<"mcp" | "skill"> = [];
  if (mcp.state === "missing") plannedChanges.push("mcp");
  if (skill.state === "missing") plannedChanges.push("skill");

  let state: AgentIntegrationState = "available";
  let reason: string | undefined;
  if (!detected) {
    state = "not-detected";
  } else if (mcp.state === "conflict" || skill.state === "conflict") {
    state = "conflict";
    reason = mcp.message || skill.message;
  } else if (resourceReady(mcp) && resourceReady(skill)) {
    state = "installed";
  } else if (resourceReady(mcp) || resourceReady(skill)) {
    state = "partial";
  }

  return {
    agentId: profile.id,
    displayName: profile.displayName,
    detected,
    eligible: true,
    state,
    mcp,
    skill,
    reason,
    plannedChanges
  };
}

function detectProfile(profile: AgentProfile, adapter: AgentAdapter | undefined, ctx: WorkContext): boolean {
  const commands = adapter?.commands || commandNames[profile.id] || [];
  if (commands.some((name) => commandExists(name, ctx.pathEnv))) return true;

  if (adapter && existsSync(adapter.configPath(ctx.homeDir))) return true;

  for (const configPath of profile.mcp.configPaths) {
    const resolved = resolveHomePath(configPath, ctx.homeDir);
    if (resolved && existsSync(resolved)) return true;
  }
  return false;
}

function commandExists(name: string, pathEnv: string): boolean {
  return commandPath(name, pathEnv) !== undefined;
}

function commandPath(name: string, pathEnv: string): string | undefined {
  const suffixes = process.platform === "win32"
    ? (process.env.PATHEXT || ".EXE;.CMD;.BAT;.COM").split(";")
    : [""];
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    for (const suffix of suffixes) {
      const candidate = path.join(dir, process.platform === "win32" ? `${name}${suffix}` : name);
      try {
        const info = statSync(candidate);
        if (!info.isFile()) continue;
        if (process.platform === "win32" || (info.mode & 0o111) !== 0) return candidate;
      } catch {
        // PATH commonly contains stale directories.
      }
    }
  }
  return undefined;
}

function mcpStatus(
  profile: AgentProfile,
  adapter: AgentAdapter,
  ctx: WorkContext,
  owned: OwnedResource | undefined
): AgentResourceStatus {
  const configPath = adapter.configPath(ctx.homeDir);
  if (owned && path.resolve(owned.path) !== path.resolve(configPath)) {
    return { state: "conflict", path: configPath, owned: true, message: "The tracked MCP config path changed. Uninstall the old integration first." };
  }

  if (adapter.configKind === "json") {
    const info = inspectJsonConfig(configPath, adapter.jsonContainer || "mcpServers");
    if (info.state === "conflict") {
      return { state: "conflict", path: configPath, owned: Boolean(owned), message: info.message };
    }
    if (!info.entry) {
      if (!executableAvailable(ctx.mcpCommand, ctx.pathEnv)) {
        return {
          state: "conflict",
          path: configPath,
          owned: Boolean(owned),
          message: "s-gw-mcp is not available on PATH, so s-gw cannot write a working agent registration."
        };
      }
      return { state: "missing", path: configPath, owned: Boolean(owned) };
    }
    if (!isSgwServerEntry(info.entry)) {
      return {
        state: "conflict",
        path: configPath,
        owned: Boolean(owned),
        message: `${configPath} already has an unrelated 's-gw' MCP server entry. s-gw left it unchanged.`
      };
    }
    if (owned && owned.fingerprint !== fingerprintObject(info.entry)) {
      return {
        state: "conflict",
        path: configPath,
        owned: true,
        message: `${configPath} has changes inside the s-gw-owned MCP entry. Resolve them before installing or uninstalling.`
      };
    }
    if (owned && owned.fingerprint !== fingerprintObject(expectedJsonEntry(profile, ctx))) {
      return { state: "missing", path: configPath, owned: true, message: "The s-gw-owned MCP entry needs to be refreshed." };
    }
    if (!sgwServerEntryAvailable(info.entry, ctx.pathEnv)) {
      return {
        state: "conflict",
        path: configPath,
        owned: Boolean(owned),
        message: `${configPath} points to an s-gw MCP command that is no longer available.`
      };
    }
    return { state: owned ? "installed" : "existing", path: configPath, owned: Boolean(owned) };
  }

  const text = readTextIfPresent(configPath);
  if (text.error) return { state: "conflict", path: configPath, owned: Boolean(owned), message: text.error };
  const section = findCodexSection(text.value || "");
  if (!section) {
    if (!executableAvailable(ctx.mcpCommand, ctx.pathEnv)) {
      return {
        state: "conflict",
        path: configPath,
        owned: Boolean(owned),
        message: "s-gw-mcp is not available on PATH, so s-gw cannot write a working agent registration."
      };
    }
    return { state: "missing", path: configPath, owned: Boolean(owned) };
  }
  if (!isSgwCommand(section.command, section.args)) {
    return {
      state: "conflict",
      path: configPath,
      owned: Boolean(owned),
      message: `${configPath} already has an unrelated [mcp_servers.s-gw] section. s-gw left it unchanged.`
    };
  }
  if (owned && owned.fingerprint !== fingerprintText(section.text)) {
    return {
      state: "conflict",
      path: configPath,
      owned: true,
      message: `${configPath} has changes inside the s-gw-owned MCP block. Resolve them before installing or uninstalling.`
    };
  }
  if (owned && owned.fingerprint !== fingerprintText(codexManagedBlock(profile, ctx))) {
    return { state: "missing", path: configPath, owned: true, message: "The s-gw-owned MCP block needs to be refreshed." };
  }
  if (!sgwCommandAvailable(section.command, section.args, ctx.pathEnv)) {
    return {
      state: "conflict",
      path: configPath,
      owned: Boolean(owned),
      message: `${configPath} points to an s-gw MCP command that is no longer available.`
    };
  }
  return { state: owned ? "installed" : "existing", path: configPath, owned: Boolean(owned) };
}

function skillStatus(adapter: AgentAdapter, ctx: WorkContext, owned: OwnedResource | undefined): AgentResourceStatus {
  if (!adapter.skillPath) return { state: "unsupported", owned: false };
  const skillPath = adapter.skillPath(ctx.homeDir);
  if (owned && path.resolve(owned.path) !== path.resolve(skillPath)) {
    return { state: "conflict", path: skillPath, owned: true, message: "The tracked skill path changed. Uninstall the old integration first." };
  }

  const source = readFileSync(ctx.skillSourcePath, "utf8");
  const current = readTextIfPresent(skillPath);
  if (current.error) return { state: "conflict", path: skillPath, owned: Boolean(owned), message: current.error };
  if (current.value === undefined) return { state: "missing", path: skillPath, owned: Boolean(owned) };
  if (owned) {
    if (fingerprintText(current.value) !== owned.fingerprint) {
      return { state: "conflict", path: skillPath, owned: true, message: `${skillPath} has user changes. s-gw left it unchanged.` };
    }
    if (current.value !== source) {
      return { state: "missing", path: skillPath, owned: true, message: "A newer packaged s-gw skill is ready to install." };
    }
    return { state: "installed", path: skillPath, owned: true };
  }
  if (current.value !== source) {
    return {
      state: "conflict",
      path: skillPath,
      owned: false,
      message: `${skillPath} already exists with different content. s-gw left it unchanged.`
    };
  }
  return { state: "existing", path: skillPath, owned: false };
}

function installOne(profile: AgentProfile, ctx: WorkContext): AgentIntegrationResult {
  const adapter = requiredAdapter(profile.id);
  const before = statusForProfile(profile, ctx);
  const backups: string[] = [];
  const rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }> = [];
  const manifestBefore = structuredClone(ctx.manifest);
  let ownershipChanged = false;
  const owned = ctx.manifest.agents[profile.id] || { updatedAt: new Date().toISOString() };

  try {
    if (before.mcp.state === "missing") {
      const installed = installMcp(profile, adapter, ctx, backups, rollbacks);
      owned.mcp = installed;
      ownershipChanged = true;
    }
    if (before.skill.state === "missing" && adapter.skillPath) {
      const installed = installSkill(adapter, ctx, backups, rollbacks);
      owned.skill = installed;
      ownershipChanged = true;
    }

    if (ownershipChanged) {
      rememberFile(ctx.manifestPath, rollbacks);
      owned.updatedAt = new Date().toISOString();
      ctx.manifest.agents[profile.id] = owned;
      writeManifest(ctx.manifestPath, ctx.manifest);
    }
  } catch (error) {
    rollbackFiles(rollbacks);
    ctx.manifest = manifestBefore;
    const failed = statusForProfile(profile, ctx);
    return asResult(
      { ...failed, state: "conflict", reason: error instanceof Error ? error.message : String(error) },
      "install",
      false,
      false,
      backups
    );
  }

  const after = statusForProfile(profile, ctx);
  return asResult(after, "install", ownershipChanged, false, backups);
}

function installMcp(
  profile: AgentProfile,
  adapter: AgentAdapter,
  ctx: WorkContext,
  backups: string[],
  rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }>
): OwnedResource {
  const configPath = adapter.configPath(ctx.homeDir);
  rememberFile(configPath, rollbacks);
  const mode = currentMode(configPath, 0o600);
  if (existsSync(configPath)) backups.push(backupFile(configPath, ctx.homeDir, profile.id, "mcp"));

  if (adapter.configKind === "json") {
    const info = inspectJsonConfig(configPath, adapter.jsonContainer || "mcpServers");
    if (info.state === "conflict") throw new Error(info.message);
    const doc = info.document || {};
    const container = adapter.jsonContainer || "mcpServers";
    const parentCreated = !(container in doc);
    const servers = isPlainObject(doc[container]) ? doc[container] as Record<string, unknown> : {};
    const entry = expectedJsonEntry(profile, ctx);
    servers["s-gw"] = entry;
    doc[container] = servers;
    atomicWrite(configPath, `${JSON.stringify(doc, null, 2)}\n`, mode);
    return { path: configPath, kind: "json-entry", fingerprint: fingerprintObject(entry), parentCreated };
  }

  const current = existsSync(configPath) ? readFileSync(configPath, "utf8") : "";
  const block = codexManagedBlock(profile, ctx);
  const ownedSection = ctx.manifest.agents[profile.id]?.mcp ? findCodexSection(current) : undefined;
  if (ownedSection) {
    atomicWrite(
      configPath,
      `${current.slice(0, ownedSection.start)}${block}${current.slice(ownedSection.end)}`,
      mode
    );
    return { path: configPath, kind: "toml-block", fingerprint: fingerprintText(block) };
  }
  const prefix = current.length === 0 ? "" : current.endsWith("\n\n") ? "" : current.endsWith("\n") ? "\n" : "\n\n";
  atomicWrite(configPath, `${current}${prefix}${block}\n`, mode);
  return { path: configPath, kind: "toml-block", fingerprint: fingerprintText(block) };
}

function installSkill(
  adapter: AgentAdapter,
  ctx: WorkContext,
  backups: string[],
  rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }>
): OwnedResource {
  const skillPath = adapter.skillPath?.(ctx.homeDir);
  if (!skillPath) throw new Error("This agent does not expose a supported user-level skill directory.");
  rememberFile(skillPath, rollbacks);
  if (existsSync(skillPath)) backups.push(backupFile(skillPath, ctx.homeDir, adapter.id, "skill"));
  const content = readFileSync(ctx.skillSourcePath, "utf8");
  atomicWrite(skillPath, content, currentMode(skillPath, 0o644));
  return { path: skillPath, kind: "skill", fingerprint: fingerprintText(content) };
}

function uninstallConflict(profile: AgentProfile, ctx: WorkContext, owned: AgentOwnership): string | undefined {
  const adapter = adapters.find((candidate) => candidate.id === profile.id);
  if (!adapter) return "The owned integration no longer has a supported installer adapter.";

  if (owned.mcp) {
    if (adapter.configKind === "json") {
      const info = inspectJsonConfig(owned.mcp.path, adapter.jsonContainer || "mcpServers");
      if (info.state === "conflict") return info.message;
      if (info.entry && fingerprintObject(info.entry) !== owned.mcp.fingerprint) {
        return `${owned.mcp.path} has changes inside the s-gw-owned MCP entry. It was not removed.`;
      }
    } else {
      const current = readTextIfPresent(owned.mcp.path);
      if (current.error) return current.error;
      const section = findCodexSection(current.value || "");
      if (section && fingerprintText(section.text) !== owned.mcp.fingerprint) {
        return `${owned.mcp.path} has changes inside the s-gw-owned MCP block. It was not removed.`;
      }
    }
  }

  if (owned.skill && existsSync(owned.skill.path)) {
    const current = readTextIfPresent(owned.skill.path);
    if (current.error) return current.error;
    if (current.value !== undefined && fingerprintText(current.value) !== owned.skill.fingerprint) {
      return `${owned.skill.path} has user changes. It was not removed.`;
    }
  }
  return undefined;
}

function uninstallOne(
  profile: AgentProfile,
  ctx: WorkContext,
  owned: AgentOwnership
): AgentIntegrationResult {
  const adapter = requiredAdapter(profile.id);
  const backups: string[] = [];
  const rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }> = [];
  const manifestBefore = structuredClone(ctx.manifest);
  let changed = false;

  try {
    if (owned.mcp && existsSync(owned.mcp.path)) {
      rememberFile(owned.mcp.path, rollbacks);
      backups.push(backupFile(owned.mcp.path, ctx.homeDir, profile.id, "mcp-uninstall"));
      if (adapter.configKind === "json") {
        const info = inspectJsonConfig(owned.mcp.path, adapter.jsonContainer || "mcpServers");
        const doc = info.document || {};
        const container = adapter.jsonContainer || "mcpServers";
        const servers = isPlainObject(doc[container]) ? doc[container] as Record<string, unknown> : {};
        delete servers["s-gw"];
        if (Object.keys(servers).length === 0 && owned.mcp.parentCreated) delete doc[container];
        else doc[container] = servers;
        atomicWrite(owned.mcp.path, `${JSON.stringify(doc, null, 2)}\n`, currentMode(owned.mcp.path, 0o600));
      } else {
        const current = readFileSync(owned.mcp.path, "utf8");
        const section = findCodexSection(current);
        if (section) atomicWrite(owned.mcp.path, removeTomlSection(current, section), currentMode(owned.mcp.path, 0o600));
      }
      changed = true;
    }

    if (owned.skill && existsSync(owned.skill.path)) {
      rememberFile(owned.skill.path, rollbacks);
      backups.push(backupFile(owned.skill.path, ctx.homeDir, profile.id, "skill-uninstall"));
      unlinkSync(owned.skill.path);
      removeEmptyDir(path.dirname(owned.skill.path));
      changed = true;
    }

    rememberFile(ctx.manifestPath, rollbacks);
    delete ctx.manifest.agents[profile.id];
    writeManifest(ctx.manifestPath, ctx.manifest);
  } catch (error) {
    rollbackFiles(rollbacks);
    ctx.manifest = manifestBefore;
    const failed = statusForProfile(profile, ctx);
    return asResult(
      { ...failed, state: "conflict", reason: error instanceof Error ? error.message : String(error) },
      "uninstall",
      false,
      false,
      backups
    );
  }

  const after = statusForProfile(profile, ctx);
  return asResult(after, "uninstall", changed, false, backups);
}

function inspectJsonConfig(configPath: string, container: JsonContainer): JsonConfigInfo {
  if (!existsSync(configPath)) return { state: "missing", document: {} };
  const current = readTextIfPresent(configPath);
  if (current.error) return { state: "conflict", message: current.error };

  let parsed: unknown;
  try {
    parsed = JSON.parse(current.value || "{}");
  } catch (error) {
    return {
      state: "conflict",
      message: `${configPath} is not valid JSON (${error instanceof Error ? error.message : String(error)}). s-gw left it unchanged.`
    };
  }
  if (!isPlainObject(parsed)) return { state: "conflict", message: `${configPath} must contain a JSON object. s-gw left it unchanged.` };

  const rawContainer = parsed[container];
  if (rawContainer !== undefined && !isPlainObject(rawContainer)) {
    return { state: "conflict", message: `${configPath} has a non-object '${container}' value. s-gw left it unchanged.` };
  }
  const servers = rawContainer as Record<string, unknown> | undefined;
  const entry = servers?.["s-gw"];
  if (entry !== undefined && !isPlainObject(entry)) {
    return { state: "conflict", message: `${configPath} has an invalid 's-gw' MCP entry. s-gw left it unchanged.` };
  }
  return { state: entry ? "existing" : "missing", document: parsed, entry: entry as Record<string, unknown> | undefined };
}

function expectedJsonEntry(profile: AgentProfile, ctx: WorkContext): Record<string, unknown> {
  const snippet = JSON.parse(renderAgentMcpSnippet(profile.id, {
    command: ctx.mcpCommand,
    env: { SGW_HOME: ctx.sgwHome }
  })) as Record<string, unknown>;
  const servers = snippet.mcpServers;
  if (!isPlainObject(servers) || !isPlainObject(servers["s-gw"])) {
    throw new Error(`The ${profile.displayName} MCP snippet is not a supported user-level JSON shape.`);
  }
  return servers["s-gw"] as Record<string, unknown>;
}

function codexManagedBlock(profile: AgentProfile, ctx: WorkContext): string {
  return `${managedStart}\n${renderAgentMcpSnippet(profile.id, {
    command: ctx.mcpCommand,
    env: { SGW_HOME: ctx.sgwHome }
  })}\n${managedEnd}`;
}

function findCodexSection(text: string): TomlSection | undefined {
  const heading = /^\s*\[mcp_servers\.(?:s-gw|"s-gw"|'s-gw')\]\s*(?:#.*)?$/m;
  const match = heading.exec(text);
  if (!match || match.index === undefined) return undefined;

  const lineStart = text.lastIndexOf("\n", match.index - 1) + 1;
  const priorLineEnd = lineStart > 0 ? lineStart - 1 : 0;
  const priorLineStart = lineStart > 0 ? text.lastIndexOf("\n", priorLineEnd - 1) + 1 : 0;
  const priorLine = text.slice(priorLineStart, priorLineEnd).trim();
  const managed = priorLine === managedStart;
  const start = managed ? priorLineStart : lineStart;

  let next = text.length;
  const table = /^\s*\[[^\]]+\]\s*(?:#.*)?$/gm;
  table.lastIndex = match.index + match[0].length;
  const nextTable = table.exec(text);
  if (nextTable?.index !== undefined) next = nextTable.index;

  if (managed) {
    const marker = text.indexOf(managedEnd, match.index + match[0].length);
    if (marker !== -1 && marker < next) {
      const markerEnd = text.indexOf("\n", marker);
      next = markerEnd === -1 ? text.length : markerEnd;
    }
  }

  const sectionText = text.slice(start, next).trimEnd();
  const body = text.slice(lineStart, next);
  const command = tomlStringValue(body, "command");
  const args = tomlStringArray(body, "args");
  return { start, end: next, text: sectionText, command, args, managed };
}

function tomlStringValue(text: string, key: string): string | undefined {
  const match = new RegExp(`^\\s*${key}\\s*=\\s*("(?:[^"\\\\]|\\\\.)*")\\s*(?:#.*)?$`, "m").exec(text);
  if (!match) return undefined;
  try {
    return JSON.parse(match[1]) as string;
  } catch {
    return undefined;
  }
}

function tomlStringArray(text: string, key: string): string[] {
  const match = new RegExp(`^\\s*${key}\\s*=\\s*(\\[[^\\n]*\\])\\s*(?:#.*)?$`, "m").exec(text);
  if (!match) return [];
  try {
    const value = JSON.parse(match[1]);
    return Array.isArray(value) && value.every((item) => typeof item === "string") ? value : [];
  } catch {
    return [];
  }
}

function isSgwServerEntry(entry: Record<string, unknown>): boolean {
  if (Array.isArray(entry.command)) {
    const command = entry.command.filter((item): item is string => typeof item === "string");
    if (command.length !== entry.command.length || command.length === 0) return false;
    return isSgwCommand(command[0], command.slice(1));
  }
  if (typeof entry.command !== "string") return false;
  const args = Array.isArray(entry.args) && entry.args.every((item) => typeof item === "string") ? entry.args as string[] : [];
  return isSgwCommand(entry.command, args);
}

function sgwServerEntryAvailable(entry: Record<string, unknown>, pathEnv: string): boolean {
  if (Array.isArray(entry.command)) {
    const command = entry.command.filter((item): item is string => typeof item === "string");
    return command.length === entry.command.length && command.length > 0 &&
      sgwCommandAvailable(command[0], command.slice(1), pathEnv);
  }
  if (typeof entry.command !== "string") return false;
  const args = Array.isArray(entry.args) && entry.args.every((item) => typeof item === "string")
    ? entry.args as string[]
    : [];
  return sgwCommandAvailable(entry.command, args, pathEnv);
}

function isSgwCommand(command: string | undefined, args: string[]): boolean {
  if (!command) return false;
  const base = path.basename(command).toLowerCase().replace(/\.cmd$|\.exe$/, "");
  if (base === "s-gw-mcp" || base === "secret-gateway-mcp") return args.length === 0;
  if (base !== "node" && base !== "nodejs") return false;
  return args.length === 1 && /(?:^|[\\/])dist[\\/]mcp-server\.js$/.test(args[0]);
}

function sgwCommandAvailable(command: string | undefined, args: string[], pathEnv: string): boolean {
  if (!isSgwCommand(command, args) || !command) return false;
  if (!executableAvailable(command, pathEnv)) return false;
  const base = path.basename(command).toLowerCase().replace(/\.cmd$|\.exe$/, "");
  if (base === "node" || base === "nodejs") {
    return existsSync(args[0]) && statSync(args[0]).isFile();
  }
  return true;
}

function executableAvailable(command: string, pathEnv: string): boolean {
  if (!path.isAbsolute(command) && !command.includes("/") && !command.includes("\\")) {
    return commandPath(command, pathEnv) !== undefined;
  }
  try {
    const info = statSync(command);
    return info.isFile() && (process.platform === "win32" || (info.mode & 0o111) !== 0);
  } catch {
    return false;
  }
}

function removeTomlSection(text: string, section: TomlSection): string {
  let start = section.start;
  let end = section.end;
  while (end < text.length && text[end] === "\n") end += 1;
  if (start > 0 && text[start - 1] === "\n") start -= 1;
  const next = `${text.slice(0, start)}${text.slice(end)}`;
  return next.replace(/\n{3,}/g, "\n\n");
}

function resourceReady(resource: AgentResourceStatus): boolean {
  return resource.state === "installed" || resource.state === "existing" || resource.state === "unsupported";
}

function asResult(
  status: AgentIntegrationStatus,
  action: "install" | "uninstall",
  changed: boolean,
  dryRun: boolean,
  backups: string[]
): AgentIntegrationResult {
  return { ...status, action, changed, dryRun, backups };
}

function readManifest(manifestPath: string): AgentManifest {
  if (!existsSync(manifestPath)) return { version: 1, agents: {} };
  const current = readTextIfPresent(manifestPath);
  if (current.error) throw new Error(current.error);
  try {
    const parsed = JSON.parse(current.value || "") as unknown;
    if (!validManifest(parsed)) throw new Error("unsupported manifest shape");
    return parsed;
  } catch (error) {
    throw new Error(`Cannot read ${manifestPath}: ${error instanceof Error ? error.message : String(error)}. s-gw will not overwrite it.`);
  }
}

function validManifest(value: unknown): value is AgentManifest {
  if (!isPlainObject(value) || value.version !== 1 || !isPlainObject(value.agents)) return false;
  for (const ownership of Object.values(value.agents)) {
    if (!isPlainObject(ownership) || typeof ownership.updatedAt !== "string") return false;
    if (ownership.mcp !== undefined && !validOwnedResource(ownership.mcp, ["json-entry", "toml-block"])) return false;
    if (ownership.skill !== undefined && !validOwnedResource(ownership.skill, ["skill"])) return false;
  }
  return true;
}

function validOwnedResource(value: unknown, kinds: OwnedResource["kind"][]): value is OwnedResource {
  if (!isPlainObject(value)) return false;
  return typeof value.path === "string" && value.path.length > 0 &&
    typeof value.fingerprint === "string" && /^[a-f0-9]{64}$/i.test(value.fingerprint) &&
    typeof value.kind === "string" && kinds.includes(value.kind as OwnedResource["kind"]) &&
    (value.parentCreated === undefined || typeof value.parentCreated === "boolean");
}

function writeManifest(manifestPath: string, manifest: AgentManifest): void {
  atomicWrite(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, currentMode(manifestPath, 0o600));
}

function readTextIfPresent(filePath: string): { value?: string; error?: string } {
  if (!existsSync(filePath)) return {};
  try {
    const info = lstatSync(filePath);
    if (info.isSymbolicLink()) return { error: `${filePath} is a symbolic link. s-gw refuses to modify it automatically.` };
    if (!info.isFile()) return { error: `${filePath} is not a regular file. s-gw refuses to modify it automatically.` };
    return { value: readFileSync(filePath, "utf8") };
  } catch (error) {
    return { error: `Cannot read ${filePath}: ${error instanceof Error ? error.message : String(error)}` };
  }
}

function backupFile(filePath: string, homeDir: string, agentId: string, label: string): string {
  const backupDir = path.join(homeDir, ".s-gw", "backups", "agents");
  mkdirSync(backupDir, { recursive: true, mode: 0o700 });
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const backupPath = path.join(backupDir, `${stamp}-${agentId}-${label}-${path.basename(filePath)}-${randomUUID().slice(0, 8)}.bak`);
  const tmp = `${backupPath}.tmp`;
  copyFileSync(filePath, tmp);
  chmodSync(tmp, 0o600);
  renameSync(tmp, backupPath);
  return backupPath;
}

function atomicWrite(filePath: string, content: string | Buffer, mode: number): void {
  mkdirSync(path.dirname(filePath), { recursive: true, mode: 0o700 });
  const tmp = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`);
  let fd: number | undefined;
  try {
    fd = openSync(tmp, "wx", mode);
    writeFileSync(fd, content);
    fsyncSync(fd);
    closeSync(fd);
    fd = undefined;
    renameSync(tmp, filePath);
    chmodSync(filePath, mode);
  } catch (error) {
    if (fd !== undefined) closeSync(fd);
    if (existsSync(tmp)) unlinkSync(tmp);
    throw error;
  }
}

function currentMode(filePath: string, fallback: number): number {
  if (!existsSync(filePath)) return fallback;
  return lstatSync(filePath).mode & 0o777;
}

function rememberFile(
  filePath: string,
  rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }>
): void {
  if (!existsSync(filePath)) {
    rollbacks.push({ path: filePath, existed: false });
    return;
  }
  const info = lstatSync(filePath);
  if (info.isSymbolicLink() || !info.isFile()) throw new Error(`${filePath} is not a regular file. s-gw left it unchanged.`);
  rollbacks.push({ path: filePath, existed: true, content: readFileSync(filePath), mode: info.mode & 0o777 });
}

function rollbackFiles(rollbacks: Array<{ path: string; existed: boolean; content?: Buffer; mode?: number }>): void {
  for (const rollback of [...rollbacks].reverse()) {
    try {
      if (!rollback.existed) {
        if (existsSync(rollback.path)) unlinkSync(rollback.path);
        removeEmptyDir(path.dirname(rollback.path));
        continue;
      }
      atomicWrite(rollback.path, rollback.content || Buffer.alloc(0), rollback.mode || 0o600);
    } catch {
      // The original error is more useful; backups remain available for recovery.
    }
  }
}

function removeEmptyDir(dir: string): void {
  try {
    if (readdirSync(dir).length === 0) rmdirSync(dir);
  } catch {
    // Parent directories belong to the agent and may contain new files.
  }
}

function resolveHomePath(input: string, homeDir: string): string | undefined {
  if (input === "~") return homeDir;
  if (input.startsWith("~/")) return path.join(homeDir, input.slice(2));
  return undefined;
}

function requiredAdapter(agentId: string): AgentAdapter {
  const adapter = adapters.find((candidate) => candidate.id === agentId);
  if (!adapter) throw new Error(`No safe automatic installer is available for ${agentId}.`);
  return adapter;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function fingerprintObject(value: Record<string, unknown>): string {
  return fingerprintText(JSON.stringify(sortObject(value)));
}

function sortObject(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortObject);
  if (!isPlainObject(value)) return value;
  const next: Record<string, unknown> = {};
  for (const key of Object.keys(value).sort()) next[key] = sortObject(value[key]);
  return next;
}

function fingerprintText(value: string): string {
  return createHash("sha256").update(value.replace(/\r\n/g, "\n").trim()).digest("hex");
}
