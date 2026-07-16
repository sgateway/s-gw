import type { RequestRecord, SecretSeverity } from "@/lib/types";

export function shortHandle(value: string): string {
  if (!value || value.length <= 30) return value;
  return `${value.slice(0, 16)}...${value.slice(-8)}`;
}

export function commandName(request: RequestRecord): string {
  if (request.action.kind === "ssh_session") return "ssh";
  const parts = String(request.action.command || "").replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || request.action.command || "command";
}

export function requestTarget(request: RequestRecord): string {
  if (request.action.kind === "ssh_session" && request.action.ssh?.target) {
    const port = request.action.ssh.port;
    return port && port !== 22 ? `${request.action.ssh.target}:${port}` : request.action.ssh.target;
  }
  if (request.action.workingDir) return request.action.workingDir;
  if (request.action.args[0] === "-e") return `${commandName(request)} inline script`;
  for (const arg of request.action.args) {
    if (arg && !arg.startsWith("-")) return arg;
  }
  return request.action.injectEnv || "local command";
}

export function relativeTime(iso?: string): string {
  if (!iso) return "-";
  const time = new Date(iso).getTime();
  if (!Number.isFinite(time)) return "-";
  const diff = Date.now() - time;
  if (diff < 60_000) return "just now";
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function severityRank(severity?: SecretSeverity): number {
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  if (severity === "low") return 1;
  return 0;
}

export function titleCase(value: string): string {
  return String(value || "")
    .split(/[-_\s]+/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

export function policyConditionSummary(conditions: Record<string, unknown>): string {
  const parts: string[] = [];
  for (const [key, value] of Object.entries(conditions)) {
    if (key === "envBindings" && Array.isArray(value) && value.length > 0) {
      const bindings = value
        .filter((binding): binding is { handle: string; injectEnv: string } => {
          return Boolean(binding) && typeof binding === "object" &&
            typeof (binding as { handle?: unknown }).handle === "string" &&
            typeof (binding as { injectEnv?: unknown }).injectEnv === "string";
        })
        .map((binding) => `${binding.injectEnv} → ${shortHandle(binding.handle)}`);
      if (bindings.length > 0) {
        parts.push(`Credential bindings: ${bindings.slice(0, 2).join(", ")}${bindings.length > 2 ? ` +${bindings.length - 2}` : ""}`);
      }
      continue;
    }
    if (Array.isArray(value) && value.length > 0) {
      parts.push(`${titleCase(key)}: ${value.slice(0, 2).join(", ")}${value.length > 2 ? ` +${value.length - 2}` : ""}`);
    } else if (typeof value === "string" && value) {
      parts.push(`${titleCase(key)}: ${value}`);
    }
  }
  return parts.join(" · ") || "All matching credential requests";
}

export function durationLabel(ms?: number): string {
  if (!ms) return "-";
  const minutes = Math.max(1, Math.round(ms / 60_000));
  if (minutes < 60) return `${minutes} minutes`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hours`;
  return `${Math.round(hours / 24)} days`;
}
