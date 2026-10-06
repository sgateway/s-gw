import type { CommandAction } from "./types.js";

export interface NetworkDestination {
  host: string;
  port?: number;
}

const HOST_FLAGS = new Set([
  "--host",
  "--hostname",
  "--endpoint",
  "--url",
  "--server",
  "--connect-to"
]);

export function extractActionDestinations(action: CommandAction): NetworkDestination[] {
  if (action.kind === "http_request" && action.http) {
    const url = new URL(action.http.url);
    return [{ host: url.hostname.replace(/^\[|\]$/g, ""), port: Number(url.port || 443) }];
  }
  if (action.kind === "ssh_session") {
    const host = sshDestinationHost(action.ssh?.target || "");
    return host ? [{ host, port: action.ssh?.port || 22 }] : [];
  }

  const found: NetworkDestination[] = [];
  for (let index = 0; index < action.args.length; index += 1) {
    const arg = action.args[index] ?? "";
    const fromValue = parseDestinationValue(arg);
    if (fromValue) {
      found.push(fromValue);
      continue;
    }

    const flag = arg.split("=", 2);
    if (flag.length === 2 && HOST_FLAGS.has(flag[0].toLowerCase())) {
      const nested = parseDestinationValue(flag[1]);
      if (nested) {
        found.push(nested);
      }
      continue;
    }

    if (HOST_FLAGS.has(arg.toLowerCase())) {
      const nested = parseDestinationValue(action.args[index + 1] || "");
      if (nested) {
        found.push(nested);
      }
    }
  }

  return uniqueDestinations(found);
}

export function sshDestinationHost(target: string): string {
  const trimmed = target.trim();
  if (!trimmed) {
    return "";
  }

  const withoutUser = trimmed.includes("@") ? trimmed.slice(trimmed.lastIndexOf("@") + 1) : trimmed;
  if (withoutUser.startsWith("[") && withoutUser.includes("]")) {
    return withoutUser.slice(1, withoutUser.indexOf("]")).toLowerCase();
  }

  const ipv4Port = withoutUser.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d+)$/);
  if (ipv4Port) {
    return ipv4Port[1];
  }

  return withoutUser.toLowerCase();
}

export function destinationKey(destination: NetworkDestination): string {
  return destination.port ? `${destination.host}:${destination.port}` : destination.host;
}

export function assertDestinationsAllowed(
  allowed: string[] | undefined,
  destinations: NetworkDestination[]
): void {
  const rules = (allowed || []).map((item) => item.trim().toLowerCase()).filter(Boolean);
  if (rules.length === 0) {
    return;
  }

  if (destinations.length === 0) {
    throw new Error("This handle requires an explicit destination in the approved command or SSH target.");
  }

  const blocked = destinations.find((destination) => !rules.some((rule) => destinationMatches(rule, destination)));
  if (blocked) {
    throw new Error(`Destination ${destinationKey(blocked)} is not allowed by this handle policy.`);
  }
}

export function parseAllowedDestination(value: string): string {
  const trimmed = value.trim().toLowerCase();
  if (!trimmed || trimmed.includes("\0") || /[\s/\\]/.test(trimmed)) {
    throw new Error(`Invalid destination allowlist entry: ${value || "(empty)"}`);
  }
  if (trimmed.startsWith("-")) {
    throw new Error(`Invalid destination allowlist entry: ${value}`);
  }
  return trimmed;
}

function parseDestinationValue(value: string): NetworkDestination | undefined {
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith("-")) {
    return undefined;
  }

  const fromUrl = parseUrlDestination(trimmed);
  if (fromUrl) {
    return fromUrl;
  }

  if (trimmed.includes("@") && !trimmed.includes("://")) {
    const host = sshDestinationHost(trimmed);
    return host && isHostname(host) ? { host } : undefined;
  }

  const hostPort = trimmed.match(/^([A-Za-z0-9.-]+):(\d{1,5})$/);
  if (hostPort && isHostname(hostPort[1])) {
    const port = Number(hostPort[2]);
    if (port >= 1 && port <= 65535) {
      return { host: hostPort[1].toLowerCase(), port };
    }
  }

  if (isHostname(trimmed)) {
    return { host: trimmed.toLowerCase() };
  }

  return undefined;
}

function parseUrlDestination(value: string): NetworkDestination | undefined {
  try {
    const url = new URL(value);
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return undefined;
    }
    if (url.username || url.password) {
      return undefined;
    }
    const host = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    if (!host) {
      return undefined;
    }
    const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
    return { host, port };
  } catch {
    return undefined;
  }
}

function destinationMatches(rule: string, destination: NetworkDestination): boolean {
  const [ruleHostRaw, rulePortRaw] = splitHostPort(rule);
  const ruleHost = ruleHostRaw.replace(/^\*\./, ".");
  const host = destination.host;
  const hostOk = ruleHostRaw.startsWith("*.")
    ? host === ruleHostRaw.slice(2) || host.endsWith(ruleHost)
    : host === ruleHostRaw;
  if (!hostOk) {
    return false;
  }
  if (!rulePortRaw) {
    return true;
  }
  const rulePort = Number(rulePortRaw);
  return Number.isInteger(rulePort) && destination.port === rulePort;
}

function splitHostPort(value: string): [string, string | undefined] {
  const match = value.match(/^(.*?):(\d{1,5})$/);
  if (match && isHostname(match[1].replace(/^\*\./, "x."))) {
    return [match[1], match[2]];
  }
  return [value, undefined];
}

function isHostname(value: string): boolean {
  const host = value.toLowerCase();
  if (host === "localhost") {
    return true;
  }
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) {
    return host.split(".").every((part) => Number(part) <= 255);
  }
  return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(host);
}

function uniqueDestinations(items: NetworkDestination[]): NetworkDestination[] {
  const seen = new Set<string>();
  const out: NetworkDestination[] = [];
  for (const item of items) {
    const key = destinationKey(item);
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    out.push(item);
  }
  return out;
}
