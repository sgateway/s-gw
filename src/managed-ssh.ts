import { createHash } from "node:crypto";
import path from "node:path";

export interface ManagedSshRoute {
  host: string;
  user: string;
  port: number;
  hostPublicKey: string;
}

const hostKeyTypes = new Set([
  "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
  "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com"
]);

export function normalizeManagedSshRoute(route: ManagedSshRoute): ManagedSshRoute {
  if (!route || typeof route !== "object") throw new Error("Managed SSH route is required.");
  const host = String(route.host || "").trim();
  const user = String(route.user || "").trim();
  const port = route.port;
  if (!host || host.length > 253 || !/^[A-Za-z0-9_.:-]+$/.test(host) || host.startsWith("-")) {
    throw new Error("Managed SSH host must be a hostname or IP address without options or whitespace.");
  }
  if (!user || user.length > 128 || !/^[A-Za-z0-9_.-]+$/.test(user) || user.startsWith("-")) {
    throw new Error("Managed SSH user is invalid.");
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error("Managed SSH port must be an integer from 1 to 65535.");
  }
  const key = String(route.hostPublicKey || "").trim();
  const parts = key.split(/\s+/);
  if (parts.length !== 2 || !hostKeyTypes.has(parts[0]) || !/^[A-Za-z0-9+/]+={0,2}$/.test(parts[1]) || parts[1].length > 16_384) {
    throw new Error("Managed SSH route requires one valid pinned host public key.");
  }
  const wireKey = Buffer.from(parts[1], "base64");
  if (wireKey.length < 8 || wireKey.toString("base64") !== parts[1] || wireKey.readUInt32BE(0) > wireKey.length - 4) {
    throw new Error("Managed SSH host public key is malformed.");
  }
  const wireType = wireKey.subarray(4, 4 + wireKey.readUInt32BE(0)).toString("utf8");
  if (wireType !== parts[0]) throw new Error("Managed SSH host public key type does not match its contents.");
  return { host, user, port, hostPublicKey: `${parts[0]} ${parts[1]}` };
}

export function managedSshHostFingerprint(route: ManagedSshRoute): string {
  const key = normalizeManagedSshRoute(route).hostPublicKey.split(" ")[1];
  return `SHA256:${createHash("sha256").update(Buffer.from(key, "base64")).digest("base64").replace(/=+$/, "")}`;
}

export function managedSshKnownHostsLine(route: ManagedSshRoute): { alias: string; line: string } {
  const normalized = normalizeManagedSshRoute(route);
  const alias = `sgw-managed-${createHash("sha256")
    .update(JSON.stringify(normalized))
    .digest("hex")
    .slice(0, 32)}`;
  return { alias, line: `${alias} ${normalized.hostPublicKey}\n` };
}

export function managedSshArgs(route: ManagedSshRoute, knownHostsFile: string, authArgs: string[], remoteArgs: string[], keyAuth: boolean): string[] {
  const normalized = normalizeManagedSshRoute(route);
  if (!path.isAbsolute(knownHostsFile) || /[\x00\r\n]/.test(knownHostsFile)) {
    throw new Error("Managed SSH known-hosts file must have an absolute local path.");
  }
  const { alias } = managedSshKnownHostsLine(normalized);
  return [
    "-T", "-F", "none",
    "-o", "ControlMaster=no", "-o", "ControlPath=none",
    "-o", "CanonicalizeHostname=no", "-o", "ProxyCommand=none", "-o", "ProxyJump=none",
    "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no", "-o", "ForwardX11=no",
    "-o", "PermitLocalCommand=no", "-o", "IdentityAgent=none", "-o", "GSSAPIAuthentication=no",
    "-o", "HostbasedAuthentication=no", "-o", "AddKeysToAgent=no",
    "-o", "IdentityFile=none", "-o", "IdentitiesOnly=yes",
    "-o", "StrictHostKeyChecking=yes", "-o", "VerifyHostKeyDNS=no", "-o", "UpdateHostKeys=no",
    "-o", "CheckHostIP=no", "-o", "KnownHostsCommand=none",
    "-o", `HostKeyAlias=${alias}`,
    "-o", `UserKnownHostsFile=${knownHostsFile}`,
    "-o", `GlobalKnownHostsFile=${process.platform === "win32" ? "NUL" : "/dev/null"}`,
    "-o", `PubkeyAuthentication=${keyAuth ? "yes" : "no"}`,
    "-o", `PasswordAuthentication=${keyAuth ? "no" : "yes"}`,
    "-o", `KbdInteractiveAuthentication=${keyAuth ? "no" : "yes"}`,
    "-o", `BatchMode=${keyAuth ? "yes" : "no"}`,
    ...authArgs,
    "-l", normalized.user, "-p", String(normalized.port), normalized.host,
    ...remoteArgs
  ];
}
