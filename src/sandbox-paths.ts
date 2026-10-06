import os from "node:os";
import path from "node:path";

export const DEFAULT_GUARD_ALLOWLIST = [
  "api.anthropic.com", "api.openai.com", "api.github.com", "github.com",
  "objects.githubusercontent.com", "registry.npmjs.org", "api2.cursor.sh",
  "www.googleapis.com", "generativelanguage.googleapis.com", "openrouter.ai"
];

export function sensitiveChildPaths(home: string): string[] {
  const userHome = os.homedir();
  return [home, path.join(userHome, ".s-gw"), path.join(userHome, ".ssh"),
    path.join(userHome, ".gnupg"), path.join(userHome, ".aws"),
    path.join(userHome, ".azure"), path.join(userHome, ".config", "gcloud"),
    path.join(userHome, "Library", "Keychains"), "/etc/shadow", "/etc/master.passwd"];
}
