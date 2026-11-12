import { accessSync, constants, existsSync, lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const systemDirs = ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"];

function trustedPathParts(file: string, executable: boolean): string | undefined {
  if (!path.isAbsolute(file)) return;
  const check = (target: string) => {
    let current = path.parse(target).root;
    const parts = target.slice(current.length).split(path.sep).filter(Boolean);
    for (let index = 0; index <= parts.length; index++) {
      if (index) current = path.join(current, parts[index - 1]);
      const info = lstatSync(current);
      if (info.uid !== 0) return false;
      if (info.isSymbolicLink()) continue;
      if ((info.mode & 0o022) !== 0) return false;
      if (index === parts.length) {
        if (executable ? !info.isFile() : !info.isDirectory()) return false;
      } else if (!info.isDirectory()) return false;
    }
    return true;
  };
  try {
    if (!check(file)) return;
    const real = realpathSync.native(file);
    if (!check(real)) return;
    if (executable) accessSync(real, constants.X_OK);
    return real;
  } catch { return; }
}

export function trustedLinuxExecutable(file: string): string | undefined {
  return trustedPathParts(file, true);
}

export function findTrustedLinuxHelper(name: string, directories: string[]): string {
  if (!/^[a-z][a-z0-9-]*$/.test(name)) throw new Error("Invalid Linux sandbox helper name.");
  for (const dir of directories) {
    const resolved = trustedLinuxExecutable(path.join(dir, name));
    if (resolved) return resolved;
  }
  throw new Error(`Trusted Linux sandbox helper ${name} is unavailable; install it in a root-owned, agent-unwritable directory.`);
}

export function resolveTrustedLinuxSandboxHelpers(agentPath?: string) {
  if (process.platform !== "linux" || process.getuid?.() === 0) {
    throw new Error("Trusted Linux sandbox helpers require a non-root Linux launcher.");
  }
  const directories: string[] = [];
  for (const value of [...(agentPath || "").split(path.delimiter), ...systemDirs]) {
    const real = trustedPathParts(value, false);
    if (real && !directories.includes(real)) directories.push(real);
  }
  const bwrap = findTrustedLinuxHelper("bwrap", directories);
  const socat = findTrustedLinuxHelper("socat", directories);
  const rg = findTrustedLinuxHelper("rg", directories);
  const whichDirectories = ["/usr/bin", "/bin", ...directories]
    .map(dir => trustedPathParts(dir, false)).filter((dir): dir is string => Boolean(dir));
  const which = findTrustedLinuxHelper("which", whichDirectories);
  const bash = findTrustedLinuxHelper("bash", directories);
  const whichDir = whichDirectories.find(dir => trustedLinuxExecutable(path.join(dir, "which")) === which);
  if (!whichDir) throw new Error("Trusted Linux sandbox which is unavailable on the outer PATH.");
  const npm = path.join(whichDir, "npm");
  if (existsSync(npm) && !trustedLinuxExecutable(npm)) {
    throw new Error("Trusted Linux sandbox PATH contains an untrusted npm executable.");
  }
  const arch = process.arch === "x64" ? "x64" : process.arch === "arm64" ? "arm64" : undefined;
  if (!arch) throw new Error("Trusted Linux sandbox helpers require a supported seccomp architecture.");
  const runtimeEntry = fileURLToPath(import.meta.resolve("@anthropic-ai/sandbox-runtime"));
  const seccompFile = path.resolve(path.dirname(runtimeEntry), "../vendor/seccomp", arch, "apply-seccomp");
  const applySeccomp = trustedLinuxExecutable(seccompFile);
  if (!applySeccomp) {
    throw new Error("Trusted Linux sandbox helpers require a root-owned, agent-unwritable bundled apply-seccomp binary.");
  }
  return {
    pathEnv: whichDir,
    applySeccomp,
    bwrap, socat, rg, which, bash
  };
}

export async function withTrustedLinuxPathAsync<T>(pathEnv: string, action: () => Promise<T>): Promise<T> {
  const previous = process.env.PATH;
  process.env.PATH = pathEnv;
  try { return await action(); }
  finally {
    if (previous === undefined) delete process.env.PATH;
    else process.env.PATH = previous;
  }
}
