import { accessSync, constants, lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import { assertNoMacAclAllow } from "./macos-path-acl.js";

async function trustedMacPath(file: string, executable: boolean): Promise<string> {
  if (!path.isAbsolute(file) || process.platform !== "darwin") {
    throw new Error("Trusted macOS sandbox helpers require an absolute path on macOS.");
  }

  const check = async (target: string) => {
    let current = path.parse(target).root;
    const parts = target.slice(current.length).split(path.sep).filter(Boolean);
    for (let index = 0; index <= parts.length; index++) {
      if (index) current = path.join(current, parts[index - 1]);
      const info = lstatSync(current);
      if (info.uid !== 0 || (!info.isSymbolicLink() && (info.mode & 0o022) !== 0)) {
        throw new Error(`Trusted macOS sandbox helper path is agent-writable or not root-owned: ${current}`);
      }
      if (!info.isSymbolicLink()) {
        if (index === parts.length) {
          if (executable ? !info.isFile() : !info.isDirectory()) {
            throw new Error(`Trusted macOS sandbox helper path has the wrong file type: ${current}`);
          }
        } else if (!info.isDirectory()) {
          throw new Error(`Trusted macOS sandbox helper path has a non-directory parent: ${current}`);
        }
      }
      await assertNoMacAclAllow(current);
    }
  };

  await check(file);
  const real = realpathSync.native(file);
  await check(real);
  if (executable) accessSync(real, constants.X_OK);
  return real;
}

export async function resolveTrustedMacSandboxHelpers() {
  const which = await trustedMacPath("/usr/bin/which", true);
  const env = await trustedMacPath("/usr/bin/env", true);
  const sandboxExec = await trustedMacPath("/usr/bin/sandbox-exec", true);
  const bash = await trustedMacPath("/bin/bash", true);
  const pathEnv = await trustedMacPath("/usr/bin", false);
  if (which !== "/usr/bin/which" || env !== "/usr/bin/env" || sandboxExec !== "/usr/bin/sandbox-exec") {
    throw new Error("Trusted macOS sandbox helpers must resolve to the expected OS paths.");
  }
  return { pathEnv, which, env, sandboxExec, bash };
}

export async function withTrustedMacPathAsync<T>(pathEnv: string, action: () => Promise<T>): Promise<T> {
  const previous = process.env.PATH;
  process.env.PATH = pathEnv;
  try { return await action(); }
  finally {
    if (previous === undefined) delete process.env.PATH;
    else process.env.PATH = previous;
  }
}
