import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

export async function assertNoMacAclAllow(location: string): Promise<void> {
  if (process.platform !== "darwin") return;
  if (/[\x00-\x1f\x7f]/.test(location)) throw new Error("macOS trusted path contains a control character.");

  let stdout: string;
  let stderr: string;
  try {
    ({ stdout, stderr } = await run("/bin/ls", ["-ldne", "--", location], {
      env: { LC_ALL: "C" }, timeout: 1500, maxBuffer: 64 * 1024
    }));
  } catch {
    throw new Error("Could not verify macOS path ACL.");
  }
  if (stderr || !stdout.endsWith("\n")) throw new Error("Could not verify macOS path ACL.");

  const lines = stdout.slice(0, -1).split("\n");
  const mode = /^\S+/.exec(lines[0])?.[0];
  if (!mode || mode.length < 10 || (mode.includes("+") && lines.length === 1)) {
    throw new Error("Could not verify macOS path ACL.");
  }
  for (const line of lines.slice(1)) {
    if (!/^\s+\d+:\s+.+\s+deny\s+\S.*$/.test(line)) {
      throw new Error("macOS trusted path has an extended ACL allow entry.");
    }
  }
}
