import { spawnSync } from "node:child_process";
import { rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { expect, it } from "vitest";
import {
  createPrivateWindowsSshDirectory,
  verifyPrivateWindowsKeyFile
} from "../src/windows-acl.js";
import {
  trustedWindowsPowerShellSync,
  windowsSystemEnvironment
} from "../src/windows-system.js";

it.skipIf(process.platform !== "win32")(
  "protects a generated SSH key for only the current user and SYSTEM",
  async () => {
    const { dirPath, sid } = await createPrivateWindowsSshDirectory();
    const keyPath = path.join(dirPath, "id_ed25519");
    try {
      await writeFile(keyPath, "test private key material", { mode: 0o600 });
      const revalidate = await verifyPrivateWindowsKeyFile(keyPath, sid);

      const script = String.raw`
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$sections = [Security.AccessControl.AccessControlSections]::Access -bor [Security.AccessControl.AccessControlSections]::Owner
$acl = [IO.FileInfo]::new($env:SGW_WINDOWS_ACL_INSPECT_PATH).GetAccessControl($sections)
$full = [Security.AccessControl.FileSystemRights]::FullControl
$rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]) | ForEach-Object {
  [ordered]@{
    sid = $_.IdentityReference.Value
    allow = $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow
    full = ($_.FileSystemRights -band $full) -eq $full
    inherited = $_.IsInherited
    inheritance = [string]$_.InheritanceFlags
    propagation = [string]$_.PropagationFlags
  }
})
[Console]::Out.WriteLine(([ordered]@{
  current = $identity.User.Value
  owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  protected = $acl.AreAccessRulesProtected
  rules = $rules
} | ConvertTo-Json -Depth 5 -Compress))
`;
      const encoded = Buffer.from(script, "utf16le").toString("base64");
      const result = spawnSync(trustedWindowsPowerShellSync(), [
        "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
        "-EncodedCommand", encoded
      ], {
        encoding: "utf8",
        env: windowsSystemEnvironment({ SGW_WINDOWS_ACL_INSPECT_PATH: keyPath }),
        shell: false,
        windowsHide: true
      });
      expect(result.error).toBeUndefined();
      expect(result.status, result.stderr).toBe(0);

      const acl = JSON.parse(result.stdout.trim()) as {
        current: string;
        owner: string;
        protected: boolean;
        rules: Array<{
          sid: string;
          allow: boolean;
          full: boolean;
          inherited: boolean;
          inheritance: string;
          propagation: string;
        }>;
      };
      const expectedSids = acl.current === "S-1-5-18"
        ? [acl.current]
        : [acl.current, "S-1-5-18"].sort();
      expect(acl.owner).toBe(acl.current);
      expect(acl.protected).toBe(true);
      expect(acl.rules.map((rule) => rule.sid).sort()).toEqual(expectedSids);
      for (const rule of acl.rules) {
        expect(rule).toMatchObject({
          allow: true,
          full: true,
          inherited: false,
          inheritance: "None",
          propagation: "None"
        });
      }

      await expect(revalidate()).resolves.toBeUndefined();
      await rename(keyPath, `${keyPath}.original`);
      await writeFile(keyPath, "replacement private key material", { mode: 0o600 });
      await expect(revalidate()).rejects.toThrow(/changed while its access was secured/i);
    } finally {
      await rm(dirPath, { recursive: true, force: true });
    }
  },
  30_000
);
