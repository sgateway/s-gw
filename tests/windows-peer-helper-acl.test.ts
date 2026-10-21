import { describe, expect, it } from "vitest";
import {
  assessWindowsPeerHelperAcl,
  inspectWindowsPeerHelperAcl,
  type WindowsHelperAclSnapshot
} from "../src/windows-peer-helper-acl.js";

const helperPath = String.raw`C:\Program Files\s-gw\s-gw-windows-peer-identity.exe`;
const digest = "a".repeat(64);
const trustedInstallerSid = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";

function protectedSnapshot(): WindowsHelperAclSnapshot {
  return {
    path: helperPath,
    sha256: digest,
    localFixedDrive: true,
    entries: [
      helperPath,
      String.raw`C:\Program Files\s-gw`,
      String.raw`C:\Program Files`,
      "C:\\"
    ].map((entryPath, index) => ({
      path: entryPath,
      kind: index === 0 ? "file" as const : "directory" as const,
      reparsePoint: false,
      ownerSid: index > 1 ? trustedInstallerSid : "S-1-5-32-544",
      daclPresent: true,
      aces: [
        { type: "AccessAllowed", sid: "S-1-5-18", mask: 0x1f01ff, flags: 0x13 },
        { type: "AccessAllowed", sid: "S-1-5-32-544", mask: 0x1f01ff, flags: 0x13 },
        { type: "AccessAllowed", sid: "S-1-5-21-1-2-3-1001", mask: 0x1200a9, flags: 0x13 }
      ]
    }))
  };
}

describe("Windows peer helper ACL assessment", () => {
  it("accepts a pinned helper in an installer-owned, nonwritable path", () => {
    expect(() => assessWindowsPeerHelperAcl(protectedSnapshot(), helperPath, digest)).not.toThrow();
  });

  it("rejects helper and parent-directory write grants", () => {
    for (let index = 0; index < 4; index++) {
      const snapshot = protectedSnapshot();
      snapshot.entries[index].aces.push({
        type: "AccessAllowed", sid: "S-1-15-2-111-222", mask: index === 0 ? 0x2 : 0x40,
        flags: 0
      });
      expect(() => assessWindowsPeerHelperAcl(snapshot, helperPath, digest)).toThrow("agent-writable");
    }
  });

  it("accepts ancestor create rights and inherit-only CREATOR OWNER grants", () => {
    const snapshot = protectedSnapshot();
    snapshot.entries[2].aces.push({ type: "AccessAllowed", sid: "S-1-5-32-545", mask: 0x2,
      flags: 0 });
    snapshot.entries[3].aces.push({ type: "AccessAllowed", sid: "S-1-5-32-545", mask: 0x4,
      flags: 0 });
    for (const entry of snapshot.entries) {
      entry.aces.push({ type: "AccessAllowed", sid: "S-1-3-0", mask: 0x10000000,
        flags: 0x0b });
    }
    expect(() => assessWindowsPeerHelperAcl(snapshot, helperPath, digest)).not.toThrow();
  });

  it("still rejects creating a sibling DLL or subdirectory beside the helper", () => {
    for (const mask of [0x2, 0x4]) {
      const snapshot = protectedSnapshot();
      snapshot.entries[1].aces.push({ type: "AccessAllowed", sid: "S-1-5-32-545", mask,
        flags: 0x10 });
      expect(() => assessWindowsPeerHelperAcl(snapshot, helperPath, digest)).toThrow("agent-writable");
    }
  });

  it("rejects user ownership, reparse points, absent DACLs, and an uninspected ancestor", () => {
    const changes = [
      (s: WindowsHelperAclSnapshot) => { s.entries[0].ownerSid = "S-1-5-21-1-2-3-1001"; },
      (s: WindowsHelperAclSnapshot) => { s.entries[1].reparsePoint = true; },
      (s: WindowsHelperAclSnapshot) => { s.entries[2].daclPresent = false; },
      (s: WindowsHelperAclSnapshot) => { s.entries.pop(); }
    ];
    for (const change of changes) {
      const snapshot = protectedSnapshot();
      change(snapshot);
      expect(() => assessWindowsPeerHelperAcl(snapshot, helperPath, digest)).toThrow();
    }
  });

  it("rejects unknown ACEs, generic write, and write-DAC even if another rule denies access", () => {
    for (const ace of [
      { type: "AccessAllowedCallback", sid: "S-1-15-2-111-222", mask: 0x2, flags: 0 },
      { type: "AccessAllowed", sid: "S-1-15-2-111-222", mask: 0x40000000, flags: 0 },
      { type: "AccessAllowed", sid: "S-1-15-2-111-222", mask: 0x40000, flags: 0 }
    ]) {
      const snapshot = protectedSnapshot();
      snapshot.entries[1].aces.push({ type: "AccessDenied", sid: "S-1-15-2-111-222",
        mask: 0x1f01ff, flags: 0 });
      snapshot.entries[1].aces.push(ace);
      expect(() => assessWindowsPeerHelperAcl(snapshot, helperPath, digest)).toThrow();
    }
  });

  it("ignores a deny ACE and an inherit-only grant on the current object", () => {
    const snapshot = protectedSnapshot();
    snapshot.entries[1].aces.push({ type: "AccessDenied", sid: "S-1-5-32-545",
      mask: 0x1f01ff, flags: 0 });
    snapshot.entries[1].aces.push({ type: "AccessAllowed", sid: "S-1-3-0",
      mask: 0x10000000, flags: 0x0b });
    expect(() => assessWindowsPeerHelperAcl(snapshot, helperPath, digest)).not.toThrow();
  });

  it("rejects malformed inheritance flags and effective inherited write grants", () => {
    for (const flags of [0x08, 0x40, 0x10]) {
      const snapshot = protectedSnapshot();
      snapshot.entries[0].aces.push({ type: "AccessAllowed", sid: "S-1-5-32-545",
        mask: 0x2, flags });
      expect(() => assessWindowsPeerHelperAcl(snapshot, helperPath, digest)).toThrow();
    }
  });

  it("rejects mismatched hashes, remote paths, alternate streams, and normalized aliases", () => {
    expect(() => assessWindowsPeerHelperAcl(protectedSnapshot(), helperPath, "b".repeat(64)))
      .toThrow("installer attestation");
    const snapshot = protectedSnapshot();
    snapshot.localFixedDrive = false;
    expect(() => assessWindowsPeerHelperAcl(snapshot, helperPath, digest)).toThrow("installer attestation");
    for (const otherPath of [
      String.raw`\\server\share\s-gw-windows-peer-identity.exe`,
      helperPath + ":other",
      String.raw`C:\Program Files\s-gw\..\s-gw-windows-peer-identity.exe`,
      String.raw`C:\Program Files\s-gw.\s-gw-windows-peer-identity.exe`
    ]) {
      expect(() => assessWindowsPeerHelperAcl(protectedSnapshot(), otherPath, digest)).toThrow();
    }
  });

  it.skipIf(process.platform === "win32")("keeps the native inspector Windows-only", async () => {
    await expect(inspectWindowsPeerHelperAcl(helperPath, digest)).rejects.toThrow("requires Windows");
  });
});
