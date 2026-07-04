import { describe, expect, it } from "vitest";
import {
  credentialBackendLabel,
  credentialProviderPresentation
} from "../src/console-ui/src/lib/credential-presentation.js";

describe("credential presentation", () => {
  it("normalizes 1Password provider and backend spellings", () => {
    expect(credentialProviderPresentation("1password", "onepassword")).toEqual({
      kind: "onepassword",
      label: "1Password"
    });
    expect(credentialBackendLabel("onepassword", "MacIntel")).toBe("1Password");
  });

  it("replaces unknown local provider and backend labels on macOS", () => {
    expect(credentialProviderPresentation(undefined, "local")).toEqual({
      kind: "sgw",
      label: "s-gw Local"
    });
    expect(credentialProviderPresentation("unknown", "local").label).toBe("s-gw Local");
    expect(credentialBackendLabel("local", "MacIntel")).toBe("macOS Keychain");
  });

  it("names Windows secure storage without generic local wording", () => {
    expect(credentialBackendLabel("local", "Win32")).toBe("Windows Credential Manager");
    expect(credentialBackendLabel("windows-credential-manager", "Win32")).toBe("Windows Credential Manager");
    expect(credentialBackendLabel("tpm", "Win32")).toBe("Windows TPM");
  });
});
