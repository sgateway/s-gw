export type CredentialProviderKind = "onepassword" | "sgw" | "aws" | "github" | "ssh" | "openai" | "generic";

export interface CredentialProviderPresentation {
  kind: CredentialProviderKind;
  label: string;
}

export function credentialProviderPresentation(
  provider?: string,
  backend?: string
): CredentialProviderPresentation {
  const value = normalize(provider);
  const storage = normalize(backend);

  if (isOnePassword(value) || isOnePassword(storage)) {
    return { kind: "onepassword", label: "1Password" };
  }
  if (!value || value === "unknown" || value === "generic" || value === "local") {
    return { kind: "sgw", label: "s-gw Local" };
  }
  if (value === "aws" || value === "amazon" || value === "amazon-web-services") {
    return { kind: "aws", label: "AWS" };
  }
  if (value === "github") {
    return { kind: "github", label: "GitHub" };
  }
  if (value === "ssh") {
    return { kind: "ssh", label: "SSH" };
  }
  if (value === "openai") {
    return { kind: "openai", label: "OpenAI" };
  }

  return { kind: "generic", label: titleCase(value) };
}

export function credentialBackendLabel(value?: string, platform = runtimePlatform()): string {
  const normalized = normalize(value);
  if (isOnePassword(normalized)) return "1Password";
  if (normalized === "keychain" || normalized === "macos-keychain") return "macOS Keychain";
  if (normalized === "windows-credential-manager") return "Windows Credential Manager";
  if (normalized === "tpm" || normalized === "windows-tpm") return "Windows TPM";

  if (!normalized || normalized === "local" || normalized === "unknown") {
    const os = platform.toLowerCase();
    if (os.includes("mac")) return "macOS Keychain";
    if (os.includes("win")) return "Windows Credential Manager";
    return "Encrypted local store";
  }

  return titleCase(normalized);
}

function isOnePassword(value: string): boolean {
  return value === "1password" || value === "onepassword" || value === "one-password";
}

function normalize(value?: string): string {
  return String(value || "").trim().toLowerCase();
}

function runtimePlatform(): string {
  if (typeof navigator === "undefined") return "";
  return navigator.platform || navigator.userAgent || "";
}

function titleCase(value: string): string {
  return value
    .replace(/[-_]+/g, " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}
