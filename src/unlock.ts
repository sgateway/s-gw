import { execFileSync, spawnSync } from "node:child_process";
import {
  accessSync,
  chmodSync,
  constants,
  copyFileSync,
  existsSync,
  linkSync,
  mkdirSync,
  rmSync,
  statSync
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { getSgwHome } from "./paths.js";

const defaultService = "com.s-gw.sgw.master-passphrase";
const defaultSecretService = "com.s-gw.sgw.secret";
const nativeHelperName = "s-gw-keychain-helper";
const windowsCredentialHelperName = "s-gw-credential.ps1";

export interface KeychainInfo {
  supported: boolean;
  service: string;
  account: string;
  provider: "native-helper" | "security-cli" | "windows-helper" | "none";
  helperPath?: string;
}

export interface UnlockStatus {
  envConfigured: boolean;
  activeSource: "env" | "macos-keychain" | "windows-credential-manager" | "none";
  keychain: KeychainInfo & {
    configured: boolean;
  };
}

export interface MacKeychainItemRef {
  service: string;
  account: string;
  label?: string;
}

export interface PersistentKeychainHelperInstall {
  helperPath: string;
  sourcePath: string;
  changed: boolean;
}

export interface PersistentKeychainHelperOptions {
  sourcePath?: string;
  sgwHome?: string;
}

export function requireUnlockPassphrase(): string {
  const fromEnv = process.env.SGW_MASTER_PASSPHRASE;
  if (validPassphrase(fromEnv)) {
    return fromEnv;
  }

  const fromKeychain = readKeychainPassphrase();
  if (validPassphrase(fromKeychain)) {
    return fromKeychain;
  }

  throw new Error(
    "s-gw needs a local unlock passphrase. Run `s-gw unlock keychain set --value-stdin` or set SGW_MASTER_PASSPHRASE."
  );
}

export function unlockStatus(): UnlockStatus {
  const envConfigured = validPassphrase(process.env.SGW_MASTER_PASSPHRASE);
  const keychain = keychainInfo();
  const configured = hasKeychainPassphrase();

  let activeSource: UnlockStatus["activeSource"] = "none";
  if (envConfigured) {
    activeSource = "env";
  } else if (configured) {
    activeSource = process.platform === "win32" ? "windows-credential-manager" : "macos-keychain";
  }

  return {
    envConfigured,
    activeSource,
    keychain: {
      ...keychain,
      configured
    }
  };
}

export function setKeychainPassphrase(passphrase: string): void {
  if (!validPassphrase(passphrase)) {
    throw new Error("Unlock passphrase must be at least 8 characters.");
  }

  ensureLocalCredentialStore();
  preparePersistentMacHelper();
  runKeychainSet(keychainInfo(), passphrase);
}

export function deleteKeychainPassphrase(): boolean {
  ensureLocalCredentialStore();
  preparePersistentMacHelper();
  try {
    runKeychainDelete(keychainInfo());
    return true;
  } catch {
    return false;
  }
}

export function hasKeychainPassphrase(): boolean {
  const info = keychainInfo();
  if (!info.supported || info.provider === "none" || process.env.SGW_DISABLE_KEYCHAIN === "1") {
    return false;
  }

  try {
    return keychainItemExists(info);
  } catch {
    return false;
  }
}

export function keychainInfo(): KeychainInfo {
  return {
    supported: supportsLocalCredentialStore(),
    service: process.env.SGW_KEYCHAIN_SERVICE || defaultService,
    account: process.env.SGW_KEYCHAIN_ACCOUNT || os.userInfo().username || "local-user",
    ...keychainProvider()
  };
}

export function defaultSecretKeychainService(): string {
  return process.env.SGW_SECRET_KEYCHAIN_SERVICE || defaultSecretService;
}

export function setMacKeychainItem(ref: MacKeychainItemRef, value: string): void {
  if (!value) {
    throw new Error("Cannot store an empty Keychain item.");
  }

  preparePersistentMacHelper();
  const info = keychainInfoForItem(ref);
  ensureNativeCredentialStore(info);
  runKeychainSet(info, value, ref.label || "s-gw local secret");
}

export function getMacKeychainItem(ref: MacKeychainItemRef): string {
  preparePersistentMacHelper();
  const info = keychainInfoForItem(ref);
  ensureNativeCredentialStore(info);
  return runKeychainGet(info).replace(/\r?\n$/, "");
}

export function deleteMacKeychainItem(ref: MacKeychainItemRef): boolean {
  try {
    preparePersistentMacHelper();
    const info = keychainInfoForItem(ref);
    ensureNativeCredentialStore(info);
    runKeychainDelete(info);
    return true;
  } catch {
    return false;
  }
}

function readKeychainPassphrase(): string | undefined {
  if (!supportsLocalCredentialStore() || process.env.SGW_DISABLE_KEYCHAIN === "1") {
    return undefined;
  }

  preparePersistentMacHelper();
  const info = keychainInfo();
  try {
    const output = runKeychainGet(info);

    return output.replace(/\r?\n$/, "");
  } catch {
    return undefined;
  }
}

function ensureLocalCredentialStore(): void {
  if (!keychainInfo().supported) {
    throw new Error("OS credential-store unlock is only available on macOS or Windows.");
  }
}

function ensureNativeCredentialStore(info: KeychainInfo): void {
  if (!info.supported) {
    throw new Error("OS credential-store secret storage is only available on macOS or Windows.");
  }

  if ((info.provider !== "native-helper" && info.provider !== "windows-helper") || !info.helperPath) {
    throw missingCredentialStoreError();
  }
}

function keychainInfoForItem(ref: MacKeychainItemRef): KeychainInfo {
  const service = ref.service.trim();
  const account = ref.account.trim();
  if (!service || !account) {
    throw new Error("Keychain service and account are required.");
  }

  return {
    supported: supportsLocalCredentialStore(),
    service,
    account,
    ...keychainProvider()
  };
}

function validPassphrase(value: string | undefined): value is string {
  return typeof value === "string" && value.trim().length >= 8;
}

function keychainProvider(): Pick<KeychainInfo, "provider" | "helperPath"> {
  if (process.platform === "win32") {
    const helperPath = findWindowsCredentialHelper();
    return helperPath ? { provider: "windows-helper", helperPath } : { provider: "none" };
  }

  if (process.platform !== "darwin") {
    return { provider: "none" };
  }

  const helperPath = findNativeHelper();
  if (helperPath) {
    return { provider: "native-helper", helperPath };
  }

  if (process.env.SGW_ALLOW_SECURITY_CLI === "1") {
    return { provider: "security-cli" };
  }

  return { provider: "none" };
}

function supportsLocalCredentialStore(): boolean {
  return process.platform === "darwin" || process.platform === "win32";
}

function findNativeHelper(): string | undefined {
  const fromEnv = process.env.SGW_KEYCHAIN_HELPER;
  if (fromEnv && existsSync(fromEnv)) {
    return fromEnv;
  }

  const persistent = persistentKeychainHelperPath();
  if (existsSync(persistent)) {
    return persistent;
  }

  return findPackagedNativeHelper();
}

function findPackagedNativeHelper(): string | undefined {
  if (process.platform !== "darwin") {
    return undefined;
  }

  const here = path.dirname(fileURLToPath(import.meta.url));
  const nativeTarget = `${process.platform}-${process.arch}`;
  const candidates = [
    path.resolve(here, "native", nativeTarget, nativeHelperName),
    path.resolve(process.cwd(), "dist", "native", nativeTarget, nativeHelperName),
    path.resolve(here, "native", nativeHelperName),
    path.resolve(process.cwd(), "dist", "native", nativeHelperName)
  ];

  return candidates.find((candidate) => existsSync(candidate));
}

export function persistentKeychainHelperPath(sgwHome = getSgwHome()): string {
  const nativeTarget = `${process.platform}-${process.arch}`;
  return path.join(path.resolve(sgwHome), "native", nativeTarget, nativeHelperName);
}

export function installPersistentKeychainHelper(
  options: PersistentKeychainHelperOptions = {}
): PersistentKeychainHelperInstall {
  if (process.platform !== "darwin") {
    throw new Error("The persistent Keychain helper is only available on macOS.");
  }

  const source = options.sourcePath || findPackagedNativeHelper();
  if (!source) {
    throw missingCredentialStoreError();
  }
  const sourcePath = path.resolve(source);
  if (!existsSync(sourcePath)) throw missingCredentialStoreError();
  assertUsableHelper(sourcePath);

  const helperPath = persistentKeychainHelperPath(options.sgwHome);
  if (existsSync(helperPath)) {
    assertUsableHelper(helperPath);
    chmodSync(helperPath, 0o700);
    return { helperPath, sourcePath, changed: false };
  }

  const helperDir = path.dirname(helperPath);
  mkdirSync(helperDir, { recursive: true, mode: 0o700 });
  chmodSync(helperDir, 0o700);
  const staging = `${helperPath}.install-${process.pid}-${Date.now()}`;

  try {
    copyFileSync(sourcePath, staging);
    chmodSync(staging, 0o700);
    try {
      linkSync(staging, helperPath);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
    }
  } finally {
    rmSync(staging, { force: true });
  }

  assertUsableHelper(helperPath);
  return { helperPath, sourcePath, changed: true };
}

function preparePersistentMacHelper(): void {
  if (process.platform !== "darwin" || process.env.SGW_KEYCHAIN_HELPER) {
    return;
  }
  if (!existsSync(persistentKeychainHelperPath())) {
    installPersistentKeychainHelper();
  }
}

function assertUsableHelper(helperPath: string): void {
  const info = statSync(helperPath);
  if (!info.isFile() || info.size === 0) {
    throw new Error(`Keychain helper is not a usable file: ${helperPath}`);
  }
  accessSync(helperPath, constants.X_OK);
}

function findWindowsCredentialHelper(): string | undefined {
  const fromEnv = process.env.SGW_WINDOWS_CREDENTIAL_HELPER || process.env.SGW_KEYCHAIN_HELPER;
  if (fromEnv && existsSync(fromEnv)) {
    return fromEnv;
  }

  const here = path.dirname(fileURLToPath(import.meta.url));
  const candidates = [
    path.resolve(here, "windows", windowsCredentialHelperName),
    path.resolve(process.cwd(), "dist", "windows", windowsCredentialHelperName)
  ];

  return candidates.find((candidate) => existsSync(candidate));
}

function runKeychainGet(info: KeychainInfo): string {
  if (info.provider === "native-helper" && info.helperPath) {
    return runNativeHelper(info.helperPath, ["get", "--service", info.service, "--account", info.account]);
  }

  if (info.provider === "security-cli") {
    return runSecurity([
      "find-generic-password",
      "-a",
      info.account,
      "-s",
      info.service,
      "-w"
    ]);
  }

  if (info.provider === "windows-helper" && info.helperPath) {
    return runWindowsCredentialHelper(info.helperPath, ["get", "-Service", info.service, "-Account", info.account]);
  }

  throw missingCredentialStoreError();
}

function keychainItemExists(info: KeychainInfo): boolean {
  if (process.platform === "darwin") {
    const result = spawnSync(
      keychainStatusCliPath(),
      ["find-generic-password", "-a", info.account, "-s", info.service],
      { encoding: "utf8", stdio: ["ignore", "ignore", "pipe"] }
    );

    if (result.error) {
      throw result.error;
    }
    if (result.status === 0) {
      return true;
    }
    if (result.status === 44) {
      return false;
    }
    throw new Error(result.stderr.trim() || `Keychain status check failed with status ${result.status}`);
  }

  if (info.provider === "windows-helper" && info.helperPath) {
    const output = runWindowsCredentialHelper(
      info.helperPath,
      ["status", "-Service", info.service, "-Account", info.account]
    );
    const status = JSON.parse(output) as { configured?: unknown };
    return status.configured === true;
  }

  return false;
}

function runKeychainSet(info: KeychainInfo, passphrase: string, label = "s-gw local unlock passphrase"): void {
  if (info.provider === "native-helper" && info.helperPath) {
    runNativeHelper(info.helperPath, ["set", "--service", info.service, "--account", info.account, "--label", label], passphrase);
    return;
  }

  if (info.provider === "security-cli") {
    runSecurity([
      "add-generic-password",
      "-U",
      "-a",
      info.account,
      "-s",
      info.service,
      "-l",
      label,
      "-w",
      passphrase
    ]);
    return;
  }

  if (info.provider === "windows-helper" && info.helperPath) {
    runWindowsCredentialHelper(
      info.helperPath,
      ["set", "-Service", info.service, "-Account", info.account, "-Label", label],
      passphrase
    );
    return;
  }

  throw missingCredentialStoreError();
}

function runKeychainDelete(info: KeychainInfo): void {
  if (info.provider === "native-helper" && info.helperPath) {
    runNativeHelper(info.helperPath, ["delete", "--service", info.service, "--account", info.account]);
    return;
  }

  if (info.provider === "security-cli") {
    runSecurity(["delete-generic-password", "-a", info.account, "-s", info.service]);
    return;
  }

  if (info.provider === "windows-helper" && info.helperPath) {
    runWindowsCredentialHelper(info.helperPath, ["delete", "-Service", info.service, "-Account", info.account]);
    return;
  }

  throw missingCredentialStoreError();
}

function missingCredentialStoreError(): Error {
  if (process.platform === "darwin") {
    return new Error(
      `No compatible macOS Keychain helper is available for darwin-${process.arch}. ` +
      "Public npm and DMG releases currently include Apple Silicon native surfaces; Intel Macs must build them from source."
    );
  }
  return new Error("No local OS credential-store provider is available. Run `npm run build:native`.");
}

function runNativeHelper(helperPath: string, args: string[], input?: string): string {
  const result = spawnSync(helperPath, args, {
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"]
  });

  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `Native Keychain helper failed with status ${result.status}`);
  }

  return result.stdout;
}

function runSecurity(args: string[]): string {
  return execFileSync("/usr/bin/security", args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
}

function keychainStatusCliPath(): string {
  return process.env.SGW_KEYCHAIN_STATUS_CLI || "/usr/bin/security";
}

function runWindowsCredentialHelper(helperPath: string, args: string[], input?: string): string {
  const result = spawnSync("powershell.exe", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", helperPath, ...args], {
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"]
  });

  if (result.status !== 0) {
    throw new Error(result.stderr.trim() || `Windows Credential Manager helper failed with status ${result.status}`);
  }

  return result.stdout;
}
