const dedicatedGroups = Object.freeze({
  store: ["tests/store.test.ts"],
  "client-package": ["tests/windows-client.test.ts"],
  "client-session": ["tests/windows-client.test.ts"],
  "client-startup": ["tests/windows-client.test.ts"],
  credential: ["tests/windows-credential-e2e.test.ts"],
  acl: ["tests/windows-acl.test.ts"]
});

const clientTestPatterns = Object.freeze({
  "client-package": [
    "selects helpers only from the current Windows user session",
    "stages launchers for the client, tray helper, and Credential Manager helper",
    "cleans up when the helper bootstrap fails after starting",
    "restores a running console after an update failure"
  ].join("|"),
  "client-session": [
    "reuses a directly started console with default host and port arguments",
    "reuses one tray helper across repeated opens",
    "keeps a healthy console but refuses a new tray with only foreground unlock",
    "rejects a healthy console from another credential home",
    "stops only the requested Windows credential authority",
    "rejects a matching health response from a different listener process",
    "does not open another credential home's console in the browser"
  ].join("|"),
  "client-startup": [
    "returns one live tray helper when two CLI opens race",
    "keeps one authority when two credential homes race on one port",
    "starts headless and stops every Windows surface through the CLI",
    "persists alternate Windows authority settings and optional tray without credential environment",
    "refuses background startup when only an environment passphrase is available",
    "preserves an unmanaged Startup shortcut collision"
  ].join("|")
});

export const windowsTestGroups = Object.freeze(["all", "core", ...Object.keys(dedicatedGroups)]);

export function parseWindowsTestGroup(args) {
  if (args.length === 0) return "all";
  if (args.length !== 2 || args[0] !== "--group") {
    throw new Error(`Usage: node scripts/run-windows-tests.mjs [--group ${windowsTestGroups.join("|")}]`);
  }

  const group = args[1];
  if (!windowsTestGroups.includes(group)) {
    throw new Error(`Unknown Windows test group: ${group}`);
  }
  return group;
}

export function filesForWindowsTestGroup(group, discoveredFiles) {
  if (!windowsTestGroups.includes(group)) {
    throw new Error(`Unknown Windows test group: ${group}`);
  }

  const allFiles = [...new Set(discoveredFiles)].sort();
  const knownFiles = new Set(allFiles);
  const dedicated = new Set();

  for (const files of Object.values(dedicatedGroups)) {
    for (const file of files) {
      if (!knownFiles.has(file)) {
        throw new Error(`Windows test group references a missing file: ${file}`);
      }
      dedicated.add(file);
    }
  }

  if (group === "all") return allFiles;
  if (group === "core") return allFiles.filter((file) => !dedicated.has(file));
  return [...dedicatedGroups[group]];
}

export function testNamePatternForWindowsTestGroup(group) {
  if (!windowsTestGroups.includes(group)) {
    throw new Error(`Unknown Windows test group: ${group}`);
  }
  return clientTestPatterns[group];
}
