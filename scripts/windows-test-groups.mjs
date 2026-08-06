const dedicatedGroups = Object.freeze({
  store: ["tests/store.test.ts"],
  client: ["tests/windows-client.test.ts"],
  credential: ["tests/windows-acl.test.ts", "tests/windows-credential-e2e.test.ts"]
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
