import { chmodSync, copyFileSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const distRoot = resolve(root, "dist/windows");
const packageInfo = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8"));

const staged = [
  {
    source: "native/windows-client/s-gw-client.ps1",
    target: "s-gw-client.ps1",
    launcher: "s-gw-client.cmd"
  },
  {
    source: "native/windows-helper/s-gw-helper.ps1",
    target: "s-gw-helper.ps1",
    launcher: "s-gw-helper.cmd"
  },
  {
    source: "native/windows-credential/SgwCredential.ps1",
    target: "s-gw-credential.ps1",
    launcher: "s-gw-credential.cmd"
  }
];

mkdirSync(distRoot, { recursive: true });

for (const item of staged) {
  const source = resolve(root, item.source);
  if (!existsSync(source)) {
    console.error(`Missing Windows source: ${source}`);
    process.exit(1);
  }

  const target = resolve(distRoot, item.target);
  copyFileSync(source, target);
  chmodSync(target, 0o755);
  writeFileSync(resolve(distRoot, item.launcher), launcherFor(item.target));
}

writeFileSync(resolve(distRoot, "VERSION.txt"), `${packageInfo.name} ${packageInfo.version}\n`);
console.log(`Staged Windows client helpers: ${distRoot}`);

function launcherFor(scriptName) {
  return `@echo off\r
setlocal\r
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0${scriptName}" %*\r
exit /b %ERRORLEVEL%\r
`;
}
