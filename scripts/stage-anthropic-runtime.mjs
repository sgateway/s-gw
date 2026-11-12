import { createHash } from "node:crypto";
import { copyFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const runtimeName = "@anthropic-ai/sandbox-runtime";
const originalZodRange = "^3.24.1";
const bundledZodRange = "^4.6.7";
const upstreamManifestHash = "3eceb56ff6423bf8d942ba7bbdad3f536620cb40976f5795e7a96f7e75f2b1f2";
const upstreamSeccompSourceHash = "4fa515faf61274ab5058fe60dbb6da8a92a7bc243c72476fd2b6d798cfc9ab01";
export const seccompHelpers = new Map([
  ["x64", { upstream: "b46118d36051d364b8857fd182251b209f8b339cb5772a0f81e814aba3c23a10",
    patched: "c8364995249b76accbc29253aef3f22bf972bb536436af436b4714e493a7252c" }],
  ["arm64", { upstream: "e547755917a7343619e80a00a192842e125ee00454a3ee1e11af4fae0504315e",
    patched: "29f717c1b0ee79b5ddda69beef52d759a0dc238ed8389300f7b7875b291cb639" }]
]);

export const bundledPackages = new Map([
  [runtimeName, { version: "0.0.50", integrity: "sha512-2j0K7jfk72YM+JitJ+O/ml1U+XOlSduR3Vet8YI49ot9ah6TWHyDzFLVBAEk5NCWMdNPULPHok/H6/L9meoxmg==" }],
  ["zod", { version: "4.6.7", integrity: "sha512-g8W2D2kU6a8untc053fX1uVBKzM7yqAxW/3zwk83+6RyF2+SKOuV+c0wBDhUwzV1PaGapmZH+rmcUzPf+3CGwg==" }],
  ["@pondwader/socks5-server", { version: "1.0.10", integrity: "sha512-bQY06wzzR8D2+vVCUoBsr5QS2U6UgPUQRmErNwtsuI6vLcyRKkafjkr3KxbtGFf9aBBIV2mcvlsKD1UYaIV+sg==" }],
  ["commander", { version: "12.1.0", integrity: "sha512-Vw8qHK3bZM9y/P10u3Vib8o/DdkvA2OtPtZvD871QKjy74Wj1WSKFILMPRPSdUSx5RFK1arlJzEtA4PkFgnbuA==" }],
  ["shell-quote", { version: "1.12.0", integrity: "sha512-PcByqNyT/38F2kDNi006HAMRJaULuBzq/FOsw3qdZvX/GA9W/jamDaRskgHjubHiftXK5sIFxLNkvrXUwcof6Q==" }]
]);

export function stageAnthropicRuntime(packageRoot = root) {
  const pkg = readJson(resolve(packageRoot, "package.json"));
  const lock = readJson(resolve(packageRoot, "package-lock.json"));
  if (pkg.dependencies?.[runtimeName] !== "0.0.50"
      || pkg.overrides?.[runtimeName]?.zod !== "4.6.7"
      || JSON.stringify(pkg.bundleDependencies) !== JSON.stringify([runtimeName, "zod"])) {
    throw new Error("The Anthropic runtime bundle declaration changed; review its packaging contract.");
  }

  for (const [name, expected] of bundledPackages) {
    const installed = readJson(resolve(packageRoot, "node_modules", name, "package.json"));
    const locked = lock.packages?.[`node_modules/${name}`];
    const tarballName = name.split("/").at(-1);
    const source = `https://registry.npmjs.org/${name}/-/${tarballName}-${expected.version}.tgz`;
    if (installed.version !== expected.version || locked?.version !== expected.version
        || locked.resolved !== source || locked.integrity !== expected.integrity) {
      throw new Error(`The bundled ${name} version or registry provenance changed.`);
    }
  }

  const runtimeFile = resolve(packageRoot, "node_modules", runtimeName, "package.json");
  const runtime = readJson(runtimeFile);
  const currentRange = runtime.dependencies?.zod;
  if (currentRange !== originalZodRange && currentRange !== bundledZodRange) {
    throw new Error(`Unexpected ${runtimeName} Zod dependency: ${currentRange}`);
  }

  runtime.dependencies.zod = originalZodRange;
  if (hashManifest(runtime) !== upstreamManifestHash) {
    throw new Error(`The ${runtimeName}@0.0.50 manifest differs from the reviewed upstream package.`);
  }
  if (existsSync(resolve(packageRoot, "node_modules", runtimeName, "node_modules", "zod"))) {
    throw new Error("The Anthropic runtime has an unexpected nested Zod copy.");
  }

  const seccompSource = resolve(packageRoot, "node_modules", runtimeName, "vendor/seccomp-src/apply-seccomp.c");
  if (sha256(seccompSource) !== upstreamSeccompSourceHash) {
    throw new Error("The Anthropic seccomp source differs from the reviewed upstream package.");
  }
  const replacements = [];
  for (const [arch, hashes] of seccompHelpers) {
    const candidate = resolve(packageRoot, "vendor/anthropic-seccomp", arch, "apply-seccomp");
    if (sha256(candidate) !== hashes.patched) {
      throw new Error(`The patched Anthropic ${arch} seccomp helper changed.`);
    }
    for (const prefix of ["vendor", "dist/vendor"]) {
      const installed = resolve(packageRoot, "node_modules", runtimeName, prefix, "seccomp", arch, "apply-seccomp");
      const digest = sha256(installed);
      if (digest !== hashes.upstream && digest !== hashes.patched) {
        throw new Error(`The installed Anthropic ${arch} seccomp helper changed.`);
      }
      if (digest === hashes.upstream) replacements.push([candidate, installed]);
    }
  }

  if (currentRange !== bundledZodRange) {
    runtime.dependencies.zod = bundledZodRange;
    writeFileSync(runtimeFile, `${JSON.stringify(runtime, null, 2)}\n`);
  }
  for (const [candidate, installed] of replacements) copyFileSync(candidate, installed);
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`Could not read ${file}: ${error.message}`, { cause: error });
  }
}

function hashManifest(manifest) {
  return createHash("sha256").update(JSON.stringify(sorted(manifest))).digest("hex");
}

function sha256(file) {
  try {
    return createHash("sha256").update(readFileSync(file)).digest("hex");
  } catch (error) {
    throw new Error(`Could not read ${file}: ${error.message}`, { cause: error });
  }
}

function sorted(value) {
  if (Array.isArray(value)) return value.map(sorted);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sorted(value[key])]));
  }
  return value;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  stageAnthropicRuntime();
  console.log("Staged Anthropic sandbox runtime 0.0.50 with Zod 4.6.7 and patched Linux seccomp helpers.");
}
