import { createRequire } from "node:module";
const require = createRequire(import.meta.url);

export function nativePackageName(platform = process.platform, arch = process.arch, musl = false) {
  if (platform === "darwin" && ["arm64", "x64"].includes(arch)) return `@crabnebula/packager-darwin-${arch}`;
  if (platform === "win32" && ["x64", "arm64", "ia32"].includes(arch)) return `@crabnebula/packager-win32-${arch}-msvc`;
  if (platform === "linux" && ["x64", "arm64"].includes(arch)) return `@crabnebula/packager-linux-${arch}-${musl ? "musl" : "gnu"}`;
  if (platform === "linux" && arch === "arm") return "@crabnebula/packager-linux-arm-gnueabihf";
  throw new Error(`Unsupported desktop packaging host: ${platform}-${arch}`);
}

let binding;
export function packageApp(config) {
  if (!binding) {
    const report = process.platform === "linux" ? process.report.getReport() : undefined;
    const name = nativePackageName(process.platform, process.arch, report && !report.header.glibcVersionRuntime);
    try { binding = require(name); }
    catch (error) { throw new Error(`Desktop packager ${name} is unavailable. Install optional build dependencies.`, { cause: error }); }
    // s-gw packages native binaries; the upstream Electron plugin is unused.
    binding.initTracingSubscriber(0);
  }
  return binding.packageApp(JSON.stringify(config));
}
