import { cpSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = resolve(root, "assets/icons/s-gw-source.png");
const outDir = resolve(root, "dist/assets/icons");
const iconsetDir = resolve(outDir, "s-gw.iconset");
const icnsPath = resolve(outDir, "AppIcon.icns");

const pngSizes = [16, 32, 64, 128, 180, 192, 256, 512, 1024];
const iconsetSizes = [
  [16, 1],
  [16, 2],
  [32, 1],
  [32, 2],
  [128, 1],
  [128, 2],
  [256, 1],
  [256, 2],
  [512, 1]
];

if (!existsSync(source)) {
  console.error(`Missing s-gw icon source: ${source}`);
  process.exit(1);
}

if (process.platform !== "darwin") {
  console.log("Skipping s-gw .icns generation on non-macOS platform.");
  process.exit(0);
}

const sourceDimensions = pngDimensions(source);
if (sourceDimensions.width >= 1024 && sourceDimensions.height >= 1024) {
  iconsetSizes.push([512, 2]);
} else {
  console.log(
    `Skipping 1024px AppIcon slot; source is ${sourceDimensions.width}x${sourceDimensions.height}.`
  );
}

mkdirSync(outDir, { recursive: true });
rmSync(iconsetDir, { recursive: true, force: true });
mkdirSync(iconsetDir, { recursive: true });

for (const size of pngSizes) {
  resample(source, resolve(outDir, `s-gw-${size}.png`), size, size);
}

for (const [points, scale] of iconsetSizes) {
  const pixels = points * scale;
  const suffix = scale === 2 ? "@2x" : "";
  resample(source, resolve(iconsetDir, `icon_${points}x${points}${suffix}.png`), pixels, pixels);
}

const iconutil = spawnSync("iconutil", ["-c", "icns", iconsetDir, "-o", icnsPath], {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "pipe"]
});
if (iconutil.status !== 0) {
  console.error(iconutil.stderr || iconutil.stdout);
  process.exit(iconutil.status || 1);
}

rmSync(iconsetDir, { recursive: true, force: true });
cpSync(resolve(outDir, "s-gw-32.png"), resolve(root, "docs/ui/favicon-32.png"));
cpSync(resolve(outDir, "s-gw-180.png"), resolve(root, "docs/ui/apple-touch-icon.png"));

console.log(`Built s-gw icon assets: ${outDir}`);

function resample(input, output, width, height) {
  const result = spawnSync("sips", [input, "--resampleHeightWidth", String(height), String(width), "--out", output], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (result.status !== 0) {
    console.error(result.stderr || result.stdout);
    process.exit(result.status || 1);
  }
}

function pngDimensions(file) {
  const png = readFileSync(file);
  const signature = "89504e470d0a1a0a";
  if (png.length < 24 || png.subarray(0, 8).toString("hex") !== signature) {
    throw new Error(`Icon source is not a PNG: ${file}`);
  }

  return {
    width: png.readUInt32BE(16),
    height: png.readUInt32BE(20)
  };
}
