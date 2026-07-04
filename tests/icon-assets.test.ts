import { spawnSync } from "node:child_process";
import { readFile, stat } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..");

const describeMac = process.platform === "darwin" ? describe : describe.skip;

describeMac("native icon assets", () => {
  it("does not upsample a small source into a bloated 1024px AppIcon slot", async () => {
    const source = path.join(root, "assets/icons/s-gw-source.png");
    const dimensions = await pngDimensions(source);

    const result = spawnSync(process.execPath, ["scripts/build-icon-assets.mjs"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"]
    });

    expect(result.status, result.stderr || result.stdout).toBe(0);
    if (dimensions.width < 1024 || dimensions.height < 1024) {
      expect(result.stdout).toContain("Skipping 1024px AppIcon slot");
    }

    const icon = await stat(path.join(root, "dist/assets/icons/AppIcon.icns"));
    expect(icon.size).toBeLessThan(1_400_000);
  });
});

async function pngDimensions(file: string): Promise<{ width: number; height: number }> {
  const png = await readFile(file);
  const signature = "89504e470d0a1a0a";
  if (png.length < 24 || png.subarray(0, 8).toString("hex") !== signature) {
    throw new Error(`Icon source is not a PNG: ${file}`);
  }

  return {
    width: png.readUInt32BE(16),
    height: png.readUInt32BE(20)
  };
}
