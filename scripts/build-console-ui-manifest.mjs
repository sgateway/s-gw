import { createHash } from "node:crypto";
import { readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

const uiDir = path.resolve("dist/console-ui");
const entries = {};
let totalBytes = 0;

async function addFiles(dir, prefix = "") {
  for (const item of await readdir(dir, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${item.name}` : item.name;
    const target = path.join(dir, item.name);
    if (item.isDirectory()) {
      await addFiles(target, relative);
      continue;
    }
    if (!item.isFile()) throw new Error(`Unexpected console UI path: ${relative}`);
    const bytes = await readFile(target);
    totalBytes += bytes.length;
    if (bytes.length > 16 * 1024 * 1024 || totalBytes > 32 * 1024 * 1024) {
      throw new Error("Console UI bundle is too large for protected mode.");
    }
    entries[relative] = createHash("sha256").update(bytes).digest("hex");
  }
}

await addFiles(uiDir);
if (!entries["index.html"] || Object.keys(entries).length > 512) {
  throw new Error("Console UI bundle has no entry page or has too many files.");
}
const ordered = Object.fromEntries(Object.entries(entries).sort(([a], [b]) => a.localeCompare(b)));
const manifest = JSON.stringify(ordered, null, 2) + "\n";
if (Buffer.byteLength(manifest) > 256 * 1024) {
  throw new Error("Console UI manifest is too large for protected mode.");
}
await writeFile(path.resolve("dist/console-ui-manifest.json"), manifest);
