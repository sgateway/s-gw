import { createHash } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../native/desktop-app");
const vendorRoot = join(appRoot, "vendor/glib-0.18.5");
const expectedUpstreamTree = "c52a2c6c879157ecc49c3e6aba04f4b01a1b7026823c54897711596deff71b81";
const expectedPatchedFile = "a0f5ee8acb8faa089bcdfbc9a57372609fce7654026ccef7d9a224d05a654ccc";
const patchFile = "src/variant_iter.rs";

const manifest = readFileSync(join(appRoot, "Cargo.toml"), "utf8");
const lock = readFileSync(join(appRoot, "Cargo.lock"), "utf8");
const crateManifest = readFileSync(join(vendorRoot, "Cargo.toml"), "utf8");
const patchSection = manifest.split("[patch.crates-io]")[1]?.split(/\r?\n\[/u)[0] || "";
if (count(manifest, "[patch.crates-io]") !== 1
  || !/^glib = \{ path = "vendor\/glib-0\.18\.5" \}\r?$/mu.test(patchSection)) {
  throw new Error("The desktop app must use the reviewed local glib patch.");
}
if (!/^name = "glib"$/mu.test(crateManifest) || !/^version = "0\.18\.5"$/mu.test(crateManifest)) {
  throw new Error("The vendored crate must remain glib 0.18.5.");
}
const locked = [...lock.matchAll(/\[\[package\]\]\r?\nname = "glib"\r?\nversion = "0\.18\.5"([\s\S]*?)(?=\r?\n\[\[package\]\]|$)/gu)];
if (locked.length !== 1 || /^(source|checksum) = /mu.test(locked[0][1])) {
  throw new Error("Cargo.lock must resolve glib 0.18.5 from the local patch.");
}

const patched = readFileSync(join(vendorRoot, patchFile), "utf8");
const mutableLocal = "            let mut p: *mut libc::c_char = std::ptr::null_mut();";
const mutableArgument = "                &mut p,\n                std::ptr::null::<i8>(),";
if (count(patched, mutableLocal) !== 1 || count(patched, mutableArgument) !== 1) {
  throw new Error("The reviewed VariantStrIter out-pointer fix is missing or changed.");
}
const patchedHash = createHash("sha256").update(patched).digest("hex");
if (patchedHash !== expectedPatchedFile) {
  throw new Error("The vendored VariantStrIter source differs from the reviewed patch.");
}

const upstreamSource = patched
  .replace(mutableLocal, "            let p: *mut libc::c_char = std::ptr::null_mut();")
  .replace(mutableArgument, "                &p,\n                std::ptr::null::<i8>(),");
const files = sourceFiles(vendorRoot);
if (files.length !== 121) {
  throw new Error(`Expected 121 upstream glib files, found ${files.length}.`);
}

const tree = createHash("sha256");
for (const file of files) {
  const data = file === patchFile
    ? Buffer.from(upstreamSource)
    : readFileSync(join(vendorRoot, file));
  tree.update(file).update("\0");
  tree.update(String(data.length)).update("\0");
  tree.update(data).update("\0");
}
if (tree.digest("hex") !== expectedUpstreamTree) {
  throw new Error("Vendored glib differs from the verified crates.io archive beyond the upstream fix.");
}

process.stdout.write("Vendored glib 0.18.5 matches the reviewed two-line backport.\n");

function count(value, needle) {
  return value.split(needle).length - 1;
}

function sourceFiles(root, prefix = "") {
  const files = [];
  for (const entry of readdirSync(join(root, prefix), { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) {
      files.push(...sourceFiles(root, relative));
      continue;
    }
    if (!entry.isFile()) throw new Error(`Unexpected vendored glib entry: ${relative}.`);
    files.push(relative);
  }
  return files.sort();
}
