import { createHash, createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { chmod, mkdir, open, readFile, readdir, rename, rmdir, rm } from "node:fs/promises";
import { lstatSync, realpathSync, type Stats } from "node:fs";
import path from "node:path";
import { getSgwHome, getSgwRecoveryHome } from "../../src/paths.js";
import { openSealedHistory, sealHistory, type HistoryRows, type SealedHistoryV3 } from "../../src/sealed-history-codec.js";

interface HistoryHeadBody {
  version: 3;
  instanceId: string;
  generation: number;
  primaryName: string;
  journalName: string;
  recoveryName: string;
  sealedSha256: string;
  journalSha256: string;
  revisions: Array<[string, number]>;
  previousHeadSha256: string | null;
}

interface HistoryHead extends HistoryHeadBody {
  mac: string;
}

export interface StagedHistoryGeneration {
  generation: number;
  primaryPath: string;
  journalPath: string;
  recoveryPath: string;
  baseHeadSha256: string | null;
  head: HistoryHead;
}

const folderName = "sealed-history-v3-prototype";
const fileNamePattern = /^generation-\d{12}-[a-f0-9-]+\.json$/;

/** Test-only candidate. The head is not protected from a full-tree rollback. */
export class SealedHistoryPrototype {
  private readonly home: string;
  private readonly recoveryHome: string;
  private readonly key: Buffer;
  private readonly primaryDir: string;
  private readonly journalDir: string;
  private readonly recoveryDir: string;
  private readonly headPath: string;
  private readonly initializedPath: string;
  private readonly instanceId: string;

  constructor(home: string, recoveryHome: string, key: Uint8Array) {
    if (process.env.SGW_TEST_MODE !== "1"
        || path.resolve(home) !== getSgwHome()
        || path.resolve(recoveryHome) !== getSgwRecoveryHome(home)) {
      throw new Error("Sealed history prototype requires an explicit disposable test home and recovery home.");
    }
    if (!(key instanceof Uint8Array) || key.byteLength !== 32) {
      throw new Error("Sealed history prototype requires a 32-byte independent key.");
    }
    this.home = home;
    this.recoveryHome = recoveryHome;
    this.assertNoV1Evidence();
    this.key = Buffer.from(key);
    this.instanceId = sha256(`${path.resolve(home)}\0${path.resolve(recoveryHome)}`);
    this.primaryDir = path.join(home, folderName, "primary");
    this.journalDir = path.join(home, folderName, "journal");
    const namespace = sha256(path.resolve(home)).slice(0, 24);
    this.recoveryDir = path.join(recoveryHome, folderName, namespace);
    this.headPath = path.join(this.recoveryDir, "head.json");
    this.initializedPath = path.join(home, folderName, "initialized.json");
    this.assertStoragePaths();
  }

  async stage(rows: HistoryRows): Promise<StagedHistoryGeneration> {
    this.assertStoragePaths();
    this.assertNoV1Evidence();
    const current = await this.readHead();
    if (current) await this.read();
    const generation = (current?.head.generation || 0) + 1;
    const name = `generation-${String(generation).padStart(12, "0")}-${randomUUID()}.json`;
    const primaryPath = path.join(this.primaryDir, name);
    const recoveryPath = path.join(this.recoveryDir, name);
    const journalName = name.replace(/\.json$/, ".jsonl");
    const journalPath = path.join(this.journalDir, journalName);
    const sealed = sealHistory(rows, this.key);
    const sealedRaw = `${JSON.stringify(sealed)}\n`;
    const journalRaw = journalFor(sealed);
    const body: HistoryHeadBody = {
      version: 3, instanceId: this.instanceId, generation, primaryName: name, journalName, recoveryName: name,
      sealedSha256: sha256(sealedRaw), journalSha256: sha256(journalRaw),
      revisions: revisionPairs(rows), previousHeadSha256: current ? sha256(current.raw) : null
    };
    const head = { ...body, mac: this.mac(body) };

    await writeNewFile(primaryPath, sealedRaw, () => this.assertStoragePaths());
    await writeNewFile(journalPath, journalRaw, () => this.assertStoragePaths());
    await writeNewFile(recoveryPath, sealedRaw, () => this.assertStoragePaths());
    return { generation, primaryPath, journalPath, recoveryPath,
      baseHeadSha256: body.previousHeadSha256, head };
  }

  async commit(candidate: StagedHistoryGeneration): Promise<void> {
    this.assertStoragePaths();
    this.assertNoV1Evidence();
    const lockPath = path.join(this.recoveryDir, ".commit.lock");
    await mkdir(this.recoveryDir, { recursive: true, mode: 0o700 });
    try { await mkdir(lockPath); }
    catch { throw new Error("Another sealed history writer may be active; refusing to commit."); }
    try {
      const current = await this.readHead(candidate);
      if ((current ? sha256(current.raw) : null) !== candidate.baseHeadSha256
          || candidate.generation !== (current?.head.generation || 0) + 1) {
        throw new Error("Sealed history generation changed before commit.");
      }
      this.checkCandidate(candidate);
      const stagedRows = await this.readCandidate(candidate);
      if (current) {
        const committed = await this.read();
        assertNextHistory(committed.rows, stagedRows);
      }
      if (!current) {
        await writeNewFile(this.initializedPath, '{"version":3}\n', () => this.assertStoragePaths());
      }
      await writeAtomic(this.headPath, `${JSON.stringify(candidate.head)}\n`, () => this.assertStoragePaths());
    } finally {
      await rmdir(lockPath).catch(() => undefined);
    }
  }

  async read(): Promise<{ generation: number; rows: HistoryRows }> {
    this.assertStoragePaths();
    this.assertNoV1Evidence();
    const current = await this.readHead();
    if (!current) throw new Error("No committed sealed history generation exists.");
    const head = current.head;
    const expected = new Map(head.revisions);
    const copies = [
      { path: path.join(this.primaryDir, head.primaryName), hash: head.sealedSha256, journal: false },
      { path: path.join(this.recoveryDir, head.recoveryName), hash: head.sealedSha256, journal: false },
      { path: path.join(this.journalDir, head.journalName), hash: head.journalSha256, journal: true }
    ];
    for (const copy of copies) {
      checkOwnedFile(copy.path);
      const raw = await readFile(copy.path, "utf8").catch(() => undefined);
      if (raw === undefined || sha256(raw) !== copy.hash) continue;
      try {
        const sealed = copy.journal ? parseJournal(raw) : raw;
        return { generation: head.generation, rows: openSealedHistory(sealed, this.key, expected) };
      } catch {
        continue;
      }
    }
    throw new Error(`No complete copy matches committed sealed history generation ${head.generation}.`);
  }

  private async readCandidate(candidate: StagedHistoryGeneration): Promise<HistoryRows> {
    for (const filePath of [candidate.primaryPath, candidate.recoveryPath, candidate.journalPath]) {
      checkOwnedFile(filePath);
    }
    const primary = await readFile(candidate.primaryPath, "utf8");
    const recovery = await readFile(candidate.recoveryPath, "utf8");
    const journal = await readFile(candidate.journalPath, "utf8");
    if (sha256(primary) !== candidate.head.sealedSha256
        || sha256(recovery) !== candidate.head.sealedSha256
        || primary !== recovery || sha256(journal) !== candidate.head.journalSha256) {
      throw new Error("Staged sealed history copies differ.");
    }
    const expected = new Map(candidate.head.revisions);
    const rows = openSealedHistory(primary, this.key, expected);
    const journalRows = openSealedHistory(parseJournal(journal), this.key, expected);
    if (JSON.stringify(rows) !== JSON.stringify(journalRows)) {
      throw new Error("Staged sealed history journal differs from the primary.");
    }
    return rows;
  }

  private checkCandidate(candidate: StagedHistoryGeneration): void {
    const head = candidate.head;
    const { mac, ...body } = head;
    if (!validHead(head) || !sameMac(mac, this.mac(body))
        || head.instanceId !== this.instanceId
        || candidate.generation !== head.generation
        || candidate.baseHeadSha256 !== head.previousHeadSha256
        || candidate.primaryPath !== path.join(this.primaryDir, head.primaryName)
        || candidate.journalPath !== path.join(this.journalDir, head.journalName)
        || candidate.recoveryPath !== path.join(this.recoveryDir, head.recoveryName)) {
      throw new Error("Invalid staged sealed history generation.");
    }
  }

  private async readHead(initialCandidate?: StagedHistoryGeneration): Promise<{ head: HistoryHead; raw: string } | undefined> {
    checkOwnedFile(this.headPath);
    checkOwnedFile(this.initializedPath);
    const raw = await readFile(this.headPath, "utf8").catch((error: NodeJS.ErrnoException) => {
      if (error.code === "ENOENT") return undefined;
      throw error;
    });
    if (raw === undefined) {
      if (hasPath(this.initializedPath)) {
        throw new Error("Sealed history generation head is missing after initialization.");
      }
      const artifacts = await this.generationArtifacts();
      if (artifacts.length > 0) {
        const firstStage = initialCandidate?.generation === 1
          && initialCandidate.baseHeadSha256 === null
          && samePaths(artifacts, [
            initialCandidate.primaryPath, initialCandidate.journalPath, initialCandidate.recoveryPath
          ]);
        if (!firstStage) {
          throw new Error("Sealed history generation head is missing while generation files remain.");
        }
      }
      return undefined;
    }
    if (!hasPath(this.initializedPath)) {
      throw new Error("Sealed history initialization marker is missing.");
    }
    let head: HistoryHead;
    try { head = JSON.parse(raw) as HistoryHead; }
    catch { throw new Error("Invalid sealed history generation head."); }
    if (!validHead(head)) throw new Error("Invalid sealed history generation head.");
    const { mac, ...body } = head;
    if (!sameMac(mac, this.mac(body))) {
      throw new Error("Sealed history generation head is not authenticated.");
    }
    if (head.instanceId !== this.instanceId) {
      throw new Error("Sealed history generation belongs to another home.");
    }
    return { head, raw };
  }

  private mac(body: HistoryHeadBody): string {
    return createHmac("sha256", this.key).update(JSON.stringify(body)).digest("hex");
  }

  private assertStoragePaths(): void {
    if (process.env.SGW_TEST_MODE !== "1"
        || path.resolve(this.home) !== getSgwHome()
        || path.resolve(this.recoveryHome) !== getSgwRecoveryHome(this.home)) {
      throw new Error("Sealed history prototype paths changed outside test mode.");
    }
    checkOwnedDirs(this.home, [folderName, "primary"]);
    checkOwnedDirs(this.home, [folderName, "journal"]);
    checkOwnedDirs(this.recoveryHome, [folderName, path.basename(this.recoveryDir)]);
  }

  private async generationArtifacts(): Promise<string[]> {
    const files: string[] = [];
    for (const dir of [this.primaryDir, this.journalDir, this.recoveryDir]) {
      const names = await readdir(dir).catch((error: NodeJS.ErrnoException) => {
        if (error.code === "ENOENT") return [];
        throw error;
      });
      for (const name of names) {
        if (name !== ".commit.lock") files.push(path.join(dir, name));
      }
    }
    return files;
  }

  private assertNoV1Evidence(): void {
    const evidence = [
      "store.json", ".store-control.json", ".store-control.pending.json",
      ".store-initialized", "backups", "journal", "recovery"
    ].map(name => path.join(this.home, name));
    evidence.push(path.join(this.recoveryHome, "control-plane"));
    for (const candidate of evidence) {
      try {
        lstatSync(candidate);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
      throw new Error("Sealed history prototype refuses a home with v1 ledger evidence.");
    }
  }
}

function revisionPairs(rows: HistoryRows): Array<[string, number]> {
  return [
    ...rows.requests.map(item => [item.record.id, item.revision] as [string, number]),
    ...rows.audit.map(item => [item.record.id, item.revision] as [string, number])
  ];
}

function assertNextHistory(previous: HistoryRows, next: HistoryRows): void {
  for (const kind of ["requests", "audit"] as const) {
    const oldRows = previous[kind];
    const newRows = next[kind];
    if (newRows.length < oldRows.length) {
      throw new Error("Sealed history revision cannot remove a committed row.");
    }
    for (let index = 0; index < oldRows.length; index += 1) {
      const before = oldRows[index];
      const after = newRows[index];
      if (before.record.id !== after.record.id) {
        throw new Error("Sealed history revision cannot reorder a committed row.");
      }
      const changed = JSON.stringify(before.record) !== JSON.stringify(after.record);
      if (kind === "audit" && changed) {
        throw new Error("Sealed audit history revision cannot change an event.");
      }
      const wanted = before.revision + (changed ? 1 : 0);
      if (after.revision !== wanted) {
        throw new Error("Sealed history revision does not match the row change.");
      }
    }
    for (const added of newRows.slice(oldRows.length)) {
      if (added.revision !== 1) {
        throw new Error("A new sealed history row must start at revision 1.");
      }
    }
  }
}

function journalFor(sealed: SealedHistoryV3): string {
  const lines = [
    ...sealed.requests.map(row => JSON.stringify({ kind: "request", row })),
    ...sealed.audit.map(row => JSON.stringify({ kind: "audit", row }))
  ];
  return `${lines.join("\n")}\n`;
}

function parseJournal(raw: string): SealedHistoryV3 {
  if (!raw.endsWith("\n")) throw new Error("Torn sealed history journal.");
  const requests: SealedHistoryV3["requests"] = [];
  const audit: SealedHistoryV3["audit"] = [];
  for (const line of raw.split("\n")) {
    if (!line) continue;
    const entry = JSON.parse(line) as { kind?: string; row?: unknown };
    if (entry.kind === "request") requests.push(entry.row as SealedHistoryV3["requests"][number]);
    else if (entry.kind === "audit") audit.push(entry.row as SealedHistoryV3["audit"][number]);
    else throw new Error("Invalid sealed history journal row.");
  }
  return { version: 3, requests, audit };
}

function validHead(value: unknown): value is HistoryHead {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const h = value as Partial<HistoryHead>;
  return Object.keys(h).length === 11 && h.version === 3 && isHash(h.instanceId)
    && Number.isSafeInteger(h.generation) && (h.generation as number) > 0
    && typeof h.primaryName === "string" && fileNamePattern.test(h.primaryName)
    && typeof h.journalName === "string" && fileNamePattern.test(h.journalName.replace(/\.jsonl$/, ".json"))
    && typeof h.recoveryName === "string" && fileNamePattern.test(h.recoveryName)
    && isHash(h.sealedSha256) && isHash(h.journalSha256) && isHash(h.mac)
    && (h.previousHeadSha256 === null || isHash(h.previousHeadSha256))
    && Array.isArray(h.revisions) && h.revisions.every(item =>
      Array.isArray(item) && item.length === 2 && typeof item[0] === "string"
      && Number.isSafeInteger(item[1]) && item[1] > 0);
}

function isHash(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function sameMac(left: string, right: string): boolean {
  if (!isHash(left) || !isHash(right)) return false;
  return timingSafeEqual(Buffer.from(left, "hex"), Buffer.from(right, "hex"));
}

function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function hasPath(filePath: string): boolean {
  try { lstatSync(filePath); return true; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

function samePaths(left: string[], right: string[]): boolean {
  if (left.length !== right.length) return false;
  const expected = [...right].sort();
  return [...left].sort().every((item, index) => item === expected[index]);
}

function checkOwnedDirs(root: string, parts: string[]): void {
  let current = root;
  let rootReal: string | undefined;
  for (const name of ["", ...parts]) {
    if (name) current = path.join(current, name);
    let info: Stats;
    try { info = lstatSync(current) as Stats; }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
      throw error;
    }
    if (info.isSymbolicLink()) throw new Error("Sealed history path contains a symlink.");
    if (!info.isDirectory()) throw new Error("Sealed history path is not a directory.");
    checkOwner(info);
    const real = realpathSync.native(current);
    if (!rootReal) rootReal = real;
    else if (!isInside(real, rootReal)) {
      throw new Error("Sealed history directory resolves outside its home.");
    }
  }
}

function checkOwnedFile(filePath: string): void {
  let info: Stats;
  try { info = lstatSync(filePath) as Stats; }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return;
    throw error;
  }
  if (info.isSymbolicLink()) throw new Error("Sealed history file is a symlink.");
  if (!info.isFile()) throw new Error("Sealed history path is not a regular file.");
  checkOwner(info);
}

function checkOwner(info: Stats): void {
  if (process.platform === "win32") return;
  if (typeof process.getuid === "function" && info.uid !== process.getuid()) {
    throw new Error("Sealed history path has another owner.");
  }
  if (info.mode & 0o077) {
    throw new Error("Sealed history path is accessible by another user.");
  }
}

function isInside(candidate: string, root: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

async function writeNewFile(filePath: string, content: string, checkPaths: () => void): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
  checkPaths();
  const file = await open(filePath, "wx", 0o600);
  try {
    await file.writeFile(content);
    await file.sync();
  } finally {
    await file.close();
  }
  await syncDirectory(path.dirname(filePath));
}

async function writeAtomic(filePath: string, content: string, checkPaths: () => void): Promise<void> {
  const tmp = path.join(path.dirname(filePath), `.${path.basename(filePath)}.${randomUUID()}.tmp`);
  try {
    await writeNewFile(tmp, content, checkPaths);
    await rename(tmp, filePath);
    await chmod(filePath, 0o600);
    await syncDirectory(path.dirname(filePath));
  } catch (error) {
    await rm(tmp, { force: true }).catch(() => undefined);
    throw error;
  }
}

async function syncDirectory(dir: string): Promise<void> {
  try {
    const handle = await open(dir, "r");
    try { await handle.sync(); }
    finally { await handle.close(); }
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (code !== "EINVAL" && code !== "EPERM" && code !== "EISDIR") throw error;
  }
}
