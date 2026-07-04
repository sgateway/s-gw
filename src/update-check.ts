import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { getSgwHome } from "./paths.js";
import { CURRENT_VERSION } from "./version.js";

export const UPDATE_REPOSITORY = "sgateway/s-gw";
export const UPDATE_CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

export interface UpdateCheckResult {
  checked: boolean;
  currentVersion: string;
  latestVersion: string | null;
  available: boolean;
  releaseUrl: string | null;
  prerelease: boolean;
  publishedAt: string | null;
  checkedAt: string | null;
  error?: string;
}

interface GitHubRelease {
  tag_name: string;
  html_url: string;
  draft: boolean;
  prerelease: boolean;
  published_at?: string | null;
}

interface UpdateCache {
  result: UpdateCheckResult;
}

interface ReleaseCheckerOptions {
  cachePath?: string;
  currentVersion?: string;
  endpoint?: string;
  enabled?: boolean;
  fetcher?: typeof fetch;
  now?: () => number;
}

export function isNewerVersion(candidate: string, current: string): boolean {
  const left = versionParts(candidate);
  const right = versionParts(current);
  const count = Math.max(left.length, right.length);

  for (let index = 0; index < count; index += 1) {
    const a = left[index] ?? 0;
    const b = right[index] ?? 0;
    if (a > b) return true;
    if (a < b) return false;
  }

  return false;
}

export class ReleaseChecker {
  private readonly cachePath: string;
  private readonly currentVersion: string;
  private readonly endpoint: string;
  private readonly enabled: boolean;
  private readonly fetcher: typeof fetch;
  private readonly now: () => number;
  private latest: UpdateCheckResult | null = null;
  private inFlight: Promise<UpdateCheckResult> | null = null;

  constructor(options: ReleaseCheckerOptions = {}) {
    this.cachePath = options.cachePath ?? path.join(getSgwHome(), "update-check.json");
    this.currentVersion = options.currentVersion ?? CURRENT_VERSION;
    this.endpoint = options.endpoint ?? `https://api.github.com/repos/${UPDATE_REPOSITORY}/releases?per_page=20`;
    this.enabled = options.enabled ?? process.env.SGW_DISABLE_UPDATE_CHECK !== "1";
    this.fetcher = options.fetcher ?? fetch;
    this.now = options.now ?? Date.now;
  }

  current(): UpdateCheckResult | null {
    return this.latest;
  }

  async check(force = false): Promise<UpdateCheckResult> {
    if (!this.enabled) {
      const result = emptyResult(this.currentVersion);
      this.latest = result;
      return result;
    }

    if (this.inFlight) return this.inFlight;
    this.inFlight = this.performCheck(force).finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  private async performCheck(force: boolean): Promise<UpdateCheckResult> {
    const cached = await this.readCache();
    if (!force && cached && cacheIsFresh(cached, this.now())) {
      this.latest = cached;
      return cached;
    }

    try {
      const response = await this.fetcher(this.endpoint, {
        headers: {
          Accept: "application/vnd.github+json",
          "User-Agent": "s-gw-updater"
        },
        signal: AbortSignal.timeout(5_000)
      });
      if (!response.ok) {
        throw new Error(`GitHub release check returned HTTP ${response.status}.`);
      }

      const payload = await response.json();
      if (!Array.isArray(payload)) {
        throw new Error("GitHub release check returned an invalid response.");
      }

      const release = newestRelease(payload as GitHubRelease[]);
      const checkedAt = new Date(this.now()).toISOString();
      const result: UpdateCheckResult = release ? {
        checked: true,
        currentVersion: this.currentVersion,
        latestVersion: cleanVersion(release.tag_name),
        available: isNewerVersion(release.tag_name, this.currentVersion),
        releaseUrl: release.html_url,
        prerelease: release.prerelease,
        publishedAt: release.published_at ?? null,
        checkedAt
      } : {
        ...emptyResult(this.currentVersion),
        checked: true,
        checkedAt
      };

      this.latest = result;
      await this.writeCache(result);
      return result;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const result = cached ? { ...cached, checked: false, error: message } : {
        ...emptyResult(this.currentVersion),
        error: message
      };
      this.latest = result;
      return result;
    }
  }

  private async readCache(): Promise<UpdateCheckResult | null> {
    try {
      const parsed = JSON.parse(await readFile(this.cachePath, "utf8")) as UpdateCache;
      if (!validResult(parsed.result) || parsed.result.currentVersion !== this.currentVersion) {
        return null;
      }
      return parsed.result;
    } catch {
      return null;
    }
  }

  private async writeCache(result: UpdateCheckResult): Promise<void> {
    try {
      await mkdir(path.dirname(this.cachePath), { recursive: true, mode: 0o700 });
      await writeFile(this.cachePath, `${JSON.stringify({ result }, null, 2)}\n`, { mode: 0o600 });
      await chmod(this.cachePath, 0o600);
    } catch {
      // A read-only home should not turn an optional update check into a product failure.
    }
  }
}

export const releaseChecker = new ReleaseChecker();

function newestRelease(releases: GitHubRelease[]): GitHubRelease | null {
  let newest: GitHubRelease | null = null;
  for (const release of releases) {
    if (release.draft || !cleanVersion(release.tag_name)) continue;
    if (!newest || isNewerVersion(release.tag_name, newest.tag_name)) {
      newest = release;
    }
  }
  return newest;
}

function emptyResult(currentVersion: string): UpdateCheckResult {
  return {
    checked: false,
    currentVersion,
    latestVersion: null,
    available: false,
    releaseUrl: null,
    prerelease: false,
    publishedAt: null,
    checkedAt: null
  };
}

function cleanVersion(version: string): string {
  return version.trim().replace(/^v/i, "");
}

function versionParts(version: string): number[] {
  return cleanVersion(version).split(".").map((part) => {
    const match = part.match(/^\d+/);
    return match ? Number(match[0]) : 0;
  });
}

function cacheIsFresh(result: UpdateCheckResult, now: number): boolean {
  if (!result.checkedAt) return false;
  const checkedAt = Date.parse(result.checkedAt);
  return Number.isFinite(checkedAt) && now - checkedAt < UPDATE_CHECK_INTERVAL_MS;
}

function validResult(value: unknown): value is UpdateCheckResult {
  if (!value || typeof value !== "object") return false;
  const result = value as Partial<UpdateCheckResult>;
  return typeof result.currentVersion === "string" &&
    typeof result.available === "boolean" &&
    (result.latestVersion === null || typeof result.latestVersion === "string") &&
    (result.releaseUrl === null || typeof result.releaseUrl === "string") &&
    (result.checkedAt === null || typeof result.checkedAt === "string");
}
