import { fetchJson, TIMEOUT_MS, TOO_LARGE, type FetchResult } from "./fetch";
import type { Ecosystem } from "./normalize";

export type RegistryCheck =
  | {
      status: "found";
      latestVersion: string | null;
      firstSeenAt: string | null;
      maintainers: number;
      installScripts: string[];
      hasRepo: boolean;
      weeklyDownloads?: number;
      downloadsError?: string;
    }
  | { status: "not_found" }
  | { status: "error"; reason: string }
  // The name itself was rejected, so no lookup was made.
  | { status: "skipped"; reason: string };

type Found = Extract<RegistryCheck, { status: "found" }>;

// PyPI only offers the full project record (every release's files); the largest seen is botocore at 3.8 MB.
const PYPI_MAX_BYTES = 10 * 1024 * 1024;
// Most npm records are tiny, but a few long-lived ones are huge (next 31 MB, vite 39 MB) and too big to parse
// safely in 128 MB. Those get the small /latest manifest instead.
const NPM_RECORD_MAX_BYTES = 4 * 1024 * 1024;
// api.npmjs.org rate-limits hard (6 of 40 back-to-back requests got 429), so download counts are only fetched
// where they change the verdict: packages young enough that low usage is a warning sign.
const DOWNLOADS_MATTER_UNDER_DAYS = 365;
const DAY_MS = 86_400_000;
const NPM_INSTALL_HOOKS = ["preinstall", "install", "postinstall"];
const REPO_URL = /^https?:\/\/(?:www\.)?(?:github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|git\.sr\.ht)\//i;

type DownloadStats = { weeklyDownloads: number; firstSeenAt: string | null } | { downloadsError: string };

export const NPM_REGISTRY = "https://registry.npmjs.org";
export const npmRecordUrl = (name: string) => `${NPM_REGISTRY}/${name.replace("/", "%2F")}`;
const pypiRecordUrl = (name: string) => `https://pypi.org/pypi/${name}/json`;

// Names reaching here are already validated, so they are safe to place in a URL path.
export async function lookup(ecosystem: Ecosystem, name: string, now = Date.now()): Promise<RegistryCheck> {
  if (ecosystem === "pypi") {
    return toCheck(await fetchJson(pypiRecordUrl(name), { maxBytes: PYPI_MAX_BYTES }), parsePypi);
  }

  const recordUrl = npmRecordUrl(name);
  const full = await fetchJson(recordUrl, { maxBytes: NPM_RECORD_MAX_BYTES });
  if (full.status === "error" && full.reason === TOO_LARGE) {
    const [latest, downloads] = await Promise.all([fetchJson(`${recordUrl}/latest`), npmDownloads(name)]);
    const check = toCheck(latest, (manifest) => parseManifest(manifest, null));
    return check.status === "found" ? { ...check, ...downloads } : check;
  }

  const check = toCheck(full, parseNpmRecord);
  if (check.status !== "found") return check;
  const ageDays = check.firstSeenAt === null ? 0 : (now - Date.parse(check.firstSeenAt)) / DAY_MS;
  if (ageDays >= DOWNLOADS_MATTER_UNDER_DAYS) return check;
  const downloads = await npmDownloads(name);
  return "downloadsError" in downloads ? { ...check, ...downloads } : { ...check, weeklyDownloads: downloads.weeklyDownloads };
}

// Only whether a name exists and when it was created: the record alone, never the rate-limited downloads API.
export async function exists(
  ecosystem: Ecosystem,
  name: string,
): Promise<{ status: "found"; firstSeenAt: string | null } | { status: "not_found" } | { status: "error"; reason: string }> {
  const full =
    ecosystem === "pypi"
      ? await fetchJson(pypiRecordUrl(name), { maxBytes: PYPI_MAX_BYTES })
      : await fetchJson(npmRecordUrl(name), { maxBytes: NPM_RECORD_MAX_BYTES });
  // Only long-lived npm packages have records this big; it exists, its creation date is unknown.
  if (full.status === "error" && full.reason === TOO_LARGE && ecosystem === "npm") return { status: "found", firstSeenAt: null };
  if (full.status !== "ok") return full;
  const check = ecosystem === "pypi" ? parsePypi(record(full.data)) : parseNpmRecord(record(full.data));
  return check.status === "found" ? check : { status: "not_found" };
}

// The downloads API rate-limits, so lookups take turns (per isolate) and a 429 backs off before retrying.
// Note: isolates don't coordinate; caching the stats is what keeps the volume down.
const MAX_CONCURRENT_DOWNLOAD_LOOKUPS = 2;
const DOWNLOAD_RETRY_DELAYS_MS = [1_000, 2_000, 4_000];
// Every attempt timing out plus every backoff: no lookup holds a slot longer than this.
const LONGEST_LOOKUP_MS = (DOWNLOAD_RETRY_DELAYS_MS.length + 1) * TIMEOUT_MS + DOWNLOAD_RETRY_DELAYS_MS.reduce((a, b) => a + b);
const SLOT_POLL_MS = 50;
const downloadSlots = new Set<{ takenAt: number }>();

// Waiters poll instead of being woken by the lookup that finishes: the Workers runtime won't let one request resume a
// promise another request is waiting on (it cancels the waiting request as hung). A request cancelled mid-lookup never
// releases its slot, so a slot older than any lookup can take counts as free. Note: polling lets a newcomer take a
// freed slot before an earlier waiter.
async function takeDownloadSlot() {
  for (;;) {
    const now = Date.now();
    for (const slot of downloadSlots) if (now - slot.takenAt > LONGEST_LOOKUP_MS) downloadSlots.delete(slot);
    if (downloadSlots.size < MAX_CONCURRENT_DOWNLOAD_LOOKUPS) {
      const slot = { takenAt: now };
      downloadSlots.add(slot);
      return slot;
    }
    await new Promise((resolve) => setTimeout(resolve, SLOT_POLL_MS));
  }
}

async function npmDownloads(name: string): Promise<DownloadStats> {
  const slot = await takeDownloadSlot();
  try {
    return parseDownloads(await fetchDownloads(`https://api.npmjs.org/downloads/range/last-year/${name}`));
  } finally {
    downloadSlots.delete(slot);
  }
}

async function fetchDownloads(url: string): Promise<FetchResult> {
  let result = await fetchJson(url);
  for (const delayMs of DOWNLOAD_RETRY_DELAYS_MS) {
    if (result.status !== "error" || result.reason !== "rate limited") break;
    await new Promise((resolve) => setTimeout(resolve, delayMs));
    result = await fetchJson(url);
  }
  return result;
}

function parseDownloads(result: FetchResult): DownloadStats {
  // The downloads API lags new packages by a day or so and answers 404 until then.
  if (result.status === "not_found") return { weeklyDownloads: 0, firstSeenAt: null };
  if (result.status === "error") return { downloadsError: result.reason };
  const days = record(result.data).downloads;
  if (!Array.isArray(days)) return { downloadsError: "invalid response" };
  const history = days.map(record).map((d) => ({ day: string(d.day), count: typeof d.downloads === "number" ? d.downloads : 0 }));
  const first = history.find((d) => d.count > 0)?.day;
  return {
    weeklyDownloads: history.slice(-7).reduce((sum, d) => sum + d.count, 0),
    // Note: a lower bound past a year, and a package nobody downloaded looks newer than it is; both err toward
    // caution. Only used when the full record is too big to read the real creation date.
    firstSeenAt: first ? new Date(first).toISOString() : null,
  };
}

function toCheck(result: FetchResult, parse: (doc: Record<string, unknown>) => RegistryCheck): RegistryCheck {
  if (result.status === "ok") return parse(record(result.data));
  return result;
}

function parseNpmRecord(doc: Record<string, unknown>): RegistryCheck {
  const latest = string(record(doc["dist-tags"]).latest);
  const version = latest === undefined ? undefined : record(doc.versions)[latest];
  // A fully unpublished package keeps a stub record with no versions; it can't be installed.
  if (version === undefined) return { status: "not_found" };
  return parseManifest(record(version), string(record(doc.time).created) ?? null);
}

function parseManifest(manifest: Record<string, unknown>, firstSeenAt: string | null): RegistryCheck {
  if (typeof manifest.version !== "string") return { status: "not_found" };
  const scripts = record(manifest.scripts);
  return {
    status: "found",
    latestVersion: manifest.version,
    firstSeenAt,
    maintainers: Array.isArray(manifest.maintainers) ? manifest.maintainers.length : 0,
    installScripts: NPM_INSTALL_HOOKS.filter((hook) => typeof scripts[hook] === "string"),
    hasRepo: repoUrl(manifest.repository) !== undefined,
  };
}

function parsePypi(doc: Record<string, unknown>): Found {
  const info = record(doc.info);
  const ownership = record(doc.ownership);
  const roles = Array.isArray(ownership.roles) ? ownership.roles.length : 0;
  const uploads = Object.values(record(doc.releases))
    .flatMap((files) => (Array.isArray(files) ? files : []))
    .map((file) => Date.parse(string(record(file).upload_time_iso_8601) ?? ""))
    .filter((time) => !Number.isNaN(time));
  const latestFiles = Array.isArray(doc.urls) ? doc.urls.map(record) : [];
  // Without a wheel, pip builds from source and runs the package's setup code at install time.
  const sourceOnly = latestFiles.length > 0 && latestFiles.every((file) => file.packagetype === "sdist");
  const links = [info.home_page, ...Object.values(record(info.project_urls))];
  return {
    status: "found",
    latestVersion: string(info.version) ?? null,
    firstSeenAt: uploads.length ? new Date(Math.min(...uploads)).toISOString() : null,
    maintainers: roles + (ownership.organization ? 1 : 0),
    installScripts: sourceOnly ? ["source-only release"] : [],
    hasRepo: links.some((link) => typeof link === "string" && REPO_URL.test(link)),
  };
}

function repoUrl(repository: unknown): string | undefined {
  const url = typeof repository === "string" ? repository : string(record(repository).url);
  return url?.trim() ? url : undefined;
}

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function string(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

// Runs fn over items with at most `limit` in flight, keeping results in order.
export async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
