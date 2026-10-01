import { vi } from "vitest";

type Route = (body?: unknown) => Response | Promise<Response>;

export const OSV_URL = "https://api.osv.dev/v1/querybatch";

const DAY_MS = 86_400_000;

export const daysAgo = (days: number) => new Date(Date.now() - days * DAY_MS).toISOString();

export const json =
  (data: unknown, status = 200): Route =>
  () =>
    Response.json(data, { status });

export const status =
  (code: number): Route =>
  () =>
    new Response(null, { status: code });

// Routes outbound fetches by exact URL; anything unrouted fails loudly so a test can't pass by accident.
// The malware check answers "no advisories" unless a test routes it differently.
export function fakeFetch(routes: Record<string, Route>) {
  const all: Record<string, Route> = { [OSV_URL]: osv(), ...routes };
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input, init) => {
    const url = input instanceof Request ? input.url : String(input);
    const route = all[url];
    if (!route) throw new Error(`unexpected fetch: ${url}`);
    return route(init?.body ? JSON.parse(await new Response(init.body).text()) : undefined);
  });
}

interface OsvQuery {
  package: { name: string; ecosystem: string };
  version?: string;
}

// Answers an OSV querybatch, giving each named package the listed advisory IDs.
export const osv =
  (advisories: Record<string, string[]> = {}): Route =>
  (body) =>
    Response.json({
      results: (body as { queries: OsvQuery[] }).queries.map((q) => {
        const ids = advisories[q.package.name] ?? [];
        return ids.length ? { vulns: ids.map((id) => ({ id, modified: "2026-01-01T00:00:00Z" })) } : {};
      }),
    });

interface NpmOptions {
  version?: string;
  firstSeenDaysAgo?: number;
  maintainers?: number;
  scripts?: Record<string, string>;
  repo?: boolean;
  weeklyDownloads?: number;
}

const HISTORY_DAYS = 365;
const LAST_WEEK_START = HISTORY_DAYS - 7;

// Download history shaped like api.npmjs.org/downloads/range/last-year: oldest day first, ending yesterday.
// The first non-zero day lands on `firstSeenDaysAgo`, and the last seven days sum to `weeklyDownloads`.
function downloadHistory(firstSeenDaysAgo: number, weeklyDownloads: number) {
  const days = Array.from({ length: HISTORY_DAYS }, (_, i) => ({ downloads: 0, day: daysAgo(HISTORY_DAYS - i).slice(0, 10) }));
  const first = Math.max(0, HISTORY_DAYS - firstSeenDaysAgo);
  if (weeklyDownloads > 0) days[Math.max(first, LAST_WEEK_START)]!.downloads = weeklyDownloads;
  if (first < LAST_WEEK_START) days[first]!.downloads ||= 1;
  return days;
}

export function npmPackage(name: string, opts: NpmOptions = {}): Record<string, Route> {
  const firstSeenDaysAgo = opts.firstSeenDaysAgo ?? 1000;
  const manifest = {
    name,
    version: opts.version ?? "1.0.0",
    scripts: opts.scripts ?? { test: "node test" },
    maintainers: Array.from({ length: opts.maintainers ?? 2 }, (_, i) => ({ name: `maintainer${i}` })),
    ...(opts.repo === false ? {} : { repository: { type: "git", url: `git+https://github.com/example/${name}.git` } }),
  };
  const record = {
    name,
    "dist-tags": { latest: manifest.version },
    time: { created: daysAgo(firstSeenDaysAgo) },
    maintainers: manifest.maintainers,
    versions: { [manifest.version]: manifest },
  };
  const path = `https://registry.npmjs.org/${name.replace("/", "%2F")}`;
  return {
    [path]: json(record),
    [`${path}/latest`]: json(manifest),
    [`https://api.npmjs.org/downloads/range/last-year/${name}`]: json({
      package: name,
      downloads: downloadHistory(firstSeenDaysAgo, opts.weeklyDownloads ?? 1_000_000),
    }),
  };
}

interface PypiOptions {
  created?: string;
  owners?: number;
  organization?: string | null;
  sdistOnly?: boolean;
  repo?: boolean;
}

export function pypiPackage(name: string, opts: PypiOptions = {}): Record<string, Route> {
  const created = opts.created ?? daysAgo(1000);
  const latestFiles = opts.sdistOnly
    ? [{ packagetype: "sdist", upload_time_iso_8601: created }]
    : [
        { packagetype: "bdist_wheel", upload_time_iso_8601: created },
        { packagetype: "sdist", upload_time_iso_8601: created },
      ];
  const doc = {
    info: {
      name,
      version: "1.0.0",
      home_page: null,
      project_urls: opts.repo === false ? { Documentation: "https://docs.example.org" } : { Source: `https://github.com/example/${name}` },
    },
    ownership: {
      organization: opts.organization ?? null,
      roles: Array.from({ length: opts.owners ?? 2 }, (_, i) => ({ role: "Owner", user: `owner${i}` })),
    },
    releases: { "1.0.0": latestFiles },
    urls: latestFiles,
  };
  return { [`https://pypi.org/pypi/${name}/json`]: json(doc) };
}
