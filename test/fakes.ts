import { exports } from "cloudflare:workers";
import { vi } from "vitest";

type Route = (body?: unknown, init?: RequestInit) => Response | Promise<Response>;

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
    // JSON bodies arrive parsed; anything else (an audit's gzip bytes) as raw bytes.
    const raw = init?.body ? new Uint8Array(await new Response(init.body).arrayBuffer()) : undefined;
    let body: unknown = raw;
    try {
      body = raw && JSON.parse(new TextDecoder().decode(raw));
    } catch {}
    return route(body, init);
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
  main?: string;
  // Where the manifest says the archive is; null for a manifest without one.
  tarball?: string | null;
  // The latest version's archive; a package.json and an index.js unless a test gives its own.
  archive?: Route;
  firstSeenDaysAgo?: number;
  maintainers?: number;
  scripts?: Record<string, string>;
  // Other versions in the record, with their scripts.
  earlier?: Record<string, Record<string, string>>;
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
    ...(opts.main === undefined ? {} : { main: opts.main }),
    ...(opts.tarball === null ? {} : { dist: { tarball: opts.tarball ?? tarballUrl(name, opts.version ?? "1.0.0") } }),
    maintainers: Array.from({ length: opts.maintainers ?? 2 }, (_, i) => ({ name: `maintainer${i}` })),
    ...(opts.repo === false ? {} : { repository: { type: "git", url: `git+https://github.com/example/${name}.git` } }),
  };
  const record = {
    name,
    "dist-tags": { latest: manifest.version },
    time: { created: daysAgo(firstSeenDaysAgo) },
    maintainers: manifest.maintainers,
    versions: {
      ...Object.fromEntries(Object.entries(opts.earlier ?? {}).map(([version, scripts]) => [version, { ...manifest, version, scripts }])),
      [manifest.version]: manifest,
    },
  };
  const path = `https://registry.npmjs.org/${name.replace("/", "%2F")}`;
  return {
    [path]: json(record),
    [`${path}/latest`]: json(manifest),
    [tarballUrl(name, manifest.version)]:
      opts.archive ?? (async () => new Response(await tgz([{ path: "package/package.json", body: "{}" }, { path: "package/index.js", body: "" }]))),
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

const MODERN = "2026-07-28";
const LEGACY = "2025-11-25";

// One JSON-RPC request to /mcp. 2026 clients put their version and capabilities on every request; 2025 clients send
// only the version header (a stateless server answers them without the initialize handshake).
export function mcp(method: string, params: Record<string, unknown> = {}, era: "modern" | "legacy" = "legacy", extra: Record<string, string> = {}) {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    "mcp-protocol-version": era === "modern" ? MODERN : LEGACY,
    ...extra,
  };
  if (era === "modern") {
    headers["mcp-method"] = method;
    if (typeof params.name === "string") headers["mcp-name"] = params.name;
    params = {
      ...params,
      _meta: {
        "io.modelcontextprotocol/protocolVersion": MODERN,
        "io.modelcontextprotocol/clientCapabilities": {},
        "io.modelcontextprotocol/clientInfo": { name: "test", version: "1.0.0" },
      },
    };
  }
  return exports.default.fetch("http://localhost/mcp", {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
}

// Answers come back as plain JSON or as a one-message event stream.
export async function rpcAnswer(res: Response) {
  const text = await res.text();
  const body = text.startsWith("{") ? text : text.split("\n").find((line) => line.startsWith("data: "))!.slice(6);
  return JSON.parse(body) as { result?: Record<string, unknown>; error?: { code: number; message: string }; id?: unknown };
}

export const tarballUrl = (name: string, version: string) => `https://registry.npmjs.org/${name}/-/${name.replace(/^@[^/]+\//, "")}-${version}.tgz`;

export interface TarEntry {
  path: string;
  body?: string | Uint8Array;
  // "0" file (default), "1" hard link, "2" symlink, "5" folder, "x" pax, "L" GNU long name.
  type?: string;
  // Raw header fields, to build broken headers.
  size?: string;
  prefix?: string;
  checksum?: string;
}

// A tar archive as npm publishes one (ustar headers, 512-byte blocks, two zero blocks at the end).
export function tar(entries: TarEntry[], { end = true } = {}): Uint8Array {
  const blocks: Uint8Array[] = [];
  for (const entry of entries) {
    const body = typeof entry.body === "string" ? new TextEncoder().encode(entry.body) : (entry.body ?? new Uint8Array(0));
    blocks.push(tarHeader(entry, body.length), body, new Uint8Array((512 - (body.length % 512)) % 512));
  }
  if (end) blocks.push(new Uint8Array(1024));
  return concat(blocks);
}

export function tarHeader(entry: TarEntry, length: number): Uint8Array {
  const header = new Uint8Array(512);
  const put = (at: number, text: string) => header.set(new TextEncoder().encode(text), at);
  put(0, entry.path);
  put(100, "0000644\0");
  put(108, "0000000\0");
  put(116, "0000000\0");
  put(124, entry.size ?? `${length.toString(8).padStart(11, "0")}\0`);
  put(136, "00000000000\0");
  put(156, entry.type ?? "0");
  put(257, "ustar\0" + "00");
  if (entry.prefix) put(345, entry.prefix);
  put(148, "        ");
  const sum = header.reduce((a, b) => a + b, 0);
  put(148, entry.checksum ?? `${sum.toString(8).padStart(6, "0")}\0 `);
  return header;
}

export async function gzip(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer());
}

export const tgz = (entries: TarEntry[], opts?: { end?: boolean }) => gzip(tar(entries, opts));

// A pax record: "<length> path=<value>\n", where the length counts itself.
export function paxRecord(key: string, value: string): string {
  const rest = ` ${key}=${value}\n`;
  let length = rest.length + 1;
  while (String(length).length + rest.length !== length) length++;
  return length + rest;
}

export function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
}
