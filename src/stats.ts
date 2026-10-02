import { jsonError } from "./api";

const DAYS = 7;
const DAY_MS = 86_400_000;
const MAX_AGE_SECONDS = 300;

interface Day {
  day: string;
  checks: number;
  blocks: number;
  cautions: number;
  invented: number;
}

// Counts only: names, caller hashes and dedupe keys never leave D1.
export async function handleStats(request: Request, env: Env): Promise<Response> {
  // One key whatever the query string or headers, so callers can neither split the cache nor skip it. The origin is
  // in the key, but Cloudflare only sends the Worker its own hostnames. Note: the Cache API is per data center, so
  // each one reads D1 once per window.
  const key = new URL("/api/stats", request.url).toString();
  const cached = await caches.default.match(key).catch((error) => console.error("stats cache read failed", error));
  if (cached) return forBrowsers(cached);

  const now = Date.now();
  const days = Array.from({ length: DAYS }, (_, i) => new Date(now - i * DAY_MS).toISOString().slice(0, 10));
  let rows: Day[];
  let watchlist: Record<string, number>;
  try {
    const [stats, watch] = (await env.DB.batch([
      env.DB.prepare("SELECT day, checks, blocks, cautions, invented FROM stats WHERE day >= ?").bind(days.at(-1)),
      // A count over every row: no index makes that cheaper.
      env.DB.prepare(
        `SELECT COUNT(*) AS total, COUNT(confirmed_at) AS confirmed, COUNT(CASE WHEN status = 'unregistered' THEN 1 END) AS unregistered,
         COUNT(CASE WHEN status = 'registered' THEN 1 END) AS registered, COUNT(CASE WHEN status = 'cleared' THEN 1 END) AS cleared
         FROM watch`,
      ),
    ])) as [D1Result<Day>, D1Result<Record<string, number>>];
    rows = stats.results;
    watchlist = watch.results[0]!;
  } catch (error) {
    console.error("stats read failed", error);
    return jsonError(503, "stats unavailable");
  }

  const byDay = new Map(rows.map((row) => [row.day, row]));
  // Never cached past the end of the day the answer describes, counted from after the read (the clock moves during
  // I/O) and keeping a second for the cache write, so "today" is always today; near midnight, not cached at all.
  const endOfDay = (Math.floor(now / DAY_MS) + 1) * DAY_MS;
  const maxAge = Math.min(MAX_AGE_SECONDS, Math.floor((endOfDay - Date.now()) / 1000) - 1);
  const res = Response.json(
    {
      today: days[0],
      days: days.map((day) => byDay.get(day) ?? { day, checks: 0, blocks: 0, cautions: 0, invented: 0 }),
      watchlist,
      generatedAt: new Date(now).toISOString(),
    },
    { headers: { "cache-control": `public, max-age=${maxAge}` } },
  );
  // Awaited: at most once per window per data center, and a later request can't miss a write still in flight.
  if (maxAge > 0) await caches.default.put(key, res.clone()).catch((error) => console.error("stats cache write failed", error));
  return forBrowsers(res);
}

// A browser would keep a copy for its full max-age even when it came from the cache late in its life (an Age header
// isn't promised), so it could show yesterday as today; it asks again instead, and the data center's copy answers.
// Also: a cached response's headers are immutable, and the security headers are added on the way out.
function forBrowsers(res: Response): Response {
  const copy = new Response(res.body, res);
  copy.headers.set("cache-control", "no-cache");
  return copy;
}
