import { waitUntil } from "cloudflare:workers";
import type { Ecosystem } from "./normalize";
import type { CheckResult } from "./score";

export type Source = "api" | "mcp" | "npm";

// Who asked and through which front door, so names seen not to exist can be counted once per caller per day.
export interface Watch {
  db: D1Database;
  // Keys the stored caller hashes; without it nothing is sighted (checks are unaffected).
  key: string | undefined;
  caller: string;
  source: Source;
}

// A registration this young of a name callers saw invented is how a slopsquat starts; after that the package gets
// its normal verdict.
export const WATCH_BLOCK_DAYS = 30;

export const watchFor = (env: Env, request: Request | undefined, source: Source): Watch => ({
  db: env.DB,
  key: env.SIGHTING_KEY,
  caller: caller(request?.headers.get("cf-connecting-ip") ?? null),
  source,
});

// The IP is only ever a rate-limit key or hashed with a secret: never stored or logged. One IPv6 user usually holds a
// whole /64, so a /64 is one caller.
export function caller(ip: string | null): string {
  if (!ip) return "unknown";
  if (!ip.includes(":")) return ip;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  if (mapped) return mapped[1]!;
  const [head, tail] = ip.split("::");
  const groups = head ? head.split(":") : [];
  if (tail !== undefined) {
    const rest = tail ? tail.split(":") : [];
    groups.push(...Array<string>(8 - groups.length - rest.length).fill("0"), ...rest);
  }
  return `${groups.slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(":")}::/64`;
}

// Names at least two callers saw invented and nobody cleared, with when they were first seen. A broken watchlist
// means "not watched": it may never fail a check.
export async function watchedNames(db: D1Database, ecosystem: Ecosystem, names: string[]): Promise<Map<string, number>> {
  if (!names.length) return new Map();
  try {
    const { results } = await db
      .prepare(
        `SELECT name, first_seen FROM watch WHERE ecosystem = ? AND confirmed_at IS NOT NULL AND status != 'cleared'
         AND name IN (${names.map(() => "?").join(", ")})`,
      )
      .bind(ecosystem, ...names)
      .all<{ name: string; first_seen: number }>();
    return new Map(results.map((r) => [r.name, r.first_seen]));
  } catch (error) {
    console.error("watchlist read failed", error);
    return new Map();
  }
}

// Runs after the response, inside the request that made it; a failure is only logged.
export function record(watch: Watch, results: CheckResult[], now = Date.now()): void {
  waitUntil(save(watch, results, now).catch((error) => console.error("watchlist write failed", error)));
}

async function save({ db, key, caller, source }: Watch, results: CheckResult[], now: number) {
  const day = new Date(now).toISOString().slice(0, 10);
  const missing = results.filter((r) => r.checks.registry.status === "not_found");
  if (missing.length && !key) console.warn("SIGHTING_KEY is not set; sightings are not counted");
  const sightings = key ? missing : [];
  const sign = key ? await signer(key) : null;
  const seenKeys = await Promise.all(sightings.map((r) => sign!(day, caller, r.ecosystem, r.name)));

  // One transaction, so parallel requests from one caller can't both count.
  const insert = db.prepare("INSERT OR IGNORE INTO daily (day, key) VALUES (?, ?)");
  const [, ...inserted] = await db.batch([
    db.prepare("DELETE FROM daily WHERE day < ?").bind(day),
    ...results.map((r) => insert.bind(day, `check:${r.ecosystem}:${r.name}`)),
    ...seenKeys.map((k) => insert.bind(day, `seen:${k}`)),
  ]);
  const isNew = (i: number) => inserted[i]!.meta.changes > 0;
  const counted = results.filter((_, i) => isNew(i));
  const sighted = sightings.filter((_, i) => isNew(results.length + i));

  const writes: D1PreparedStatement[] = [];
  if (counted.length) {
    const count = (match: (r: CheckResult) => boolean) => counted.filter(match).length;
    writes.push(
      db
        .prepare(
          `INSERT INTO stats (day, checks, blocks, cautions, invented) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (day) DO UPDATE SET checks = checks + excluded.checks, blocks = blocks + excluded.blocks,
           cautions = cautions + excluded.cautions, invented = invented + excluded.invented`,
        )
        .bind(
          day,
          counted.length,
          count((r) => r.verdict === "block"),
          count((r) => r.verdict === "caution"),
          count((r) => r.checks.registry.status === "not_found"),
        ),
    );
  }
  // The first caller's hash (no day in it, so the same caller on another day matches) is kept only until a different
  // caller sees the name; then it is erased and the name counts as confirmed.
  for (const r of sighted) {
    writes.push(
      db
        .prepare(
          `INSERT INTO watch (ecosystem, name, first_seen, last_seen, sightings, source, first_caller)
           VALUES (?1, ?2, ?3, ?3, 1, ?4, ?5)
           ON CONFLICT (ecosystem, name) DO UPDATE SET last_seen = excluded.last_seen, sightings = sightings + 1,
           confirmed_at = COALESCE(confirmed_at, CASE WHEN first_caller IS excluded.first_caller THEN NULL ELSE excluded.last_seen END),
           first_caller = CASE WHEN first_caller = excluded.first_caller THEN first_caller END`,
        )
        .bind(r.ecosystem, r.name, now, source, await sign!(caller, r.ecosystem, r.name)),
    );
  }
  if (writes.length) await db.batch(writes);
}

// HMAC-SHA-256 with the secret key: without the key a stored hash can't be matched to an IP, even by trying them all.
async function signer(key: string) {
  const encoder = new TextEncoder();
  const hmac = await crypto.subtle.importKey("raw", encoder.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return async (...parts: string[]) => {
    const mac = await crypto.subtle.sign("HMAC", hmac, encoder.encode(parts.join("\n")));
    return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
  };
}
