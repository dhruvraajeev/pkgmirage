import { waitUntil } from "cloudflare:workers";
import type { Ecosystem } from "./normalize";
import { chunks, exists, mapLimit } from "./registry";
import type { CheckResult } from "./score";

export type Source = "api" | "mcp" | "npm" | "scan";

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

// One nightly run: ~200 record requests and ~205 D1 statements, far under a cron run's limits (10,000 subrequests,
// 1,000 D1 queries). Note: a list longer than this takes several nights to go round once.
const RECHECK_BATCH = 200;
const RECHECK_CONCURRENCY = 4;
// An unconfirmed name nobody has asked about for this long can't cause a block; stop spending lookups on it.
const RECHECK_UNCONFIRMED_DAYS = 90;
// An unconfirmed name's first-caller hash is kept only this long after its last sighting.
const FORGET_CALLER_DAYS = 30;
const DAY_MS = 86_400_000;
// D1 allows 100 bound parameters per query, and a failed read means "not watched", so names are read in batches.
const WATCH_READ_NAMES = 90;

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
    // Malformed input (too many groups) must still give a key, not throw.
    groups.push(...Array<string>(Math.max(0, 8 - groups.length - rest.length)).fill("0"), ...rest);
  }
  return `${groups.slice(0, 4).map((g) => parseInt(g, 16).toString(16)).join(":")}::/64`;
}

// Names at least two callers saw invented and nobody cleared, with when they were first seen. A broken watchlist
// means "not watched": it may never fail a check.
export async function watchedNames(db: D1Database, ecosystem: Ecosystem, names: string[]): Promise<Map<string, number>> {
  if (!names.length) return new Map();
  try {
    const reads = await Promise.all(
      chunks(names, WATCH_READ_NAMES).map((batch) =>
        db
          .prepare(
            `SELECT name, first_seen FROM watch WHERE ecosystem = ? AND confirmed_at IS NOT NULL AND status != 'cleared'
             AND name IN (${batch.map(() => "?").join(", ")})`,
          )
          .bind(ecosystem, ...batch)
          .all<{ name: string; first_seen: number }>(),
      ),
    );
    return new Map(reads.flatMap(({ results }) => results.map((r) => [r.name, r.first_seen] as const)));
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
  const sign = key && missing.length ? await signer(key) : null;
  // Per sighting: today's dedupe key, and the caller's per-name hash (no day in it) for confirmation.
  const sightings = sign
    ? await Promise.all(
        missing.map(async (r) => ({
          result: r,
          seen: await sign(day, caller, r.ecosystem, r.name),
          by: await sign(caller, r.ecosystem, r.name),
        })),
      )
    : [];

  // One transaction, so parallel requests from one caller can't both count.
  const insert = db.prepare("INSERT OR IGNORE INTO daily (day, key) VALUES (?, ?)");
  const [, ...inserted] = await db.batch([
    db.prepare("DELETE FROM daily WHERE day < ?").bind(day),
    ...results.map((r) => insert.bind(day, `check:${r.ecosystem}:${r.name}`)),
    ...sightings.map(({ seen }) => insert.bind(day, `seen:${seen}`)),
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
  for (const { result: r, by } of sighted) {
    writes.push(
      db
        .prepare(
          `INSERT INTO watch (ecosystem, name, first_seen, last_seen, sightings, source, first_caller)
           VALUES (?1, ?2, ?3, ?3, 1, ?4, ?5)
           ON CONFLICT (ecosystem, name) DO UPDATE SET last_seen = excluded.last_seen, sightings = sightings + 1,
           confirmed_at = COALESCE(confirmed_at, CASE WHEN first_caller IS excluded.first_caller THEN NULL ELSE excluded.last_seen END),
           first_caller = CASE WHEN first_caller = excluded.first_caller THEN first_caller END`,
        )
        .bind(r.ecosystem, r.name, now, source, by),
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

// Asks the registry whether watched names were registered since. Failures are logged; nothing here throws, and only a
// definite answer changes a row, so an unverified name is simply first in line next run.
export async function recheck(env: Env, now = Date.now()): Promise<void> {
  const db = env.DB;
  const started = Date.now();
  try {
    await db.batch([
      db.prepare("DELETE FROM daily WHERE day < ?").bind(new Date(now).toISOString().slice(0, 10)),
      db
        .prepare("UPDATE watch SET first_caller = NULL WHERE confirmed_at IS NULL AND first_caller IS NOT NULL AND last_seen < ?")
        .bind(now - FORGET_CALLER_DAYS * DAY_MS),
    ]);
  } catch (error) {
    console.error("recheck cleanup failed", error);
  }

  let names: { ecosystem: Ecosystem; name: string }[];
  try {
    ({ results: names } = await db
      .prepare(
        `SELECT ecosystem, name FROM watch WHERE status = 'unregistered' AND (confirmed_at IS NOT NULL OR last_seen >= ?)
         ORDER BY checked_at, first_seen LIMIT ?`,
      )
      .bind(now - RECHECK_UNCONFIRMED_DAYS * DAY_MS, RECHECK_BATCH)
      .all<{ ecosystem: Ecosystem; name: string }>());
  } catch (error) {
    console.error("recheck read failed", error);
    return;
  }

  const checks = await mapLimit(names, RECHECK_CONCURRENCY, (n) => exists(n.ecosystem, n.name));
  const registered: typeof names = [];
  let unverified = 0;
  const writes: D1PreparedStatement[] = [];
  for (const [i, check] of checks.entries()) {
    const { ecosystem, name } = names[i]!;
    if (check.status === "not_found") {
      writes.push(db.prepare("UPDATE watch SET checked_at = ? WHERE ecosystem = ? AND name = ?").bind(now, ecosystem, name));
    } else if (check.status === "found") {
      registered.push(names[i]!);
      const created = check.firstSeenAt === null ? null : Date.parse(check.firstSeenAt);
      writes.push(
        db
          .prepare("UPDATE watch SET status = 'registered', registered_at = ?, checked_at = ? WHERE ecosystem = ? AND name = ? AND status = 'unregistered'")
          .bind(created, now, ecosystem, name),
      );
    } else {
      unverified++;
      console.error("recheck unverified", ecosystem, name, check.reason);
    }
  }
  try {
    if (writes.length) await db.batch(writes);
  } catch (error) {
    console.error("recheck write failed", error);
    return;
  }
  // The cached "doesn't exist" would hide the block for up to 10 minutes.
  await Promise.all(
    registered.map(({ ecosystem, name }) =>
      env.CACHE.delete(`res:${ecosystem}:${name}`).catch((error) => console.error("recheck cache delete failed", name, error)),
    ),
  );
  console.log("recheck", { names: names.length, registered: registered.length, unverified, ms: Date.now() - started });
}
