import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const URL = "http://localhost/api/stats";
const stats = (path = "", headers: HeadersInit = {}) => exports.default.fetch(URL + path, { headers });
const body = async (res: Response) => (await res.json()) as { days: Record<string, unknown>[]; watchlist: unknown };

// What the data center's cache holds for /api/stats, if anything.
const stored = async () => (await caches.default.match(URL))?.headers.get("cache-control") ?? null;

const zeros = (day: string) => ({ day, checks: 0, blocks: 0, cautions: 0, invented: 0 });
const LAST_WEEK = ["2026-10-02", "2026-10-01", "2026-09-30", "2026-09-29", "2026-09-28", "2026-09-27", "2026-09-26"];

async function day(day: string, checks: number, blocks: number, cautions: number, invented: number) {
  await env.DB.prepare("INSERT INTO stats (day, checks, blocks, cautions, invented) VALUES (?, ?, ?, ?, ?)")
    .bind(day, checks, blocks, cautions, invented)
    .run();
}

async function watched(name: string, status: string, confirmed: boolean) {
  await env.DB.prepare(
    "INSERT INTO watch (ecosystem, name, first_seen, last_seen, sightings, source, first_caller, confirmed_at, status) VALUES ('npm', ?, 1, 1, 1, 'api', ?, ?, ?)",
  )
    .bind(name, confirmed ? null : "f".repeat(64), confirmed ? 2 : null, status)
    .run();
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(new Date("2026-10-02T12:00:00Z"));
});

afterEach(async () => {
  vi.restoreAllMocks();
  vi.useRealTimers();
  await caches.default.delete(URL);
  await env.DB.batch(["watch", "stats", "daily"].map((table) => env.DB.prepare(`DELETE FROM ${table}`)));
});

describe("stats", () => {
  it("an empty database answers seven days of zeros", async () => {
    const res = await stats();
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/json");
    expect(await res.json()).toEqual({
      days: LAST_WEEK.map(zeros),
      watchlist: { total: 0, confirmed: 0, unregistered: 0, registered: 0, cleared: 0 },
      generatedAt: "2026-10-02T12:00:00.000Z",
    });
  });

  it("reports the last seven utc days and the watchlist by status", async () => {
    await day("2026-10-02", 12, 3, 2, 1);
    await day("2026-09-29", 5, 1, 0, 1);
    await day("2026-09-26", 7, 0, 1, 0);
    await day("2026-09-25", 99, 99, 99, 99);
    await watched("ghost-a", "unregistered", false);
    await watched("ghost-b", "unregistered", true);
    await watched("ghost-c", "registered", true);
    await watched("ghost-d", "cleared", true);
    await watched("ghost-e", "registered", false);

    const res = await stats();
    const { days, watchlist } = await body(res);
    expect(days).toEqual([
      { day: "2026-10-02", checks: 12, blocks: 3, cautions: 2, invented: 1 },
      zeros("2026-10-01"),
      zeros("2026-09-30"),
      { day: "2026-09-29", checks: 5, blocks: 1, cautions: 0, invented: 1 },
      zeros("2026-09-28"),
      zeros("2026-09-27"),
      { day: "2026-09-26", checks: 7, blocks: 0, cautions: 1, invented: 0 },
    ]);
    expect(watchlist).toEqual({ total: 5, confirmed: 3, unregistered: 2, registered: 2, cleared: 1 });
    // Counts only: nothing that names a package or a caller.
    const text = JSON.stringify(await (await stats("?again")).json());
    for (const secret of ["ghost", "fff"]) expect(text).not.toContain(secret);
  });

  it("repeat requests come from the cache whatever the query string", async () => {
    await day("2026-10-02", 1, 0, 0, 0);
    const first = await stats();
    expect(await stored()).toBe("public, max-age=300");
    expect((await body(first)).days[0]).toMatchObject({ checks: 1 });

    await day("2026-10-01", 4, 0, 0, 0);
    await env.DB.prepare("UPDATE stats SET checks = 2 WHERE day = '2026-10-02'").run();
    const db = vi.spyOn(env.DB, "batch");
    for (const [path, headers] of [["", {}], ["?fresh=1", {}], ["?", { "cache-control": "no-cache", pragma: "no-cache" }]] as const) {
      const res = await stats(path, headers);
      expect(res.status).toBe(200);
      // Browsers come back to the data center's copy every time, so none keeps an answer longer than it does.
      expect(res.headers.get("cache-control")).toBe("no-cache");
      expect((await body(res)).days.slice(0, 2)).toEqual([{ ...zeros("2026-10-02"), checks: 1 }, zeros("2026-10-01")]);
    }
    expect(db).not.toHaveBeenCalled();
  });

  it("a cached answer never outlives its utc day", async () => {
    vi.setSystemTime(new Date("2026-10-02T23:58:00Z"));
    const res = await stats();
    expect(res.headers.get("cache-control")).toBe("no-cache");
    expect(await stored()).toBe("public, max-age=119");
    await caches.default.delete(URL);

    // A second is kept for the cache write, so with under two seconds left nothing is stored.
    const put = vi.spyOn(caches.default, "put");
    for (const time of ["2026-10-02T23:59:58.001Z", "2026-10-02T23:59:59.000Z", "2026-10-02T23:59:59.999Z"]) {
      vi.setSystemTime(new Date(time));
      expect((await stats()).status).toBe(200);
    }
    expect(put).not.toHaveBeenCalled();

    // A read that ends after the day did must not be stored for the new day.
    vi.setSystemTime(new Date("2026-10-02T23:59:57.990Z"));
    const batch = env.DB.batch.bind(env.DB);
    vi.spyOn(env.DB, "batch").mockImplementationOnce(async (statements) => {
      const results = await batch(statements);
      vi.setSystemTime(new Date("2026-10-03T00:00:00.040Z"));
      return results;
    });
    expect((await body(await stats())).days[0]!.day).toBe("2026-10-02");
    expect(put).not.toHaveBeenCalled();

    vi.setSystemTime(new Date("2026-10-03T00:00:00Z"));
    await day("2026-10-03", 1, 1, 0, 1);
    const next = await stats();
    expect(await stored()).toBe("public, max-age=300");
    expect((await body(next)).days[0]).toEqual({ day: "2026-10-03", checks: 1, blocks: 1, cautions: 0, invented: 1 });
  });

  it("a broken database answers 503 without details and is not cached", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(env.DB, "batch").mockRejectedValueOnce(new Error("D1_ERROR: no such table: secret_table"));
    const res = await stats();
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "stats unavailable" });
    expect(log).toHaveBeenCalledWith("stats read failed", expect.objectContaining({ message: expect.stringMatching(/secret_table/) }));

    await day("2026-10-02", 3, 0, 0, 0);
    const next = await stats();
    expect(next.status).toBe(200);
    expect((await body(next)).days[0]).toMatchObject({ checks: 3 });
  });

  it("a broken cache still answers", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.spyOn(caches.default, "match").mockRejectedValue(new Error("cache down"));
    vi.spyOn(caches.default, "put").mockRejectedValue(new Error("cache down"));
    await day("2026-10-02", 2, 0, 0, 0);
    const res = await stats();
    expect(res.status).toBe(200);
    expect((await body(res)).days[0]).toMatchObject({ checks: 2 });
    expect(log).toHaveBeenCalledWith("stats cache write failed", expect.anything());
    expect(log).toHaveBeenCalledWith("stats cache read failed", expect.anything());
  });

  it("one uncached request is one d1 round trip", async () => {
    const batch = vi.spyOn(env.DB, "batch");
    const prepare = vi.spyOn(env.DB, "prepare");
    await stats();
    expect(batch).toHaveBeenCalledTimes(1);
    expect(prepare).toHaveBeenCalledTimes(2);
    const [read, count] = await batch.mock.results[0]!.value;
    expect(read.meta.rows_read).toBeLessThanOrEqual(7);
    expect(count.meta.rows_read).toBeLessThanOrEqual(1);
  });

  it("stats share the api limit", async () => {
    const limit = vi.spyOn(env.CHECK_LIMIT, "limit").mockResolvedValue({ success: false });
    const res = await stats("", { "cf-connecting-ip": "203.0.113.50" });
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
    expect(await res.json()).toEqual({ error: "pkgMirage rate limit exceeded; try again in 60 seconds" });
    expect(limit).toHaveBeenCalledWith({ key: "203.0.113.50" });
  });
});
