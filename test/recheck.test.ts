import { createScheduledController, env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { recheck } from "../src/engine/watch";
import worker from "../src/index";
import { daysAgo, fakeFetch, json, npmPackage, pypiPackage, status } from "./fakes";

const NPM = "https://registry.npmjs.org";
const DAY_MS = 86_400_000;

afterEach(async () => {
  vi.restoreAllMocks();
  await env.DB.batch(["watch", "stats", "daily"].map((table) => env.DB.prepare(`DELETE FROM ${table}`)));
  const { keys } = await env.CACHE.list();
  await Promise.all(keys.map(({ name }) => env.CACHE.delete(name)));
});

interface Row {
  ecosystem: string;
  name: string;
  status: string;
  registered_at: number | null;
  checked_at: number | null;
  first_caller: string | null;
  sightings: number;
  last_seen: number;
}

const rows = async () => (await env.DB.prepare("SELECT * FROM watch ORDER BY ecosystem, name").all<Row>()).results;
const row = async (name: string) => (await rows()).find((r) => r.name === name)!;

// A watched name: confirmed and seen yesterday unless told otherwise.
async function watched(
  name: string,
  { ecosystem = "npm", lastSeenDaysAgo = 1, confirmed = true, status = "unregistered", checkedAt = null as number | null, firstCaller = null as string | null } = {},
) {
  const seen = Date.parse(daysAgo(lastSeenDaysAgo));
  await env.DB.prepare(
    `INSERT INTO watch (ecosystem, name, first_seen, last_seen, sightings, source, first_caller, confirmed_at, status, checked_at)
     VALUES (?, ?, ?, ?, 2, 'api', ?, ?, ?, ?)`,
  )
    .bind(ecosystem, name, seen, seen, firstCaller, confirmed ? seen : null, status, checkedAt)
    .run();
}

const missing = (...names: string[]) => Object.fromEntries(names.map((n) => [`${NPM}/${n}`, status(404)]));
const record = (name: string, firstSeenDaysAgo: number) => ({ [`${NPM}/${name}`]: npmPackage(name, { firstSeenDaysAgo })[`${NPM}/${name}`]! });

describe("nightly re-check", () => {
  it("the scheduled handler re-checks watched names", async () => {
    await watched("ghost-one");
    fakeFetch(record("ghost-one", 2));
    await worker.scheduled(createScheduledController({ scheduledTime: Date.now(), cron: "17 4 * * *" }), env);
    expect((await row("ghost-one")).status).toBe("registered");
  });

  it("re-checks at most 200 names, least recently checked first", async () => {
    const now = Date.now();
    const statements = Array.from({ length: 205 }, (_, i) =>
      env.DB.prepare(
        `INSERT INTO watch (ecosystem, name, first_seen, last_seen, sightings, source, confirmed_at, checked_at)
         VALUES ('npm', ?, ?, ?, 2, 'api', ?, ?)`,
      ).bind(`ghost-${String(i).padStart(3, "0")}`, now, now, now, i < 5 ? null : now - i * 1000),
    );
    await env.DB.batch(statements);
    const asked: string[] = [];
    vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
      asked.push(String(input).slice(NPM.length + 1));
      return new Response(null, { status: 404 });
    });
    await recheck(env, now + 1);
    expect(asked).toHaveLength(200);
    // Never checked (000-004) first, then the oldest check times (the highest numbers); 005-009 are the newest.
    for (const name of ["ghost-000", "ghost-004", "ghost-204", "ghost-010"]) expect(asked).toContain(name);
    for (const name of ["ghost-005", "ghost-009"]) expect(asked).not.toContain(name);
  });

  it("skips registered, cleared and long-unseen unconfirmed names", async () => {
    await watched("ghost-registered", { status: "registered" });
    await watched("ghost-cleared", { status: "cleared" });
    await watched("ghost-stale", { confirmed: false, lastSeenDaysAgo: 91 });
    await watched("ghost-stale-confirmed", { lastSeenDaysAgo: 200 });
    await watched("ghost-recent", { confirmed: false, lastSeenDaysAgo: 89 });
    const spy = fakeFetch(missing("ghost-stale-confirmed", "ghost-recent"));
    await recheck(env);
    expect(spy.mock.calls.map(([url]) => String(url)).sort()).toEqual([`${NPM}/ghost-recent`, `${NPM}/ghost-stale-confirmed`]);
  });

  it("asks only the registry, four names at a time", async () => {
    const names = Array.from({ length: 10 }, (_, i) => `ghost-${i}`);
    for (const name of names) await watched(name);
    let running = 0;
    let peak = 0;
    const spy = vi.spyOn(globalThis, "fetch").mockImplementation(async () => {
      peak = Math.max(peak, ++running);
      await new Promise((resolve) => setTimeout(resolve, 5));
      running--;
      return new Response(null, { status: 404 });
    });
    await recheck(env);
    expect(peak).toBe(4);
    expect(spy.mock.calls.map(([url]) => String(url)).sort()).toEqual(names.map((n) => `${NPM}/${n}`).sort());
  });

  it("a name registered since is marked with its creation date and its cached answer dropped", async () => {
    await watched("ghost-taken");
    await env.CACHE.put("res:npm:ghost-taken", "{}");
    // A young package: lookup() would also ask the downloads API, which is not routed here.
    fakeFetch(record("ghost-taken", 3));
    const now = Date.now();
    await recheck(env, now);
    const r = await row("ghost-taken");
    expect(r.status).toBe("registered");
    expect(Math.abs(r.registered_at! - (now - 3 * DAY_MS))).toBeLessThan(5_000);
    expect(r.checked_at).toBe(now);
    expect(await env.CACHE.get("res:npm:ghost-taken")).toBeNull();
  });

  it("a pypi name and an oversized npm record count as registered", async () => {
    const created = daysAgo(4);
    await watched("ghost-py", { ecosystem: "pypi" });
    await watched("ghost-huge");
    fakeFetch({
      ...pypiPackage("ghost-py", { created }),
      [`${NPM}/ghost-huge`]: () => new Response("x".repeat(4 * 1024 * 1024 + 1)),
    });
    await recheck(env);
    expect(await row("ghost-py")).toMatchObject({ status: "registered", registered_at: Date.parse(created) });
    expect(await row("ghost-huge")).toMatchObject({ status: "registered", registered_at: null });
  });

  it("a name that still doesn't exist only moves its check time", async () => {
    await watched("ghost-gone");
    await watched("ghost-unpublished");
    fakeFetch({ ...missing("ghost-gone"), [`${NPM}/ghost-unpublished`]: json({ name: "ghost-unpublished", time: { unpublished: {} } }) });
    const before = await rows();
    const now = Date.now();
    await recheck(env, now);
    for (const [i, r] of (await rows()).entries()) expect(r).toEqual({ ...before[i], checked_at: now });
  });

  it("a registry failure leaves the name untouched and the run goes on", async () => {
    await watched("ghost-limited");
    await watched("ghost-down");
    await watched("ghost-taken");
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    fakeFetch({ [`${NPM}/ghost-limited`]: status(429), [`${NPM}/ghost-down`]: status(503), ...record("ghost-taken", 1) });
    const before = await rows();
    await recheck(env);
    const after = await rows();
    expect(after.find((r) => r.name === "ghost-limited")).toEqual(before.find((r) => r.name === "ghost-limited"));
    expect(after.find((r) => r.name === "ghost-down")).toEqual(before.find((r) => r.name === "ghost-down"));
    expect(after.find((r) => r.name === "ghost-taken")!.status).toBe("registered");
    expect(errors.mock.calls.flat().join(" ")).toMatch(/ghost-limited.*rate limited/);
  });

  it("a broken database or cache never crashes the run", async () => {
    await watched("ghost-taken");
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    fakeFetch(record("ghost-taken", 1));
    vi.spyOn(env.CACHE, "delete").mockRejectedValue(new Error("kv down"));
    await expect(recheck(env)).resolves.toBeUndefined();
    expect((await row("ghost-taken")).status).toBe("registered");

    await watched("ghost-later");
    const before = await rows();
    vi.spyOn(env.DB, "batch").mockRejectedValue(new Error("d1 down"));
    fakeFetch(record("ghost-later", 1));
    await expect(recheck(env)).resolves.toBeUndefined();
    expect(await rows()).toEqual(before);
    vi.spyOn(env.DB, "prepare").mockImplementation(() => {
      throw new Error("d1 down");
    });
    await expect(recheck(env)).resolves.toBeUndefined();
    const logged = errors.mock.calls.flat().join(" ");
    expect(logged).toContain("kv down");
    expect(logged).toContain("d1 down");
  });

  it("a second run changes nothing it already marked and counts nothing", async () => {
    await watched("ghost-taken");
    await watched("ghost-gone");
    fakeFetch({ ...record("ghost-taken", 2), ...missing("ghost-gone") });
    await recheck(env);
    const first = await rows();
    const now = Date.now() + 1000;
    await recheck(env, now);
    const second = await rows();
    expect(second.find((r) => r.name === "ghost-taken")).toEqual(first.find((r) => r.name === "ghost-taken"));
    expect(second.find((r) => r.name === "ghost-gone")).toEqual({ ...first.find((r) => r.name === "ghost-gone"), checked_at: now });
    expect((await env.DB.prepare("SELECT COUNT(*) AS n FROM stats").first<{ n: number }>())!.n).toBe(0);
  });

  it("forgets earlier days and old first-caller hashes", async () => {
    const today = new Date().toISOString().slice(0, 10);
    await env.DB.batch([
      env.DB.prepare("INSERT INTO daily (day, key) VALUES ('2000-01-01', 'old'), (?, 'today')").bind(today),
    ]);
    await watched("ghost-old", { confirmed: false, lastSeenDaysAgo: 31, firstCaller: "a".repeat(64), status: "registered" });
    await watched("ghost-new", { confirmed: false, lastSeenDaysAgo: 29, firstCaller: "b".repeat(64), status: "registered" });
    await recheck(env);
    expect((await env.DB.prepare("SELECT key FROM daily").all<{ key: string }>()).results).toEqual([{ key: "today" }]);
    expect((await row("ghost-old")).first_caller).toBeNull();
    expect((await row("ghost-new")).first_caller).toBe("b".repeat(64));
  });
});
