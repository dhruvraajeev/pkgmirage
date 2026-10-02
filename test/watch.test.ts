import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { checkPackages } from "../src/engine/check";
import { watchFor } from "../src/engine/watch";
import { daysAgo, fakeFetch, mcp, npmPackage, rpcAnswer, status } from "./fakes";

const NPM = "https://registry.npmjs.org";
const A = "203.0.113.7";
const B = "2001:db8:abcd:12::1";

let batches: Promise<unknown>[] = [];

beforeEach(() => {
  batches = [];
  const batch = env.DB.batch.bind(env.DB);
  vi.spyOn(env.DB, "batch").mockImplementation((statements) => {
    const running = batch(statements);
    batches.push(running);
    return running;
  });
});

afterEach(async () => {
  await settled();
  vi.restoreAllMocks();
  vi.useRealTimers();
  await env.DB.batch(["watch", "stats", "daily"].map((table) => env.DB.prepare(`DELETE FROM ${table}`)));
  const { keys } = await env.CACHE.list();
  await Promise.all(keys.map(({ name }) => env.CACHE.delete(name)));
});

// Recording runs after the response, so wait until no D1 write has started or is still running for a few ticks.
async function settled() {
  let seen = -1;
  for (let quiet = 0; quiet < 3; ) {
    await new Promise((resolve) => setTimeout(resolve, 10));
    await Promise.allSettled(batches);
    quiet = batches.length === seen ? quiet + 1 : 0;
    seen = batches.length;
  }
}

const withIp = (ip: string, init: RequestInit = {}) => ({ ...init, headers: { ...init.headers, "cf-connecting-ip": ip } });
const api = (names: string[], ip: string, ecosystem = "npm") =>
  exports.default.fetch(
    "http://localhost/api/check",
    withIp(ip, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ ecosystem, names }) }),
  );
const apiResults = async (names: string[], ip: string) =>
  ((await (await api(names, ip)).json()) as { results: { verdict: string; reasons: string[] }[] }).results;
const guard = (path: string, ip: string) => exports.default.fetch(`http://localhost/npm${path}`, withIp(ip));
const viaMcp = async (name: string, ip: string) => {
  const answer = await rpcAnswer(
    await mcp("tools/call", { name: "check_package", arguments: { ecosystem: "npm", name } }, "legacy", { "cf-connecting-ip": ip }),
  );
  return (answer.result as { content: { text: string }[] }).content[0]!.text;
};

const all = async <T>(sql: string) => (await env.DB.prepare(sql).all<T>()).results;
const watchRow = async (name: string) => (await all<Record<string, unknown>>(`SELECT * FROM watch WHERE name = '${name}'`))[0];
const statsFor = async (day: string) => (await all<Record<string, unknown>>(`SELECT * FROM stats WHERE day = '${day}'`))[0];

// A name callers already saw invented: first seen `daysAgoSeen` days ago, confirmed by a second caller unless not.
async function watched(name: string, { daysAgoSeen = 5, confirmed = true, status = "unregistered" } = {}) {
  const seen = Date.parse(daysAgo(daysAgoSeen));
  await env.DB.prepare(
    "INSERT INTO watch (ecosystem, name, first_seen, last_seen, sightings, source, confirmed_at, status) VALUES ('npm', ?, ?, ?, 2, 'api', ?, ?)",
  )
    .bind(name, seen, seen, confirmed ? seen : null, status)
    .run();
}

async function hmacHex(key: string, text: string) {
  const encoder = new TextEncoder();
  const hmac = await crypto.subtle.importKey("raw", encoder.encode(key), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", hmac, encoder.encode(text));
  return [...new Uint8Array(mac)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

describe("watchlist", () => {
  it("a missing name seen through the api, mcp or the guard is a sighting", async () => {
    fakeFetch({
      [`${NPM}/ghost-api`]: status(404),
      [`${NPM}/ghost-mcp`]: status(404),
      [`${NPM}/ghost-npm`]: status(404),
      "https://pypi.org/pypi/ghost-py/json": status(404),
    });
    await api(["ghost-api"], A);
    // PyPI names are watched in their normalized form.
    await api(["Ghost_Py"], A, "pypi");
    await viaMcp("ghost-mcp", A);
    expect((await guard("/ghost-npm", A)).status).toBe(403);
    await settled();
    const rows = await all("SELECT ecosystem, name, source, sightings, confirmed_at, status FROM watch ORDER BY name");
    expect(rows).toEqual([
      { ecosystem: "npm", name: "ghost-api", source: "api", sightings: 1, confirmed_at: null, status: "unregistered" },
      { ecosystem: "npm", name: "ghost-mcp", source: "mcp", sightings: 1, confirmed_at: null, status: "unregistered" },
      { ecosystem: "npm", name: "ghost-npm", source: "npm", sightings: 1, confirmed_at: null, status: "unregistered" },
      { ecosystem: "pypi", name: "ghost-py", source: "api", sightings: 1, confirmed_at: null, status: "unregistered" },
    ]);
  });

  it("a caller counts once per day, even in parallel or from the cache, and a second caller confirms the name", async () => {
    const spy = fakeFetch({ [`${NPM}/ghost-pkg`]: status(404) });
    await Promise.all([
      ...Array.from({ length: 5 }, () => api(["ghost-pkg"], A)),
      guard("/ghost-pkg", A),
      guard("/ghost-pkg/-/ghost-pkg-1.0.0.tgz", A),
      viaMcp("ghost-pkg", A),
    ]);
    await settled();
    const first = await watchRow("ghost-pkg");
    expect(first).toMatchObject({ sightings: 1, confirmed_at: null, first_caller: expect.stringMatching(/^[0-9a-f]{64}$/) });

    const lookups = spy.mock.calls.length;
    await api(["ghost-pkg"], B);
    expect(spy.mock.calls.length).toBe(lookups);
    await settled();
    expect(await watchRow("ghost-pkg")).toMatchObject({ sightings: 2, confirmed_at: expect.any(Number), first_caller: null });
  });

  it("the same caller on another day adds a sighting without confirming, and earlier days are forgotten", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-02T23:00:00Z"));
    fakeFetch({ [`${NPM}/ghost-pkg`]: status(404) });
    await api(["ghost-pkg"], A);
    await settled();
    const { first_caller } = (await watchRow("ghost-pkg"))!;

    vi.setSystemTime(new Date("2026-10-03T01:00:00Z"));
    await api(["ghost-pkg"], A);
    await settled();
    expect(await watchRow("ghost-pkg")).toMatchObject({ sightings: 2, confirmed_at: null, first_caller });
    expect(new Set((await all<{ day: string }>("SELECT day FROM daily")).map((r) => r.day))).toEqual(new Set(["2026-10-03"]));
  });

  it("stores no ip, only hashes keyed with the secret", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-02T12:00:00Z"));
    fakeFetch({ [`${NPM}/ghost-pkg`]: status(404) });
    await api(["ghost-pkg"], A);
    await api(["ghost-pkg"], B);
    await settled();

    const stored = JSON.stringify([await all("SELECT * FROM watch"), await all("SELECT * FROM stats"), await all("SELECT * FROM daily")]);
    for (const part of ["203.0.113", "2001:db8", "db8:abcd"]) expect(stored).not.toContain(part);
    const keys = (await all<{ key: string }>("SELECT key FROM daily")).map((r) => r.key);
    // An IPv6 caller is its /64, so any address in the same /64 is the same caller.
    expect(keys).toContain(`seen:${await hmacHex("test-sighting-key", `2026-10-02\n${A}\nnpm\nghost-pkg`)}`);
    expect(keys).toContain(`seen:${await hmacHex("test-sighting-key", "2026-10-02\n2001:db8:abcd:12::/64\nnpm\nghost-pkg")}`);
  });

  it("invalid names and unverified results are not sightings", async () => {
    fakeFetch({ [`${NPM}/flaky-pkg`]: status(503) });
    const results = await apiResults(["bad name", "flaky-pkg"], A);
    expect(results.map((r) => r.verdict)).toEqual(["block", "caution"]);
    await settled();
    expect(await all("SELECT * FROM watch")).toEqual([]);
  });

  it("without the secret key nothing is sighted and the check still answers", async () => {
    fakeFetch({ [`${NPM}/ghost-pkg`]: status(404) });
    const warn = vi.spyOn(console, "warn");
    const [result] = await checkPackages("npm", ["ghost-pkg"], env.CACHE, { db: env.DB, key: undefined, caller: A, source: "api" });
    expect(result!.verdict).toBe("block");
    await settled();
    expect(await all("SELECT * FROM watch")).toEqual([]);
    expect(warn).toHaveBeenCalledWith("SIGHTING_KEY is not set; sightings are not counted");
  });

  it("stats count each name once per day, across front doors, with its first verdict", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(new Date("2026-10-02T12:00:00Z"));
    fakeFetch({
      ...npmPackage("react"),
      ...npmPackage("my-tool", { scripts: { postinstall: "node setup.js" } }),
      [`${NPM}/ghost-pkg`]: status(404),
    });
    await api(["react", "ghost-pkg", "my-tool", "bad name"], A);
    await guard("/react", B);
    await viaMcp("ghost-pkg", B);
    await settled();
    expect(await statsFor("2026-10-02")).toEqual({ day: "2026-10-02", checks: 4, blocks: 2, cautions: 1, invented: 1 });

    vi.setSystemTime(new Date("2026-10-03T12:00:00Z"));
    await api(["react"], A);
    await settled();
    expect(await statsFor("2026-10-03")).toEqual({ day: "2026-10-03", checks: 1, blocks: 0, cautions: 0, invented: 0 });
  });

  it("a watched name registered since is blocked through every front door", async () => {
    await watched("squat-pkg");
    fakeFetch(npmPackage("squat-pkg", { firstSeenDaysAgo: 2 }));
    const reason = `registered after being seen as an invented name on ${daysAgo(5).slice(0, 10)}`;

    const [result] = await apiResults(["squat-pkg"], A);
    expect(result).toMatchObject({ verdict: "block", reasons: [reason, "first seen 2 days ago"] });
    await env.CACHE.delete("res:npm:squat-pkg");
    expect(await viaMcp("squat-pkg", A)).toBe(`squat-pkg (npm): BLOCK, do not install. ${reason}; first seen 2 days ago`);
    await env.CACHE.delete("res:npm:squat-pkg");
    const res = await guard("/squat-pkg", A);
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: `pkgMirage blocked squat-pkg: ${reason}; first seen 2 days ago` });
  });

  it("only names confirmed, not cleared and registered under 30 days ago are blocked", async () => {
    await watched("lone-pkg", { confirmed: false });
    await watched("cleared-pkg", { status: "cleared" });
    await watched("old-pkg", { daysAgoSeen: 60 });
    fakeFetch({
      ...npmPackage("lone-pkg", { firstSeenDaysAgo: 2 }),
      ...npmPackage("cleared-pkg", { firstSeenDaysAgo: 2 }),
      ...npmPackage("old-pkg", { firstSeenDaysAgo: 40 }),
    });
    expect((await apiResults(["lone-pkg", "cleared-pkg"], A)).map((r) => r.verdict)).toEqual(["caution", "caution"]);

    // A package past the window never touches the watchlist.
    const prepare = vi.spyOn(env.DB, "prepare");
    expect((await apiResults(["old-pkg"], A)).map((r) => r.verdict)).toEqual(["safe"]);
    expect(prepare.mock.calls.filter(([sql]) => sql.includes("FROM watch"))).toEqual([]);
  });

  it("a watched name is found in a batch of more than 100 young packages", async () => {
    const names = Array.from({ length: 120 }, (_, i) => `young-${i}`);
    await watched("young-110");
    fakeFetch(Object.assign({}, ...names.map((name) => npmPackage(name, { firstSeenDaysAgo: 2 }))));
    const prepare = vi.spyOn(env.DB, "prepare");
    const results = await checkPackages("npm", names, env.CACHE, watchFor(env, undefined, "api"));
    expect(results[110]).toMatchObject({ verdict: "block", reasons: [expect.stringMatching(/^registered after/), "first seen 2 days ago"] });
    expect(results.filter((r) => r.verdict === "block")).toHaveLength(1);
    // D1 allows 100 bound parameters per query.
    const reads = prepare.mock.calls.map(([sql]) => sql).filter((sql) => sql.includes("FROM watch"));
    for (const sql of reads) expect(sql.split("?").length - 1).toBeLessThanOrEqual(100);
  });

  it("a malformed caller address still gets its verdict and counts as a caller", async () => {
    fakeFetch({ [`${NPM}/ghost-pkg`]: status(404) });
    const res = await api(["ghost-pkg"], "1:2:3:4:5:6:7:8:9::1");
    expect(res.status).toBe(200);
    await settled();
    expect(await watchRow("ghost-pkg")).toMatchObject({ sightings: 1 });
  });

  it("a block for registering a watched name is cached for ten minutes", async () => {
    await watched("squat-pkg");
    fakeFetch(npmPackage("squat-pkg", { firstSeenDaysAgo: 2 }));
    const put = vi.spyOn(env.CACHE, "put");
    await api(["squat-pkg"], A);
    expect(put.mock.calls.find(([key]) => key === "res:npm:squat-pkg")?.[2]).toEqual({ expirationTtl: 600 });
  });

  it("a broken watchlist never fails or changes a check", async () => {
    await watched("squat-pkg");
    fakeFetch({ ...npmPackage("squat-pkg", { firstSeenDaysAgo: 2 }), [`${NPM}/ghost-pkg`]: status(404) });
    const error = vi.spyOn(console, "error");
    vi.spyOn(env.DB, "prepare").mockImplementation(() => {
      throw new Error("d1 down");
    });
    const res = await api(["ghost-pkg", "squat-pkg"], A);
    expect(res.status).toBe(200);
    const { results } = (await res.json()) as { results: { verdict: string; reasons: string[] }[] };
    expect(results).toMatchObject([
      { verdict: "block", reasons: ["doesn't exist on npm (likely hallucinated)"] },
      { verdict: "caution", reasons: ["first seen 2 days ago"] },
    ]);
    expect((await guard("/ghost-pkg", A)).status).toBe(403);
    expect(await viaMcp("ghost-pkg", A)).toMatch(/^ghost-pkg \(npm\): BLOCK/);
    await settled();
    expect(error.mock.calls.map(([message]) => message)).toEqual(expect.arrayContaining(["watchlist read failed", "watchlist write failed"]));
  });
});
