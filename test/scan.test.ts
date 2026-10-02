import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { daysAgo, fakeFetch, npmPackage, OSV_URL, status } from "./fakes";

afterEach(async () => {
  vi.restoreAllMocks();
  await env.DB.batch(["watch", "stats", "daily"].map((table) => env.DB.prepare(`DELETE FROM ${table}`)));
  const { keys } = await env.CACHE.list();
  await Promise.all(keys.map(({ name }) => env.CACHE.delete(name)));
});

const NPM = "https://registry.npmjs.org";
const KIB = 1024;

// Scans have a tight per-caller limit and the pool keeps its counters per file, so each request is its own caller
// unless a test says otherwise.
let callers = 0;
const scan = (body: unknown, init: RequestInit = {}) =>
  exports.default.fetch("http://localhost/api/scan", {
    method: "POST",
    body: typeof body === "string" || body instanceof ReadableStream ? body : JSON.stringify(body),
    ...init,
    headers: { "cf-connecting-ip": `198.51.100.${++callers}`, ...init.headers },
  });

interface Report {
  summary: Record<string, number>;
  results: { name: string; verdict: string; reasons: string[]; suggestions: string[]; from: string }[];
  skipped: { name: string; reason: string }[];
}
const report = async (res: Response) => {
  expect(res.status).toBe(200);
  return res.json<Report>();
};

const lockfile = (packages: Record<string, object>, root: object = {}) => ({
  name: "app",
  version: "1.0.0",
  lockfileVersion: 3,
  requires: true,
  packages: { "": { name: "app", version: "1.0.0", ...root }, ...packages },
});
const fromRegistry = (name: string, version = "1.0.0") => ({
  version,
  resolved: `${NPM}/${name}/-/${name.split("/").pop()}-${version}.tgz`,
  integrity: "sha512-AAAA",
});

async function expectBadRequest(res: Response, message: RegExp) {
  expect(res.status).toBe(400);
  expect(await res.json()).toEqual({ error: expect.stringMatching(message) });
}

describe("scan", () => {
  it("reads every registry package in a lockfile once", async () => {
    const spy = fakeFetch({
      ...npmPackage("react"),
      ...npmPackage("loose-envify"),
      ...npmPackage("@types/node"),
      ...npmPackage("lodash"),
      ...npmPackage("no-resolved"),
    });
    const body = lockfile(
      {
        "node_modules/@types/node": { ...fromRegistry("@types/node", "20.0.0"), dev: true },
        "node_modules/lodash-old": { name: "lodash", ...fromRegistry("lodash", "4.17.21") },
        "node_modules/loose-envify": fromRegistry("loose-envify"),
        "node_modules/loose-envify/node_modules/react": fromRegistry("react", "17.0.0"),
        "node_modules/no-resolved": { version: "1.0.0" },
        "node_modules/react": fromRegistry("react", "18.0.0"),
        "packages/ui": { name: "ui", version: "0.0.1" },
      },
      { dependencies: { react: "^18", "lodash-old": "npm:lodash@^4", ui: "*" }, devDependencies: { "@types/node": "^20" } },
    );
    const { summary, results, skipped } = await report(await scan(body));
    expect(results.map((r) => [r.name, r.verdict, r.from])).toEqual([
      ["@types/node", "safe", "devDependencies"],
      ["lodash", "safe", "dependencies"],
      ["loose-envify", "safe", "transitive"],
      ["react", "safe", "dependencies"],
      ["no-resolved", "safe", "transitive"],
    ]);
    expect(skipped).toEqual([]);
    expect(summary).toEqual({ checked: 5, block: 0, caution: 0, safe: 5, unverified: 0, skipped: 0 });
    // One record each (no download lookups for old packages) plus one malware lookup.
    expect(spy.mock.calls.map(([url]) => String(url)).filter((url) => url === `${NPM}/react`)).toHaveLength(1);
    expect(spy).toHaveBeenCalledTimes(6);
  });

  it("skips git, file, tarball and workspace entries without fetching them", async () => {
    const spy = fakeFetch(npmPackage("is-number"));
    const body = lockfile({
      "node_modules/git-dep": { version: "1.0.0", resolved: "git+ssh://git@github.com/someone/git-dep.git#abc123" },
      "node_modules/git-short": { version: "1.0.0", resolved: "git://github.com/someone/git-short.git" },
      "node_modules/local-dep": { version: "1.0.0", resolved: "file:../local-dep" },
      "node_modules/tar-dep": { version: "1.0.0", resolved: "https://evil.example/tar-dep.tgz" },
      "node_modules/corp-dep": { version: "1.0.0", resolved: "https://npm.corp.example/corp-dep/-/corp-dep-1.0.0.tgz" },
      "node_modules/mirror-dep": { version: "1.0.0", resolved: "https://mirror.example/registry.npmjs.org/mirror-dep/-/mirror-dep-1.0.0.tgz" },
      "node_modules/corp-dep/node_modules/git-dep": { version: "1.0.0", resolved: "git+ssh://git@github.com/someone/git-dep.git#abc123" },
      "node_modules/ui": { resolved: "packages/ui", link: true },
      "node_modules/local-folder": { resolved: "../local-folder", link: true },
      "node_modules/Bad Name": fromRegistry("bad"),
      "node_modules/is-number": fromRegistry("is-number"),
      "packages/ui": { name: "ui", version: "0.0.1" },
    });
    const res = await scan(body);
    const text = await res.clone().text();
    const { summary, results, skipped } = await report(res);
    expect(skipped).toEqual([
      { name: "git-dep", reason: "git source" },
      { name: "git-short", reason: "git source" },
      { name: "local-dep", reason: "local file" },
      { name: "tar-dep", reason: "not from registry.npmjs.org" },
      { name: "corp-dep", reason: "not from registry.npmjs.org" },
      { name: "mirror-dep", reason: "not from registry.npmjs.org" },
      { name: "ui", reason: "linked local folder" },
      { name: "local-folder", reason: "linked local folder" },
    ]);
    expect(results.map((r) => [r.name, r.verdict, r.reasons])).toEqual([
      ["Bad Name", "block", ["not a valid npm package name"]],
      ["is-number", "safe", []],
    ]);
    expect(summary).toMatchObject({ checked: 2, block: 1, safe: 1, skipped: 8 });
    const urls = spy.mock.calls.map(([url]) => String(url));
    expect(urls.every((url) => url === `${NPM}/is-number` || url === OSV_URL)).toBe(true);
    expect(text).not.toMatch(/evil\.example|corp\.example|mirror\.example|github\.com|\.\.\//);
  });

  it("checks a package.json's direct dependencies, with did-you-mean for a typo", async () => {
    const spy = fakeFetch({
      ...npmPackage("react"),
      ...npmPackage("@types/node"),
      ...npmPackage("vitest"),
      ...npmPackage("fsevents"),
      ...npmPackage("react-dom"),
      [`${NPM}/expresss`]: status(404),
      [`${NPM}/fastjson-parse-xyz`]: status(404),
    });
    const body = {
      name: "app",
      dependencies: {
        expresss: "^4.19.0",
        "fastjson-parse-xyz": "^1.0.0",
        react: "^18",
        "node-types": "npm:@types/node@^20",
        "../evil": "^1",
        local: "file:../local",
        lnk: "link:../lnk",
        rel: "./vendor/rel",
        ws: "workspace:*",
        gh: "github:someone/gh",
        short: "someone/short",
        gitdep: "git+https://github.com/someone/gitdep.git",
        tar: "https://evil.example/tar.tgz",
      },
      devDependencies: { vitest: "^4" },
      optionalDependencies: { fsevents: "^2" },
      peerDependencies: { "react-dom": ">=18 <20" },
    };
    const { summary, results, skipped } = await report(await scan(body));
    expect(results.map((r) => [r.name, r.verdict, r.from])).toEqual([
      ["expresss", "block", "dependencies"],
      ["fastjson-parse-xyz", "block", "dependencies"],
      ["../evil", "block", "dependencies"],
      ["react", "safe", "dependencies"],
      ["@types/node", "safe", "dependencies"],
      ["vitest", "safe", "devDependencies"],
      ["fsevents", "safe", "optionalDependencies"],
      ["react-dom", "safe", "peerDependencies"],
    ]);
    expect(results[0]).toMatchObject({ reasons: ["doesn't exist on npm (likely hallucinated)"], suggestions: expect.arrayContaining(["express"]) });
    expect(results[2]!.reasons).toEqual(["not a valid npm package name"]);
    expect(skipped).toEqual([
      { name: "local", reason: "local file" },
      { name: "lnk", reason: "local file" },
      { name: "rel", reason: "local file" },
      { name: "ws", reason: "workspace link" },
      { name: "gh", reason: "git source" },
      { name: "short", reason: "git source" },
      { name: "gitdep", reason: "git source" },
      { name: "tar", reason: "not from registry.npmjs.org" },
    ]);
    expect(summary).toEqual({ checked: 8, block: 3, caution: 0, safe: 5, unverified: 0, skipped: 8 });
    expect(spy.mock.calls.map(([url]) => String(url)).some((url) => url.includes("evil"))).toBe(false);
  });

  it("the report lists blocks first and says where each package came from", async () => {
    fakeFetch({
      ...npmPackage("old-pkg"),
      ...npmPackage("young-pkg", { firstSeenDaysAgo: 3 }),
      [`${NPM}/gone-pkg`]: status(404),
    });
    const body = lockfile(
      {
        "node_modules/a-parent/node_modules/old-pkg": fromRegistry("old-pkg", "0.9.0"),
        "node_modules/young-pkg": fromRegistry("young-pkg"),
        "node_modules/gone-pkg": fromRegistry("gone-pkg"),
        "node_modules/old-pkg": fromRegistry("old-pkg"),
      },
      { dependencies: { "old-pkg": "^1" }, devDependencies: { "gone-pkg": "^1" } },
    );
    const { summary, results } = await report(await scan(body));
    expect(results.map((r) => [r.name, r.verdict, r.from])).toEqual([
      ["gone-pkg", "block", "devDependencies"],
      ["young-pkg", "caution", "transitive"],
      ["old-pkg", "safe", "dependencies"],
    ]);
    expect(results[1]).toMatchObject({ reasons: ["first seen 3 days ago"], checks: { registry: { status: "found" } } });
    expect(summary).toEqual({ checked: 3, block: 1, caution: 1, safe: 1, unverified: 0, skipped: 0 });
  });

  it("a failing lookup leaves that package unverified and the scan completes", async () => {
    fakeFetch({ ...npmPackage("react"), [`${NPM}/down-pkg`]: status(503) });
    const { summary, results } = await report(await scan({ name: "app", dependencies: { react: "^18", "down-pkg": "^1" } }));
    expect(results.map((r) => [r.name, r.verdict, r.reasons])).toEqual([
      ["down-pkg", "caution", ["unverified: couldn't reach npm (server error 503)"]],
      ["react", "safe", []],
    ]);
    expect(summary).toMatchObject({ checked: 2, caution: 1, safe: 1, unverified: 1 });
  });

  it("malformed files are a 400 naming the problem", async () => {
    const spy = fakeFetch({});
    await expectBadRequest(await scan("{not json"), /JSON/);
    for (const body of ["[]", '"text"', "null", "42", { foo: 1 }]) {
      await expectBadRequest(await scan(body), /not a package-lock\.json or package\.json/);
    }
    await expectBadRequest(await scan({ lockfileVersion: "3", packages: {} }), /^lockfileVersion: /);
    await expectBadRequest(await scan({ lockfileVersion: 3 }), /^packages: /);
    await expectBadRequest(await scan({ lockfileVersion: 3, packages: [] }), /^packages: /);
    await expectBadRequest(await scan({ lockfileVersion: 3, packages: { "node_modules/a": { resolved: 5 } } }), /^packages\.node_modules\/a\.resolved: /);
    await expectBadRequest(await scan({ lockfileVersion: 3, packages: { "node_modules/a": "1.0.0" } }), /^packages\.node_modules\/a: /);
    await expectBadRequest(await scan({ lockfileVersion: 3, packages: { "": { dependencies: [] } } }), /^packages\.\.dependencies: /);
    await expectBadRequest(await scan({ name: "app", dependencies: ["react"] }), /^dependencies: /);
    await expectBadRequest(await scan({ name: "app", devDependencies: { react: 18 } }), /^devDependencies\.react: /);
    await expectBadRequest(await scan({ name: 7 }), /^name: /);
    expect(spy).not.toHaveBeenCalled();
  });

  it("a version 1 lockfile is refused with how to regenerate it", async () => {
    await expectBadRequest(
      await scan({ name: "app", lockfileVersion: 1, dependencies: { react: { version: "16.0.0" } } }),
      /^lockfile version 1 isn't supported; regenerate it with npm 7 or newer \(npm install --package-lock-only\)$/,
    );
    await expectBadRequest(await scan({ lockfileVersion: 4, packages: {} }), /^lockfile version 4 isn't supported/);
  });

  it("more than 750 names is refused before any lookup", async () => {
    const spy = fakeFetch({});
    // Names that break npm's rules are blocked without a lookup, so 750 of them make a scan with no network.
    const packages: Record<string, object> = {};
    for (let i = 0; i < 750; i++) packages[`node_modules/_n${i}`] = fromRegistry(`n${i}`);
    packages["node_modules/x/node_modules/_n0"] = fromRegistry("n0", "2.0.0");
    packages["node_modules/git-dep"] = { resolved: "git+https://github.com/someone/git-dep.git" };
    const { summary } = await report(await scan(lockfile(packages)));
    expect(summary).toMatchObject({ checked: 750, block: 750, skipped: 1 });

    packages["node_modules/_n750"] = fromRegistry("n750");
    await expectBadRequest(await scan(lockfile(packages)), /^this project has 751 packages; a scan checks at most 750$/);
    const deps = Object.fromEntries(Array.from({ length: 751 }, (_, i) => [`pkg-${i}`, "^1"]));
    await expectBadRequest(await scan({ name: "app", dependencies: deps }), /751 packages/);
    expect(spy).not.toHaveBeenCalled();
  });

  it("an oversized file is refused without being read to the end", async () => {
    const spy = fakeFetch({});
    let chunks = 0;
    const endless = new ReadableStream<Uint8Array>(
      {
        pull(controller) {
          chunks++;
          controller.enqueue(new Uint8Array(16 * KIB).fill(0x20));
        },
      },
      { highWaterMark: 0 },
    );
    const res = await scan(endless);
    expect(res.status).toBe(413);
    expect(await res.json()).toEqual({ error: "request body too large" });
    expect(chunks).toBeLessThan(70);
    // A declared length over the cap is refused on the header alone: this body is tiny.
    const declared = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("{}"));
        controller.close();
      },
    });
    expect((await scan(declared, { headers: { "content-length": String(1024 * KIB + 1) } })).status).toBe(413);

    const json = JSON.stringify({ name: "app" });
    expect((await scan(json + " ".repeat(1024 * KIB - json.length))).status).toBe(200);
    expect((await scan(json + " ".repeat(1024 * KIB - json.length + 1))).status).toBe(413);
    expect(spy).not.toHaveBeenCalled();
  });

  it("scans neither sight nor count, but still block a registered watched name", async () => {
    const seen = Date.parse(daysAgo(5));
    await env.DB.prepare(
      "INSERT INTO watch (ecosystem, name, first_seen, last_seen, sightings, source, confirmed_at, status) VALUES ('npm', 'squat-pkg', ?, ?, 2, 'api', ?, 'unregistered')",
    )
      .bind(seen, seen, seen)
      .run();
    fakeFetch({ ...npmPackage("squat-pkg", { firstSeenDaysAgo: 2 }), [`${NPM}/ghost-pkg`]: status(404) });
    const batch = vi.spyOn(env.DB, "batch");
    const { results } = await report(await scan({ name: "app", dependencies: { "squat-pkg": "^1", "ghost-pkg": "^1" } }));
    expect(results.map((r) => [r.name, r.verdict, r.reasons[0]])).toEqual([
      ["squat-pkg", "block", `registered after being seen as an invented name on ${daysAgo(5).slice(0, 10)}`],
      ["ghost-pkg", "block", "doesn't exist on npm (likely hallucinated)"],
    ]);
    // Recording would run after the response; give it time to show up.
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(batch).not.toHaveBeenCalled();
    const rows = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM watch) + (SELECT COUNT(*) FROM stats) + (SELECT COUNT(*) FROM daily) AS n").first<{ n: number }>();
    expect(rows!.n).toBe(1);
  });

  it("a repeat scan is served from the cache", async () => {
    const spy = fakeFetch({ ...npmPackage("react"), ...npmPackage("young-pkg", { firstSeenDaysAgo: 3 }) });
    const body = { name: "app", dependencies: { react: "^18", "young-pkg": "^1" } };
    const first = await report(await scan(body));
    const calls = spy.mock.calls.length;
    const second = await report(await scan(body));
    expect(spy.mock.calls.length).toBe(calls);
    expect(second).toEqual(first);
  });

  it("scans have their own limit", { timeout: 15_000 }, async () => {
    // Windows are aligned to the clock; start early in one so the burst can't straddle two.
    const left = 60_000 - (Date.now() % 60_000);
    if (left < 5_000) await new Promise((resolve) => setTimeout(resolve, left + 50));
    const ip = { "cf-connecting-ip": "203.0.113.99" };
    const shared = vi.spyOn(env.CHECK_LIMIT, "limit");
    const statuses = [];
    for (let i = 0; i < 6; i++) statuses.push((await scan({ name: "app" }, { headers: ip })).status);
    expect(statuses).toEqual([200, 200, 200, 200, 200, 429]);
    const limited = await scan({ name: "app" }, { headers: ip });
    expect(limited.headers.get("retry-after")).toBe("60");
    expect(await limited.json()).toEqual({ error: "pkgMirage rate limit exceeded; try again in 60 seconds" });
    expect(shared).not.toHaveBeenCalled();

    fakeFetch(npmPackage("react"));
    const check = await exports.default.fetch("http://localhost/api/check", {
      method: "POST",
      headers: ip,
      body: JSON.stringify({ ecosystem: "npm", names: ["react"] }),
    });
    expect(check.status).toBe(200);
  });
});
