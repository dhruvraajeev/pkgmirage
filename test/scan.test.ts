import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { daysAgo, fakeFetch, npmPackage, OSV_URL, pypiPackage, status } from "./fakes";

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
    body: typeof body === "string" || body instanceof ReadableStream || body instanceof Uint8Array ? body : JSON.stringify(body),
    ...init,
    headers: { "cf-connecting-ip": `198.51.100.${++callers}`, ...init.headers },
  });

interface Report {
  summary: Record<string, number>;
  results: { name: string; verdict: string; reasons: string[]; suggestions: string[]; from?: string }[];
  skipped: { name?: string; line?: number; reason: string }[];
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
      { dependencies: { react: "^18", "lodash-old": "npm:lodash@^4", ui: "*" }, devDependencies: { "@types/node": "^20", react: "^18" } },
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
      "node_modules/": fromRegistry("empty"),
      "node_modules/x/node_modules/": fromRegistry("empty"),
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
      ["", "block", ["not a valid npm package name"]],
      ["is-number", "safe", []],
    ]);
    expect(summary).toMatchObject({ checked: 3, block: 2, safe: 1, skipped: 8 });
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
      ...npmPackage("lodash"),
      [`${NPM}/expresss`]: status(404),
      [`${NPM}/fastjson-parse-xyz`]: status(404),
    });
    const body = {
      name: "app",
      dependencies: {
        expresss: "^4.19.0",
        "fastjson-parse-xyz": "^1.0.0",
        react: "^18",
        lodash: "~4.17.21",
        "node-types": "npm:@types/node@^20",
        "../evil": "^1",
        local: "file:../local",
        lnk: "link:../lnk",
        rel: "./vendor/rel",
        home: "~/src/home",
        win: "C:\\src\\win",
        unc: "\\\\server\\share\\unc",
        packed: "vendor/packed-1.0.0.tgz",
        packed2: "packed2-1.0.0.tgz",
        ws: "workspace:*",
        gh: "github:someone/gh",
        short: "someone/short",
        gitdep: "git+https://github.com/someone/gitdep.git",
        tar: "https://evil.example/tar.tgz",
      },
      // A name in two sections counts where npm installs it from; padding around a name is ignored, as in /api/check.
      devDependencies: { " vitest ": "^4", react: "^18" },
      optionalDependencies: { fsevents: "^2" },
      peerDependencies: { "react-dom": ">=18 <20" },
    };
    // Editors on Windows may save a byte-order mark.
    const { summary, results, skipped } = await report(await scan("\uFEFF" + JSON.stringify(body)));
    expect(results.map((r) => [r.name, r.verdict, r.from])).toEqual([
      ["expresss", "block", "dependencies"],
      ["fastjson-parse-xyz", "block", "dependencies"],
      ["../evil", "block", "dependencies"],
      ["react", "safe", "dependencies"],
      ["lodash", "safe", "dependencies"],
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
      { name: "home", reason: "local file" },
      { name: "win", reason: "local file" },
      { name: "unc", reason: "local file" },
      // npm reads "dir/file.tgz" as a GitHub shortcut, and so does the scan.
      { name: "packed", reason: "git source" },
      { name: "packed2", reason: "local file" },
      { name: "ws", reason: "workspace link" },
      { name: "gh", reason: "git source" },
      { name: "short", reason: "git source" },
      { name: "gitdep", reason: "git source" },
      { name: "tar", reason: "not from registry.npmjs.org" },
    ]);
    expect(summary).toEqual({ checked: 9, block: 3, caution: 0, safe: 6, unverified: 0, skipped: 13 });
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
    // Registry details stay in /api/check; a report carries what to act on.
    expect(results[1]).toEqual({
      name: "young-pkg",
      ecosystem: "npm",
      verdict: "caution",
      reasons: ["first seen 3 days ago"],
      suggestions: [],
      checkedAt: expect.any(String),
      from: "transitive",
    });
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
    await expectBadRequest(await scan({ foo: 1 }), /not a package-lock\.json or package\.json/);
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

const PYPI = "https://pypi.org/pypi";

describe("requirements scan", () => {
  it("reads every name in a compiled requirements file with hashes, extras and markers", async () => {
    const spy = fakeFetch(
      Object.assign({}, ...["django", "requests", "flask-login", "pywin32", "typing-extensions", "numpy"].map((name) => pypiPackage(name))),
    );
    const file = [
      "\uFEFF# This file was autogenerated by uv via the following command:",
      "#    uv pip compile requirements.in -o requirements.txt --generate-hashes",
      "Django==6.1.1 \\",
      "    --hash=sha256:aaaa \\",
      "    --hash=sha256:bbbb",
      "    # via -r requirements.in",
      "# a comment line never continues \\",
      'requests[socks,security] >= 2.31, <3 ; python_version >= "3.8"  # pinned below',
      "Flask_Login~=0.6",
      "flask-login==0.6.3",
      "-r \\",
      "    base.txt",
      'pywin32==306 ; sys_platform == "win32"',
      "",
      'typing_extensions (>=4.0)\rnumpy;python_version>="3.9"',
    ].join("\r\n");
    const { summary, results, skipped } = await report(await scan(file));
    expect(results.map((r) => [r.name, r.verdict])).toEqual([
      ["django", "safe"],
      ["requests", "safe"],
      ["flask-login", "safe"],
      ["pywin32", "safe"],
      ["typing-extensions", "safe"],
      ["numpy", "safe"],
    ]);
    // A requirements file doesn't say which packages are direct, so there is no `from`.
    expect(results[0]).toEqual({ name: "django", ecosystem: "pypi", verdict: "safe", reasons: [], suggestions: [], checkedAt: expect.any(String) });
    // A continued line keeps the number of its first line.
    expect(skipped).toEqual([{ line: 11, reason: "include not followed" }]);
    expect(summary).toEqual({ checked: 6, block: 0, caution: 0, safe: 6, unverified: 0, skipped: 1 });
    // One record each plus one malware lookup.
    expect(spy).toHaveBeenCalledTimes(7);
  });

  it("a typo, an invented name and a look-alike name in a requirements file are blocked", async () => {
    const spy = fakeFetch({ ...pypiPackage("numpy"), [`${PYPI}/reqeusts/json`]: status(404), [`${PYPI}/fastjson-parse-xyz/json`]: status(404) });
    // pip only reads "#" as a comment at the start of a line or after whitespace.
    const file = "reqeusts==2.0\nfastjson-parse-xyz\nrequ\u0435sts>=2\nnumpy\n==1.0\nblack#x\n";
    const { summary, results, skipped } = await report(await scan(file));
    expect(results.map((r) => [r.name, r.verdict, r.reasons])).toEqual([
      ["reqeusts", "block", ["doesn't exist on PyPI (likely hallucinated)"]],
      ["fastjson-parse-xyz", "block", ["doesn't exist on PyPI (likely hallucinated)"]],
      ["requ\u0435sts", "block", ["uses look-alike characters from another alphabet"]],
      ["black#x", "block", ["not a valid PyPI package name"]],
      ["numpy", "safe", []],
    ]);
    expect(results[0]!.suggestions).toContain("requests");
    expect(skipped).toEqual([{ line: 5, reason: "not a requirement" }]);
    expect(summary).toMatchObject({ checked: 5, block: 4, safe: 1, skipped: 1 });
    expect(spy.mock.calls.map(([url]) => String(url)).some((url) => url.includes("requ\u0435sts") || url.includes("%D0"))).toBe(false);
  });

  it("skips includes, options, links and local paths without fetching or echoing them", async () => {
    const spy = fakeFetch(pypiPackage("requests"));
    const lines = [
      ["-r base-secret.txt", "include not followed"],
      ["--requirement=dev-secret.txt", "include not followed"],
      ["-c constraints-secret.txt", "include not followed"],
      ["-cconstraints-secret.txt", "include not followed"],
      ["--constraint constraints-secret.txt", "include not followed"],
      ["-e git+https://github.com/someone/proj.git#egg=proj", "editable install"],
      ["--editable ./local-secret", "editable install"],
      ["--index-url https://user:secret@evil.example/simple", "pip option, ignored"],
      ["--extra-index-url https://evil.example/simple", "pip option, ignored"],
      ["-f https://evil.example/links", "pip option, ignored"],
      ["--find-links=./wheels-secret", "pip option, ignored"],
      ["--pre", "pip option, ignored"],
      ["git+https://github.com/someone/vcs.git@v1#egg=vcs", "VCS source"],
      ["hg+https://evil.example/repo", "VCS source"],
      ["https://evil.example/pkg-1.0.tar.gz", "not from pypi.org"],
      ["file:///home/me/pkg-secret", "local path"],
      ["./local-secret", "local path"],
      [".", "local path"],
      ["/abs/path/pkg-secret", "local path"],
      ["~/src/pkg-secret", "local path"],
      ["C:\\src\\pkg-secret", "local path"],
      ["vendor-secret/pkg", "local path"],
      ["pkg_secret-1.0-py3-none-any.whl", "local path"],
      ["pkg-secret-1.0.tar.gz", "local path"],
    ];
    const file = [...lines.map(([line]) => line), "My_Pkg[extra] @ https://evil.example/my_pkg-1.0.whl", "bad name!x @ https://evil.example/x", "requests"].join("\n");
    const res = await scan(file);
    const text = await res.clone().text();
    const { summary, results, skipped } = await report(res);
    expect(skipped).toEqual([
      ...lines.map(([, reason], i) => ({ line: i + 1, reason })),
      { line: 25, name: "my-pkg", reason: "not from pypi.org" },
      { line: 26, reason: "not from pypi.org" },
    ]);
    expect(results.map((r) => [r.name, r.verdict])).toEqual([["requests", "safe"]]);
    expect(summary).toMatchObject({ checked: 1, safe: 1, skipped: 26 });
    expect(spy.mock.calls.map(([url]) => String(url)).every((url) => url === `${PYPI}/requests/json` || url === OSV_URL)).toBe(true);
    expect(text).not.toMatch(/secret|evil\.example|github\.com|wheels|egg=/);
  });

  it("continued lines join like pip's, in time linear in the file", { timeout: 15_000 }, async () => {
    const spy = fakeFetch({ ...pypiPackage("requests"), ...pypiPackage("numpy") });
    // A comment line ends a continuation instead of swallowing the line after it.
    const { results } = await report(await scan("requests\\\n# pinned \\\nnumpy\n"));
    expect(results.map((r) => r.name)).toEqual(["requests", "numpy"]);
    // ~350,000 continued lines make one 350 KB name: refused as too long, without a lookup, and quickly.
    const started = Date.now();
    const { summary } = await report(await scan("a\\\n".repeat(349_000) + "a"));
    expect(summary).toMatchObject({ checked: 1, block: 1 });
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(spy).toHaveBeenCalledTimes(3);
  });

  it("the skipped list stops at 750 entries, while the summary counts them all", async () => {
    const spy = fakeFetch({});
    const { summary, skipped } = await report(await scan(".\n".repeat(5_000)));
    expect(summary).toMatchObject({ checked: 0, skipped: 5_000 });
    expect(skipped).toHaveLength(750);
    expect(skipped.at(-1)).toEqual({ line: 750, reason: "local path" });
    expect(spy).not.toHaveBeenCalled();
  });

  it("empty, binary and json-looking bodies are told apart", async () => {
    const spy = fakeFetch({});
    await expectBadRequest(await scan(""), /^empty file$/);
    await expectBadRequest(await scan(" \r\n\t\n"), /^empty file$/);
    await expectBadRequest(await scan("\uFEFF"), /^empty file$/);
    await expectBadRequest(await scan(new Uint8Array([0x72, 0x65, 0x71, 0x00, 0x73])), /^not a text file$/);
    await expectBadRequest(await scan(new Uint8Array([0x72, 0x65, 0xff, 0xfe])), /^not a text file$/);
    // Anything starting with "{" is an npm file, so a broken lockfile is still reported as broken JSON.
    await expectBadRequest(await scan("\uFEFF \n {\"lockfileVersion\": 3,"), /JSON/);
    const { summary } = await report(await scan("# only comments\n\n# and blank lines\n"));
    expect(summary).toEqual({ checked: 0, block: 0, caution: 0, safe: 0, unverified: 0, skipped: 0 });
    expect(spy).not.toHaveBeenCalled();
  });

  it("other python project files are refused with how to export a requirements file", async () => {
    const spy = fakeFetch({});
    const toml = /^this looks like pyproject\.toml, Pipfile, poetry\.lock or uv\.lock; send a requirements file instead/;
    await expectBadRequest(await scan('[project]\nname = "app"\ndependencies = ["requests"]\n'), toml);
    await expectBadRequest(await scan('# managed by hand\n[[source]]\nurl = "https://pypi.org/simple"\n\n[packages]\nrequests = "*"\n'), toml);
    await expectBadRequest(await scan('version = 1\nrequires-python = ">=3.12"\n\n[[package]]\nname = "requests"\n'), toml);
    await expectBadRequest(await scan({ _meta: { hash: { sha256: "x" } }, default: { requests: { version: "==2.32.0" } } }), /^Pipfile\.lock isn't supported/);
    expect(spy).not.toHaveBeenCalled();
  });

  it("a requirements scan is capped like an npm scan", async () => {
    const spy = fakeFetch(pypiPackage("flask-login"));
    // Names PyPI can't have are blocked without a lookup, and three spellings of one package count once.
    const names = [...Array.from({ length: 749 }, (_, i) => `_n${i}`), "Flask_Login", "flask.login", "FLASK-LOGIN"];
    const { summary } = await report(await scan(names.join("\n")));
    expect(summary).toMatchObject({ checked: 750, block: 749, safe: 1 });
    expect(spy).toHaveBeenCalledTimes(2);
    await expectBadRequest(await scan([...names, "_n749"].join("\n")), /^this project has 751 packages; a scan checks at most 750$/);
    expect(spy).toHaveBeenCalledTimes(2);
  });

  it("a requirements scan reports failures as unverified, uses the cache and the watchlist, and sights nothing", async () => {
    const seen = Date.parse(daysAgo(5));
    await env.DB.prepare(
      "INSERT INTO watch (ecosystem, name, first_seen, last_seen, sightings, source, confirmed_at, status) VALUES ('pypi', 'squat-py', ?, ?, 2, 'api', ?, 'unregistered')",
    )
      .bind(seen, seen, seen)
      .run();
    const spy = fakeFetch({
      ...pypiPackage("numpy"),
      ...pypiPackage("squat-py", { created: daysAgo(2) }),
      [`${PYPI}/ghost-py/json`]: status(404),
      [`${PYPI}/down-py/json`]: status(503),
    });
    const file = "numpy\nSquat_Py==1.0\nghost-py\ndown-py\n";
    const first = await report(await scan(file));
    expect(first.results.map((r) => [r.name, r.verdict, r.reasons[0]])).toEqual([
      ["squat-py", "block", `registered after being seen as an invented name on ${daysAgo(5).slice(0, 10)}`],
      ["ghost-py", "block", "doesn't exist on PyPI (likely hallucinated)"],
      ["down-py", "caution", "unverified: couldn't reach PyPI (server error 503)"],
      ["numpy", "safe", undefined],
    ]);
    expect(first.summary).toMatchObject({ checked: 4, block: 2, caution: 1, safe: 1, unverified: 1 });

    // Only the unverified package is looked up again.
    const calls = spy.mock.calls.length;
    const second = await report(await scan(file));
    expect(spy.mock.calls.slice(calls).map(([url]) => String(url))).toEqual([`${PYPI}/down-py/json`]);
    expect(second.results.map((r) => r.verdict)).toEqual(first.results.map((r) => r.verdict));

    await new Promise((resolve) => setTimeout(resolve, 200));
    const rows = await env.DB.prepare("SELECT (SELECT COUNT(*) FROM watch) + (SELECT COUNT(*) FROM stats) + (SELECT COUNT(*) FROM daily) AS n").first<{ n: number }>();
    expect(rows!.n).toBe(1);
  });
});
