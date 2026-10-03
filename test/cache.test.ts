import { env } from "cloudflare:test";
import { afterEach, describe, expect, it, vi } from "vitest";
import { checkPackages } from "../src/engine/check";
import { daysAgo, fakeFetch, npmPackage, OSV_URL, osv, pypiPackage, status } from "./fakes";

afterEach(async () => {
  vi.restoreAllMocks();
  const { keys } = await env.CACHE.list();
  await Promise.all(keys.map(({ name }) => env.CACHE.delete(name)));
});

const NPM = "https://registry.npmjs.org";

async function cacheTtlFor(name: string, ecosystem: "npm" | "pypi" = "npm") {
  const putSpy = vi.spyOn(env.CACHE, "put");
  await checkPackages(ecosystem, [name], env.CACHE);
  const call = putSpy.mock.calls.find(([key]) => key === `res:${ecosystem}:${name}`);
  putSpy.mockRestore();
  return call ? (call[2] as KVNamespacePutOptions).expirationTtl : undefined;
}

describe("cache", () => {
  it("a repeat check makes no requests", async () => {
    const spy = fakeFetch(npmPackage("react"));
    const [first] = await checkPackages("npm", ["react"], env.CACHE);
    const calls = spy.mock.calls.length;
    const [second] = await checkPackages("npm", ["react"], env.CACHE);
    expect(spy.mock.calls.length).toBe(calls);
    expect(second).toEqual(first);
  });

  it("each verdict gets its cache time", async () => {
    fakeFetch({
      ...npmPackage("react"),
      ...npmPackage("young-pkg", { firstSeenDaysAgo: 3 }),
      ...npmPackage("evil-pkg"),
      [OSV_URL]: osv({ "evil-pkg": ["MAL-2025-1"] }),
      [`${NPM}/nope-xyz`]: status(404),
    });
    expect(await cacheTtlFor("react")).toBe(6 * 3600);
    expect(await cacheTtlFor("young-pkg")).toBe(3600);
    expect(await cacheTtlFor("evil-pkg")).toBe(24 * 3600);
    expect(await cacheTtlFor("nope-xyz")).toBe(600);
  });

  it("unverified results are never cached", async () => {
    fakeFetch({
      [`${NPM}/down-pkg`]: status(503),
      ...npmPackage("young-pkg", { firstSeenDaysAgo: 100 }),
      "https://api.npmjs.org/downloads/range/last-year/young-pkg": status(500),
      ...pypiPackage("requests"),
    });
    await checkPackages("npm", ["down-pkg", "young-pkg", ".bad"], env.CACHE);
    vi.restoreAllMocks();
    fakeFetch({ ...pypiPackage("requests"), [OSV_URL]: status(503) });
    await checkPackages("pypi", ["requests"], env.CACHE);
    // young-pkg's archive was read, and that count is kept; its verdict isn't.
    expect((await env.CACHE.list({ prefix: "res:" })).keys).toEqual([]);
  });

  it("a broken cache never fails a check", async () => {
    fakeFetch(npmPackage("react"));
    vi.spyOn(env.CACHE, "get").mockRejectedValue(new Error("kv down"));
    vi.spyOn(env.CACHE, "put").mockRejectedValue(new Error("kv down"));
    const [result] = await checkPackages("npm", ["react"], env.CACHE);
    expect(result!.verdict).toBe("safe");
  });

  it("cached verdicts are read 100 names at a time", async () => {
    const names = Array.from({ length: 150 }, (_, i) => `pkg-${i}`);
    fakeFetch(Object.assign({}, ...names.map((name) => npmPackage(name))));
    await checkPackages("npm", names, env.CACHE);
    const get = vi.spyOn(env.CACHE, "get");
    const results = await checkPackages("npm", names, env.CACHE);
    expect(results.map((r) => r.verdict)).toEqual(names.map(() => "safe"));
    expect(get.mock.calls.map(([keys]) => (keys as string[]).length)).toEqual([100, 50]);
  });

  it("keeps the original check time on a cache hit", async () => {
    fakeFetch(pypiPackage("requests", { created: daysAgo(900) }));
    const [first] = await checkPackages("pypi", ["requests"], env.CACHE);
    await new Promise((resolve) => setTimeout(resolve, 5));
    const [second] = await checkPackages("pypi", ["requests"], env.CACHE);
    expect(second!.checkedAt).toBe(first!.checkedAt);
  });
});
