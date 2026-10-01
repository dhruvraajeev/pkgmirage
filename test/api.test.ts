import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeFetch, npmPackage, status } from "./fakes";

afterEach(async () => {
  vi.restoreAllMocks();
  const { keys } = await env.CACHE.list();
  await Promise.all(keys.map(({ name }) => env.CACHE.delete(name)));
});

const check = (body: unknown) =>
  exports.default.fetch("http://localhost/api/check", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });

async function expectBadRequest(res: Response, message: RegExp) {
  expect(res.status).toBe(400);
  expect(res.headers.get("content-type")).toContain("application/json");
  expect(await res.json()).toEqual({ error: expect.stringMatching(message) });
}

describe("api", () => {
  it("returns verdicts for a valid request", async () => {
    fakeFetch({ ...npmPackage("react"), ...npmPackage("@types/node") });
    const res = await check({ ecosystem: "npm", names: [" react ", "@types/node", "react"] });
    expect(res.status).toBe(200);
    const body = await res.json<{ results: { name: string; verdict: string }[] }>();
    expect(body.results.map((r) => [r.name, r.verdict])).toEqual([
      ["react", "safe"],
      ["@types/node", "safe"],
    ]);
  });

  it("repeat requests are served from the cache", async () => {
    const spy = fakeFetch(npmPackage("react"));
    await check({ ecosystem: "npm", names: ["react"] });
    const calls = spy.mock.calls.length;
    const res = await check({ ecosystem: "npm", names: ["react"] });
    expect(res.status).toBe(200);
    expect(spy.mock.calls.length).toBe(calls);
  });

  it("rejects a body that is not JSON", async () => {
    await expectBadRequest(await check("{not json"), /JSON/);
  });

  it("rejects an unknown ecosystem", async () => {
    await expectBadRequest(await check({ ecosystem: "cargo", names: ["serde"] }), /ecosystem/);
    await expectBadRequest(await check({ names: ["serde"] }), /ecosystem/);
  });

  it("rejects an empty names list", async () => {
    await expectBadRequest(await check({ ecosystem: "npm", names: [] }), /names.*at least 1/);
    await expectBadRequest(await check({ ecosystem: "npm", names: "react" }), /names/);
  });

  it("rejects more than 50 names", async () => {
    const names = Array.from({ length: 51 }, (_, i) => `pkg-${i}`);
    await expectBadRequest(await check({ ecosystem: "npm", names }), /names.*at most 50/);
  });

  it("rejects an empty or whitespace-only name", async () => {
    await expectBadRequest(await check({ ecosystem: "npm", names: ["react", ""] }), /names\.1.*empty/);
    await expectBadRequest(await check({ ecosystem: "npm", names: ["   "] }), /names\.0.*empty/);
    await expectBadRequest(await check({ ecosystem: "npm", names: [42] }), /names\.0/);
  });

  it("rejects a name longer than 214 characters", async () => {
    await expectBadRequest(await check({ ecosystem: "pypi", names: ["a".repeat(215)] }), /names\.0.*214/);
    fakeFetch({ [`https://pypi.org/pypi/${"a".repeat(214)}/json`]: status(404) });
    const ok = await check({ ecosystem: "pypi", names: ["a".repeat(214)] });
    expect(ok.status).toBe(200);
  });

  it("only accepts POST on /api/check", async () => {
    const res = await exports.default.fetch("http://localhost/api/check");
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("POST");
    expect(await res.json()).toEqual({ error: "method not allowed" });
  });

  it("returns JSON 404 for unknown paths", async () => {
    const res = await exports.default.fetch("http://localhost/nope");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "not found" });
  });
});
