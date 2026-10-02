import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import * as engine from "../src/engine/check";
import { fakeFetch, mcp, npmPackage, rpcAnswer, status } from "./fakes";

afterEach(async () => {
  vi.restoreAllMocks();
  const { keys } = await env.CACHE.list();
  await Promise.all(keys.map(({ name }) => env.CACHE.delete(name)));
});

// Note: the pool keeps rate-limit counters per test file, and requests without an IP share one caller, so a file
// that sends more than 60 API/MCP requests a minute without an IP would start getting 429s.
const NPM = "https://registry.npmjs.org";
const AUDIT_PATH = "/-/npm/v1/security/advisories/bulk";
const KIB = 1024;

const send = (path: string, init: RequestInit = {}, ip?: string) => {
  const headers = new Headers(init.headers);
  if (ip) headers.set("cf-connecting-ip", ip);
  return exports.default.fetch(`http://localhost${path}`, { ...init, headers });
};
const check = (body: BodyInit, ip?: string) =>
  send("/api/check", { method: "POST", headers: { "content-type": "application/json" }, body }, ip);
const checkJson = (body: unknown, ip?: string) => check(JSON.stringify(body), ip);

// Windows are aligned to the clock; start a burst early in one so it can't straddle two. Waiting can take up to
// `needMs`, so tests that call this get a longer timeout.
async function startOfWindow(periodSeconds: number, needMs: number) {
  const left = periodSeconds * 1000 - (Date.now() % (periodSeconds * 1000));
  if (left < needMs) await new Promise((resolve) => setTimeout(resolve, left + 50));
}

async function burst(limiter: RateLimit, key: string, count: number) {
  const outcomes = [];
  for (let i = 0; i < count; i++) outcomes.push((await limiter.limit({ key })).success);
  return outcomes;
}

// A slow machine can take longer than any head start in a window, so a burst that straddled two windows is repeated
// under a fresh key, from the start of a window: two tries at most for any burst shorter than the window.
async function burstInOneWindow(limiter: RateLimit, periodSeconds: number, key: string, count: number) {
  const ms = periodSeconds * 1000;
  for (let attempt = 0; ; attempt++) {
    const start = Math.floor(Date.now() / ms);
    const outcomes = await burst(limiter, `${key}#${attempt}`, count);
    if (Math.floor(Date.now() / ms) === start) return outcomes;
    await new Promise((resolve) => setTimeout(resolve, ms - (Date.now() % ms) + 50));
  }
}

// A body that never ends, counting how much of it was read (nothing is pulled until someone reads).
function endless() {
  let chunks = 0;
  const body = new ReadableStream<Uint8Array>(
    {
      pull(controller) {
        chunks++;
        controller.enqueue(new Uint8Array(16 * KIB).fill(0x20));
      },
    },
    { highWaterMark: 0 },
  );
  return { body, chunksRead: () => chunks };
}

// A valid /api/check body padded with JSON whitespace to exactly `bytes` bytes.
const paddedCheck = (bytes: number) => {
  const json = JSON.stringify({ ecosystem: "npm", names: ["react"] });
  return json + " ".repeat(bytes - json.length);
};

const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
};

describe("protect", () => {
  it("the configured limits allow a normal install and stop a flood", async () => {
    const npm = await burstInOneWindow(env.NPM_LIMIT, 10, "198.51.100.1", 1001);
    expect(npm.slice(0, 1000).every(Boolean)).toBe(true);
    expect(npm[1000]).toBe(false);

    for (const limiter of [env.CHECK_LIMIT, env.STATS_LIMIT]) {
      const calls = await burstInOneWindow(limiter, 60, "198.51.100.1", 61);
      expect(calls.slice(0, 60).every(Boolean)).toBe(true);
      expect(calls[60]).toBe(false);
    }
  }, 60_000);

  it("api and mcp share one limit, npm has its own", async () => {
    fakeFetch(npmPackage("react"));
    const ip = "198.51.100.2";
    await startOfWindow(60, 5_000);
    await burst(env.CHECK_LIMIT, ip, 60);
    expect((await checkJson({ ecosystem: "npm", names: ["react"] }, ip)).status).toBe(429);
    expect((await mcp("tools/list", {}, "legacy", { "cf-connecting-ip": ip })).status).toBe(429);
    expect((await send("/npm/react", {}, ip)).status).toBe(200);
    expect((await checkJson({ ecosystem: "npm", names: ["react"] }, "198.51.100.3")).status).toBe(200);
  }, 30_000);

  it("keys callers by IPv4 address and IPv6 /64", async () => {
    const limit = vi.spyOn(env.CHECK_LIMIT, "limit");
    const cases: [string | undefined, string][] = [
      ["203.0.113.7", "203.0.113.7"],
      ["2001:db8:1:2:aaaa::1", "2001:db8:1:2::/64"],
      ["2001:0DB8:0001:0002:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"],
      ["2001:db8::1", "2001:db8:0:0::/64"],
      ["2001:db8::1:2:3:4", "2001:db8:0:0::/64"],
      ["::1", "0:0:0:0::/64"],
      ["::ffff:198.51.100.4", "198.51.100.4"],
      [undefined, "unknown"],
    ];
    for (const [ip, key] of cases) {
      limit.mockClear();
      await check("{", ip);
      expect(limit).toHaveBeenCalledWith({ key });
    }
  });

  it("a limited request gets a 429 each front door understands", async () => {
    const spy = fakeFetch({});
    vi.spyOn(env.CHECK_LIMIT, "limit").mockResolvedValue({ success: false });
    vi.spyOn(env.NPM_LIMIT, "limit").mockResolvedValue({ success: false });

    const api = await checkJson({ ecosystem: "npm", names: ["react"] });
    expect(api.status).toBe(429);
    expect(api.headers.get("retry-after")).toBe("60");
    expect(await api.json()).toEqual({ error: "pkgMirage rate limit exceeded; try again in 60 seconds" });

    const npmMessage = "pkgMirage rate limit exceeded; try again in 10 seconds";
    for (const [path, init] of [["/npm/react", {}], [`/npm${AUDIT_PATH}`, { method: "POST", body: "{}" }]] as const) {
      const npm = await send(path, init);
      expect(npm.status).toBe(429);
      expect(npm.headers.get("retry-after")).toBe("10");
      expect(npm.headers.get("npm-notice")).toBe(npmMessage);
      expect(await npm.json()).toEqual({ error: npmMessage });
    }

    const res = await mcp("tools/call", { name: "check_package", arguments: { ecosystem: "npm", name: "react" } }, "modern");
    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBe("60");
    expect(await res.json()).toEqual({
      jsonrpc: "2.0",
      error: { code: -32000, message: "pkgMirage rate limit exceeded; try again in 60 seconds" },
      id: null,
    });
    expect(spy).not.toHaveBeenCalled();
  });

  it("a failing rate limiter lets requests through", async () => {
    fakeFetch(npmPackage("react"));
    vi.spyOn(env.CHECK_LIMIT, "limit").mockRejectedValue(new Error("limiter down"));
    vi.spyOn(env.NPM_LIMIT, "limit").mockRejectedValue(new Error("limiter down"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    expect((await checkJson({ ecosystem: "npm", names: ["react"] })).status).toBe(200);
    expect((await send("/npm/react")).status).toBe(200);
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/rate limiter/), expect.objectContaining({ message: "limiter down" }));
  });

  it("oversized bodies are refused without being read to the end", async () => {
    const spy = fakeFetch({});
    const tooLarge = { error: "request body too large" };

    const api = endless();
    const apiRes = await check(api.body);
    expect(apiRes.status).toBe(413);
    expect(await apiRes.json()).toEqual(tooLarge);
    expect(api.chunksRead()).toBeLessThan(10);

    // A declared length over the cap is refused on the header alone: this body is tiny (and not JSON).
    const declared = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("{"));
        controller.close();
      },
    });
    const declaredRes = await send("/api/check", {
      method: "POST",
      headers: { "content-type": "application/json", "content-length": String(64 * KIB + 1) },
      body: declared,
    });
    expect(declaredRes.status).toBe(413);

    const audit = endless();
    const auditRes = await send(`/npm${AUDIT_PATH}`, { method: "POST", headers: { "content-encoding": "gzip" }, body: audit.body });
    expect(auditRes.status).toBe(413);
    expect(await auditRes.json()).toEqual(tooLarge);
    expect(audit.chunksRead()).toBeLessThan(70);
    expect((await send(`/npm${AUDIT_PATH}`, { method: "POST", body: new Uint8Array(1024 * KIB + 1) })).status).toBe(413);

    const tools = endless();
    const mcpRes = await send("/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json, text/event-stream" },
      body: tools.body,
    });
    expect(mcpRes.status).toBe(413);
    expect(tools.chunksRead()).toBeLessThan(10);

    expect(spy).not.toHaveBeenCalled();
  });

  it("the largest valid requests fit under the caps", async () => {
    let forwarded: Uint8Array | undefined;
    let encoding: string | null = null;
    fakeFetch({
      ...npmPackage("react"),
      [`${NPM}${AUDIT_PATH}`]: (body, init) => {
        forwarded = body as Uint8Array;
        encoding = new Headers(init?.headers).get("content-encoding");
        return Response.json({});
      },
    });
    expect((await check(paddedCheck(64 * KIB))).status).toBe(200);
    expect((await check(paddedCheck(64 * KIB + 1))).status).toBe(413);

    // 50 names of 214 three-byte characters: rejected names, so no lookups, but every one must arrive.
    const names = Array.from({ length: 50 }, (_, i) => `${i}`.padEnd(214, "あ"));
    const body = JSON.stringify({ ecosystem: "npm", names });
    expect(new TextEncoder().encode(body).length).toBeGreaterThan(32_000);
    const res = await check(body);
    expect(res.status).toBe(200);
    expect((await res.json<{ results: unknown[] }>()).results).toHaveLength(50);

    const tool = await rpcAnswer(await mcp("tools/call", { name: "check_packages", arguments: { ecosystem: "npm", names } }));
    expect((tool.result!.structuredContent as { results: unknown[] }).results).toHaveLength(50);

    const audit = new Uint8Array(1024 * KIB);
    expect((await send(`/npm${AUDIT_PATH}`, { method: "POST", headers: { "content-encoding": "gzip" }, body: audit })).status).toBe(200);
    expect(forwarded!.byteLength).toBe(1024 * KIB);
    expect(encoding).toBe("gzip");
  });

  it("mcp offers and holds no change-notification streams", async () => {
    const discover = await rpcAnswer(await mcp("server/discover", {}, "modern"));
    expect(discover.result!.capabilities).toEqual({ tools: { listChanged: false } });

    const res = await mcp("subscriptions/listen", { notifications: { toolsListChanged: true } }, "modern");
    const answer = await rpcAnswer(res);
    expect(answer.error).toMatchObject({ code: -32603 });
    expect(answer.result).toBeUndefined();
  });

  it("an internal error is a generic 500 with details only in the log", async () => {
    vi.spyOn(engine, "checkPackages").mockRejectedValue(new Error("secret detail"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    for (const res of [await checkJson({ ecosystem: "npm", names: ["react"] }), await send("/npm/react")]) {
      expect(res.status).toBe(500);
      const text = await res.text();
      expect(JSON.parse(text)).toEqual({ error: "internal error" });
      expect(text).not.toMatch(/secret/);
      for (const [name, value] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(name)).toBe(value);
    }
    expect(log).toHaveBeenCalledWith("unhandled error", "POST", "/api/check", expect.objectContaining({ message: "secret detail" }));
    expect(log).toHaveBeenCalledWith("unhandled error", "GET", "/npm/react", expect.objectContaining({ message: "secret detail" }));
  });

  it("a failing mcp tool says unverified without details", async () => {
    vi.spyOn(engine, "checkPackages").mockRejectedValue(new Error("secret detail"));
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    for (const era of ["legacy", "modern"] as const) {
      const { result } = await rpcAnswer(
        await mcp("tools/call", { name: "check_packages", arguments: { ecosystem: "npm", names: ["react", "lodash"] } }, era),
      );
      expect(result).toMatchObject({
        isError: true,
        content: [{ type: "text", text: "pkgMirage couldn't complete the check (internal error); treat these packages as unverified" }],
      });
      expect(JSON.stringify(result)).not.toMatch(/secret/);
    }
    expect(log).toHaveBeenCalledWith("mcp check failed", expect.objectContaining({ message: "secret detail" }));
  });

  it("every response carries the security headers", async () => {
    const react = npmPackage("react");
    fakeFetch({
      ...react,
      [`${NPM}/react`]: async () => {
        const record = await react[`${NPM}/react`]!();
        return new Response(record.body, { headers: { etag: '"v1"', "last-modified": "Wed, 01 Oct 2026 00:00:00 GMT" } });
      },
      ...npmPackage("my-tool", { scripts: { postinstall: "node setup.js" } }),
      [`${NPM}/fastjson-parse-xyz`]: status(404),
    });
    const responses = [
      await checkJson({ ecosystem: "npm", names: ["react"] }),
      await check("{"),
      await send("/api/check"),
      await send("/api/scan", { method: "POST", body: "{}" }),
      await send("/nope"),
      await send("/npm/react"),
      await send("/npm/my-tool"),
      await send("/npm/fastjson-parse-xyz"),
      await mcp("tools/list"),
      await send("/mcp"),
      await send("/api/stats"),
      await send("/api/stats"),
    ];
    for (const res of responses) {
      for (const [name, value] of Object.entries(SECURITY_HEADERS)) expect(res.headers.get(name)).toBe(value);
    }
    const [, , , , , safe, caution, blocked] = responses;
    expect(safe!.headers.get("etag")).toBe('"v1"');
    expect(safe!.headers.get("last-modified")).toBe("Wed, 01 Oct 2026 00:00:00 GMT");
    expect(caution!.headers.get("cache-control")).toBe("no-store");
    expect(caution!.headers.get("npm-notice")).toMatch(/^pkgMirage caution for my-tool/);
    expect(blocked!.headers.get("npm-notice")).toMatch(/^pkgMirage blocked fastjson-parse-xyz/);
  });

  it("each route refuses other methods, including HEAD and OPTIONS", async () => {
    const spy = fakeFetch({});
    const expected: [string, string, number, string | null][] = [
      ["/mcp", "GET", 405, "POST"],
      ["/mcp", "DELETE", 405, "POST"],
      ["/mcp", "OPTIONS", 405, "POST"],
      ["/mcp", "HEAD", 405, "POST"],
      ["/api/check", "OPTIONS", 405, "POST"],
      ["/api/check", "HEAD", 405, "POST"],
      ["/api/scan", "GET", 405, "POST"],
      ["/api/scan", "OPTIONS", 405, "POST"],
      ["/api/scan", "HEAD", 405, "POST"],
      ["/api/stats", "POST", 405, "GET"],
      ["/api/stats", "OPTIONS", 405, "GET"],
      ["/api/stats", "HEAD", 405, "GET"],
      ["/npm/react", "OPTIONS", 405, "GET"],
      ["/npm/react", "HEAD", 405, "GET"],
      ["/", "OPTIONS", 404, null],
    ];
    for (const [path, method, code, allow] of expected) {
      const res = await send(path, { method });
      expect([path, method, res.status, res.headers.get("allow")]).toEqual([path, method, code, allow]);
    }
    expect(spy).not.toHaveBeenCalled();
  });
});
