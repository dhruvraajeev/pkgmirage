import { afterEach, describe, expect, it, vi } from "vitest";
import { fetchJson } from "../src/engine/fetch";
import { fakeFetch, json, status } from "./fakes";

const PYPI_URL = "https://pypi.org/pypi/requests/json";

afterEach(() => {
  vi.restoreAllMocks();
  vi.useRealTimers();
});

describe("fetch", () => {
  it("refuses hosts outside the allowlist", async () => {
    const spy = fakeFetch({});
    for (const url of ["https://example.com/x", "http://pypi.org/pypi/x/json", "https://pypi.org.evil.com/x", "https://user@evil.com/"]) {
      await expect(fetchJson(url), url).rejects.toThrow(/not allowed/);
    }
    expect(spy).not.toHaveBeenCalled();
  });

  it("returns parsed JSON on 200", async () => {
    fakeFetch({ [PYPI_URL]: json({ info: { name: "requests" } }) });
    expect(await fetchJson(PYPI_URL)).toEqual({ status: "ok", data: { info: { name: "requests" } } });
  });

  it("maps only 404 to not_found", async () => {
    fakeFetch({ [PYPI_URL]: status(404) });
    expect(await fetchJson(PYPI_URL)).toEqual({ status: "not_found" });

    for (const code of [400, 403, 410]) {
      vi.restoreAllMocks();
      fakeFetch({ [PYPI_URL]: status(code) });
      expect(await fetchJson(PYPI_URL)).toEqual({ status: "error", reason: `unexpected status ${code}` });
    }
  });

  it("maps timeouts, rate limits, server errors and redirects to errors", async () => {
    const cases: [() => Response | Promise<Response>, string][] = [
      [status(429), "rate limited"],
      [status(500), "server error 500"],
      [status(503), "server error 503"],
      [() => new Response(null, { status: 301, headers: { location: "https://evil.com/" } }), "unexpected redirect"],
      [() => Promise.reject(new DOMException("The operation was aborted due to timeout", "TimeoutError")), "timed out"],
    ];
    for (const [route, reason] of cases) {
      vi.restoreAllMocks();
      fakeFetch({ [PYPI_URL]: route });
      expect(await fetchJson(PYPI_URL)).toEqual({ status: "error", reason });
    }
  });

  it("times out a hanging request after 5 seconds", async () => {
    let signal: AbortSignal | undefined;
    vi.spyOn(globalThis, "fetch").mockImplementation((_input, init) => {
      signal = init?.signal ?? undefined;
      return new Promise((_, reject) => signal?.addEventListener("abort", () => reject(signal?.reason)));
    });
    const started = Date.now();
    expect(await fetchJson(PYPI_URL)).toEqual({ status: "error", reason: "timed out" });
    expect(Date.now() - started).toBeGreaterThanOrEqual(4_900);
  }, 10_000);

  it("maps invalid JSON and network failures to errors", async () => {
    fakeFetch({ [PYPI_URL]: () => new Response("<html>oops</html>", { status: 200 }) });
    expect(await fetchJson(PYPI_URL)).toEqual({ status: "error", reason: "invalid JSON" });

    vi.restoreAllMocks();
    fakeFetch({ [PYPI_URL]: () => Promise.reject(new TypeError("Network connection lost.")) });
    expect(await fetchJson(PYPI_URL)).toEqual({ status: "error", reason: "network error" });
  });

  it("rejects responses over the size cap", async () => {
    const big = JSON.stringify({ pad: "x".repeat(2_000) });

    fakeFetch({ [PYPI_URL]: () => new Response(big, { headers: { "content-length": String(big.length) } }) });
    expect(await fetchJson(PYPI_URL, { maxBytes: 1_000 })).toEqual({ status: "error", reason: "response too large" });

    // No Content-Length: the cap must still hold while streaming.
    vi.restoreAllMocks();
    fakeFetch({ [PYPI_URL]: () => new Response(new Blob([big]).stream()) });
    expect(await fetchJson(PYPI_URL, { maxBytes: 1_000 })).toEqual({ status: "error", reason: "response too large" });

    vi.restoreAllMocks();
    fakeFetch({ [PYPI_URL]: () => new Response(big) });
    expect(await fetchJson(PYPI_URL, { maxBytes: 10_000 })).toMatchObject({ status: "ok" });
  });

  it("sends a user agent and does not follow redirects", async () => {
    const spy = fakeFetch({ [PYPI_URL]: json({}) });
    await fetchJson(PYPI_URL);
    const init = spy.mock.calls[0]?.[1];
    expect(new Headers(init?.headers).get("user-agent")).toMatch(/^pkgmirage\//);
    expect(init?.redirect).toBe("manual");
    expect(init?.signal).toBeInstanceOf(AbortSignal);
  });
});
