import { env } from "cloudflare:test";
import { exports } from "cloudflare:workers";
import { afterEach, describe, expect, it, vi } from "vitest";
import { fakeFetch, npmPackage, OSV_URL, osv, status } from "./fakes";

afterEach(async () => {
  vi.restoreAllMocks();
  const { keys } = await env.CACHE.list();
  await Promise.all(keys.map(({ name }) => env.CACHE.delete(name)));
});

const NPM = "https://registry.npmjs.org";
const AUDIT_PATH = "/-/npm/v1/security/advisories/bulk";

const guard = (path: string, init?: RequestInit) => exports.default.fetch(`http://localhost/npm${path}`, init);

const tarball = (bytes: string) => () =>
  new Response(bytes, { headers: { "content-type": "application/octet-stream" } });

// Outbound requests the guard made for the client, beyond what the check itself needed.
const upstreamCalls = (spy: ReturnType<typeof fakeFetch>, url: string) => spy.mock.calls.filter(([input]) => input === url);

describe("guard", () => {
  it("passes a safe package record through", async () => {
    const spy = fakeFetch(npmPackage("react"));
    const res = await guard("/react", { headers: { accept: "application/json" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(await res.json()).toMatchObject({ name: "react", "dist-tags": { latest: "1.0.0" } });
    expect(res.headers.get("npm-notice")).toBeNull();
    expect(res.headers.get("cache-control")).toBeNull();
    const [, init] = upstreamCalls(spy, `${NPM}/react`).at(-1)!;
    expect(new Headers(init?.headers).get("accept")).toBe("application/json");
  });

  it("passes scoped records through either way they are encoded", async () => {
    fakeFetch(npmPackage("@types/node"));
    for (const path of ["/@types%2fnode", "/@types%2Fnode", "/@types/node"]) {
      const res = await guard(path);
      expect(res.status).toBe(200);
      expect(await res.json()).toMatchObject({ name: "@types/node" });
    }
  });

  it("lets npm revalidate a cached record", async () => {
    const spy = fakeFetch({
      ...npmPackage("react"),
      [`${NPM}/react`]: (_, init) =>
        new Headers(init?.headers).has("if-none-match")
          ? new Response(null, { status: 304, headers: { etag: '"v1"', "last-modified": "Wed, 01 Oct 2026 00:00:00 GMT" } })
          : npmPackage("react")[`${NPM}/react`]!(),
    });
    const res = await guard("/react", { headers: { "if-none-match": '"v1"', "if-modified-since": "Wed, 01 Oct 2026 00:00:00 GMT" } });
    expect(res.status).toBe(304);
    expect(res.headers.get("etag")).toBe('"v1"');
    expect(res.headers.get("last-modified")).toBe("Wed, 01 Oct 2026 00:00:00 GMT");
    const headers = new Headers(upstreamCalls(spy, `${NPM}/react`).at(-1)![1]?.headers);
    expect(headers.get("if-none-match")).toBe('"v1"');
    expect(headers.get("if-modified-since")).toBe("Wed, 01 Oct 2026 00:00:00 GMT");
  });

  it("never forwards credentials upstream", async () => {
    const spy = fakeFetch(npmPackage("react"));
    await guard("/react", { headers: { authorization: "Bearer npm_secret", cookie: "a=b" } });
    for (const [, init] of spy.mock.calls) {
      const headers = new Headers(init?.headers);
      expect(headers.get("authorization")).toBeNull();
      expect(headers.get("cookie")).toBeNull();
    }
  });

  it("refuses a blocked package with its reasons", async () => {
    const spy = fakeFetch({ [`${NPM}/fastjson-parse-xyz`]: status(404) });
    const res = await guard("/fastjson-parse-xyz");
    expect(res.status).toBe(403);
    const error = "pkgMirage blocked fastjson-parse-xyz: doesn't exist on npm (likely hallucinated)";
    expect(await res.json()).toEqual({ error });
    expect(res.headers.get("npm-notice")).toBe(error);
    expect(upstreamCalls(spy, `${NPM}/fastjson-parse-xyz`)).toHaveLength(1);
  });

  it("suggests the popular package for a blocked look-alike", async () => {
    fakeFetch({ [`${NPM}/expres`]: status(404) });
    const res = await guard("/expres");
    expect(res.status).toBe(403);
    const error = "pkgMirage blocked expres: doesn't exist on npm (likely hallucinated). Did you mean: express?";
    expect(await res.json()).toEqual({ error });
    expect(res.headers.get("npm-notice")).toBe(error);
  });

  it("escapes non-ASCII names in notices", async () => {
    const spy = fakeFetch({});
    const res = await guard("/re%D0%B0ct");
    expect(res.status).toBe(403);
    expect(res.headers.get("npm-notice")).toBe(
      "pkgMirage blocked re\\u0430ct: uses look-alike characters from another alphabet. Did you mean: react?",
    );
    expect(spy).not.toHaveBeenCalled();
  });

  it("warns about a caution package without changing its record", async () => {
    const pkg = npmPackage("my-tool", { scripts: { postinstall: "node setup.js" } });
    const upstream = JSON.stringify(await (await pkg[`${NPM}/my-tool`]!()).json());
    fakeFetch({
      ...pkg,
      [`${NPM}/my-tool`]: () => new Response(upstream, { headers: { "content-type": "application/json", etag: '"v1"', "last-modified": "Wed, 01 Oct 2026 00:00:00 GMT" } }),
    });
    const res = await guard("/my-tool");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe(upstream);
    expect(res.headers.get("npm-notice")).toBe("pkgMirage caution for my-tool: runs install scripts (postinstall)");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("etag")).toBeNull();
    expect(res.headers.get("last-modified")).toBeNull();
  });

  it("a caution is never revalidated from npm's cache", async () => {
    const pkg = npmPackage("my-tool", { scripts: { postinstall: "node setup.js" } });
    const spy = fakeFetch({
      ...pkg,
      // npm's registry answers a matching validator with 304; the guard must not send one for a caution.
      [`${NPM}/my-tool`]: (_, init) =>
        new Headers(init?.headers).has("if-none-match") ? new Response(null, { status: 304 }) : pkg[`${NPM}/my-tool`]!(),
    });
    const res = await guard("/my-tool", { headers: { "if-none-match": '"v1"', "if-modified-since": "Wed, 01 Oct 2026 00:00:00 GMT" } });
    expect(res.status).toBe(200);
    expect(res.headers.get("npm-notice")).toMatch(/^pkgMirage caution for my-tool/);
    const headers = new Headers(upstreamCalls(spy, `${NPM}/my-tool`).at(-1)![1]?.headers);
    expect(headers.get("if-none-match")).toBeNull();
    expect(headers.get("if-modified-since")).toBeNull();
  });

  it("warns on tarballs of caution packages", async () => {
    fakeFetch({
      ...npmPackage("my-tool", { scripts: { postinstall: "node setup.js" } }),
      [`${NPM}/my-tool/-/my-tool-1.0.0.tgz`]: tarball("tool-bytes"),
    });
    const res = await guard("/my-tool/-/my-tool-1.0.0.tgz");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("tool-bytes");
    expect(res.headers.get("npm-notice")).toBe("pkgMirage caution for my-tool: runs install scripts (postinstall)");
    expect(res.headers.get("cache-control")).toBe("no-store");
  });

  it("streams tarballs of allowed packages", async () => {
    fakeFetch({
      ...npmPackage("react"),
      ...npmPackage("@types/node"),
      [`${NPM}/react/-/react-1.0.0.tgz`]: tarball("react-bytes"),
      [`${NPM}/@types/node/-/node-1.0.0.tgz`]: tarball("node-bytes"),
    });
    const res = await guard("/react/-/react-1.0.0.tgz");
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("application/octet-stream");
    expect(await res.text()).toBe("react-bytes");
    expect(await (await guard("/@types/node/-/node-1.0.0.tgz")).text()).toBe("node-bytes");
  });

  it("refuses tarballs of blocked packages", async () => {
    const spy = fakeFetch({
      ...npmPackage("evil-pkg"),
      [OSV_URL]: osv({ "evil-pkg": ["MAL-2025-1"] }),
      [`${NPM}/evil-pkg/-/evil-pkg-1.0.0.tgz`]: tarball("payload"),
    });
    const res = await guard("/evil-pkg/-/evil-pkg-1.0.0.tgz");
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: "pkgMirage blocked evil-pkg: known malicious package (MAL-2025-1)" });
    expect(upstreamCalls(spy, `${NPM}/evil-pkg/-/evil-pkg-1.0.0.tgz`)).toHaveLength(0);
  });

  it("an unverified check lets the install through", async () => {
    fakeFetch({ ...npmPackage("react"), [OSV_URL]: status(503) });
    const res = await guard("/react");
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ name: "react" });
    expect(res.headers.get("npm-notice")).toMatch(/^pkgMirage caution for react: unverified: malware check unavailable/);
  });

  it("forwards npm audit", async () => {
    const spy = fakeFetch({ [`${NPM}${AUDIT_PATH}`]: (body) => Response.json({ echoed: body }) });
    const res = await guard(AUDIT_PATH, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer npm_secret" },
      body: JSON.stringify({ react: ["1.0.0"] }),
    });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ echoed: { react: ["1.0.0"] } });
    const headers = new Headers(spy.mock.calls[0]![1]?.headers);
    expect(headers.get("content-type")).toBe("application/json");
    expect(headers.get("authorization")).toBeNull();
  });

  it("refuses publish, login and other npm commands", async () => {
    const spy = fakeFetch({});
    const attempts: [string, RequestInit?][] = [
      ["/react", { method: "PUT", body: "{}" }],
      ["/-/user/org.couchdb.user:me", { method: "PUT", body: "{}" }],
      ["/-/whoami"],
      ["/-/v1/search?text=react"],
      ["/react/1.0.0"],
      [AUDIT_PATH],
      ["/%zz"],
    ];
    for (const [path, init] of attempts) {
      const res = await guard(path, init);
      expect([404, 405]).toContain(res.status);
      expect(await res.json()).toEqual({ error: expect.stringMatching(/only handles installs/) });
    }
    expect(spy).not.toHaveBeenCalled();
  });

  it("reports an unreachable registry as a bad gateway", async () => {
    fakeFetch({
      ...npmPackage("react"),
      [`${NPM}/react/-/react-1.0.0.tgz`]: () => {
        throw new TypeError("network down");
      },
    });
    const res = await guard("/react/-/react-1.0.0.tgz");
    expect(res.status).toBe(502);
    expect(await res.json()).toEqual({ error: expect.stringMatching(/registry/) });
  });
});
