import { env } from "cloudflare:test";
import { describe, expect, it } from "vitest";

// The platform serves page files before the Worker runs, so the Worker's own fetch never sees them; the ASSETS binding
// serves the same files with the same _headers rules.
const page = (path: string, init?: RequestInit) => env.ASSETS.fetch(`http://localhost${path}`, { redirect: "manual", ...init });

const PAGE_HEADERS = {
  "content-security-policy":
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; " +
    "form-action 'none'; frame-ancestors 'none'; require-trusted-types-for 'script'; trusted-types 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
};

function expectPageHeaders(res: Response) {
  for (const [name, value] of Object.entries(PAGE_HEADERS)) expect([name, res.headers.get(name)]).toEqual([name, value]);
}

describe("web", () => {
  it("serves the page and its files with the page's security headers", async () => {
    const files: [string, string][] = [
      ["/", "text/html"],
      ["/app.js", "javascript"],
      ["/style.css", "text/css"],
      ["/favicon.svg", "image/svg+xml"],
    ];
    for (const [path, type] of files) {
      const res = await page(path);
      expect([path, res.status]).toEqual([path, 200]);
      expect(res.headers.get("content-type")).toContain(type);
      expectPageHeaders(res);
    }
    const html = await (await page("/")).text();
    expect(html).toContain('<script src="/app.js" defer></script>');
    // A revalidated page keeps its headers too.
    const etag = (await page("/")).headers.get("etag")!;
    const revalidated = await page("/", { headers: { "if-none-match": etag } });
    expect(revalidated.status).toBe(304);
    expectPageHeaders(revalidated);
    // The headers file itself is never served.
    expect((await page("/_headers")).status).toBe(404);
  });

  it("answers head, refuses other methods and redirects /index.html", async () => {
    const head = await page("/", { method: "HEAD" });
    expect(head.status).toBe(200);
    expect(await head.text()).toBe("");
    expectPageHeaders(head);
    for (const method of ["OPTIONS", "POST", "PUT", "DELETE"]) {
      const res = await page("/", { method, headers: { origin: "https://elsewhere.example", "access-control-request-method": "POST" } });
      expect([method, res.status, await res.text()]).toEqual([method, 405, ""]);
      expect([...res.headers.keys()].filter((name) => name.startsWith("access-control-"))).toEqual([]);
      expectPageHeaders(res);
    }
    const index = await page("/index.html");
    expect(index.status).toBe(307);
    expect(index.headers.get("location")).toBe("/");
    expectPageHeaders(index);
  });

  it("the page builds no markup from data and calls only /api/check", async () => {
    const text = async (path: string) => (await page(path)).text();
    const [html, js, css] = await Promise.all([text("/"), text("/app.js"), text("/style.css")]);
    for (const code of [html, js]) expect(code).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/);
    expect(html).not.toMatch(/<[^>]*\son[a-z]+\s*=/i);
    expect(js).not.toMatch(/setAttribute\(\s*["'`]on/i);
    // Every script and stylesheet is a same-origin file, and nothing inline.
    expect(html.match(/<script[^>]*>/g)).toEqual(['<script src="/app.js" defer>']);
    expect(html).not.toMatch(/<style|\sstyle=/i);
    expect(html.match(/(?:src|href)="[^"]*"/g)).toEqual(['href="/favicon.svg"', 'href="/style.css"', 'src="/app.js"']);
    // Nothing on another origin, and one request: a POST to /api/check.
    for (const code of [html, js, css]) expect(code).not.toMatch(/\/\/[a-z0-9-]+\.|url\(|@import/i);
    expect(js.match(/fetch\([^,)]*/g)).toEqual(['fetch("/api/check"']);
    expect(js).not.toMatch(/XMLHttpRequest|WebSocket|EventSource|sendBeacon|import\(/);
  });
});
