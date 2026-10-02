import { handleCheck, jsonError } from "./api";
import { caller, recheck } from "./engine/watch";
import { handleMcp } from "./mcp";
import { handleNpm } from "./proxy";
import { handleScan } from "./scan";

// The windows of the rate limits in wrangler.jsonc, for Retry-After.
const NPM_WINDOW_SECONDS = 10;
const CHECK_WINDOW_SECONDS = 60;
const SCAN_WINDOW_SECONDS = 60;
// Every response is JSON or a proxied npm file, never a page: nothing may sniff, frame or load from it.
const SECURITY_HEADERS = {
  "x-content-type-options": "nosniff",
  "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
  "referrer-policy": "no-referrer",
};

export default {
  async fetch(request, env) {
    let res: Response;
    try {
      res = await route(request, env);
    } catch (error) {
      // Clients get no internals; Workers Logs get the details.
      console.error("unhandled error", request.method, new URL(request.url).pathname, error);
      res = jsonError(500, "internal error");
    }
    for (const [name, value] of Object.entries(SECURITY_HEADERS)) res.headers.set(name, value);
    return res;
  },
  async scheduled(_controller, env) {
    await recheck(env);
  },
} satisfies ExportedHandler<Env>;

async function route(request: Request, env: Env): Promise<Response> {
  const { pathname } = new URL(request.url);

  if (pathname.startsWith("/npm/")) {
    if (await overLimit(env.NPM_LIMIT, request)) {
      const message = rateLimited(NPM_WINDOW_SECONDS);
      return jsonError(429, message, { "retry-after": `${NPM_WINDOW_SECONDS}`, "npm-notice": message });
    }
    return handleNpm(request, pathname.slice("/npm".length), env);
  }

  // A scan can mean up to 750 lookups, so scans get their own, much smaller budget.
  if (pathname === "/api/scan") {
    if (await overLimit(env.SCAN_LIMIT, request)) {
      return jsonError(429, rateLimited(SCAN_WINDOW_SECONDS), { "retry-after": `${SCAN_WINDOW_SECONDS}` });
    }
    return request.method === "POST" ? handleScan(request, env) : jsonError(405, "method not allowed", { allow: "POST" });
  }

  // Each API call or MCP call can mean up to 50 lookups, so they share one, tighter budget.
  const isMcp = pathname === "/mcp";
  if ((isMcp || pathname.startsWith("/api/")) && (await overLimit(env.CHECK_LIMIT, request))) {
    const message = rateLimited(CHECK_WINDOW_SECONDS);
    const headers = { "retry-after": `${CHECK_WINDOW_SECONDS}` };
    // MCP clients read errors as JSON-RPC; this is the shape the SDK uses for its own HTTP-level errors.
    return isMcp
      ? Response.json({ jsonrpc: "2.0", error: { code: -32000, message }, id: null }, { status: 429, headers })
      : jsonError(429, message, headers);
  }
  if (isMcp) {
    const res = await handleMcp(request);
    if (res.status === 405) res.headers.set("allow", "POST");
    return res;
  }
  if (pathname === "/api/check") {
    return request.method === "POST" ? handleCheck(request, env) : jsonError(405, "method not allowed", { allow: "POST" });
  }
  return jsonError(404, "not found");
}

const rateLimited = (seconds: number) => `pkgMirage rate limit exceeded; try again in ${seconds} seconds`;

// Note: the binding counts per Cloudflare location and is eventually consistent, so a burst can overshoot a little.
async function overLimit(limiter: RateLimit, request: Request): Promise<boolean> {
  try {
    return !(await limiter.limit({ key: caller(request.headers.get("cf-connecting-ip")) })).success;
  } catch (error) {
    // The limit protects pkgMirage and isn't a verdict, so a limiter outage lets requests through.
    console.error("rate limiter unavailable", error);
    return false;
  }
}
