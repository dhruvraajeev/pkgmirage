import { handleCheck, jsonError } from "./api";
import { handleMcp } from "./mcp";
import { handleNpm } from "./proxy";

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname === "/api/check") {
      return request.method === "POST" ? handleCheck(request, env.CACHE) : jsonError(405, "method not allowed", { allow: "POST" });
    }
    if (pathname === "/mcp") return handleMcp(request);
    if (pathname.startsWith("/npm/")) return handleNpm(request, pathname.slice("/npm".length), env.CACHE);
    return jsonError(404, "not found");
  },
} satisfies ExportedHandler<Env>;
