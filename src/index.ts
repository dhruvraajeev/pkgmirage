import { handleCheck, jsonError } from "./api";

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname === "/api/check") {
      return request.method === "POST" ? handleCheck(request, env.CACHE) : jsonError(405, "method not allowed", { allow: "POST" });
    }
    return jsonError(404, "not found");
  },
} satisfies ExportedHandler<Env>;
