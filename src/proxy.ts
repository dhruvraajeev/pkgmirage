import { jsonError, readBody } from "./api";
import { checkPackages } from "./engine/check";
import { USER_AGENT } from "./engine/fetch";
import { NPM_REGISTRY, npmRecordUrl } from "./engine/registry";

const AUDIT_PATH = "/-/npm/v1/security/advisories/bulk";
// npm gzips the audit body: 9,654 bytes for a 1,175-package project, so this is room for about 100,000 packages.
const AUDIT_MAX_BYTES = 1024 * 1024;
// A record (<name>) or a tarball (<name>/-/<file>.tgz); the name may carry a scope.
const PACKAGE = /^((?:@[^/]+\/)?[^/]+)(?:\/-\/([\w.-]+\.tgz))?$/;
const UNSUPPORTED = "pkgMirage only handles installs; use https://registry.npmjs.org for anything else";
// Validators let npm revalidate a cached record with a 304 instead of downloading it again (next is 31 MB).
const REQUEST_HEADERS = ["accept", "if-none-match", "if-modified-since"];
const RESPONSE_HEADERS = ["content-type", "etag", "last-modified"];

// npm is pointed here as its registry. Records and tarballs are checked by package name (installs from a lockfile
// fetch tarballs without the record), audit passes through, and everything else is refused so no npm token ever
// reaches pkgMirage's upstream requests.
export async function handleNpm(request: Request, path: string, cache: KVNamespace): Promise<Response> {
  if (path === AUDIT_PATH && request.method === "POST") {
    const body = await readBody(request, AUDIT_MAX_BYTES);
    if (!body) return jsonError(413, "request body too large");
    const headers = pick(request.headers, ["content-type", "content-encoding"]);
    return forward(`${NPM_REGISTRY}${AUDIT_PATH}`, { method: "POST", headers, body });
  }

  let decoded: string;
  try {
    decoded = decodeURIComponent(path.slice(1));
  } catch {
    return jsonError(404, UNSUPPORTED);
  }
  const [, requested, file] = PACKAGE.exec(decoded) ?? [];
  if (!requested) return jsonError(404, UNSUPPORTED);
  if (request.method !== "GET") return jsonError(405, UNSUPPORTED, { allow: "GET" });

  // A failed check comes back as a caution, so only a definite block stops the install.
  const [result] = await checkPackages("npm", [requested], cache);
  const { name, verdict, reasons, suggestions } = result!;
  if (verdict === "block") {
    const didYouMean = suggestions.length ? `. Did you mean: ${suggestions.join(", ")}?` : "";
    const message = `pkgMirage blocked ${name}: ${reasons.join("; ")}${didYouMean}`;
    return jsonError(403, message, { "npm-notice": headerSafe(message) });
  }

  const url = file ? `${NPM_REGISTRY}/${name}/-/${file}` : npmRecordUrl(name);
  if (verdict === "safe") return forward(url, { headers: pick(request.headers, REQUEST_HEADERS) });

  // npm prints an npm-notice header only on a response it didn't replay from its own cache, so a caution is never
  // stored or revalidated (a 304 would be replayed). The body stays as npm sent it, so its ETag stays truthful.
  const res = await forward(url, { headers: pick(request.headers, ["accept"]) });
  for (const validator of ["etag", "last-modified"]) res.headers.delete(validator);
  res.headers.set("cache-control", "no-store");
  res.headers.set("npm-notice", headerSafe(`pkgMirage caution for ${name}: ${reasons.join("; ")}`));
  return res;
}

// Bodies are streamed, never parsed: records reach 39 MB and tarballs are binary.
async function forward(url: string, init: RequestInit & { headers: Record<string, string> }): Promise<Response> {
  init.headers["user-agent"] = USER_AGENT;
  let res: Response;
  try {
    res = await fetch(url, { ...init, redirect: "manual" });
  } catch {
    return jsonError(502, "couldn't reach the npm registry");
  }
  return new Response(res.body, { status: res.status, headers: pick(res.headers, RESPONSE_HEADERS) });
}

function pick(headers: Headers, names: string[]): Record<string, string> {
  return Object.fromEntries(names.flatMap((n) => (headers.has(n) ? [[n, headers.get(n)!]] : [])));
}

// Header values must be bytes; an invalid name can hold any character, so show it escaped rather than fail.
function headerSafe(text: string): string {
  return text.replace(/[^\x20-\x7e]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
