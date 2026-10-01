import { jsonError } from "./api";
import { checkPackages } from "./engine/check";
import { USER_AGENT } from "./engine/fetch";
import { NPM_REGISTRY, npmRecordUrl } from "./engine/registry";

const AUDIT_PATH = "/-/npm/v1/security/advisories/bulk";
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
    const headers = pick(request.headers, ["content-type", "content-encoding"]);
    return forward(`${NPM_REGISTRY}${AUDIT_PATH}`, { method: "POST", headers, body: request.body });
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
  const { name, verdict, reasons } = result!;
  if (verdict === "block") return jsonError(403, `pkgMirage blocked ${name}: ${reasons.join("; ")}`);

  const url = file ? `${NPM_REGISTRY}/${name}/-/${file}` : npmRecordUrl(name);
  return forward(url, { headers: pick(request.headers, REQUEST_HEADERS) });
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
