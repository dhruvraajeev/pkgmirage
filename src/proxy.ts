import { jsonError } from "./api";
import { checkPackages } from "./engine/check";
import { USER_AGENT } from "./engine/fetch";
import { NPM_REGISTRY, npmRecordUrl } from "./engine/registry";

const AUDIT_PATH = "/-/npm/v1/security/advisories/bulk";
const RECORD = /^(?:@[^/]+\/)?[^/]+$/;
const TARBALL = /^((?:@[^/]+\/)?[^/]+)\/-\/([\w.-]+\.tgz)$/;
const UNSUPPORTED = "pkgMirage only handles installs; use https://registry.npmjs.org for anything else";

// npm is pointed here as its registry. Records and tarballs are checked by package name (installs from a lockfile
// fetch tarballs without the record), audit passes through, and everything else is refused so no npm token ever
// reaches pkgMirage's upstream requests.
export async function handleNpm(request: Request, path: string, cache: KVNamespace): Promise<Response> {
  if (path === AUDIT_PATH) {
    if (request.method !== "POST") return jsonError(405, UNSUPPORTED, { allow: "POST" });
    return forward(`${NPM_REGISTRY}${AUDIT_PATH}`, {
      method: "POST",
      headers: pick(request.headers, ["content-type", "content-encoding"]),
      body: request.body,
    });
  }

  let decoded: string;
  try {
    decoded = decodeURIComponent(path.slice(1));
  } catch {
    return jsonError(404, UNSUPPORTED);
  }
  const tarball = TARBALL.exec(decoded);
  const requested = tarball ? tarball[1]! : RECORD.test(decoded) ? decoded : null;
  if (requested === null) return jsonError(404, UNSUPPORTED);
  if (request.method !== "GET") return jsonError(405, UNSUPPORTED, { allow: "GET" });

  // A failed check comes back as a caution, so only a definite block stops the install.
  const [result] = await checkPackages("npm", [requested], cache);
  const { name, verdict, reasons } = result!;
  if (verdict === "block") return jsonError(403, `pkgMirage blocked ${name}: ${reasons.join("; ")}`);

  const url = tarball ? `${NPM_REGISTRY}/${name}/-/${tarball[2]}` : npmRecordUrl(name);
  return forward(url, { headers: pick(request.headers, ["accept"]) });
}

// Bodies are streamed, never parsed: records reach 39 MB and tarballs are binary.
async function forward(url: string, init: RequestInit & { headers: Record<string, string> }): Promise<Response> {
  let res: Response;
  try {
    res = await fetch(url, { ...init, headers: { ...init.headers, "user-agent": USER_AGENT }, redirect: "manual" });
  } catch {
    return jsonError(502, "couldn't reach the npm registry");
  }
  return new Response(res.body, { status: res.status, headers: pick(res.headers, ["content-type"]) });
}

function pick(headers: Headers, names: string[]): Record<string, string> {
  return Object.fromEntries(names.flatMap((n) => (headers.has(n) ? [[n, headers.get(n)!]] : [])));
}
