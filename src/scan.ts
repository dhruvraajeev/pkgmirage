import { z } from "zod";
import { inputError, jsonError, readBody } from "./api";
import { checkPackages } from "./engine/check";
import { normalizeName, type Ecosystem } from "./engine/normalize";
import type { Verdict } from "./engine/score";
import { watchFor } from "./engine/watch";

// A lockfile takes ~510 bytes per package, so this fits about 2,000; the name cap below is what limits a scan.
const MAX_SCAN_BYTES = 1024 * 1024;
// Each name can cost one KV write and cached verdicts are read 100 per operation, so a cold scan of 750 names makes
// at most 758 of the 1,000 KV operations one request may make (derived from the documented limits; not measured on
// Cloudflare).
const MAX_SCAN_NAMES = 750;
const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;
const RANK: Record<Verdict, number> = { block: 0, caution: 1, safe: 2 };

// pip-style archives, which install from the file rather than from PyPI.
const ARCHIVE = /\.(?:whl|zip|tar\.gz|tgz|tar\.bz2|tar)$/i;
const NOT_REQUIREMENTS =
  "this looks like pyproject.toml, Pipfile, poetry.lock or uv.lock; send a requirements file instead " +
  "(uv export --format requirements.txt, poetry export -f requirements.txt, or pipenv requirements)";

type From = (typeof SECTIONS)[number] | "transitive";
interface Skip {
  name?: string;
  line?: number;
  reason: string;
}
interface Project {
  ecosystem: Ecosystem;
  // Where each name came from in an npm project; a requirements file doesn't say.
  names: Map<string, From | undefined>;
  // Keyed by name (npm) or by line (requirements), so each is listed once.
  skipped: Map<string, Skip>;
}

const dependencies = z.record(z.string(), z.string()).optional();
const manifest = z.object({
  name: z.string().optional(),
  dependencies,
  devDependencies: dependencies,
  optionalDependencies: dependencies,
  peerDependencies: dependencies,
});
const lockfileVersion = z.object({ lockfileVersion: z.number() });
const lockfile = z.object({
  packages: z.record(z.string(), manifest.extend({ resolved: z.string().optional(), link: z.boolean().optional() })),
});

// The file is untrusted: only package names come out of it, and they meet the same name rules as every other front
// door before anything is looked up. Nothing else in it (resolved URLs, git or file sources, includes, index URLs)
// is fetched or echoed.
export async function handleScan(request: Request, env: Env): Promise<Response> {
  const raw = await readBody(request, MAX_SCAN_BYTES);
  if (!raw) return jsonError(413, "request body too large");
  let text: string;
  try {
    // Drops a byte-order mark, which npm and pip both accept (some Windows editors save one).
    text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(await raw.arrayBuffer());
  } catch {
    return jsonError(400, "not a text file");
  }
  if (text.includes("\0")) return jsonError(400, "not a text file");
  if (!text.trim()) return jsonError(400, "empty file");
  const project = text.trimStart().startsWith("{") ? readJson(text) : readRequirements(text);
  if (typeof project === "string") return jsonError(400, project);
  const { names, skipped } = project;
  if (names.size > MAX_SCAN_NAMES) {
    return jsonError(400, `this project has ${names.size} packages; a scan checks at most ${MAX_SCAN_NAMES}`);
  }

  const checked = await checkPackages(project.ecosystem, [...names.keys()], env.CACHE, watchFor(env, request, "scan"));
  // Registry details stay in /api/check. Keys went through the same normalizeName as the results' names, so every
  // result finds its entry.
  const results = checked
    .map(({ checks: _, ...verdict }) => {
      const from = names.get(verdict.name);
      return from ? { ...verdict, from } : verdict;
    })
    .sort((a, b) => RANK[a.verdict] - RANK[b.verdict]);
  const count = (verdict: Verdict) => results.filter((r) => r.verdict === verdict).length;
  return Response.json({
    summary: {
      checked: results.length,
      block: count("block"),
      caution: count("caution"),
      safe: count("safe"),
      unverified: results.filter((r) => r.reasons.some((reason) => reason.startsWith("unverified:"))).length,
      skipped: skipped.size,
    },
    results,
    // A short skipped line can make a longer entry (".\n" is 2 bytes, its entry ~33), so the list is capped too.
    skipped: [...skipped.values()].slice(0, MAX_SCAN_NAMES),
  });
}

// An npm project, or what is wrong with the file.
function readJson(text: string): Project | string {
  let body: unknown;
  try {
    body = JSON.parse(text);
  } catch {
    return "body must be JSON: a package-lock.json or package.json";
  }
  if (body === null || typeof body !== "object" || Array.isArray(body)) return "not a package-lock.json or package.json";
  if ("_meta" in body) return "Pipfile.lock isn't supported; send a requirements file instead (pipenv requirements)";
  if ("lockfileVersion" in body) return readLockfile(body);
  if ("name" in body || SECTIONS.some((section) => section in body)) return readManifest(body);
  return "not a package-lock.json or package.json";
}

function readLockfile(body: object): Project | string {
  const version = lockfileVersion.safeParse(body);
  if (!version.success) return inputError(version.error);
  const v = version.data.lockfileVersion;
  // Version 1 (npm 6) only has the nested `dependencies` tree; 2 and 3 list every installed folder under `packages`.
  if (v !== 2 && v !== 3) {
    return `lockfile version ${v} isn't supported` + (v === 1 ? "; regenerate it with npm 7 or newer (npm install --package-lock-only)" : "");
  }
  const parsed = lockfile.safeParse(body);
  if (!parsed.success) return inputError(parsed.error);
  const { packages } = parsed.data;

  // A top-level folder named in the root's own lists is a direct dependency.
  const direct = new Map<string, From>();
  for (const section of SECTIONS) {
    for (const dep of Object.keys(packages[""]?.[section] ?? {})) {
      const path = `node_modules/${dep}`;
      if (!direct.has(path)) direct.set(path, section);
    }
  }
  const project: Project = { ecosystem: "npm", names: new Map(), skipped: new Map() };
  for (const [path, entry] of Object.entries(packages)) {
    const at = path.lastIndexOf("node_modules/");
    // The project itself ("") and its workspace folders.
    if (at === -1) continue;
    // An alias installs `name` under another folder name. npm writes workspaces and file: folders as links.
    const name = entry.name ?? path.slice(at + "node_modules/".length);
    const skip = entry.link ? "linked local folder" : resolvedSource(entry.resolved);
    if (skip) project.skipped.set(name, { name, reason: skip });
    else addName(project, name, direct.get(path) ?? "transitive");
  }
  return project;
}

function readManifest(body: object): Project | string {
  const parsed = manifest.safeParse(body);
  if (!parsed.success) return inputError(parsed.error);
  const project: Project = { ecosystem: "npm", names: new Map(), skipped: new Map() };
  for (const section of SECTIONS) {
    for (const [dep, spec] of Object.entries(parsed.data[section] ?? {})) {
      if (spec.startsWith("npm:")) {
        addName(project, aliasTarget(spec.slice("npm:".length)), section);
        continue;
      }
      const skip = specSource(spec);
      if (skip) project.skipped.set(dep, { name: dep, reason: skip });
      else addName(project, dep, section);
    }
  }
  return project;
}

// A requirements file, read the way pip reads one: a trailing "\" joins the next line unless the line is a comment,
// and "#" at the start or after whitespace starts a comment. Only the name of each requirement is kept.
function readRequirements(text: string): Project | string {
  const project: Project = { ecosystem: "pypi", names: new Map(), skipped: new Map() };
  const lines = text.split(/\r\n|\r|\n/);
  const isComment = (line: string) => /^\s*#/.test(line);
  for (let i = 0; i < lines.length; i++) {
    const number = i + 1;
    // Collected and joined once: appending to one growing string took 5.6 s of CPU for a 1 MiB file of "a\" lines.
    const parts: string[] = [];
    let part = lines[i]!;
    while (part.endsWith("\\") && !isComment(part)) {
      parts.push(part.slice(0, -1));
      part = lines[++i] ?? "";
      // A comment ends the continuation; the space keeps it a comment once joined.
      if (isComment(part)) part = ` ${part}`;
    }
    const line = [...parts, part].join("").replace(/(?:^|\s)#.*$/, "").trim();
    if (!line) continue;
    // No requirement starts with "[", but a TOML section does.
    if (line.startsWith("[")) return NOT_REQUIREMENTS;
    const skip = requirementSource(line);
    // Versions, extras, markers and per-line options (--hash) follow the name.
    const name = line.match(/^[^\s[(;@<>=!~,]*/)![0];
    if (!skip && name) addName(project, name, undefined);
    else project.skipped.set(`line ${number}`, { line: number, ...(skip ?? { reason: "not a requirement" }) });
  }
  return project;
}

// Why a requirements line doesn't name a pypi.org package, or null if it does. Options, links and paths are never
// repeated: they can hold private hosts, credentials or file names.
function requirementSource(line: string): Omit<Skip, "line"> | null {
  if (line.startsWith("-")) {
    const option = line.startsWith("--") ? line.split(/[\s=]/, 1)[0]! : line.slice(0, 2);
    if (["-r", "--requirement", "-c", "--constraint"].includes(option)) return { reason: "include not followed" };
    if (["-e", "--editable"].includes(option)) return { reason: "editable install" };
    return { reason: "pip option, ignored" };
  }
  if (/^(?:git|hg|svn|bzr)\+/i.test(line)) return { reason: "VCS source" };
  if (/^file:/i.test(line)) return { reason: "local path" };
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(line)) return { reason: "not from pypi.org" };
  // "name @ url" installs from the link. Its name is shown only if it is a valid one.
  const direct = line.match(/^(.*?)@\s*[a-z][a-z0-9+.-]*:/i);
  if (direct) {
    const name = normalizeName("pypi", direct[1]!.replace(/\[.*$/, ""));
    return { ...(name.ok ? { name: name.name } : {}), reason: "not from pypi.org" };
  }
  const first = line.split(/\s/, 1)[0]!;
  if (/^(?:[.~/\\]|[a-z]:[/\\])/i.test(line) || /[/\\]/.test(first) || ARCHIVE.test(first)) return { reason: "local path" };
  return null;
}

// A name at several places in the tree is checked once; being a direct dependency anywhere wins.
function addName({ ecosystem, names }: Project, raw: string, from: From | undefined) {
  const { name } = normalizeName(ecosystem, raw);
  if (!names.has(name) || (names.get(name) === "transitive" && from !== "transitive")) names.set(name, from);
}

// Why a lockfile entry isn't a registry.npmjs.org package, or null if it is. npm leaves `resolved` out for registry
// packages under omit-lockfile-registry-resolved and for bundled dependencies.
function resolvedSource(resolved: string | undefined): string | null {
  if (resolved === undefined || resolved.startsWith("https://registry.npmjs.org/")) return null;
  if (/^git[+:]/.test(resolved)) return "git source";
  if (resolved.startsWith("file:")) return "local file";
  return "not from registry.npmjs.org";
}

// The same for a package.json version spec: anything that isn't a version, range or tag. Paths follow npm's own
// rules: "~1.2.3" is a range but "~/dir" a folder, and "C:\dir" or "pkg.tgz" is a local file too.
function specSource(spec: string): string | null {
  if (/^(?:file:|link:|\.|~\/|[/\\]|[a-z]:)/i.test(spec)) return "local file";
  if (spec.startsWith("workspace:")) return "workspace link";
  if (/^https?:/.test(spec)) return "not from registry.npmjs.org";
  if (/^(?:git[+:]|github:|gitlab:|bitbucket:|gist:)/.test(spec) || spec.includes("/")) return "git source";
  if (/\.(?:tgz|tar\.gz|tar)$/i.test(spec)) return "local file";
  return null;
}

// "@scope/real@^1" or "real@^1" or "real" → the real package's name.
function aliasTarget(target: string): string {
  const at = target.lastIndexOf("@");
  return at > 0 ? target.slice(0, at) : target;
}
