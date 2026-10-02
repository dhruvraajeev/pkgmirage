import { z } from "zod";
import { inputError, jsonError, readBody } from "./api";
import { checkPackages } from "./engine/check";
import type { Verdict } from "./engine/score";
import { watchFor } from "./engine/watch";

// A lockfile takes ~510 bytes per package, so this fits about 2,000; the name cap below is what limits a scan.
const MAX_SCAN_BYTES = 1024 * 1024;
// Each name can cost one KV write and cached verdicts are read 100 per operation, so a cold scan of 750 names stays
// near 765 of the 1,000 KV operations one request may make.
const MAX_SCAN_NAMES = 750;
const SECTIONS = ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] as const;
const RANK: Record<Verdict, number> = { block: 0, caution: 1, safe: 2 };

type From = (typeof SECTIONS)[number] | "transitive";
interface Project {
  names: Map<string, From>;
  skipped: Map<string, string>;
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
// door before anything is looked up. Nothing else in it (resolved URLs, git or file sources) is fetched or echoed.
export async function handleScan(request: Request, env: Env): Promise<Response> {
  const raw = await readBody(request, MAX_SCAN_BYTES);
  if (!raw) return jsonError(413, "request body too large");
  let body: unknown;
  try {
    body = JSON.parse(await raw.text());
  } catch {
    return jsonError(400, "body must be JSON: a package-lock.json or package.json");
  }
  const project = readProject(body);
  if (typeof project === "string") return jsonError(400, project);
  const { names, skipped } = project;
  if (names.size > MAX_SCAN_NAMES) {
    return jsonError(400, `this project has ${names.size} packages; a scan checks at most ${MAX_SCAN_NAMES}`);
  }

  const checked = await checkPackages("npm", [...names.keys()], env.CACHE, watchFor(env, request, "scan"));
  const results = checked.map((r) => ({ ...r, from: names.get(r.name)! })).sort((a, b) => RANK[a.verdict] - RANK[b.verdict]);
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
    skipped: [...skipped].map(([name, reason]) => ({ name, reason })),
  });
}

// A project, or what is wrong with the file.
function readProject(body: unknown): Project | string {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return "not a package-lock.json or package.json";
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
  const project: Project = { names: new Map(), skipped: new Map() };
  for (const [path, entry] of Object.entries(packages)) {
    const at = path.lastIndexOf("node_modules/");
    // The project itself ("") and its workspace folders.
    if (at === -1) continue;
    // An alias installs `name` under another folder name. npm writes workspaces and file: folders as links.
    const name = (entry.name ?? path.slice(at + "node_modules/".length)).trim();
    const skip = entry.link ? "linked local folder" : resolvedSource(entry.resolved);
    if (skip) project.skipped.set(name, skip);
    else addName(project, name, direct.get(path) ?? "transitive");
  }
  return project;
}

function readManifest(body: object): Project | string {
  const parsed = manifest.safeParse(body);
  if (!parsed.success) return inputError(parsed.error);
  const project: Project = { names: new Map(), skipped: new Map() };
  for (const section of SECTIONS) {
    for (const [dep, spec] of Object.entries(parsed.data[section] ?? {})) {
      if (spec.startsWith("npm:")) {
        addName(project, aliasTarget(spec.slice("npm:".length)), section);
        continue;
      }
      const skip = specSource(spec);
      if (skip) project.skipped.set(dep, skip);
      else addName(project, dep.trim(), section);
    }
  }
  return project;
}

// A name at several places in the tree is checked once; being a direct dependency anywhere wins.
function addName({ names }: Project, name: string, from: From) {
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

// The same for a package.json version spec: anything that isn't a version, range or tag.
function specSource(spec: string): string | null {
  if (/^(?:file:|link:|\.|\/|~)/.test(spec)) return "local file";
  if (spec.startsWith("workspace:")) return "workspace link";
  if (/^https?:/.test(spec)) return "not from registry.npmjs.org";
  if (/^(?:git[+:]|github:|gitlab:|bitbucket:|gist:)/.test(spec) || spec.includes("/")) return "git source";
  return null;
}

// "@scope/real@^1" or "real@^1" or "real" → the real package's name.
function aliasTarget(target: string): string {
  const at = target.lastIndexOf("@");
  return (at > 0 ? target.slice(0, at) : target).trim();
}
