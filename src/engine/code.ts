import { readCode, writeCode } from "./cache";
import { fetchBytes, FetchFailed, TOO_LARGE } from "./fetch";
import { isPopular } from "./lookalike";
import { NPM_INSTALL_HOOKS, NPM_REGISTRY, strings, type Archive, type Found } from "./registry";
import { OUTBOUND, RISK } from "./score";

// Counts and fixed finding IDs only: nothing from the archive (code, strings, file names) is kept, so none of it can
// reach a reason, a log line or an AI's context.
export type CodeCheck =
  | {
      status: "read";
      files: number;
      filesRead: number;
      bytesRead: number;
      partial: boolean;
      // Files install commands name that weren't read: not in the archive (a file made at install, then run), or outside it.
      unreadScriptFiles: number;
      // Install hooks in the archive's package.json that the registry lists differently or not at all.
      undeclaredScripts: number;
      findings: Finding[];
    }
  | { status: "error"; reason: string }
  | { status: "skipped" };

export type FindingId = (typeof PATTERNS)[number][0] | "obfuscated";
// Install-time code is what an install runs; package code is the main entry and the other code read.
export interface Finding {
  id: FindingId;
  where: "install" | "package";
}

// Measured on 902 npm packages under 30 days old (2026-10-03): 10 MiB holds 90.9% of their archives (the rest are
// mostly prebuilt binaries), and everything under it unpacked to at most 55.8 MB, so 64 MiB only stops bombs; 2 had
// more than 5,000 files; 95% held under 2.8 MB of JavaScript.
const MAX_ARCHIVE_BYTES = 10 * 1024 * 1024;
const MAX_UNPACKED_BYTES = 64 * 1024 * 1024;
const MAX_ENTRIES = 5_000;
const MAX_FILE_BYTES = 1024 * 1024;
const READ_BUDGET_BYTES = 4 * 1024 * 1024;

const BLOCK = 512;
const DAY_MS = 86_400_000;
const [FILE, OLD_FILE, PAX, GNU_LONG_NAME] = ["0", "\0", "x", "L"].map((c) => c.charCodeAt(0));
const SCRIPT_TYPES = /\.(?:c|m)?js$/;
const JS_SUFFIXES = ["", ".js", ".cjs", ".mjs", "/index.js"];
// How install scripts start a file of the package: `node <file>` (after any flags), `require('./<file>')`,
// `sh <file>` (or bash, zsh) and `./<file>`. "node" counts as a word of its own, also after a path or `(`, but not in a
// file name like `re2.node` or a program like `xnode`.
const NODE = /(?:^|[^\w.-])node$/;
const SHELL = /(?:^|\/)(?:sh|bash|zsh)$/;
const NODE_FILE = /^[^"'`;&|()-][^"'`;&|()]*/;
const DIRECT = /^\.\/[^"'`;&|()]+$/;
const REQUIRE_FILE = /require\(\s*["'`](\.\.?\/[^"'`]*)["'`]\s*\)/g;
// `npm run <script>` (or run-script, pnpm, yarn run) inside an install script runs that script, with its pre and post.
const RUN_SCRIPT = /\b(?:npm|pnpm|yarn)\s+(?:run|run-script)\s+(?:-\S+\s+)*([^\s;&|()]+)/g;
const MAX_RUN_SCRIPTS = 20;
// Local modules install-time code loads; each runs at install too.
const LOCAL_IMPORT = /(?:\brequire\s*\(|\bimport\s*\(|\bfrom|\bimport)\s*["'`](\.\.?\/[^"'`]*)["'`]/g;
// Commands in binding.gyp (`<!(...)`, `<!@(...)`), which node-gyp runs at install.
const GYP_COMMAND = /<!@?\(([^()]*)\)/g;
// A shebang for anything but node.
const SHELL_SHEBANG = /^#!(?![^\n]*\bnode\b)/;
// Passes over the archive after the first, each following at least one more level of what install-time code loads (a
// module that comes after the file loading it is read in the same pass). Deeper modules are the package's library
// code, checked as package code instead.
// ponytail: each pass unpacks the archive again (at most 64 MiB); keep install-time files in memory if CPU matters.
const MAX_FOLLOW_PASSES = 3;

// Paste and request-catching sites: places to drop stolen data that need no server of one's own.
const PASTE_SITES = [
  "pastebin.com", "paste.ee", "hastebin.com", "transfer.sh", "webhook.site", "requestbin.net", "requestbin.com", "pipedream.net",
  "ngrok.io", "ngrok-free.app", "ngrok.dev", "interact.sh", "oast.fun", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.me",
  "burpcollaborator.net",
];
// What install-time code is checked for, in reason order. Measured on 907 real packages (2026-10-03): only `shell`
// appears in legitimate install-time code (22 of 89 packages with install scripts). Each pattern has no nested or
// overlapping repetition, so it runs in time linear in the text; tests hold that to a 1 MiB hostile line.
const PATTERNS = [
  ["shell", /\bchild_process\b/],
  ["ssh", /\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b/],
  ["npmrc", /\.npmrc\b/],
  [
    "cloud",
    /\.aws[\\/]credentials|\.config[\\/]gcloud|\.azure[\\/]|\.kube[\\/]config|\.docker[\\/]config\.json|\.git-credentials|\.netrc\b/,
  ],
  // The whole environment, serialized or listed; spreading it into a child's environment is common and harmless.
  ["env", /JSON\.stringify\(\s*process\.env\s*[,)]|Object\.(?:keys|entries|values)\(\s*process\.env\s*\)/],
  // A numeric address outside loopback, private and link-local ranges.
  [
    "raw-ip",
    /\b(?:https?|wss?):\/\/(?!(?:127|10|0)\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.)\d{1,3}(?:\.\d{1,3}){3}(?![\w.-])/,
  ],
  ["webhook", /discord(?:app)?\.com\/api\/webhooks|hooks\.slack\.com\/|api\.telegram\.org\/bot/],
  ["paste", new RegExp(`\\b(?:${PASTE_SITES.map((host) => host.replaceAll(".", "\\.")).join("|")})\\b`)],
  ["dynamic", /(?<![.\w$])eval\s*\(|\bnew\s+Function\s*\(|\brunIn(?:New|This)?Context\s*\(/],
] as const;
// Package code is only checked for sending data out: the other patterns match 4-27% of legitimate packages' code
// (CLIs shell out, bundles are minified), while outbound sends matched 0.9%. Paste-site addresses in package code were
// mentions, not sends (a link in a code comment, the public-suffix list), so only install-time code is checked for them.
const PACKAGE_PATTERNS = PATTERNS.filter(([id]) => id !== "paste" && OUTBOUND.includes(id));
const ORDER: FindingId[] = [...PATTERNS.map(([id]) => id), "obfuscated"];
// What obfuscators and packed payloads look like; no install-time file of the 907 packages had either.
const MAX_LINE = 10_000;
const MAX_ENCODED_RUN = 1_000;

class Refused extends Error {}
const UNREADABLE = "unreadable archive";
const UNPACKS_TOO_LARGE = "archive unpacks too large";

// Install scripts run at install, so any package with one is opened, popular or not (a hijacked popular package gains
// one). Other popular packages never are; the rest only once they already look risky.
export function shouldOpen(name: string, registry: Found, lookalike: string[], now = Date.now()): boolean {
  if (registry.installScripts.length) return true;
  if (isPopular("npm", name)) return false;
  const young = registry.firstSeenAt !== null && now - Date.parse(registry.firstSeenAt) < RISK.newPackageDays * DAY_MS;
  const fewDownloads = registry.weeklyDownloads !== undefined && registry.weeklyDownloads < RISK.minWeeklyDownloads;
  return young || fewDownloads || registry.downloadsError !== undefined || lookalike.length > 0;
}

// A published version's archive never changes, so each one is read once and the counts are shared through KV.
export async function checkCode(name: string, version: string, archive: Archive | undefined, cache?: KVNamespace): Promise<CodeCheck> {
  const cached = cache && (await readCode(cache, name, version));
  if (cached) return cached;
  const code = await readArchive(archive);
  if (cache) await writeCode(cache, name, version, code);
  return code;
}

// The archive is only ever read as bytes: nothing in it is run, evaluated or written anywhere.
async function readArchive(archive: Archive | undefined): Promise<CodeCheck> {
  if (!archive) return { status: "error", reason: "no archive listed" };
  if (!archive.url.startsWith(`${NPM_REGISTRY}/`)) return { status: "error", reason: "archive not on registry.npmjs.org" };
  const res = await fetchBytes(archive.url, MAX_ARCHIVE_BYTES);
  if (res.status === "not_found") return { status: "error", reason: "archive missing" };
  if (res.status === "error") return { status: "error", reason: res.reason === TOO_LARGE ? "archive too large" : res.reason };
  // Kept whole (at most MAX_ARCHIVE_BYTES): following what install scripts load can take more than one pass.
  const parts: Uint8Array[] = [];
  try {
    for await (const chunk of res.body) parts.push(chunk);
  } catch (err) {
    const reason = err instanceof FetchFailed ? err.message : "network error";
    return { status: "error", reason: reason === TOO_LARGE ? "archive too large" : reason };
  }
  try {
    return await readPackage(new Blob(parts), archive);
  } catch (err) {
    // Anything but a refusal is the gzip layer refusing the bytes.
    return { status: "error", reason: err instanceof Refused ? err.message : UNREADABLE };
  }
}

// How a file runs at install; "auto" is a file run directly, which its shebang decides.
type Kind = "js" | "shell" | "gyp" | "auto";
interface Ref {
  paths: string[];
  kind: Kind;
}

async function readPackage(archive: Blob, listed: Archive): Promise<CodeCheck> {
  // Every path that runs at install, with how; node-gyp reads binding.gyp at install whenever it is there.
  const install = new Map<string, Kind>([["binding.gyp", "gyp"]]);
  const addInstall = ({ paths, kind }: Ref) => paths.forEach((path) => install.has(path) || install.set(path, kind));
  // The files install commands name, by the paths each could be; one with none of them read is unread.
  const named = new Map<string, string[]>();
  const found = new Set<FindingId>();
  const runs = (scripts: Record<string, string>) => {
    for (const command of installCommands(scripts)) {
      for (const id of installFindings(command)) found.add(id);
      for (const ref of commandRefs(command)) {
        named.set(ref.paths.join("\n"), ref.paths);
        addInstall(ref);
      }
    }
  };
  runs(listed.scripts);

  const main = candidates(relative(listed.main ?? "index.js"), ["", ".js", "/index.js"]);
  const paths = new Set<string>();
  const read = new Map<string, number>();
  const scanned = new Set<string>();
  const inPackage = new Map<string, FindingId[]>();
  let packed: Record<string, string> | undefined;
  let files = 0;
  let spent = 0;
  let partial = false;

  const isInstall = (rel: string) => rel === "package.json" || install.has(rel);
  const wholeFile = (size: number) => {
    // What npm reads or runs at install must be read whole.
    if (size > MAX_FILE_BYTES) throw new Refused("install-time file too large");
    return size;
  };
  const checkInstall = (rel: string, data: Uint8Array) => {
    read.set(rel, data.length);
    scanned.add(rel);
    inPackage.delete(rel);
    if (rel === "package.json") {
      packed = scriptsOf(data);
      return;
    }
    const text = utf8.decode(data);
    let kind = install.get(rel)!;
    if (kind === "auto") kind = SHELL_SHEBANG.test(text) ? "shell" : "js";
    for (const id of installFindings(text)) found.add(id);
    if (kind === "shell") {
      found.add("shell");
      for (const line of text.split("\n")) commandRefs(line).forEach(addInstall);
    } else if (kind === "gyp") {
      for (const [, command] of text.matchAll(GYP_COMMAND)) commandRefs(command!).forEach(addInstall);
    } else {
      const dir = rel.split("/").slice(0, -1).join("/");
      for (const [, spec] of text.matchAll(LOCAL_IMPORT)) addInstall({ paths: candidates(within(dir, spec!), JS_SUFFIXES), kind: "js" });
    }
  };

  // First pass: everything known to run at install, whole; the main entry; then other code up to a budget.
  await walk(archive, {
    want(rel, size) {
      files++;
      if (rel === undefined) return undefined;
      paths.add(rel);
      if (isInstall(rel)) return wholeFile(size);
      const code = SCRIPT_TYPES.test(rel);
      const wanted = main.includes(rel);
      const n = Math.min(size, wanted ? MAX_FILE_BYTES : code ? Math.max(0, READ_BUDGET_BYTES - spent) : 0);
      if (code && n < size) partial = true;
      return wanted || n > 0 ? n : undefined;
    },
    got(rel, data) {
      spent += data.length;
      if (isInstall(rel)) return checkInstall(rel, data);
      read.set(rel, data.length);
      // Read, then dropped: only finding IDs are kept, per file in case it turns out to run at install.
      const text = utf8.decode(data);
      const ids = PACKAGE_PATTERNS.flatMap(([id, pattern]) => (pattern.test(text) ? [id] : []));
      if (ids.length) inPackage.set(rel, ids);
    },
  });

  // `npm install` runs the scripts the registry lists; an install from a lockfile runs the archive's own (npm 11.19.1,
  // 2026-10-04), so both are install-time code.
  let undeclaredScripts = 0;
  if (packed) {
    undeclaredScripts = NPM_INSTALL_HOOKS.filter((hook) => Object.hasOwn(packed!, hook) && packed![hook] !== listed.scripts[hook]).length;
    runs(packed);
  }

  // Then what install-time code turned out to load, one level per pass.
  for (let pass = 0; pass < MAX_FOLLOW_PASSES; pass++) {
    const pending = new Set([...install.keys()].filter((path) => paths.has(path) && !scanned.has(path)));
    if (!pending.size) break;
    await walk(archive, { want: (rel, size) => (rel !== undefined && pending.has(rel) ? wholeFile(size) : undefined), got: checkInstall });
  }

  const unreadScriptFiles = [...named.values()].filter((refs) => !refs.some((ref) => scanned.has(ref))).length;
  const packageFound = new Set([...inPackage.values()].flat());
  const findings: Finding[] = [
    ...ORDER.filter((id) => found.has(id)).map((id) => ({ id, where: "install" as const })),
    ...ORDER.filter((id) => packageFound.has(id)).map((id) => ({ id, where: "package" as const })),
  ];
  const bytesRead = [...read.values()].reduce((sum, n) => sum + n, 0);
  return { status: "read", files, filesRead: read.size, bytesRead, partial, unreadScriptFiles, undeclaredScripts, findings };
}

interface Visit {
  // How many bytes of a file to read, or undefined to skip it; `rel` is undefined for a path outside the package.
  want(rel: string | undefined, size: number): number | undefined;
  got(rel: string, data: Uint8Array): void;
}

// One pass over the archive's files. Links, folders, devices and global pax headers are never read or followed.
async function walk(archive: Blob, visit: Visit): Promise<void> {
  const reader = archive.stream().pipeThrough(new DecompressionStream("gzip")).getReader();
  const bytes = new Bytes(reader);
  let entries = 0;
  // A pax record or GNU long name describing the next entry.
  let next: { path?: string; size?: number } = {};
  try {
    for (;;) {
      const header = await bytes.take(BLOCK, { endOk: true });
      // The end-of-archive marker, or a stream that ends between entries (gzip has already checked it is complete).
      if (!header || header.every((b) => b === 0)) break;
      if (++entries > MAX_ENTRIES) throw new Refused("too many files in archive");
      if (!checksumOk(header)) throw new Refused(UNREADABLE);
      const size = octal(header.subarray(124, 136));
      // npm writes a pax size for some entries; one that disagrees with the header would let the two readers differ.
      if (next.size !== undefined && next.size !== size) throw new Refused(UNREADABLE);
      const padded = Math.ceil(size / BLOCK) * BLOCK;
      // Every byte pulled is a header or what one declared, so this bounds the whole unpacked stream before it is read.
      if (padded > MAX_UNPACKED_BYTES - bytes.unpacked) throw new Refused(UNPACKS_TOO_LARGE);
      const type = header[156];

      // Long names: the next entry's path, in a pax record or a GNU long-name entry.
      if (type === PAX || type === GNU_LONG_NAME) {
        if (size > MAX_FILE_BYTES) throw new Refused(UNREADABLE);
        const body = (await bytes.take(padded)).subarray(0, size);
        next = type === PAX ? paxRecords(body) : { path: cString(body) };
        continue;
      }
      const path = next.path ?? ustarPath(header);
      next = {};
      const isFile = type === FILE || type === OLD_FILE;
      const rel = isFile ? inside(path) : undefined;
      const n = isFile ? visit.want(rel, size) : undefined;
      if (n !== undefined) visit.got(rel!, await bytes.take(n));
      await bytes.skip(padded - (n ?? 0));
    }
  } finally {
    reader.cancel().catch(() => {});
  }
}

// The hook commands, then any scripts they `npm run`.
function installCommands(scripts: Record<string, string>): string[] {
  const queue = NPM_INSTALL_HOOKS.filter((hook) => Object.hasOwn(scripts, hook));
  const seen = new Set(queue);
  for (let i = 0; i < queue.length && queue.length < MAX_RUN_SCRIPTS; i++) {
    for (const [, name] of scripts[queue[i]!]!.matchAll(RUN_SCRIPT)) {
      for (const script of [`pre${name}`, name!, `post${name}`]) {
        if (Object.hasOwn(scripts, script) && !seen.has(script)) {
          seen.add(script);
          queue.push(script);
        }
      }
    }
  }
  return queue.map((script) => scripts[script]!);
}

// The files a command runs, as the paths each could be. Names built at run time ($VAR) and other packages' files
// (node_modules) can't be read from this archive, so they aren't counted.
function commandRefs(command: string): Ref[] {
  const refs: Ref[] = [];
  const ref = (file: string, kind: Kind) => {
    if (/[$%]/.test(file) || /^(?:\.\/)?node_modules\//.test(file)) return;
    refs.push({ paths: candidates(relative(file), kind === "js" ? JS_SUFFIXES : [""]), kind });
  };
  // One pass over the words: a single regex for this backtracks on a command like "node -node -node …" (13.8 s for
  // 256 KiB).
  let after: "js" | "shell" | undefined;
  for (const word of command.split(/\s+/)) {
    if (after && !(word.length > 1 && word.startsWith("-"))) {
      const file = NODE_FILE.exec(word)?.[0];
      if (file) ref(file, after === "js" || SCRIPT_TYPES.test(file) ? "js" : "shell");
      after = undefined;
    } else if (!after && DIRECT.test(word)) {
      ref(word, SCRIPT_TYPES.test(word) ? "js" : "auto");
    }
    if (NODE.test(word)) after = "js";
    else if (SHELL.test(word)) after = "shell";
  }
  for (const [, file] of command.matchAll(REQUIRE_FILE)) ref(file!, "js");
  return refs;
}

function scriptsOf(data: Uint8Array): Record<string, string> | undefined {
  try {
    const manifest: unknown = JSON.parse(utf8.decode(data));
    return strings((manifest as { scripts?: unknown } | null)?.scripts);
  } catch {
    return undefined;
  }
}

function installFindings(text: string): FindingId[] {
  const ids: FindingId[] = PATTERNS.flatMap(([id, pattern]) => (pattern.test(text) ? [id] : []));
  return obfuscated(text) ? [...ids, "obfuscated"] : ids;
}

// One pass: a line over MAX_LINE characters, or a run of base64 characters over MAX_ENCODED_RUN.
function obfuscated(text: string): boolean {
  let line = 0;
  let run = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    line = c === 0x0a ? 0 : line + 1;
    const encoded = (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a) || c === 0x2b || c === 0x2f || c === 0x3d;
    run = encoded ? run + 1 : 0;
    if (line > MAX_LINE || run > MAX_ENCODED_RUN) return true;
  }
  return false;
}

function candidates(path: string | undefined, suffixes: string[]): string[] {
  return path === undefined ? [] : suffixes.map((suffix) => path + suffix);
}

// `spec` from the folder `dir`, if it stays inside the package.
function within(dir: string, spec: string): string | undefined {
  const parts = dir ? dir.split("/") : [];
  for (const part of spec.split("/")) {
    if (part === "..") {
      if (parts.pop() === undefined) return undefined;
    } else if (part && part !== ".") parts.push(part);
  }
  return parts.length ? parts.join("/") : undefined;
}

// A path inside the package, or undefined for one that climbs out of it (`..`) or starts at the root.
function relative(path: string): string | undefined {
  if (path.startsWith("/")) return undefined;
  const parts = path.split("/").filter((part) => part !== "" && part !== ".");
  return parts.length && !parts.includes("..") ? parts.join("/") : undefined;
}

// npm unpacks everything below the archive's top folder (usually `package/`, whatever it is called).
function inside(path: string): string | undefined {
  if (path.startsWith("/")) return undefined;
  return relative(path.split("/").slice(1).join("/"));
}

function ustarPath(header: Uint8Array): string {
  const name = cString(header.subarray(0, 100));
  const prefix = ascii(header.subarray(257, 262)) === "ustar" ? cString(header.subarray(345, 500)) : "";
  return prefix ? `${prefix}/${name}` : name;
}

// Records are "<length> <key>=<value>\n"; only the path and size are used.
function paxRecords(body: Uint8Array): { path?: string; size?: number } {
  const next: { path?: string; size?: number } = {};
  for (let at = 0; at < body.length; ) {
    const space = body.indexOf(0x20, at);
    if (space < 0 || space - at > 20) throw new Refused(UNREADABLE);
    const length = Number(ascii(body.subarray(at, space)));
    if (!Number.isInteger(length) || length <= space - at + 1 || at + length > body.length) throw new Refused(UNREADABLE);
    const record = new TextDecoder().decode(body.subarray(space + 1, at + length - 1));
    const [key, value] = [record.slice(0, record.indexOf("=")), record.slice(record.indexOf("=") + 1)];
    // Only ever compared with the header's size, so an odd spelling of the same number does no harm.
    if (key === "size") next.size = Number(value);
    if (key === "path") next.path = value;
    at += length;
  }
  return next;
}

function checksumOk(header: Uint8Array): boolean {
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : header[i]!;
  return octal(header.subarray(148, 156)) === sum;
}

// Octal digits padded with NULs or spaces; an empty field is 0 (npm publishes folders like that). Anything else
// (including the base-256 form for sizes over 8 GiB) is refused.
function octal(field: Uint8Array): number {
  const digits = ascii(field).replace(/[\0 ]+$/, "").trimStart();
  if (!/^[0-7]{0,12}$/.test(digits)) throw new Refused(UNREADABLE);
  return digits ? parseInt(digits, 8) : 0;
}

const utf8 = new TextDecoder();
const cString = (bytes: Uint8Array) => new TextDecoder().decode(bytes.subarray(0, bytes.indexOf(0) < 0 ? bytes.length : bytes.indexOf(0)));
const ascii = (bytes: Uint8Array) => String.fromCharCode(...bytes);

// Pulls exact byte counts from the unpacked stream, counting them for the unpacked cap; nothing is pulled before it is
// needed, so a bomb stops at the cap.
class Bytes {
  unpacked = 0;
  private chunk: Uint8Array = new Uint8Array(0);
  private at = 0;

  constructor(private reader: ReadableStreamDefaultReader<Uint8Array>) {}

  take(n: number): Promise<Uint8Array>;
  take(n: number, opts: { endOk: true }): Promise<Uint8Array | null>;
  async take(n: number, { endOk = false } = {}): Promise<Uint8Array | null> {
    const out = new Uint8Array(n);
    return (await this.pull(n, out, endOk)) ? out : null;
  }

  async skip(n: number): Promise<void> {
    await this.pull(n, null, false);
  }

  private async pull(n: number, out: Uint8Array | null, endOk: boolean): Promise<boolean> {
    for (let filled = 0; filled < n; ) {
      if (this.at === this.chunk.length) {
        const { done, value } = await this.reader.read();
        if (done) {
          if (endOk && filled === 0) return false;
          throw new Refused(UNREADABLE);
        }
        this.unpacked += value.byteLength;
        this.chunk = value;
        this.at = 0;
      }
      const count = Math.min(n - filled, this.chunk.length - this.at);
      out?.set(this.chunk.subarray(this.at, this.at + count), filled);
      filled += count;
      this.at += count;
    }
    return true;
  }
}
