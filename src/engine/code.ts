import { readCode, writeCode } from "./cache";
import { fetchBytes, FetchFailed, TOO_LARGE } from "./fetch";
import { isPopular } from "./lookalike";
import { NPM_REGISTRY, type Archive, type Found } from "./registry";
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
      missingScriptFiles: number;
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
// How install scripts start a file of the package: `node <file>` (after any flags) and `require('<file>')`.
const NODE = /(?:^|\W)node$/;
const NODE_FILE = /^[^"'`;&|()-][^"'`;&|()]*/;
const REQUIRE_FILE = /require\(\s*["'`]([^"'`]+)["'`]\s*\)/g;

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
// (CLIs shell out, bundles are minified), while outbound sends matched 0.9%.
const PACKAGE_PATTERNS = PATTERNS.filter(([id]) => OUTBOUND.includes(id));
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
  // Fed by hand: the gzip layer reports a failed download as its own error, so the real cause is kept here.
  const gunzip = new DecompressionStream("gzip");
  const writer = gunzip.writable.getWriter();
  const fed = (async () => {
    for await (const chunk of res.body) await writer.write(chunk);
    await writer.close();
  })().then(
    () => null,
    (err: unknown) => {
      writer.abort(err).catch(() => {});
      return err;
    },
  );
  const reader = gunzip.readable.getReader();
  try {
    return await readTar(new Bytes(reader), archive);
  } catch (err) {
    if (err instanceof Refused) return { status: "error", reason: err.message };
    await reader.cancel().catch(() => {});
    const cause = await fed;
    if (cause instanceof FetchFailed) return { status: "error", reason: cause.message === TOO_LARGE ? "archive too large" : cause.message };
    // Anything else is the gzip layer refusing the bytes.
    return { status: "error", reason: UNREADABLE };
  } finally {
    reader.cancel().catch(() => {});
  }
}

async function readTar(bytes: Bytes, archive: Archive): Promise<CodeCheck> {
  const scriptFiles = scriptReferences(archive.installCommands);
  // The install commands are install-time code too: `node -e "…"` runs what it says.
  const install = new Set(archive.installCommands.flatMap(installFindings));
  const inPackage = new Set<FindingId>();
  const main = candidates(relative(archive.main ?? "index.js"), ["", ".js", "/index.js"]);
  const found = new Set<string>();
  let entries = 0;
  let files = 0;
  let filesRead = 0;
  let bytesRead = 0;
  let partial = false;
  // A pax record or GNU long name describing the next entry.
  let next: { path?: string; size?: number } = {};

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
    // Links, folders, devices and global pax headers are never read or followed.
    if (type !== FILE && type !== OLD_FILE) {
      await bytes.skip(padded);
      continue;
    }

    files++;
    const rel = inside(path);
    const installTime = rel !== undefined && (rel === "package.json" || scriptFiles.some((refs) => refs.includes(rel)));
    if (installTime) found.add(rel);
    // What npm reads or runs at install must be read whole; the main entry and other code may be read in part.
    if (installTime && size > MAX_FILE_BYTES) throw new Refused("install-time file too large");
    const wanted = installTime || (rel !== undefined && main.includes(rel));
    const code = rel !== undefined && SCRIPT_TYPES.test(rel);
    const read = Math.min(size, wanted ? MAX_FILE_BYTES : code ? Math.max(0, READ_BUDGET_BYTES - bytesRead) : 0);
    if (code && read < size) partial = true;
    if (wanted || read > 0) {
      // Read, then dropped: only the counts and finding IDs are kept.
      const data = await bytes.take(read);
      if (rel !== "package.json") {
        const text = utf8.decode(data);
        if (installTime) for (const id of installFindings(text)) install.add(id);
        else for (const [id, pattern] of PACKAGE_PATTERNS) if (!inPackage.has(id) && pattern.test(text)) inPackage.add(id);
      }
      filesRead++;
      bytesRead += read;
    }
    await bytes.skip(padded - read);
  }

  const missingScriptFiles = scriptFiles.filter((refs) => !refs.some((ref) => found.has(ref))).length;
  const findings: Finding[] = [
    ...ORDER.filter((id) => install.has(id)).map((id) => ({ id, where: "install" as const })),
    ...ORDER.filter((id) => inPackage.has(id)).map((id) => ({ id, where: "package" as const })),
  ];
  return { status: "read", files, filesRead, bytesRead, partial, missingScriptFiles, findings };
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

// Each file an install script names, as the paths node would try for it inside the package.
function scriptReferences(commands: string[]): string[][] {
  const refs = commands.flatMap((command) => [...nodeFiles(command), ...[...command.matchAll(REQUIRE_FILE)].map((m) => m[1]!)]);
  return [...new Set(refs)].map((ref) => candidates(relative(ref), ["", ".js", ".cjs", ".mjs", "/index.js"]));
}

// The file after each `node` and its flags, in one pass over the words: a single regex for this backtracks on a
// command like "node -node -node …" (13.8 s for 256 KiB).
function nodeFiles(command: string): string[] {
  const files: string[] = [];
  let afterNode = false;
  for (const word of command.split(/\s+/)) {
    if (afterNode && !(word.length > 1 && word.startsWith("-"))) {
      const file = NODE_FILE.exec(word)?.[0];
      if (file) files.push(file);
      afterNode = false;
    }
    if (NODE.test(word)) afterNode = true;
  }
  return files;
}

function candidates(path: string | undefined, suffixes: string[]): string[] {
  return path === undefined ? [] : suffixes.map((suffix) => path + suffix);
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
