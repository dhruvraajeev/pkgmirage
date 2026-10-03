import { readCode, writeCode } from "./cache";
import { fetchBytes, FetchFailed, TOO_LARGE } from "./fetch";
import { isPopular } from "./lookalike";
import { NPM_REGISTRY, type Archive, type Found } from "./registry";
import { RISK } from "./score";

// Counts only: nothing from the archive (code, strings, file names) is kept, so none of it can reach a reason, a log
// line or an AI's context.
export type CodeCheck =
  | { status: "read"; files: number; filesRead: number; bytesRead: number; partial: boolean; missingScriptFiles: number }
  | { status: "error"; reason: string }
  | { status: "skipped" };

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
// `node <file>` (after any flags) and `require('<file>')`: how install scripts start a file of the package.
const NODE_FILE = /\bnode\s+(?:-\S+\s+)*([^\s"'`;&|()-][^\s"'`;&|()]*)/g;
const REQUIRE_FILE = /require\(\s*["'`]([^"'`]+)["'`]\s*\)/g;

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
  const main = candidates(relative(archive.main ?? "index.js"), ["", ".js", "/index.js"]);
  const found = new Set<string>();
  let entries = 0;
  let files = 0;
  let filesRead = 0;
  let bytesRead = 0;
  let partial = false;
  let longPath: string | undefined;

  for (;;) {
    const header = await bytes.take(BLOCK, { endOk: true });
    // The end-of-archive marker, or a stream that ends between entries (gzip has already checked it is complete).
    if (!header || header.every((b) => b === 0)) break;
    if (++entries > MAX_ENTRIES) throw new Refused("too many files in archive");
    if (!checksumOk(header)) throw new Refused(UNREADABLE);
    const size = octal(header.subarray(124, 136));
    const padded = Math.ceil(size / BLOCK) * BLOCK;
    // Every byte pulled is a header or what one declared, so this bounds the whole unpacked stream before it is read.
    if (padded > MAX_UNPACKED_BYTES - bytes.unpacked) throw new Refused(UNPACKS_TOO_LARGE);
    const type = header[156];

    // Long names: the next entry's path, in a pax record or a GNU long-name entry.
    if (type === PAX || type === GNU_LONG_NAME) {
      if (size > MAX_FILE_BYTES) throw new Refused(UNREADABLE);
      const body = (await bytes.take(padded)).subarray(0, size);
      longPath = type === PAX ? paxPath(body) : cString(body);
      continue;
    }
    const path = longPath ?? ustarPath(header);
    longPath = undefined;
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
      // Read, then dropped: only the counts are kept.
      await bytes.take(read);
      filesRead++;
      bytesRead += read;
    }
    await bytes.skip(padded - read);
  }

  const missingScriptFiles = scriptFiles.filter((refs) => !refs.some((ref) => found.has(ref))).length;
  return { status: "read", files, filesRead, bytesRead, partial, missingScriptFiles };
}

// Each file an install script names, as the paths node would try for it inside the package.
function scriptReferences(commands: string[]): string[][] {
  const refs = commands.flatMap((command) => [...command.matchAll(NODE_FILE), ...command.matchAll(REQUIRE_FILE)].map((m) => m[1]!));
  return [...new Set(refs)].map((ref) => candidates(relative(ref), ["", ".js", ".cjs", ".mjs", "/index.js"]));
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

// Records are "<length> <key>=<value>\n"; only the path is used. A size here would override the header's, which no
// real npm archive needs, so it is refused rather than trusted.
function paxPath(body: Uint8Array): string | undefined {
  let path: string | undefined;
  for (let at = 0; at < body.length; ) {
    const space = body.indexOf(0x20, at);
    if (space < 0 || space - at > 20) throw new Refused(UNREADABLE);
    const length = Number(ascii(body.subarray(at, space)));
    if (!Number.isInteger(length) || length <= space - at + 1 || at + length > body.length) throw new Refused(UNREADABLE);
    const record = new TextDecoder().decode(body.subarray(space + 1, at + length - 1));
    const [key, value] = [record.slice(0, record.indexOf("=")), record.slice(record.indexOf("=") + 1)];
    if (key === "size") throw new Refused(UNREADABLE);
    if (key === "path") path = value;
    at += length;
  }
  return path;
}

function checksumOk(header: Uint8Array): boolean {
  let sum = 0;
  for (let i = 0; i < BLOCK; i++) sum += i >= 148 && i < 156 ? 0x20 : header[i]!;
  return octal(header.subarray(148, 156)) === sum;
}

// Octal digits padded with NULs or spaces. Anything else (including the base-256 form for sizes over 8 GiB) is refused.
function octal(field: Uint8Array): number {
  const digits = ascii(field).replace(/[\0 ]+$/, "").trimStart();
  if (!/^[0-7]{1,12}$/.test(digits)) throw new Refused(UNREADABLE);
  return parseInt(digits, 8);
}

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
