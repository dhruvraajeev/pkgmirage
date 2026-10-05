// The accuracy evaluation's own logic, kept apart from its network and file handling so it can be tested.
import { checkCode, shouldOpen, type CodeCheck } from "../src/engine/code";
import { lookup } from "../src/engine/registry";
import { score, type CheckResult } from "../src/engine/score";

export type Outcome = "block" | "caution" | "unverified" | "safe";
export type State = "live" | "removed" | "placeholder" | "clean-now" | "unreachable" | "invalid";

export interface Sample {
  name: string;
  // Malicious samples: the advisory, when it was published and which versions it covers.
  id?: string;
  published?: string;
  versions?: "all" | string[];
  rank?: number;
}

// A small seeded generator (mulberry32), so a re-run samples the same names.
function random(seed: number): () => number {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// `n` items drawn without replacement (a partial Fisher-Yates shuffle of a copy).
export function pick<T>(items: T[], n: number, seed: number): T[] {
  const copy = [...items];
  const next = random(seed);
  const count = Math.min(n, copy.length);
  for (let i = 0; i < count; i++) {
    const j = i + Math.floor(next() * (copy.length - i));
    [copy[i], copy[j]] = [copy[j]!, copy[i]!];
  }
  return copy.slice(0, count);
}

export function uniqueBy<T>(items: T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter((item) => !seen.has(key(item)) && seen.add(key(item)));
}

// The parts of an OSV advisory the evaluation reads.
export interface Advisory {
  withdrawn?: string;
  published?: string;
  affected?: { package?: { name?: string; ecosystem?: string }; ranges?: { type?: string; events?: Record<string, string>[] }[]; versions?: string[] }[];
}

// "all" when any range is open-ended (introduced and never fixed), which covers the latest version; otherwise the
// versions it lists.
export function coverage(advisory: Advisory): "all" | string[] {
  const affected = advisory.affected ?? [];
  const openEnded = affected.some((a) => (a.ranges ?? []).some((r) => (r.events ?? []).every((event) => "introduced" in event)));
  return openEnded ? "all" : affected.flatMap((a) => a.versions ?? []);
}

export function outcome(result: CheckResult): Outcome {
  if (result.verdict !== "caution") return result.verdict;
  return result.reasons.some((reason) => reason.startsWith("unverified:")) ? "unverified" : "caution";
}

export function state(sample: Sample, result: CheckResult): State {
  const registry = result.checks.registry;
  if (registry.status === "not_found") return "removed";
  if (registry.status === "error") return "unreachable";
  if (registry.status === "skipped") return "invalid";
  if (result.ecosystem === "npm" && registry.latestVersion?.endsWith("-security")) return "placeholder";
  const { versions } = sample;
  if (Array.isArray(versions) && !(registry.latestVersion !== null && versions.includes(registry.latestVersion))) return "clean-now";
  return "live";
}

// The first reason of a block is what decided it (score.ts orders them that way).
export function blockCause(result: CheckResult): string {
  if (result.checks.registry.status === "skipped") return "invalid name";
  const first = result.reasons[0] ?? "";
  if (first.startsWith("known malicious")) return "malware database";
  if (first.startsWith("taken down by npm")) return "npm takedown";
  if (first.startsWith("doesn't exist")) return "doesn't exist";
  if (/^(?:install script|package code) (?:runs|reads|sends|is) /.test(first)) return "code check";
  if (first.startsWith("looks like popular package")) return "look-alike";
  if (first.startsWith("registered after")) return "watchlist";
  return "other";
}

// Whether a row counts toward its set's rates: malware no longer in the latest version isn't malware any more, and a
// "legitimate" name that no longer exists, or that the malware database lists, isn't a legitimate package.
export function counted(set: string, sample: Sample, result: CheckResult): boolean {
  const s = state(sample, result);
  if (set === "malicious") return s !== "clean-now";
  if (set === "invented") return true;
  return s !== "removed" && !(result.verdict === "block" && blockCause(result) === "malware database");
}

export function tally(outcomes: Outcome[]): Record<Outcome, number> & { n: number } {
  const counts = { n: outcomes.length, block: 0, caution: 0, unverified: 0, safe: 0 };
  for (const o of outcomes) counts[o]++;
  return counts;
}

export const rate = (part: number, whole: number) => (whole ? `${((100 * part) / whole).toFixed(1)}% (${part}/${whole})` : "n/a");

// Groups reasons that differ only in numbers, quoted names or the detail in parentheses.
export const reasonKey = (reason: string) =>
  reason
    .replace(/\s*\(.*\)$/, "")
    .replace(/"[^"]*"/g, '"…"')
    .replace(/\d+/g, "N");

// The verdict as it would have been on the report date, with no malware database: age signals as of then, and the
// archive read if the selection rule would have opened it then. Download counts and code are as they are today.
export async function atReport(today: CheckResult, reportedAt: number): Promise<CheckResult> {
  const { name, ecosystem, checks } = today;
  const registry = checks.registry;
  let code: CodeCheck = checks.code;
  if (ecosystem === "npm" && registry.status === "found" && code.status === "skipped" && shouldOpen(name, registry, checks.lookalike, reportedAt)) {
    // The verdict leaves out the archive details, so the record is read again.
    const again = await lookup("npm", name);
    code = again.status === "found" ? await checkCode(name, again.latestVersion!, again.archive) : { status: "error", reason: "registry unavailable" };
  }
  return score(ecosystem, name, { ...checks, osv: { status: "skipped" }, code }, reportedAt);
}
