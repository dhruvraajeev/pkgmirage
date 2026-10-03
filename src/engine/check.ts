import { readCached, writeCached } from "./cache";
import { checkCode, shouldOpen, type CodeCheck } from "./code";
import { findLookalikes } from "./lookalike";
import { normalizeBatch, type Ecosystem } from "./normalize";
import { checkOsv, type OsvCheck } from "./osv";
import { lookup, mapLimit } from "./registry";
import { score, type CheckResult } from "./score";
import { record, WATCH_BLOCK_DAYS, watchedNames, type Watch } from "./watch";

// PyPI records run to 12 MB, and an isolate has 128 MB. Note: four at a time narrows the peak but doesn't bound it:
// the ten largest records, four at a time, ran out of a 72 MB heap once and always fit in 80 MB (Node, same V8).
const MAX_CONCURRENT_LOOKUPS: Record<Ecosystem, number> = { npm: 10, pypi: 4 };
const DAY_MS = 86_400_000;
// Each opened archive costs a code-cache read and write: 50 keeps a 750-name scan at 858 of the 1,000 KV operations a
// request may make.
const MAX_OPENED_PER_REQUEST = 50;
const SKIPPED: CodeCheck = { status: "skipped" };

export async function checkPackages(ecosystem: Ecosystem, names: string[], cache?: KVNamespace, watch?: Watch): Promise<CheckResult[]> {
  const parsed = normalizeBatch(ecosystem, names);
  const hits = cache ? await readCached(cache, ecosystem, parsed.flatMap((p) => (p.ok ? [p.name] : []))) : new Map<string, CheckResult>();
  const cached = parsed.map((p) => (p.ok && hits.get(p.name)) || null);
  const misses = parsed.filter((p, i) => p.ok && !cached[i]).map((p) => p.name);

  let opened = 0;
  const looked = new Map(
    await mapLimit(misses, MAX_CONCURRENT_LOOKUPS[ecosystem], async (name) => {
      const check = await lookup(ecosystem, name);
      // Only the code check needs the archive details; they stay out of the verdict.
      const archive = check.status === "found" ? check.archive : undefined;
      if (check.status === "found") delete check.archive;
      const lookalike = findLookalikes(ecosystem, name);
      let code = SKIPPED;
      if (ecosystem === "npm" && check.status === "found" && shouldOpen(name, check, lookalike)) {
        code =
          opened++ < MAX_OPENED_PER_REQUEST
            ? await checkCode(name, check.latestVersion!, archive, cache)
            : { status: "error", reason: "too many packages in one request" };
      }
      return [name, { registry: check, lookalike, code }] as const;
    }),
  );
  const registry = new Map([...looked].map(([name, { registry }]) => [name, registry]));
  const found = [...registry].flatMap(([name, check]) => (check.status === "found" ? [{ name, version: check.latestVersion }] : []));
  // Only a young package can be a fresh registration of a watched name, so older ones never touch the watchlist.
  const young = [...registry].flatMap(([name, check]) =>
    check.status === "found" && (check.firstSeenAt === null || Date.now() - Date.parse(check.firstSeenAt) < WATCH_BLOCK_DAYS * DAY_MS)
      ? [name]
      : [],
  );
  const [osvResults, watched] = await Promise.all([
    checkOsv(ecosystem, found),
    watch ? watchedNames(watch.db, ecosystem, young) : new Map<string, number>(),
  ]);
  const osv = new Map<string, OsvCheck>(found.map(({ name }, i) => [name, osvResults[i]!]));

  const results = parsed.map(
    (p, i) =>
      cached[i] ??
      score(ecosystem, p.name, {
        registry: p.ok ? registry.get(p.name)! : { status: "skipped", reason: p.reason },
        osv: osv.get(p.name) ?? { status: "skipped" },
        lookalike: looked.get(p.name)?.lookalike ?? findLookalikes(ecosystem, p.name),
        code: looked.get(p.name)?.code ?? SKIPPED,
        ...(watched.has(p.name) ? { seenInvented: new Date(watched.get(p.name)!).toISOString() } : {}),
      }),
  );
  if (cache) await Promise.all(results.filter((_, i) => parsed[i]!.ok && !cached[i]).map((r) => writeCached(cache, r)));
  // A scan lists packages someone already installed: a missing one is more likely removed or private than invented,
  // and a lockfile's hundreds of names would swamp the daily counts.
  if (watch && watch.source !== "scan") record(watch, results);
  return results;
}
