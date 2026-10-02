import { readCached, writeCached } from "./cache";
import { findLookalikes } from "./lookalike";
import { normalizeBatch, type Ecosystem } from "./normalize";
import { checkOsv, type OsvCheck } from "./osv";
import { lookup, mapLimit, type RegistryCheck } from "./registry";
import { score, type CheckResult } from "./score";
import { record, WATCH_BLOCK_DAYS, watchedNames, type Watch } from "./watch";

// PyPI records run to 12 MB, and an isolate has 128 MB. Note: four at a time narrows the peak but doesn't bound it:
// the ten largest records, four at a time, ran out of a 72 MB heap once and always fit in 80 MB (Node, same V8).
const MAX_CONCURRENT_LOOKUPS: Record<Ecosystem, number> = { npm: 10, pypi: 4 };
const DAY_MS = 86_400_000;

export async function checkPackages(ecosystem: Ecosystem, names: string[], cache?: KVNamespace, watch?: Watch): Promise<CheckResult[]> {
  const parsed = normalizeBatch(ecosystem, names);
  const hits = cache ? await readCached(cache, ecosystem, parsed.flatMap((p) => (p.ok ? [p.name] : []))) : new Map<string, CheckResult>();
  const cached = parsed.map((p) => (p.ok && hits.get(p.name)) || null);
  const misses = parsed.filter((p, i) => p.ok && !cached[i]).map((p) => p.name);

  const registry = new Map<string, RegistryCheck>(
    await mapLimit(misses, MAX_CONCURRENT_LOOKUPS[ecosystem], async (name) => [name, await lookup(ecosystem, name)] as const),
  );
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
        lookalike: findLookalikes(ecosystem, p.name),
        ...(watched.has(p.name) ? { seenInvented: new Date(watched.get(p.name)!).toISOString() } : {}),
      }),
  );
  if (cache) await Promise.all(results.filter((_, i) => parsed[i]!.ok && !cached[i]).map((r) => writeCached(cache, r)));
  // A scan lists packages someone already installed: a missing one is more likely removed or private than invented,
  // and a lockfile's hundreds of names would swamp the daily counts.
  if (watch && watch.source !== "scan") record(watch, results);
  return results;
}
