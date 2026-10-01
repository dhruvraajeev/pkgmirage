import { readCached, writeCached } from "./cache";
import { findLookalikes } from "./lookalike";
import { normalizeBatch, type Ecosystem } from "./normalize";
import { checkOsv, type OsvCheck } from "./osv";
import { lookup, type RegistryCheck } from "./registry";
import { score, type CheckResult } from "./score";

const MAX_CONCURRENT_LOOKUPS = 10;

export async function checkPackages(ecosystem: Ecosystem, names: string[], cache?: KVNamespace): Promise<CheckResult[]> {
  const parsed = normalizeBatch(ecosystem, names);
  const cached = await Promise.all(parsed.map((p) => (p.ok && cache ? readCached(cache, ecosystem, p.name) : null)));
  const misses = parsed.filter((p, i) => p.ok && !cached[i]).map((p) => p.name);

  const registry = new Map<string, RegistryCheck>(
    await mapLimit(misses, MAX_CONCURRENT_LOOKUPS, async (name) => [name, await lookup(ecosystem, name)] as const),
  );
  const found = [...registry].flatMap(([name, check]) => (check.status === "found" ? [{ name, version: check.latestVersion }] : []));
  const osvResults = await checkOsv(ecosystem, found);
  const osv = new Map<string, OsvCheck>(found.map(({ name }, i) => [name, osvResults[i]!]));

  const results = parsed.map(
    (p, i) =>
      cached[i] ??
      score(ecosystem, p.name, {
        registry: p.ok ? registry.get(p.name)! : { status: "skipped", reason: p.reason },
        osv: osv.get(p.name) ?? { status: "skipped" },
        lookalike: findLookalikes(ecosystem, p.name),
      }),
  );
  if (cache) await Promise.all(results.filter((_, i) => parsed[i]!.ok && !cached[i]).map((r) => writeCached(cache, r)));
  return results;
}

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      results[i] = await fn(items[i]!);
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}
