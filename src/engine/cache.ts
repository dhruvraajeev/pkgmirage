import type { Ecosystem } from "./normalize";
import type { CheckResult } from "./score";

const MINUTE = 60;
const HOUR = 60 * MINUTE;

const key = (ecosystem: Ecosystem, name: string) => `res:${ecosystem}:${name}`;

// The cache only saves work; if KV misbehaves the check still runs.
export async function readCached(cache: KVNamespace, ecosystem: Ecosystem, name: string): Promise<CheckResult | null> {
  try {
    return await cache.get<CheckResult>(key(ecosystem, name), "json");
  } catch {
    return null;
  }
}

export async function writeCached(cache: KVNamespace, result: CheckResult): Promise<void> {
  const ttl = cacheSeconds(result);
  if (ttl === null) return;
  try {
    await cache.put(key(result.ecosystem, result.name), JSON.stringify(result), { expirationTtl: ttl });
  } catch {
    // A failed write only costs a repeat lookup later.
  }
}

// Missing names get registered (that's the attack), so "doesn't exist" is trusted briefly; a block on a package
// that exists rarely reverses. Anything unverified is never stored, so the next request tries again.
function cacheSeconds({ verdict, checks }: CheckResult): number | null {
  const { registry, osv } = checks;
  if (registry.status === "skipped" || registry.status === "error" || osv.status === "error") return null;
  if (registry.status === "found" && registry.downloadsError) return null;
  if (registry.status === "not_found") return 10 * MINUTE;
  if (verdict === "block") return 24 * HOUR;
  return verdict === "safe" ? 6 * HOUR : HOUR;
}
