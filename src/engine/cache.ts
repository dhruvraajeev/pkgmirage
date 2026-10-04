import type { CodeCheck } from "./code";
import type { Ecosystem } from "./normalize";
import { chunks } from "./registry";
import type { CheckResult } from "./score";

// KV allows 1,000 operations per request; a bulk read of up to 100 keys is one, so a big scan doesn't run out.
const BULK_READ_KEYS = 100;

const MINUTE = 60;
const HOUR = 60 * MINUTE;

const key = (ecosystem: Ecosystem, name: string) => `res:${ecosystem}:${name}`;
// A published version's archive never changes; the version in the key changes when the rules reading it do.
const codeKey = (name: string, version: string) => `code:v3:npm:${name}@${version}`;
const CODE_SECONDS = 30 * 24 * HOUR;

// The cached verdicts among `names`. The cache only saves work; if KV misbehaves the check still runs.
export async function readCached(cache: KVNamespace, ecosystem: Ecosystem, names: string[]): Promise<Map<string, CheckResult>> {
  const hits = new Map<string, CheckResult>();
  await Promise.all(
    chunks(names, BULK_READ_KEYS).map(async (batch) => {
      try {
        const found = await cache.get<CheckResult>(batch.map((name) => key(ecosystem, name)), "json");
        for (const name of batch) {
          const result = found.get(key(ecosystem, name));
          if (result) hits.set(name, result);
        }
      } catch {}
    }),
  );
  return hits;
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

export async function readCode(cache: KVNamespace, name: string, version: string): Promise<CodeCheck | null> {
  try {
    return await cache.get<CodeCheck>(codeKey(name, version), "json");
  } catch {
    return null;
  }
}

// Only a completed read is kept; a failure is tried again next time.
export async function writeCode(cache: KVNamespace, name: string, version: string, code: CodeCheck): Promise<void> {
  if (code.status !== "read") return;
  try {
    await cache.put(codeKey(name, version), JSON.stringify(code), { expirationTtl: CODE_SECONDS });
  } catch {}
}

// Missing names get registered (that's the attack), so "doesn't exist" is trusted briefly; so is a block for
// registering a watched name, so clearing the name takes effect soon. Any other block on a package that exists
// rarely reverses. Anything unverified is never stored, so the next request tries again.
function cacheSeconds({ verdict, checks }: CheckResult): number | null {
  const { registry, osv, code } = checks;
  if (registry.status === "skipped" || registry.status === "error" || osv.status === "error" || code.status === "error") return null;
  if (registry.status === "found" && registry.downloadsError) return null;
  if (registry.status === "not_found" || checks.seenInvented) return 10 * MINUTE;
  if (verdict === "block") return 24 * HOUR;
  return verdict === "safe" ? 6 * HOUR : HOUR;
}
