import { fetchJson } from "./fetch";
import type { Ecosystem } from "./normalize";

export type OsvCheck = { status: "ok"; advisories: string[] } | { status: "error"; reason: string } | { status: "skipped" };

const OSV_ECOSYSTEMS: Record<Ecosystem, string> = { npm: "npm", pypi: "PyPI" };

// One request for the whole batch. Note: querybatch pages past 1,000 advisories per package; no real package
// comes close, so the page token is ignored.
export async function checkOsv(ecosystem: Ecosystem, packages: { name: string; version: string | null }[]): Promise<OsvCheck[]> {
  if (!packages.length) return [];
  const queries = packages.map(({ name, version }) => ({
    package: { name, ecosystem: OSV_ECOSYSTEMS[ecosystem] },
    ...(version === null ? {} : { version }),
  }));
  const result = await fetchJson("https://api.osv.dev/v1/querybatch", { body: { queries } });
  const results = result.status === "ok" ? (result.data as { results?: unknown } | null)?.results : undefined;
  if (!Array.isArray(results) || results.length !== packages.length) {
    const reason = result.status === "error" ? result.reason : "invalid response";
    return packages.map(() => ({ status: "error", reason }));
  }
  return results.map((entry) => {
    const vulns = (entry as { vulns?: unknown } | null)?.vulns;
    const ids = Array.isArray(vulns) ? vulns.map((v) => (v as { id?: unknown } | null)?.id) : [];
    return { status: "ok", advisories: ids.filter((id): id is string => typeof id === "string") };
  });
}
