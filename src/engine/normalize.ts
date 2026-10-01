export type Ecosystem = "npm" | "pypi";

export type NameResult = { ok: true; name: string } | { ok: false; name: string; reason: string };

// npm keeps case: the registry is case-sensitive and legacy names like JSONStream coexist with lowercase twins.
const NPM_NAME = /^(?:@[a-z0-9~-][a-z0-9._~-]*\/)?[a-z0-9~-][a-z0-9._~-]*$/i;
// PEP 508 name syntax
const PYPI_NAME = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/i;
const INVISIBLE = /[\p{Cc}\p{Cf}]/u;
const LATIN = /\p{Script=Latin}/u;
const NON_LATIN_LETTER = /(?!\p{Script=Latin})\p{L}/u;

export function normalizeName(ecosystem: Ecosystem, raw: string): NameResult {
  const name = raw.trim();
  if (INVISIBLE.test(name)) return { ok: false, name, reason: "contains invisible or control characters" };
  if (LATIN.test(name) && NON_LATIN_LETTER.test(name)) {
    return { ok: false, name, reason: "uses look-alike characters from another alphabet" };
  }
  if (ecosystem === "npm") {
    return NPM_NAME.test(name) ? { ok: true, name } : { ok: false, name, reason: "not a valid npm package name" };
  }
  return PYPI_NAME.test(name)
    ? { ok: true, name: name.replace(/[-_.]+/g, "-").toLowerCase() }
    : { ok: false, name, reason: "not a valid PyPI package name" };
}

export function normalizeBatch(ecosystem: Ecosystem, names: string[]): NameResult[] {
  // Duplicates normalize to identical results, so keying by name dedupes while keeping first-seen order.
  return [...new Map(names.map((raw) => normalizeName(ecosystem, raw)).map((r) => [r.name, r] as const)).values()];
}
