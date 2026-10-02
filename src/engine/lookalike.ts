import npmPopular from "../../data/popular-npm.json";
import pypiPopular from "../../data/popular-pypi.json";
import type { Ecosystem } from "./normalize";

interface Popular {
  name: string;
  lower: string;
  rank: number;
}

interface PopularIndex {
  names: Set<string>;
  byLength: Map<number, Popular[]>;
  byLower: Map<string, Popular[]>;
  byParts: Map<string, Popular[]>;
}

const MAX_SUGGESTIONS = 3;
// Measured on the 1,000 legitimate packages ranked just below each list: allowing two edits, or checking names
// under five characters, flagged 9–13% of them; one edit on longer names keeps typos like "reqeusts" and "expres".
const MAX_EDITS = 1;
const MIN_LENGTH_FOR_EDITS = 5;
const PADDING_PREFIX = /^(?:py|python|node|js)[-_.]/;
const PADDING_SUFFIX = /[-_.](?:py|python|node|js|lib)$/;

// Built once per isolate; names are ordered by popularity, so the array index is the rank.
const INDEX: Record<Ecosystem, PopularIndex> = { npm: buildIndex(npmPopular), pypi: buildIndex(pypiPopular) };

export const isPopular = (ecosystem: Ecosystem, name: string) => INDEX[ecosystem].names.has(name);

export function findLookalikes(ecosystem: Ecosystem, name: string): string[] {
  const index = INDEX[ecosystem];
  if (index.names.has(name)) return [];

  const lower = name.toLowerCase();
  const scope = scopeOf(lower);
  const matches = new Map<Popular, number>();
  const keep = (popular: Popular, edits: number) => {
    // Only a scope's owner can publish inside it, so a near-miss on a sibling package isn't a squat.
    if (scope && scopeOf(popular.lower) === scope && popular.lower !== lower) return;
    matches.set(popular, Math.min(matches.get(popular) ?? edits, edits));
  };

  if (lower.length >= MIN_LENGTH_FOR_EDITS) {
    for (let length = lower.length - MAX_EDITS; length <= lower.length + MAX_EDITS; length++) {
      for (const popular of index.byLength.get(length) ?? []) {
        const edits = editDistance(lower, popular.lower, MAX_EDITS);
        if (edits <= MAX_EDITS) keep(popular, edits);
      }
    }
  }
  for (const popular of index.byParts.get(partsKey(lower)) ?? []) keep(popular, 1);
  for (const unpadded of [lower.replace(PADDING_PREFIX, ""), lower.replace(PADDING_SUFFIX, "")]) {
    if (unpadded !== lower) for (const popular of index.byLower.get(unpadded) ?? []) keep(popular, 1);
  }

  return [...matches]
    .sort(([a, aEdits], [b, bEdits]) => aEdits - bEdits || a.rank - b.rank)
    .slice(0, MAX_SUGGESTIONS)
    .map(([popular]) => popular.name);
}

function buildIndex(names: string[]): PopularIndex {
  const index: PopularIndex = { names: new Set(names), byLength: new Map(), byLower: new Map(), byParts: new Map() };
  names.forEach((name, rank) => {
    const popular = { name, lower: name.toLowerCase(), rank };
    push(index.byLength, popular.lower.length, popular);
    push(index.byLower, popular.lower, popular);
    push(index.byParts, partsKey(popular.lower), popular);
  });
  return index;
}

function push<K>(map: Map<K, Popular[]>, key: K, popular: Popular) {
  const list = map.get(key);
  if (list) list.push(popular);
  else map.set(key, [popular]);
}

function scopeOf(lower: string): string | undefined {
  return lower.startsWith("@") ? lower.slice(0, lower.indexOf("/")) : undefined;
}

// Same parts in any order: "dateutil-python" and "python-dateutil" share a key.
function partsKey(lower: string): string {
  return lower.split(/[-_.]/).sort().join(" ");
}

// Edit distance where swapping two neighboring characters counts as one edit (optimal string alignment).
// Stops early once every path is already over `max`.
function editDistance(a: string, b: string, max: number): number {
  let twoBack: number[] = [];
  let previous = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const current = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      let value = Math.min(previous[j]! + 1, current[j - 1]! + 1, previous[j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) value = Math.min(value, twoBack[j - 2]! + 1);
      current.push(value);
      rowMin = Math.min(rowMin, value);
    }
    if (rowMin > max) return max + 1;
    twoBack = previous;
    previous = current;
  }
  return previous[b.length]!;
}
