// Accuracy evaluation: the real engine against known malware, invented names and legitimate packages.
// Usage: npm run eval -- fetch   samples the datasets into eval/samples/ (names and advisory facts only, never code)
//        npm run eval -- run     checks every sample against the live registries, writes eval/results.md
// Runs under Node (bundled with esbuild, the Workers module stubbed), with no cache and no watchlist. Run one at a time:
// api.npmjs.org rate-limits download counts, and two runs at once turn more results unverified.
import { execSync } from "node:child_process";
import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import { checkPackages } from "../src/engine/check";
import type { Ecosystem } from "../src/engine/normalize";
import { mapLimit } from "../src/engine/registry";
import type { CheckResult } from "../src/engine/score";
import { atReport, blockCause, counted, coverage, type Advisory, outcome, pick, rate, reasonKey, state, tally, uniqueBy, type Outcome, type Sample } from "./eval-core";

const SEED = 17;
const DAY_MS = 86_400_000;
const ECOSYSTEMS: Ecosystem[] = ["npm", "pypi"];
const SAMPLES_DIR = "eval/samples";
const USER_AGENT = { "user-agent": "pkgmirage-eval/0.1" };

const OSV = "https://osv-vulnerabilities.storage.googleapis.com";
const OSV_NAMES: Record<Ecosystem, string> = { npm: "npm", pypi: "PyPI" };
const MALWARE_YEARS = [2022, 2023, 2024, 2025, 2026];
const PER_YEAR = 100;
const RECENT_DAYS = 30;
const RECENT_CAP: Record<Ecosystem, number> = { npm: 200, pypi: 100 };
const INVENTED = "https://raw.githubusercontent.com/churik5/slopsquatting-replication-2026/v0.2-preprint/disclosure";
const RANKS = "https://packages.ecosyste.ms/api/v1/registries";
const RANK_REGISTRIES: Record<Ecosystem, string> = { npm: "npmjs.org", pypi: "pypi.org" };
const RANK_PAGE = 1_000;
const TOP = { n: 500, below: 10_000 };
const MID = { n: 1_000, from: 10_000, below: 100_000 };
const INSTALL_SCRIPTS_BELOW = 50_000;
// The engine already limits lookups per batch; batches run one after another with a pause, so npm's record and
// /latest endpoints and the downloads API see a steady trickle rather than bursts.
const BATCH = 50;
const PAUSE_MS = 1_000;

interface SampleFile {
  source: string;
  fetchedAt: string;
  groups: Record<string, Sample[]>;
  // Names that couldn't be sampled (a failed lookup while building the file).
  failed?: number;
}

interface Row {
  set: string;
  ecosystem: Ecosystem;
  group: string;
  sample: Sample;
  result: CheckResult;
  atReport?: CheckResult;
}

// Retries rate limits, server errors and dropped connections (sampling makes ~50,000 requests); a 404 is an answer.
async function get(url: string, headers: Record<string, string> = {}): Promise<Response> {
  for (let attempt = 0; ; attempt++) {
    try {
      const res = await fetch(url, { headers: { ...USER_AGENT, ...headers } });
      if ((res.status !== 429 && res.status < 500) || attempt === 3) return res;
    } catch (err) {
      if (attempt === 3) throw err;
    }
    await new Promise((resolve) => setTimeout(resolve, 2_000 * 2 ** attempt));
  }
}

async function getJson(url: string, headers?: Record<string, string>): Promise<unknown> {
  const res = await get(url, headers);
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  return res.json();
}

const pep503 = (name: string) => name.replace(/[-_.]+/g, "-").toLowerCase();
const key = (ecosystem: Ecosystem, name: string) => (ecosystem === "pypi" ? pep503(name) : name);

// --- fetch ---------------------------------------------------------------------------------------------------------

async function advisory(ecosystem: Ecosystem, id: string): Promise<Sample | null> {
  const v = (await getJson(`${OSV}/${OSV_NAMES[ecosystem]}/${id}.json`)) as Advisory;
  const name = v.affected?.[0]?.package?.name;
  return v.withdrawn || !name ? null : { name, id, published: v.published, versions: coverage(v) };
}

async function malicious(ecosystem: Ecosystem): Promise<SampleFile> {
  const csv = await (await get(`${OSV}/${OSV_NAMES[ecosystem]}/modified_id.csv`)).text();
  const ids = csv
    .trim()
    .split("\n")
    .map((line) => line.split(",")[1] ?? "")
    .filter((id) => id.startsWith("MAL-"));
  const number = (id: string) => Number(id.split("-")[2]);
  const seen = new Set<string>();
  const fresh = (samples: (Sample | null)[]) =>
    samples.filter((s): s is Sample => s !== null && !seen.has(key(ecosystem, s.name)) && !!seen.add(key(ecosystem, s.name)));

  // The newest IDs first, until a whole chunk was published before the window.
  const year = new Date().getUTCFullYear();
  const cutoff = Date.now() - RECENT_DAYS * DAY_MS;
  const newest = ids.filter((id) => id.startsWith(`MAL-${year}-`)).sort((a, b) => number(b) - number(a));
  let recent: Sample[] = [];
  for (let i = 0; i < newest.length; i += BATCH) {
    const chunk = (await mapLimit(newest.slice(i, i + BATCH), 16, (id) => advisory(ecosystem, id))).filter((s): s is Sample => s !== null);
    const inWindow = chunk.filter((s) => Date.parse(s.published ?? "") >= cutoff);
    recent.push(...inWindow);
    if (!inWindow.length) break;
  }
  recent = fresh(pick(uniqueBy(recent, (s) => key(ecosystem, s.name)), RECENT_CAP[ecosystem], SEED));

  const groups: Record<string, Sample[]> = { recent };
  for (const y of MALWARE_YEARS) {
    const shuffled = pick(
      ids.filter((id) => id.startsWith(`MAL-${y}-`)),
      Infinity,
      SEED + y,
    );
    const taken: Sample[] = [];
    for (let i = 0; i < shuffled.length && taken.length < PER_YEAR; i += BATCH) {
      taken.push(...fresh(await mapLimit(shuffled.slice(i, i + BATCH), 16, (id) => advisory(ecosystem, id))));
    }
    groups[String(y)] = taken.slice(0, PER_YEAR);
  }
  return { source: `OSV ${OSV}/${OSV_NAMES[ecosystem]}/ (MAL- advisories, not withdrawn)`, fetchedAt: new Date().toISOString(), groups };
}

async function invented(ecosystem: Ecosystem): Promise<SampleFile> {
  const url = `${INVENTED}/${ecosystem}_universal_hallucinations.csv`;
  const csv = await (await get(url)).text();
  const names = uniqueBy(
    csv
      .trim()
      .split("\n")
      .map((line) => line.split(",")[0]!.trim())
      .filter(Boolean),
    (name) => key(ecosystem, name),
  );
  return { source: url, fetchedAt: new Date().toISOString(), groups: { all: names.map((name) => ({ name })) } };
}

// Names by downloads, most first; the index is the rank minus one.
async function ranked(ecosystem: Ecosystem, below: number): Promise<string[]> {
  const pages = await mapLimit(
    Array.from({ length: below / RANK_PAGE }, (_, i) => i + 1),
    4,
    (page) =>
      getJson(`${RANKS}/${RANK_REGISTRIES[ecosystem]}/package_names?sort=downloads&order=desc&per_page=${RANK_PAGE}&page=${page}`) as Promise<string[]>,
  );
  return uniqueBy(pages.flat(), (name) => key(ecosystem, name));
}

async function legit(ecosystem: Ecosystem, names: string[]): Promise<SampleFile> {
  const withRank = names.map((name, i) => ({ name, rank: i + 1 }));
  return {
    source: `ecosyste.ms ${RANKS}/${RANK_REGISTRIES[ecosystem]}/package_names?sort=downloads (data CC BY-SA 4.0)`,
    fetchedAt: new Date().toISOString(),
    groups: {
      top: pick(withRank.slice(0, TOP.below), TOP.n, SEED),
      mid: pick(withRank.slice(MID.from, MID.below), MID.n, SEED),
    },
  };
}

// Every package in the top 50,000 whose latest version has an install script, from npm's abbreviated records.
async function installScripts(names: string[]): Promise<SampleFile> {
  let failed = 0;
  const found = await mapLimit(names.slice(0, INSTALL_SCRIPTS_BELOW), 24, async (name) => {
    try {
      const record = (await getJson(`https://registry.npmjs.org/${name.replace("/", "%2F")}`, {
        accept: "application/vnd.npm.install-v1+json",
      })) as { "dist-tags"?: { latest?: string }; versions?: Record<string, { hasInstallScript?: boolean }> };
      const latest = record["dist-tags"]?.latest;
      return latest && record.versions?.[latest]?.hasInstallScript ? name : null;
    } catch {
      failed++;
      return null;
    }
  });
  const rank = new Map(names.map((name, i) => [name, i + 1]));
  return {
    source: `npm abbreviated records (hasInstallScript on the latest version) of the top ${INSTALL_SCRIPTS_BELOW.toLocaleString("en")} by downloads (ecosyste.ms)`,
    fetchedAt: new Date().toISOString(),
    groups: { all: found.filter((name): name is string => name !== null).map((name) => ({ name, rank: rank.get(name)! })) },
    failed,
  };
}

async function fetchSamples() {
  await mkdir(SAMPLES_DIR, { recursive: true });
  const save = (file: string, data: SampleFile) => writeFile(`${SAMPLES_DIR}/${file}.json`, JSON.stringify(data, null, 1) + "\n");
  for (const ecosystem of ECOSYSTEMS) {
    console.error(`${ecosystem}: malicious`);
    await save(`malicious-${ecosystem}`, await malicious(ecosystem));
    console.error(`${ecosystem}: invented`);
    await save(`invented-${ecosystem}`, await invented(ecosystem));
    console.error(`${ecosystem}: ranks`);
    const names = await ranked(ecosystem, MID.below);
    await save(`legit-${ecosystem}`, await legit(ecosystem, names));
    if (ecosystem === "npm") {
      console.error("npm: install scripts");
      await save("install-scripts-npm", await installScripts(names));
    }
  }
}

// --- run -----------------------------------------------------------------------------------------------------------

async function check(ecosystem: Ecosystem, samples: Sample[]): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  for (let i = 0; i < samples.length; i += BATCH) {
    const batch = samples.slice(i, i + BATCH);
    const answers = await checkPackages(
      ecosystem,
      batch.map((s) => s.name),
    );
    // Samples are unique after normalization, so answers line up with them.
    if (answers.length !== batch.length) throw new Error(`${ecosystem}: ${batch.length} names gave ${answers.length} results`);
    results.push(...answers);
    console.error(`  ${ecosystem} ${Math.min(i + BATCH, samples.length)}/${samples.length}`);
    await new Promise((resolve) => setTimeout(resolve, PAUSE_MS));
  }
  return results;
}

async function run() {
  const started = new Date();
  const files = (await readdir(SAMPLES_DIR)).filter((f) => f.endsWith(".json")).sort();
  const rows: Row[] = [];
  const meta: Record<string, SampleFile> = {};
  for (const file of files) {
    const [, set, ecosystem] = /^(.+)-(npm|pypi)\.json$/.exec(file)!;
    const data = JSON.parse(await readFile(`${SAMPLES_DIR}/${file}`, "utf8")) as SampleFile;
    meta[file] = data;
    for (const [group, samples] of Object.entries(data.groups)) {
      console.error(`${set} ${ecosystem} ${group}: ${samples.length}`);
      const results = await check(ecosystem as Ecosystem, samples);
      for (const [i, sample] of samples.entries()) {
        const result = results[i]!;
        const row: Row = { set: set!, ecosystem: ecosystem as Ecosystem, group, sample, result };
        if (set === "malicious" && sample.published && state(sample, result) === "live") row.atReport = await atReport(result, Date.parse(sample.published));
        rows.push(row);
      }
    }
  }
  await writeFile("eval/raw.json", JSON.stringify(rows) + "\n");
  await writeFile("eval/results.md", render(rows, meta, started, new Date()));
  console.error("wrote eval/results.md");
}

// --- report --------------------------------------------------------------------------------------------------------

const included = (row: Row) => counted(row.set, row.sample, row.result);

function table(header: string[], lines: (string | number)[][]): string {
  return [header, header.map(() => "---"), ...lines].map((cells) => `| ${cells.join(" | ")} |`).join("\n");
}

function outcomeLine(label: string[], rows: Row[], left: number, of: (row: Row) => CheckResult = (row) => row.result) {
  const t = tally(rows.map((row) => outcome(of(row))));
  return [...label, t.n + left, left, t.block, t.caution, t.unverified, t.safe, rate(t.block, t.n), rate(t.block, t.n - t.unverified), rate(t.n - t.safe, t.n)];
}

function count<T extends string>(items: T[]): [T, number][] {
  const counts = new Map<T, number>();
  for (const item of items) counts.set(item, (counts.get(item) ?? 0) + 1);
  return [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

function render(rows: Row[], meta: Record<string, SampleFile>, started: Date, finished: Date): string {
  const sh = (cmd: string) => execSync(cmd, { encoding: "utf8" }).trim();
  const commit = sh("git rev-parse --short HEAD") + (sh("git status --porcelain -- src scripts") ? " plus uncommitted changes" : "");
  const sets = ["malicious", "invented", "legit", "install-scripts"];
  const groupsOf = (set: string, ecosystem: Ecosystem) => [...new Set(rows.filter((r) => r.set === set && r.ecosystem === ecosystem).map((r) => r.group))];
  const head = ["set", "ecosystem", "group", "samples", "left out", "block", "caution", "unverified", "safe", "blocked", "blocked (verified only)", "flagged"];

  const lines: (string | number)[][] = [];
  for (const set of sets) {
    for (const ecosystem of ECOSYSTEMS) {
      for (const group of groupsOf(set, ecosystem)) {
        const all = rows.filter((r) => r.set === set && r.ecosystem === ecosystem && r.group === group);
        if (set === "invented") {
          for (const [label, exists] of [["doesn't exist", false], ["exists today", true]] as const) {
            const part = all.filter((r) => (state(r.sample, r.result) !== "removed") === exists);
            if (part.length) lines.push(outcomeLine([set, ecosystem, label], part, 0));
          }
        } else {
          const kept = all.filter(included);
          lines.push(outcomeLine([set, ecosystem, group], kept, all.length - kept.length));
        }
      }
    }
  }

  const states = ECOSYSTEMS.map((ecosystem) => {
    const mal = rows.filter((r) => r.set === "malicious" && r.ecosystem === ecosystem);
    const by = new Map(count(mal.map((r) => state(r.sample, r.result))));
    return [ecosystem, mal.length, ...(["live", "removed", "placeholder", "clean-now", "unreachable", "invalid"] as const).map((s) => by.get(s) ?? 0)];
  });

  const causes = sets.flatMap((set) =>
    ECOSYSTEMS.flatMap((ecosystem) => {
      const blocked = rows.filter((r) => r.set === set && r.ecosystem === ecosystem && included(r) && r.result.verdict === "block");
      return blocked.length ? [[set, ecosystem, count(blocked.map((r) => blockCause(r.result))).map(([c, n]) => `${c} ${n}`).join(", ")]] : [];
    }),
  );

  const early = ECOSYSTEMS.flatMap((ecosystem) => {
    const live = rows.filter((r) => r.set === "malicious" && r.ecosystem === ecosystem && r.atReport);
    const byGroup = (["all", ...groupsOf("malicious", ecosystem)] as string[]).map((group) => live.filter((r) => group === "all" || r.group === group));
    return byGroup.flatMap((part, i) => (part.length ? [outcomeLine(["malicious", ecosystem, i ? groupsOf("malicious", ecosystem)[i - 1]! : "all"], part, 0, (r) => r.atReport!)] : []));
  });

  const reasons = (set: string, ecosystem: Ecosystem) =>
    count(
      rows
        .filter((r) => r.set === set && r.ecosystem === ecosystem && included(r) && r.result.verdict !== "safe")
        .flatMap((r) => [...new Set(r.result.reasons.map(reasonKey))]),
    ).slice(0, 12);
  const reasonTables = (["legit", "install-scripts"] as const).flatMap((set) =>
    ECOSYSTEMS.filter((ecosystem) => rows.some((r) => r.set === set && r.ecosystem === ecosystem)).map(
      (ecosystem) => `**${set}, ${ecosystem}** (packages with each reason; a package can have several)\n\n${table(["reason", "packages"], reasons(set, ecosystem))}`,
    ),
  );

  const falseBlocks = rows.filter((r) => (r.set === "legit" || r.set === "install-scripts") && included(r) && r.result.verdict === "block");
  const malwareInLegit = rows.filter((r) => (r.set === "legit" || r.set === "install-scripts") && r.result.verdict === "block" && blockCause(r.result) === "malware database");
  const code = rows.filter((r) => r.set === "install-scripts");
  const codeStatus = count(code.map((r) => r.result.checks.code.status));
  const findings = count(
    code.flatMap((r) => (r.result.checks.code.status === "read" ? r.result.checks.code.findings.map((f) => `${f.where}:${f.id}` as string) : [])),
  );
  const outcomesOf = (set: string) => count(rows.filter((r) => r.set === set).map((r) => outcome(r.result) as Outcome));

  return `# Accuracy evaluation

Measured ${started.toISOString().slice(0, 16).replace("T", " ")}–${finished.toISOString().slice(11, 16)} UTC on commit ${commit}, Node ${process.version}, npm ${sh("npm -v")}.

**How:** \`npm run eval -- run\` checks every sampled name with the same \`checkPackages()\` the guard, MCP tools and API
use, bundled for Node, against the live npm, PyPI and OSV services, with no cache and no watchlist, ${BATCH} names at a
time, one run at a time. Samples were drawn with seed ${SEED} by \`npm run eval -- fetch\` and are committed in
\`eval/samples/\` (names and advisory facts only).

**Reading the table:** *block*, *caution* and *safe* are the verdicts; *unverified* is a caution where some lookup
couldn't finish (usually api.npmjs.org's rate limit on download counts), never counted as safe. *Blocked* is the share
blocked (the catch rate for malicious and invented names, the false-block rate for legitimate ones); *flagged* is
blocked, caution or unverified. *Left out*: malicious packages whose latest version is no longer affected by the
advisory, and "legitimate" names that no longer exist or that the malware database lists (listed below).

## Results

${table(head, lines)}

## Malicious packages: what is on the registry today

${table(["ecosystem", "samples", "live", "removed", "npm placeholder", "clean now", "unreachable", "invalid name"], states)}

## What caused each block

${table(["set", "ecosystem", "causes (by first reason)"], causes)}

## Would it have been caught before it was reported?

Live malicious packages only (the others can no longer be read), scored as of the advisory's publish date with the
malware database removed: age as it was then, the archive opened if the selection rule would have opened it then.
Download counts and code are today's.

${table(head, early)}

## Most common reasons on legitimate packages

${reasonTables.join("\n\n")}

## False blocks

${falseBlocks.length ? table(["set", "ecosystem", "package", "rank", "reasons"], falseBlocks.map((r) => [r.set, r.ecosystem, `\`${r.sample.name}\``, r.sample.rank ?? "", r.result.reasons.join("; ")])) : "None."}

Known malware among the "legitimate" samples (left out of their rows): ${malwareInLegit.map((r) => `\`${r.sample.name}\` (${r.set}, rank ${r.sample.rank}, ${r.result.reasons[0]})`).join(", ") || "none"}.

## Code checks on popular npm packages with install scripts

Code check status: ${codeStatus.map(([s, n]) => `${s} ${n}`).join(", ")}. Findings (packages with each): ${findings.map(([f, n]) => `${f} ${n}`).join(", ") || "none"}.
Outcomes: ${outcomesOf("install-scripts").map(([o, n]) => `${o} ${n}`).join(", ")}.

## Datasets

${Object.entries(meta)
  .map(([file, m]) => `- \`${file}\`: ${m.source}; sampled ${m.fetchedAt.slice(0, 10)}${m.failed ? `; ${m.failed} records couldn't be read while sampling` : ""}.`)
  .join("\n")}
- Malicious: ${PER_YEAR} per advisory ID year ${MALWARE_YEARS[0]}–${MALWARE_YEARS.at(-1)} (every one where a year has fewer), plus those published in the ${RECENT_DAYS} days before sampling (npm at most ${RECENT_CAP.npm}, PyPI ${RECENT_CAP.pypi}); one sample per package name. OSV data: ossf/malicious-packages and others, Apache-2.0 / CC-BY 4.0 per source.
- Invented: the universal-hallucination list of "The Range Shrinks, the Threat Remains" (Churilov, 2026; arXiv 2605.17062), tag v0.2-preprint, CC BY 4.0. Its own caveats: some names were registered later, and PyPI already refuses many of them.
- Legitimate: ${TOP.n} of the top ${TOP.below.toLocaleString("en")} and ${MID.n.toLocaleString("en")} of ranks ${(MID.from + 1).toLocaleString("en")}–${MID.below.toLocaleString("en")} by downloads, per ecosystem (ecosyste.ms, CC BY-SA 4.0).

## Limits of this measurement

- The malicious set is what OSV lists, which leans towards what scanners already find; packages taken down before
  this run (most PyPI ones) can only be judged by name, and "doesn't exist" blocks them for that reason alone.
- "Before it was reported" rewinds the clock for age only: download counts and the code read are today's, and code
  that was swapped or removed since can't be seen.
- The invented-name list is small (${rows.filter((r) => r.set === "invented").length} names) and drawn from one study's prompts.
- The top ${TOP.below.toLocaleString("en")} overlap the bundled popular lists, which are never look-alikes and skip the download count by
  design, so their rates show the floor; ranks above that are the fairer false-alarm test.
- Each figure is one run on one day against live services; verdicts for young packages change as they age.
`;
}

const command = process.argv[2];
if (command === "fetch") await fetchSamples();
else if (command === "run") await run();
else {
  console.error("usage: npm run eval -- fetch | run");
  process.exitCode = 2;
}
