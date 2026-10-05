# pkgMirage

**Checks a package before your AI assistant installs it.**

AI coding assistants sometimes suggest packages that don't exist, and attackers register those names with malware
("slopsquatting"). pkgMirage is a tool your assistant calls before it suggests or installs an npm or PyPI package. It
checks that the package exists, isn't known malware or a copycat of a popular name and, for risky npm packages, reads
the code that would run at install (it never runs it). It also remembers the names it was asked about that didn't
exist, and checks every night whether someone has registered one.

pkgMirage isn't deployed yet: `https://pkgmirage.example` below stands for its address. To try it now, run your own
copy ([Run locally](#run-locally)).

## Connect your AI assistant (MCP)

Claude Code:

```bash
claude mcp add --transport http pkgmirage https://pkgmirage.example/mcp
```

Cursor, project-wide setup and the other options: [docs/setup.md](docs/setup.md#connect-an-ai-assistant-mcp).

The assistant gets two tools, `check_package` and `check_packages` (up to 50 at once), and is told to check every
package it hasn't verified and what to do with each answer:

- **safe**: install as usual.
- **caution**: it exists but something about it is risky, or a check couldn't be finished. Tell you the reasons and
  let you decide.
- **block**: don't install it, and offer the suggested names instead.

A real answer:

```text
typescirpt (npm): BLOCK, do not install. doesn't exist on npm (likely hallucinated). Did you mean: typescript?
esbuild (npm): CAUTION. runs install scripts (postinstall); install script runs shell commands; only one maintainer
react (npm): SAFE
```

When Claude Code was asked to install `typescirpt` through it (Claude Code 2.1.278, 2026-10-02), it called the
tool, said not to run that command and suggested `npm install typescript`. Answers carry only pkgMirage's own
wording: nothing written by a package's author (descriptions, READMEs, code) reaches the assistant, so a package
can't talk to it.

## Guard npm installs (optional)

The assistant only checks what it's about to install. To check everything npm installs, including dependencies of
dependencies and installs from a lockfile, point npm at pkgMirage:

```bash
npm config set registry https://pkgmirage.example/npm/
npm config set prefer-online true
```

A caution installs and npm prints the reasons; a block stops the install with them:

```text
$ npm install esbuild
npm notice pkgMirage caution for esbuild: runs install scripts (postinstall); install script runs shell commands; only one maintainer
added 2 packages in 3s

$ npm install lodahs
npm notice pkgMirage blocked lodahs: known malicious package (MAL-2025-25502). Did you mean: lodash?
npm error code E403
```

Turning it off, using it for one project or skipping it for one command, what works through it and a CI step:
[docs/setup.md](docs/setup.md#guard-npm-installs).

There's no guard for pip: Python projects get the assistant's tools, the website and the project scan.

## Website and API

The website (`/`) checks one package by hand and shows what was checked. Scripts and CI can call the same check:

```bash
curl -s https://pkgmirage.example/api/check \
  -H 'content-type: application/json' \
  -d '{"ecosystem": "pypi", "names": ["requests", "fastjson-parse-xyz"]}'
```

`/api/scan` checks a whole `package-lock.json`, `package.json` or `requirements.txt`, and `/api/stats` counts what
was checked: [docs/setup.md](docs/setup.md#use-the-api).

Every way in (the assistant, the guard, the website, the API) runs the same check and gets the same answer.

## What it checks

- **Does it exist?** A name the registry doesn't know is the clearest sign of an invented package.
- **Known malware and vulnerabilities**, from the [OSV](https://osv.dev) database. npm's placeholders for removed
  malware count as malware.
- **Copycat names**: one typo, a swapped scope (`@type/react`), reordered parts (`dateutil-python`) or padding
  (`react-js`) away from one of the 10,000 most-downloaded packages, and names with invisible or look-alike
  characters.
- **Warning signs**: first published under 30 days ago, fewer than 100 downloads last week (npm packages under a
  year old), install scripts, an install script that appeared in the latest version. One maintainer and no source
  repository are mentioned alongside these, never on their own.
- **What its code does (npm only).** A package with install scripts, or one that isn't popular and is new, rarely
  downloaded or has a copycat name, is opened: the latest version's archive is read as bytes, never run. The code that runs at install
  (the install scripts, the files they run and the files those load) is checked for shell commands, reading SSH keys,
  npm tokens, cloud credentials or all environment variables, sending data to a raw IP address, a chat webhook or a
  paste site, code built from strings, and obfuscation. The rest of the package is checked only for sends to raw IP
  addresses and chat webhooks, because ordinary code trips the other patterns too often.
- **Names seen invented.** A name that didn't exist when someone asked about it (through an assistant, the guard,
  the website or the API; scans don't count) goes on a watchlist. Once
  two different callers have asked about it, it is trusted; if it is registered later, the new package is blocked
  for its first 30 days. A nightly job asks the registries whether watched names have been registered.

A check that couldn't be finished (a registry, the malware database or the archive not answering, a rate-limited
download count, an archive too big to read) is a **caution marked unverified, never safe**.

## Verdicts

| Verdict | When |
|---|---|
| `safe` | exists, established, no warning signs |
| `caution` | exists but has a warning sign: brand new, very few downloads, install scripts, an install script added in the latest version, known vulnerabilities, a name close to a popular package, or something its code does; or a check couldn't be finished |
| `block` | doesn't exist (likely invented), known malware or taken down by npm, a copycat name that is also new, rarely downloaded or otherwise risky, invisible or look-alike characters, registered after being seen as an invented name, or install-time code that runs shell commands or reads secrets **and** sends data out |

Most findings only warn. A block needs a strong case, because a false block stops real work.

## Architecture

```
 npm install ──(registry set to pkgMirage)──┐            ┌── registry.npmjs.org  (records, archives)
 Claude Code / Cursor ──MCP─────────────────┤            ├── api.npmjs.org       (download counts)
 Website / scripts / CI ──HTTP──────────────┤            ├── pypi.org            (project records)
                                            ▼            ├── api.osv.dev         (malware, vulnerabilities)
   ┌──────────────── Cloudflare Worker ──────────────────┴───────────────────┐
   │ /npm/*       the guard: refuse a block, pass a caution with a notice    │
   │ /mcp         check_package, check_packages (stateless)                  │
   │ /api/check   names → verdicts      /api/scan   lockfile or requirements │
   │ /api/stats   daily counts          /           the website             │
   │ engine:  names · registry · malware · copycats · code · score           │
   │          one checkPackages() behind every route                         │
   │ KV: verdicts and code reads    D1: watchlist, daily counts              │
   │ Cron: nightly re-check of watched names                                 │
   └─────────────────────────────────────────────────────────────────────────┘
```

One engine answers every route. Verdicts are cached in Workers KV (a missing name 10 minutes, a caution 1 hour, safe
6 hours, other blocks 24 hours; unverified answers never), and each package version's code is read once and kept for
30 days, since a published version never changes. Its lookups go only to the four hosts above, over https, with timeouts
and size limits. Cloudflare is a good fit rather than a requirement: the guard sits in front of every
install, so it runs close to every user, and proxying large npm records and archives has no bandwidth charges.

## Measured results

### Accuracy

From [eval/results.md](eval/results.md), one run on 2026-10-04 against the live registries and OSV, with no cache:

| Set | Result |
|---|---|
| Malicious packages listed in OSV (npm 675, PyPI 506) | **100% blocked** (1,181 of 1,181): 448 by the malware database, 716 because they no longer exist on the registry, 17 npm takedowns |
| **Same, without the malware database**: the 131 malicious npm packages still installable, scored as of the day each was reported | **62.6% flagged** (82 of 131), but only **2 blocked**; 76 cautions, 4 unverified, **49 looked safe** |
| … of those, reported in the last 30 days | 27 of 27 flagged, none blocked |
| Invented names from a public study, not registered | 100% blocked (132 of 132) |
| Invented names someone has registered since | 1 blocked, 2 cautions, 4 safe (of 7) |
| Legitimate packages, npm and PyPI, top 100,000 by downloads | **0 blocked** (of 2,978); cautions: npm 1.2% (top 10,000) and 4.2% (ranks 10,001–100,000), PyPI 6.4% and 13.8% |
| Popular npm packages with install scripts (top 50,000) | 1 blocked (of 671); the rest cautions by design, 110 of them unverified |

What this means: against malware that the database already lists, or names that were never registered, pkgMirage
blocks reliably. Most of those blocks come from the database or from the package already being gone. Against brand-new
malware the database doesn't know yet, it mostly warns rather than blocks, and about a third of the live samples
looked safe (most were from 2025's floods of spam packages with no code to find). The first run blocked 17
legitimate packages; the rule that caused it was changed and the numbers above are the re-run (before and after:
[eval/results.md](eval/results.md#threshold-change-from-this-evaluation)).

### Speed

Measured on 2026-10-04 with a local Worker (`wrangler dev`) on a Mac (arm64, home connection), real registries:

| What | Through pkgMirage | npm directly |
|---|---|---|
| `npm install next react react-dom express typescript eslint vitest` (192 packages), empty caches, 3 runs | 59–64 s | 20–23 s |
| Same install again, verdicts and npm cache warm, 2 runs | 3.4–3.6 s | |
| Scan of that project's lockfile (267 names), cold / warm | 5.4–7.2 s / 23 ms | |
| Scan of `requirements.txt` files of 26 and 212 packages, cold / warm | 6.9–7.6 s and 14.3–16.5 s / under 20 ms | |

The first install of a package through the guard is slower: each package is checked before npm gets it, and npm's
download-count service rate-limits. Repeat installs and checks come from the cache. Reading a package's code took
22–53 ms of CPU for esbuild, 57–97 ms for core-js and 618–787 ms for nx, whose install script loads a large module
tree (measured in Node, an upper bound); packages that aren't opened take a few milliseconds.

## What it won't catch

- **Code checks look for patterns, so they can be evaded.** Code that hides a module name or builds a file path at
  run time gets past them, and legitimate packages trip them (esbuild's installer runs shell commands). That's why a
  single finding only warns.
- **Only the latest version** is checked against the malware database and has its code read, even when a lockfile
  pins an older one.
- **Big archives aren't read.** Archives over 10 MiB, 64 MiB unpacked or 5,000 files are skipped: 92 of 672 popular
  npm packages with install scripts (13.7%, mostly prebuilt binaries) come out unverified. An author could pad an
  archive past the limit; it then shows as a caution, never safe.
- **PyPI gets fewer checks**: no code checks and no download counts. Source-only releases count as install scripts,
  which is most of the PyPI cautions above.
- **Known malware comes from OSV.** Without it, pkgMirage warns about most new malware but blocks little of it (see
  Accuracy).
- **The invented-name test set is small**: 139 names from one study.
- **The guard is npm only** (yarn and pnpm untested), can't install private packages (it never forwards tokens), and
  refuses `npm publish`, `login` and `search`. If pkgMirage can't be reached, installs fail rather than going
  around it. `--silent` hides the caution notices. Details: [docs/setup.md](docs/setup.md#what-the-guard-doesnt-do).
- **Cautions are noisier than blocks.** Install scripts alone are a caution, so every package with one gets a
  notice, including ones npm reads but doesn't install (canvas in the install above).
- **A cold scan of a large npm project** can come back with a few packages unverified when npm's download-count
  service rate-limits; scanning again checks just those.
- **The watchlist starts empty** and learns only from names people actually ask about.

## Rate limits and privacy

| Route | Rate limit per caller | Request body |
|---|---|---|
| `/npm/*` | 1,000 requests per 10 seconds | `npm audit`: 1 MiB as sent |
| `/api/check`, `/api/stats` and `/mcp` (shared) | 60 requests per minute | 64 KiB (stats: GET) |
| `/api/scan` | 5 scans per minute | 1 MiB |

The install above, with an empty npm cache, peaked at 260 requests in 10 seconds (382 with verdicts already cached),
and a 1,174-package project at 453 (2026-10-02). Over a limit the answer is `429` with `Retry-After`; npm retries on its own after 10 seconds. Limits
are counted per Cloudflare location and are approximate.

The caller is the connecting IP address (an IPv6 address by its /64). It is never stored or logged: it is the rate
limiter's key, and the watchlist keeps only a keyed hash of it (with the day and the package name, deleted after that
day; with the package name alone, erased once a second caller asks about the name). Otherwise only package names, counts and
times are kept; scanned files are not. Errors never include internal details.

## Run locally

```bash
npm install
npx wrangler d1 migrations apply pkgmirage --local
echo "SIGHTING_KEY=$(openssl rand -hex 32)" > .dev.vars
npm run dev
```

Then open `localhost:8787`. To run
the nightly job by hand: `npx wrangler dev --test-scheduled`, then open `/__scheduled`. The popular-package lists are
refreshed with `node scripts/popular.mjs`.

```bash
npm test
npm run typecheck
```

## Data sources and licenses

The code is MIT licensed. The data files keep their sources' licenses:

- `data/popular-npm.json` and, in `eval/samples/`, `legit-npm.json`, `legit-pypi.json` and `install-scripts-npm.json`
  (package names ranked by downloads): [ecosyste.ms](https://ecosyste.ms), CC BY-SA 4.0. These files are shared under
  CC BY-SA 4.0.
- `data/popular-pypi.json`: [hugovk/top-pypi-packages](https://github.com/hugovk/top-pypi-packages) (no license
  stated; package names only).
- `eval/samples/invented-*.json`: the universal-hallucination list from Churilov, "The Range Shrinks, the Threat
  Remains" (2026, [arXiv 2605.17062](https://arxiv.org/abs/2605.17062)), CC BY 4.0.
- `eval/samples/malicious-*.json` (names and advisory facts, no code): [OSV](https://osv.dev), mostly from
  [ossf/malicious-packages](https://github.com/ossf/malicious-packages) (Apache-2.0), other sources under their own
  terms.

Live checks use the npm registry, PyPI and the OSV API.

## License

MIT. See [LICENSE](LICENSE).
