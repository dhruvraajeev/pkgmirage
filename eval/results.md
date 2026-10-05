# Accuracy evaluation

Measured 2026-10-04 23:48–00:02 UTC on commit 1221d60 plus uncommitted changes, Node v26.10.0, npm 11.19.1.

**How:** `npm run eval -- run` checks every sampled name with the same `checkPackages()` the guard, MCP tools and API
use, bundled for Node, against the live npm, PyPI and OSV services, with no cache and no watchlist, 50 names at a
time, one run at a time. Samples were drawn with seed 17 by `npm run eval -- fetch` and are committed in
`eval/samples/` (names and advisory facts only).

**Reading the table:** *block*, *caution* and *safe* are the verdicts; *unverified* is a caution where some lookup
couldn't finish (usually api.npmjs.org's rate limit on download counts), never counted as safe. *Blocked* is the share
blocked (the catch rate for malicious and invented names, the false-block rate for legitimate ones); *flagged* is
blocked, caution or unverified. *Left out*: malicious packages whose latest version is no longer affected by the
advisory, and "legitimate" names that no longer exist or that the malware database lists (listed below).

## Results

| set | ecosystem | group | samples | left out | block | caution | unverified | safe | blocked | blocked (verified only) | flagged |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| malicious | npm | 2022 | 100 | 0 | 100 | 0 | 0 | 0 | 100.0% (100/100) | 100.0% (100/100) | 100.0% (100/100) |
| malicious | npm | 2023 | 100 | 2 | 98 | 0 | 0 | 0 | 100.0% (98/98) | 100.0% (98/98) | 100.0% (98/98) |
| malicious | npm | 2024 | 100 | 2 | 98 | 0 | 0 | 0 | 100.0% (98/98) | 100.0% (98/98) | 100.0% (98/98) |
| malicious | npm | 2025 | 100 | 0 | 100 | 0 | 0 | 0 | 100.0% (100/100) | 100.0% (100/100) | 100.0% (100/100) |
| malicious | npm | 2026 | 100 | 12 | 88 | 0 | 0 | 0 | 100.0% (88/88) | 100.0% (88/88) | 100.0% (88/88) |
| malicious | npm | recent | 200 | 9 | 191 | 0 | 0 | 0 | 100.0% (191/191) | 100.0% (191/191) | 100.0% (191/191) |
| malicious | pypi | 2022 | 20 | 0 | 20 | 0 | 0 | 0 | 100.0% (20/20) | 100.0% (20/20) | 100.0% (20/20) |
| malicious | pypi | 2023 | 100 | 0 | 100 | 0 | 0 | 0 | 100.0% (100/100) | 100.0% (100/100) | 100.0% (100/100) |
| malicious | pypi | 2024 | 100 | 0 | 100 | 0 | 0 | 0 | 100.0% (100/100) | 100.0% (100/100) | 100.0% (100/100) |
| malicious | pypi | 2025 | 100 | 1 | 99 | 0 | 0 | 0 | 100.0% (99/99) | 100.0% (99/99) | 100.0% (99/99) |
| malicious | pypi | 2026 | 100 | 2 | 98 | 0 | 0 | 0 | 100.0% (98/98) | 100.0% (98/98) | 100.0% (98/98) |
| malicious | pypi | recent | 90 | 1 | 89 | 0 | 0 | 0 | 100.0% (89/89) | 100.0% (89/89) | 100.0% (89/89) |
| invented | npm | doesn't exist | 15 | 0 | 15 | 0 | 0 | 0 | 100.0% (15/15) | 100.0% (15/15) | 100.0% (15/15) |
| invented | npm | exists today | 3 | 0 | 1 | 2 | 0 | 0 | 33.3% (1/3) | 33.3% (1/3) | 100.0% (3/3) |
| invented | pypi | doesn't exist | 117 | 0 | 117 | 0 | 0 | 0 | 100.0% (117/117) | 100.0% (117/117) | 100.0% (117/117) |
| invented | pypi | exists today | 4 | 0 | 0 | 0 | 0 | 4 | 0.0% (0/4) | 0.0% (0/4) | 0.0% (0/4) |
| legit | npm | top | 500 | 0 | 0 | 6 | 0 | 494 | 0.0% (0/500) | 0.0% (0/500) | 1.2% (6/500) |
| legit | npm | mid | 1000 | 11 | 0 | 33 | 9 | 947 | 0.0% (0/989) | 0.0% (0/980) | 4.2% (42/989) |
| legit | pypi | top | 500 | 0 | 0 | 32 | 0 | 468 | 0.0% (0/500) | 0.0% (0/500) | 6.4% (32/500) |
| legit | pypi | mid | 1000 | 11 | 0 | 136 | 0 | 853 | 0.0% (0/989) | 0.0% (0/989) | 13.8% (136/989) |
| install-scripts | npm | all | 672 | 1 | 1 | 560 | 110 | 0 | 0.1% (1/671) | 0.2% (1/561) | 100.0% (671/671) |

## Malicious packages: what is on the registry today

| ecosystem | samples | live | removed | npm placeholder | clean now | unreachable | invalid name |
| --- | --- | --- | --- | --- | --- | --- | --- |
| npm | 700 | 131 | 212 | 332 | 25 | 0 | 0 |
| pypi | 510 | 2 | 504 | 0 | 4 | 0 | 0 |

## What caused each block

| set | ecosystem | causes (by first reason) |
| --- | --- | --- |
| malicious | npm | malware database 446, doesn't exist 212, npm takedown 17 |
| malicious | pypi | doesn't exist 504, malware database 2 |
| invented | npm | doesn't exist 15, npm takedown 1 |
| invented | pypi | doesn't exist 117 |
| install-scripts | npm | look-alike 1 |

## Would it have been caught before it was reported?

Live malicious packages only (the others can no longer be read), scored as of the advisory's publish date with the
malware database removed: age as it was then, the archive opened if the selection rule would have opened it then.
Download counts and code are today's.

| set | ecosystem | group | samples | left out | block | caution | unverified | safe | blocked | blocked (verified only) | flagged |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| malicious | npm | all | 131 | 0 | 2 | 76 | 4 | 49 | 1.5% (2/131) | 1.6% (2/127) | 62.6% (82/131) |
| malicious | npm | 2022 | 17 | 0 | 1 | 7 | 0 | 9 | 5.9% (1/17) | 5.9% (1/17) | 47.1% (8/17) |
| malicious | npm | 2023 | 1 | 0 | 0 | 1 | 0 | 0 | 0.0% (0/1) | 0.0% (0/1) | 100.0% (1/1) |
| malicious | npm | 2024 | 8 | 0 | 0 | 6 | 0 | 2 | 0.0% (0/8) | 0.0% (0/8) | 75.0% (6/8) |
| malicious | npm | 2025 | 73 | 0 | 0 | 35 | 0 | 38 | 0.0% (0/73) | 0.0% (0/73) | 47.9% (35/73) |
| malicious | npm | 2026 | 5 | 0 | 1 | 3 | 1 | 0 | 20.0% (1/5) | 25.0% (1/4) | 100.0% (5/5) |
| malicious | npm | recent | 27 | 0 | 0 | 24 | 3 | 0 | 0.0% (0/27) | 0.0% (0/24) | 100.0% (27/27) |
| malicious | pypi | all | 2 | 0 | 0 | 2 | 0 | 0 | 0.0% (0/2) | 0.0% (0/2) | 100.0% (2/2) |
| malicious | pypi | 2025 | 1 | 0 | 0 | 1 | 0 | 0 | 0.0% (0/1) | 0.0% (0/1) | 100.0% (1/1) |
| malicious | pypi | 2026 | 1 | 0 | 0 | 1 | 0 | 0 | 0.0% (0/1) | 0.0% (0/1) | 100.0% (1/1) |

## Most common reasons on legitimate packages

**legit, npm** (packages with each reason; a package can have several)

| reason | packages |
| --- | --- |
| runs install scripts | 18 |
| only one maintainer | 15 |
| name is close to popular package "…" | 10 |
| unverified: download count unavailable | 8 |
| no source repository linked | 6 |
| only N downloads last week | 6 |
| first seen N days ago | 4 |
| install script runs shell commands | 3 |
| N known vulnerability in the latest version | 3 |
| package code sends data to a chat webhook | 1 |
| unverified: code check unavailable | 1 |

**legit, pypi** (packages with each reason; a package can have several)

| reason | packages |
| --- | --- |
| runs install scripts | 140 |
| only one maintainer | 110 |
| name is close to popular package "…" | 28 |
| no source repository linked | 27 |
| N known vulnerabilities in the latest version | 3 |
| N known vulnerability in the latest version | 2 |
| first seen N days ago | 1 |

**install-scripts, npm** (packages with each reason; a package can have several)

| reason | packages |
| --- | --- |
| runs install scripts | 671 |
| only one maintainer | 288 |
| install script runs shell commands | 132 |
| unverified: code check unavailable | 100 |
| no source repository linked | 68 |
| install script added in the latest version | 16 |
| name is close to popular package "…" | 11 |
| unverified: couldn't read every file its install scripts run | 8 |
| install script runs shell commands and reads npm tokens | 4 |
| install script reads npm tokens | 3 |
| N known vulnerability in the latest version | 3 |
| package code sends data to a chat webhook | 3 |

## False blocks

| set | ecosystem | package | rank | reasons |
| --- | --- | --- | --- | --- |
| install-scripts | npm | `9router` | 33090 | looks like popular package "router"; runs install scripts (postinstall); unverified: code check unavailable (archive too large); only one maintainer; no source repository linked |

Known malware among the "legitimate" samples (left out of their rows): `@andrewstory18/is-real-odd` (install-scripts, rank 14361, known malicious package (MAL-2026-10093)).

## Code checks on popular npm packages with install scripts

Code check status: read 572, error 100. Findings (packages with each): install:shell 138, install:npmrc 7, package:webhook 3, install:dynamic 1, install:obfuscated 1, install:ssh 1, package:raw-ip 1.
Outcomes: caution 560, unverified 110, block 2.

## Datasets

- `install-scripts-npm.json`: npm abbreviated records (hasInstallScript on the latest version) of the top 50,000 by downloads (ecosyste.ms); sampled 2026-10-04; 118 records couldn't be read while sampling.
- `invented-npm.json`: https://raw.githubusercontent.com/churik5/slopsquatting-replication-2026/v0.2-preprint/disclosure/npm_universal_hallucinations.csv; sampled 2026-10-04.
- `invented-pypi.json`: https://raw.githubusercontent.com/churik5/slopsquatting-replication-2026/v0.2-preprint/disclosure/pypi_universal_hallucinations.csv; sampled 2026-10-04.
- `legit-npm.json`: ecosyste.ms https://packages.ecosyste.ms/api/v1/registries/npmjs.org/package_names?sort=downloads (data CC BY-SA 4.0); sampled 2026-10-04.
- `legit-pypi.json`: ecosyste.ms https://packages.ecosyste.ms/api/v1/registries/pypi.org/package_names?sort=downloads (data CC BY-SA 4.0); sampled 2026-10-04.
- `malicious-npm.json`: OSV https://osv-vulnerabilities.storage.googleapis.com/npm/ (MAL- advisories, not withdrawn); sampled 2026-10-04.
- `malicious-pypi.json`: OSV https://osv-vulnerabilities.storage.googleapis.com/PyPI/ (MAL- advisories, not withdrawn); sampled 2026-10-04.
- Malicious: 100 per advisory ID year 2022–2026 (every one where a year has fewer), plus those published in the 30 days before sampling (npm at most 200, PyPI 100); one sample per package name. OSV data: ossf/malicious-packages and others, Apache-2.0 / CC-BY 4.0 per source.
- Invented: the universal-hallucination list of "The Range Shrinks, the Threat Remains" (Churilov, 2026; arXiv 2605.17062), tag v0.2-preprint, CC BY 4.0. Its own caveats: some names were registered later, and PyPI already refuses many of them.
- Legitimate: 500 of the top 10,000 and 1,000 of ranks 10,001–100,000 by downloads, per ecosystem (ecosyste.ms, CC BY-SA 4.0).

## Limits of this measurement

- The malicious set is what OSV lists, which leans towards what scanners already find; packages taken down before
  this run (most PyPI ones) can only be judged by name, and "doesn't exist" blocks them for that reason alone.
- "Before it was reported" rewinds the clock for age only: download counts and the code read are today's, and code
  that was swapped or removed since can't be seen.
- The invented-name list is small (139 names) and drawn from one study's prompts.
- The top 10,000 overlap the bundled popular lists, which are never look-alikes and skip the download count by
  design, so their rates show the floor; ranks above that are the fairer false-alarm test.
- Each figure is one run on one day against live services; verdicts for young packages change as they age.

## Threshold change from this evaluation

The first run (2026-10-04 23:29–23:43 UTC, same samples) blocked 17 legitimate packages, every one a look-alike of a
popular name whose only strong signal was its install scripts or the shell commands they run (on PyPI, a source-only
release): 12 of 671 popular npm packages with install scripts (`tldjs`, `libpq`, `cloudflared`, `cline`,
`rs-module-lexer`, `9router`, `parse-server`, `fmerge`, `mcrypt`, `scrypt`, `bcrypto`, `compresion`) and 5 of 989 PyPI
packages ranked 10,001–100,000 (`readtime`, `cache`, `fsutil`, `dynamodb`, `segeval`). Since then, install scripts and
install-time shell commands alone leave a look-alike a caution; being new, rarely downloaded, unverified, or any other
code finding still makes it a block. The run above is after the change:

| | before | after |
| --- | --- | --- |
| npm with install scripts, top 50,000: blocked | 1.8% (12/671) | 0.1% (1/671) |
| PyPI ranks 10,001–100,000: blocked | 0.5% (5/989) | 0.0% (0/989) |
| npm ranks 10,001–100,000: blocked | 0.0% (0/989) | 0.0% (0/989) |
| malicious, npm and PyPI: blocked | 100% of 1,180 verified (1 unverified) | 100% (1,181/1,181) |
| invented, not registered: blocked | 100% (132/132) | 100% (132/132) |
| live malicious npm, as of report, no malware database: flagged | 61.8% (81/131) | 62.6% (82/131) |

The one remaining block, `9router`, is a look-alike whose archive is over the 10 MiB reading cap, so its code is
unverified. Verdicts that changed for other reasons between the runs (10 of 3,000 legitimate packages, 1 malicious)
are young packages ageing past a threshold and download counts that were rate-limited in one run but not the other.
