# Setup

pkgMirage isn't deployed yet: `https://pkgmirage.example` below stands for its address and won't resolve. To try
everything against your own copy, start it as in the README's [Run locally](../README.md#run-locally) and use
`http://localhost:8787` instead.

## Connect an AI assistant (MCP)

Connect pkgMirage to your coding assistant once. Its tools ask the assistant to check each package before suggesting
or installing it, and tell it what to do with each verdict: `safe`, install as usual; `caution`, tell you the reasons
and let you decide; `block`, don't install it and offer the suggested names instead. The answer carries only
pkgMirage's own wording (what the tools return: [README](../README.md#connect-your-ai-assistant-mcp)).

Claude Code:

```bash
claude mcp add --transport http pkgmirage https://pkgmirage.example/mcp
```

Add `--scope project` to write it to the project's `.mcp.json` for the whole team (Claude Code asks each person to
approve it the next time they run `claude` there), or `--scope user` for all your projects.

Cursor: add this to `.cursor/mcp.json` in a project, or `~/.cursor/mcp.json` for all projects:

```json
{
  "mcpServers": {
    "pkgmirage": { "url": "https://pkgmirage.example/mcp" }
  }
}
```

## Guard npm installs

Turn the guard on for every project on this machine:

```bash
npm config set registry https://pkgmirage.example/npm/
npm config set prefer-online true
```

The second line makes npm ask the guard about every package, even one already in npm's cache; without it, a package
cached before the guard was on, or installed with the guard skipped, installs from a lockfile unchecked. The file is
downloaded again only if it changed, so it costs little: a warm-cache `npm ci` of 198 packages took 2.8–3.2 s with it
and 2.5–2.9 s without (local, 2026-10-02).

Turn it off:

```bash
npm config delete registry
npm config delete prefer-online
```

For one project only, put these lines in a `.npmrc` next to its `package.json` (commit it to guard the whole team):

```ini
registry=https://pkgmirage.example/npm/
prefer-online=true
```

A project's `.npmrc` wins over the global setting, so `npm config delete registry` doesn't turn it off there; remove
the lines instead.

Skip the guard for one command:

```bash
npm install is-number --registry=https://registry.npmjs.org/
```

### What you'll see

| Verdict | During `npm install` |
|---|---|
| `safe` | installs as usual |
| `caution` | installs, and npm prints the reasons: `npm notice pkgMirage caution for esbuild: runs install scripts (postinstall); install script runs shell commands; only one maintainer` (`--loglevel=warn` or `--silent` hide it) |
| `block` | the install stops with `npm error code E403` and the reasons: `pkgMirage blocked lodahs: known malicious package (MAL-2025-25502). Did you mean: lodash?` |

A check that couldn't be completed (a registry, malware, download or package-archive lookup failing) is a `caution` with an
`unverified:` reason, never `safe`. If pkgMirage itself can't be reached, npm retries for about a minute and then
fails (`ECONNREFUSED`, or `ECONNRESET` at once if it goes away mid-install); nothing is installed and it doesn't
fall back to npm on its own.

Every package npm downloads is checked, including dependencies of dependencies and installs from a lockfile. Only the
latest version of each package is looked up in the malware database and has its code read, even when a lockfile pins
an older one.

### What the guard doesn't do

- **Only installs.** `npm install`, `ci`, `update`, `outdated`, `view` and `audit` work through it. `npm publish`,
  `login` and `search` are refused: run them with `--registry=https://registry.npmjs.org/`.
- **No tokens.** pkgMirage never forwards npm credentials, so don't put an auth token in `.npmrc` for it. Private
  packages won't install through the guard.
- **npm only.** yarn and pnpm aren't supported.

## Check a project in CI

Scan the lockfile on every push and fail the job if any package is blocked. Cautions and unverified packages are
reported but don't fail it (npm's download-count API rate-limits, so a cold scan can come back with a few
unverified packages).

```yaml
name: Package check

on: [push, pull_request]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - name: Check packages with pkgMirage
        run: |
          curl -sS --fail-with-body --data-binary @package-lock.json https://pkgmirage.example/api/scan -o scan.json \
            || { cat scan.json; exit 1; }
          jq -r '.results[] | select(.verdict == "block") | "blocked: \(.name): \(.reasons | join("; "))"' scan.json
          jq -e '.summary.block == 0' scan.json > /dev/null
```

Use `@requirements.txt` for a Python project. A refused scan fails the job too, with the reason (too many packages,
a file too large, or the rate limit; see [Use the API](#use-the-api)). To install through the guard in CI instead, run
`npm ci --prefer-online --registry=https://pkgmirage.example/npm/` (`--prefer-online` so a cached `~/.npm` can't skip
the check).

## Use the API

Check up to 50 names at once; `ecosystem` is `npm` or `pypi`:

```bash
curl -s https://pkgmirage.example/api/check \
  -H 'content-type: application/json' \
  -d '{"ecosystem": "npm", "names": ["react", "expres"]}'
```

Each result has the `verdict`, the `reasons`, any `suggestions` and what was checked (`checks`).

### Scan a project

```bash
curl -s https://pkgmirage.example/api/scan --data-binary @package-lock.json
curl -s https://pkgmirage.example/api/scan --data-binary @requirements.txt
```

Send a `package-lock.json` (npm 7 or newer), a `package.json` or a pip requirements file as it is. Every package in a
lockfile is checked, including dependencies of dependencies; a `package.json` gives its direct dependencies
(`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`); a requirements file gives every
package it names (pinned files from `pip-compile`, `uv pip compile` or `pip freeze` list them all). The report lists
blocks first, then cautions, then safe packages, plus counts for CI. npm packages say where they came from
(`dependencies`, `devDependencies`, ... or `transitive`):

```json
{ "summary": { "checked": 267, "block": 0, "caution": 1, "safe": 266, "unverified": 0, "skipped": 0 },
  "results": [ ... ], "skipped": [ { "name": "my-lib", "reason": "git source" } ] }
```

Git, local, linked and tarball dependencies and packages from other registries are listed under `skipped` and never
fetched. In a requirements file, includes (`-r`, `-c`), editable installs, pip options, links, VCS sources and local
paths are skipped by line number (`{ "line": 3, "reason": "include not followed" }`) and their contents are never
repeated; every other name is checked against pypi.org. `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `poetry.lock`
and `uv.lock` aren't read: export a requirements file first (`uv export --format requirements.txt`,
`poetry export -f requirements.txt`, `pipenv requirements`). Up to 750 distinct packages per scan (more is refused
with both numbers), 1 MiB per file and 5 scans a minute; `skipped` lists the first 750 entries and `summary.skipped`
counts them all. Files are not stored, and scanned names don't go on the watchlist (a lockfile lists packages that
were already installed).

### Usage stats

```bash
curl -s https://pkgmirage.example/api/stats
```

Counts for the last 7 UTC days (today first, so far) and the watchlist, never names:

```json
{ "days": [ { "day": "2026-10-02", "checks": 10, "blocks": 4, "cautions": 2, "invented": 3 }, ... ],
  "watchlist": { "total": 3, "confirmed": 1, "unregistered": 3, "registered": 0, "cleared": 0 },
  "generatedAt": "2026-10-02T21:33:26.135Z" }
```

Each package name counts once a day, with its first verdict that day, whichever way it was checked; scans don't
count. `invented` is names that don't exist on their registry. On the watchlist, `confirmed` names were asked about
by two different callers, and `registered` ones have been registered since. Anyone can ask about names that don't
exist, so these count what was asked, not what AI assistants invented. The answer is cached for up to 5 minutes, never
past midnight UTC.
