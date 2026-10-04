# Setup

pkgmirage isn't deployed yet: `https://pkgmirage.example` below stands for its address and won't resolve. To try
everything against your own copy, start it as in the README's [Run locally](../README.md#run-locally) and use
`http://localhost:8787` instead.

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
`unverified:` reason, never `safe`. If pkgmirage itself can't be reached, npm retries for about a minute and then
fails (`ECONNREFUSED`, or `ECONNRESET` at once if it goes away mid-install); nothing is installed and it doesn't
fall back to npm on its own.

Every package npm downloads is checked, including dependencies of dependencies and installs from a lockfile. Only the
latest version of each package is looked up in the malware database, even when a lockfile pins an older one.

### What the guard doesn't do

- **Only installs.** `npm install`, `ci`, `update`, `outdated`, `view` and `audit` work through it. `npm publish`,
  `login` and `search` are refused: run them with `--registry=https://registry.npmjs.org/`.
- **No tokens.** pkgmirage never forwards npm credentials, so don't put an auth token in `.npmrc` for it. Private
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
      - name: Check packages with pkgmirage
        run: |
          curl -sS --fail-with-body --data-binary @package-lock.json https://pkgmirage.example/api/scan -o scan.json \
            || { cat scan.json; exit 1; }
          jq -r '.results[] | select(.verdict == "block") | "blocked: \(.name): \(.reasons | join("; "))"' scan.json
          jq -e '.summary.block == 0' scan.json > /dev/null
```

Use `@requirements.txt` for a Python project. A refused scan fails the job too, with the reason (too many packages,
a file too large, or the rate limit; see the README). To install through the guard in CI instead, run
`npm ci --prefer-online --registry=https://pkgmirage.example/npm/` (`--prefer-online` so a cached `~/.npm` can't skip
the check).

## Connect an AI assistant (MCP)

Once connected, assistants can check packages before suggesting or installing them (what the tools return:
[README](../README.md#connect-an-ai-assistant-mcp)).

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
