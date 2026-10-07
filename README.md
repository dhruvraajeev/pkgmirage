# pkgMirage

**Checks a package before your AI assistant installs it.**

AI assistants sometimes suggest packages that don't exist, and attackers register those names with malware
("slopsquatting"). pkgMirage checks that an npm or PyPI package exists, isn't known malware or a copycat of a popular
name, and for risky npm packages reads (never runs) the code that would run at install. Names it was asked about that
didn't exist are watched nightly in case someone registers them.

**Live: [pkgmirage.dhruvr.workers.dev](https://pkgmirage.dhruvr.workers.dev)**

## Use it

**AI assistant (MCP).** Gives the assistant `check_package` and `check_packages`. Cursor and other setups:
[docs/setup.md](docs/setup.md).

```bash
claude mcp add --transport http pkgmirage https://pkgmirage.dhruvr.workers.dev/mcp
```

**npm guard (optional).** Checks everything npm installs, dependencies included: a block stops the install, a caution
prints the reasons.

```bash
npm config set registry https://pkgmirage.dhruvr.workers.dev/npm/
npm config set prefer-online true
```

**Website and API.** Check by hand at `/`, or from scripts with `POST /api/check`. `/api/scan` checks a whole
lockfile or `requirements.txt`, and `/api/stats` returns daily counts.

```text
typescirpt (npm): BLOCK, do not install. doesn't exist on npm (likely hallucinated). Did you mean: typescript?
esbuild (npm): CAUTION. runs install scripts (postinstall); install script runs shell commands; only one maintainer
react (npm): SAFE
```

## Verdicts

- **safe**: exists, established, no warning signs.
- **caution**: exists but something is risky (new, few downloads, install scripts, a near-copycat name, suspicious
  code), or a check couldn't be finished. A check that couldn't be finished is never reported as safe.
- **block**: doesn't exist, known malware, a risky copycat, or install code that reads secrets **and** sends data out.

Answers use only pkgMirage's own wording, so nothing a package's author wrote reaches the assistant.

## Results

From [eval/results.md](eval/results.md) (2026-10-04): **100%** of 1,181 known-malicious packages blocked, **100%** of
132 unregistered invented names blocked, and **0** of 2,978 popular legitimate packages blocked.

## Limitations

- The assistant decides when to call the tool, so it can skip the check. The guard makes it certain, but only for npm.
- Code checks are pattern matches: they can be evaded, and legitimate packages trip them, so one finding only warns.
- Against new malware that OSV doesn't list yet, it mostly warns rather than blocks.
- Only the latest version is checked, and archives over 10 MiB aren't read (they come back unverified).
- PyPI gets fewer checks: no code reading and no download counts.
- The guard can't install private packages, and installs fail if pkgMirage is unreachable.
- A first install through the guard is about 3× slower than npm directly; repeats come from the cache.

**Hosting:** it currently runs on the Workers Free plan, whose limits (10 ms CPU, 1,000 KV writes a day) can cut off
code reads and caching under load. I'll move it to Workers Paid through the Cloudflare for Students plan once that's
active; only the plan changes, not the code.

## Run locally

```bash
npm install
npx wrangler d1 migrations apply pkgmirage --local
echo "SIGHTING_KEY=$(openssl rand -hex 32)" > .dev.vars
npm run dev
npm test
```

## Data sources and licenses

Code is MIT ([LICENSE](LICENSE)). Data files keep their sources' licenses:

- `data/popular-npm.json` and `eval/samples/` `legit-npm.json`, `legit-pypi.json`, `install-scripts-npm.json`:
  [ecosyste.ms](https://ecosyste.ms), CC BY-SA 4.0 (shared under the same license).
- `data/popular-pypi.json`: [hugovk/top-pypi-packages](https://github.com/hugovk/top-pypi-packages) (package names
  only).
- `eval/samples/invented-*.json`: Churilov, "The Range Shrinks, the Threat Remains" (2026,
  [arXiv 2605.17062](https://arxiv.org/abs/2605.17062)), CC BY 4.0.
- `eval/samples/malicious-*.json`: [OSV](https://osv.dev), mostly
  [ossf/malicious-packages](https://github.com/ossf/malicious-packages) (Apache-2.0).
