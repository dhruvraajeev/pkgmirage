# pkgmirage

AI coding assistants sometimes suggest packages that don't exist, and attackers register those names
("slopsquatting"). pkgmirage checks a package name against npm or PyPI before you install it and returns a
verdict with plain-English reasons and, for copycat names, the package you probably meant.

| Verdict | Meaning |
|---|---|
| `safe` | exists, established, no risk signals |
| `caution` | exists but looks risky (brand new, install scripts, very few downloads, known vulnerabilities in the latest version, a name close to a popular package), or a check failed and it couldn't be verified |
| `block` | doesn't exist (likely hallucinated), known malware, taken down by npm, a new or unused copycat of a popular package, a name with invisible or look-alike characters, or a name callers saw invented that was registered in the last 30 days |

A failed check is never reported as `safe`.

Checks use the npm and PyPI registries, [OSV](https://osv.dev) for malware and vulnerabilities, and lists of
the 10,000 most-downloaded packages on each registry for copycat detection (`node scripts/popular.mjs`
refreshes them). Results are cached in Workers KV.

Names checked and found not to exist go on a watchlist in D1. A name counts once per caller per day, and needs
callers on two different networks before it is trusted; if such a name is registered later, the new package is
blocked for its first 30 days. A nightly job asks the registry whether watched names have been registered since. Daily
counts of distinct names checked, blocked, cautioned and invented are kept with it.

## Run locally

```bash
npm install
npx wrangler d1 migrations apply pkgmirage --local
echo "SIGHTING_KEY=$(openssl rand -hex 32)" > .dev.vars
npm run dev
```

To run the nightly job by hand: `npx wrangler dev --test-scheduled`, then open `/__scheduled`.

```bash
curl -s localhost:8787/api/check \
  -H 'content-type: application/json' \
  -d '{"ecosystem": "pypi", "names": ["requests", "fastjson-parse-xyz"]}'
```

Up to 50 names per request; `ecosystem` is `npm` or `pypi`.

## Guard npm installs

```bash
npm config set registry http://localhost:8787/npm/
```

Every package npm asks for, including dependencies and downloads listed in a lockfile, is checked first. A blocked
package fails the install with its reasons and, for copycat names, the package you probably meant. A `caution`
package installs, and npm prints the reasons as an `npm notice` line (hidden by `--loglevel=warn` or `--silent`). `npm config delete registry` turns it
off. Only installs and `npm audit` go through: publish, login and search are refused, and npm credentials are never
forwarded, so private packages won't install through it.

## Connect an AI assistant (MCP)

```bash
claude mcp add --transport http pkgmirage http://localhost:8787/mcp
```

`/mcp` is a stateless MCP endpoint with two tools: `check_package` (one name) and `check_packages` (up to 50). The
assistant gets the same verdicts as the API, with only pkgmirage's own wording: nothing written by package authors
(descriptions, READMEs) is passed on, and rejected names have unusual characters shown as `\uXXXX` codes.

## Limits

| Route | Rate limit per caller | Request body |
|---|---|---|
| `/npm/*` | 1,000 requests per 10 seconds | `npm audit`: 1 MiB as sent |
| `/api/*` and `/mcp` (shared) | 60 requests per minute | 64 KiB |

A cold `npm install` of next, react, react-dom, express, typescript, eslint and vitest peaked at 382 requests in
10 seconds; a 1,174-package project at 453. Over a limit the answer is `429` with `Retry-After`; npm retries it on
its own after 10 seconds. Limits are counted per Cloudflare location and are approximate. The caller is the
connecting IP address (an IPv6 address by its /64). It is never stored or logged: it is the rate limiter's key, and
the watchlist keeps only an HMAC of it keyed with the `SIGHTING_KEY` secret (with the day and the package name, deleted
after that day; with the package name alone, erased once a second caller sees the name).

Errors never include internal details: an unexpected failure is a `500` with `{"error": "internal error"}`, and an
MCP check that fails tells the assistant to treat the packages as unverified.

## Test

```bash
npm test
npm run typecheck
```

## License

MIT. See [LICENSE](LICENSE).
