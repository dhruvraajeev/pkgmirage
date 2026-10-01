# pkgmirage

AI coding assistants sometimes suggest packages that don't exist, and attackers register those names
("slopsquatting"). pkgmirage checks a package name against npm or PyPI before you install it and returns a
verdict with plain-English reasons and, for copycat names, the package you probably meant.

| Verdict | Meaning |
|---|---|
| `safe` | exists, established, no risk signals |
| `caution` | exists but looks risky (brand new, install scripts, very few downloads, known vulnerabilities in the latest version, a name close to a popular package), or a check failed and it couldn't be verified |
| `block` | doesn't exist (likely hallucinated), known malware, taken down by npm, a new or unused copycat of a popular package, or a name with invisible or look-alike characters |

A failed check is never reported as `safe`.

Checks use the npm and PyPI registries, [OSV](https://osv.dev) for malware and vulnerabilities, and lists of
the 10,000 most-downloaded packages on each registry for copycat detection (`node scripts/popular.mjs`
refreshes them). Results are cached in Workers KV.

## Run locally

```bash
npm install
npm run dev
```

```bash
curl -s localhost:8787/api/check \
  -H 'content-type: application/json' \
  -d '{"ecosystem": "pypi", "names": ["requests", "fastjson-parse-xyz"]}'
```

Up to 50 names per request; `ecosystem` is `npm` or `pypi`.

## Test

```bash
npm test
npm run typecheck
```

## License

MIT. See [LICENSE](LICENSE).
