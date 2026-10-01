// Regenerates data/popular-*.json, the most-downloaded package names used for look-alike checks.
// Usage: node scripts/popular.mjs
import { writeFile } from "node:fs/promises";

const COUNT = 10_000;
const PAGE_SIZE = 1_000;

async function getJson(url) {
  const res = await fetch(url, { headers: { "user-agent": "pkgmirage/0.1" } });
  if (!res.ok) throw new Error(`${url}: ${res.status}`);
  return res.json();
}

async function npmNames() {
  const pages = [];
  for (let page = 1; page <= COUNT / PAGE_SIZE; page++) {
    pages.push(
      await getJson(
        `https://packages.ecosyste.ms/api/v1/registries/npmjs.org/package_names?sort=downloads&order=desc&per_page=${PAGE_SIZE}&page=${page}`,
      ),
    );
  }
  return [...new Set(pages.flat())].slice(0, COUNT);
}

async function pypiNames() {
  const { rows } = await getJson("https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json");
  // PEP 503, matching how names are normalized before lookup
  return [...new Set(rows.map((row) => row.project.replace(/[-_.]+/g, "-").toLowerCase()))].slice(0, COUNT);
}

const [npm, pypi] = await Promise.all([npmNames(), pypiNames()]);
if (npm.length < COUNT || pypi.length < COUNT) throw new Error(`short lists: npm ${npm.length}, pypi ${pypi.length}`);
await writeFile("data/popular-npm.json", JSON.stringify(npm) + "\n");
await writeFile("data/popular-pypi.json", JSON.stringify(pypi) + "\n");
console.log(`npm ${npm.length}, pypi ${pypi.length}`);
