import { describe, expect, it } from "vitest";
import npmPopular from "../data/popular-npm.json";
import pypiPopular from "../data/popular-pypi.json";
import { findLookalikes } from "../src/engine/lookalike";

describe("lookalike", () => {
  it("skips short names and keeps legitimate near-misses rare", () => {
    expect(findLookalikes("npm", "umd")).toEqual([]);
    expect(findLookalikes("pypi", "old-py")).toEqual([]);
    expect(findLookalikes("npm", "redlock")).toEqual([]);
  });

  it("catches typos, swaps and case changes", () => {
    expect(findLookalikes("npm", "expres")).toContain("express");
    expect(findLookalikes("npm", "lodahs")).toContain("lodash");
    expect(findLookalikes("npm", "Axios")).toContain("axios");
    expect(findLookalikes("pypi", "reqeusts")).toContain("requests");
    expect(findLookalikes("pypi", "nunpy")).toContain("numpy");
    expect(findLookalikes("npm", "totally-original-name-xyz")).toEqual([]);
  });

  it("catches scope squats", () => {
    expect(findLookalikes("npm", "@type/react")).toContain("@types/react");
    // Only the scope's owner can publish inside it, so siblings aren't squats.
    expect(findLookalikes("npm", "@types/reactt")).toEqual([]);
  });

  it("catches reordered name parts", () => {
    expect(findLookalikes("pypi", "dateutil-python")).toContain("python-dateutil");
  });

  it("catches padded names", () => {
    expect(findLookalikes("pypi", "requests-py")).toContain("requests");
    expect(findLookalikes("pypi", "py-requests")).toContain("requests");
    expect(findLookalikes("npm", "react-js")).toContain("react");
    expect(findLookalikes("npm", "node-lodash")).toContain("lodash");
  });

  it("never flags a popular package itself", () => {
    for (const name of ["react", "@types/node", "JSONStream", "ms", "next"]) expect(findLookalikes("npm", name), name).toEqual([]);
    for (const name of ["requests", "flask-login", "python-dateutil"]) expect(findLookalikes("pypi", name), name).toEqual([]);
  });

  it("orders suggestions by closeness then popularity", () => {
    const suggestions = findLookalikes("npm", "expresss");
    expect(suggestions[0]).toBe("express");
    expect(suggestions.length).toBeLessThanOrEqual(3);

    // Every suggestion is one edit from "colorz"; the more popular comes first.
    const ties = findLookalikes("npm", "colorz");
    const ranks = ties.map((name) => npmPopular.indexOf(name));
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
    expect(ties.length).toBeGreaterThan(1);

    // Both one edit away; the more popular wins even though it's the longer name.
    expect(findLookalikes("npm", "semve").slice(0, 2)).toEqual(["semver", "serve"]);
  });

  it("popular lists are loaded and normalized", () => {
    expect(npmPopular).toHaveLength(10_000);
    expect(pypiPopular).toHaveLength(10_000);
    expect(npmPopular).toContain("react");
    expect(pypiPopular.every((name) => name === name.toLowerCase() && !/[_.]/.test(name))).toBe(true);
  });
});
