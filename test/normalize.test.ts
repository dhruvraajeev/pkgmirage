import { describe, expect, it } from "vitest";
import { normalizeBatch, normalizeName } from "../src/engine/normalize";

describe("normalize", () => {
  it("accepts plain and scoped npm names as given", () => {
    expect(normalizeName("npm", "react")).toEqual({ ok: true, name: "react" });
    expect(normalizeName("npm", "@types/node")).toEqual({ ok: true, name: "@types/node" });
    expect(normalizeName("npm", "lodash.merge")).toEqual({ ok: true, name: "lodash.merge" });
    // Legacy mixed-case names still exist and differ from their lowercase twins.
    expect(normalizeName("npm", "JSONStream")).toEqual({ ok: true, name: "JSONStream" });
  });

  it("rejects npm names that break registry rules", () => {
    for (const name of [".hidden", "_private", "has space", "semi;colon", "@scope", "@scope/", "a/b", "@a/b/c", "caf%C3%A9"]) {
      const result = normalizeName("npm", name);
      expect(result.ok, name).toBe(false);
      expect(result).toMatchObject({ reason: expect.stringContaining("not a valid npm package name") });
    }
  });

  it("normalizes pypi names per PEP 503", () => {
    expect(normalizeName("pypi", "Flask_Login")).toEqual({ ok: true, name: "flask-login" });
    expect(normalizeName("pypi", "zope.interface")).toEqual({ ok: true, name: "zope-interface" });
    expect(normalizeName("pypi", "Some__Weird-._Name")).toEqual({ ok: true, name: "some-weird-name" });
  });

  it("rejects invalid pypi names", () => {
    for (const name of ["-leading", "trailing_", "has space", "@scope/name", "a/b"]) {
      expect(normalizeName("pypi", name), name).toMatchObject({
        ok: false,
        reason: expect.stringContaining("not a valid PyPI package name"),
      });
    }
  });

  it("flags zero-width and control characters", () => {
    for (const name of ["re​act", "‮react", "re\u0000act", "re\tact"]) {
      expect(normalizeName("npm", name), JSON.stringify(name)).toMatchObject({
        ok: false,
        reason: expect.stringContaining("invisible or control characters"),
      });
    }
  });

  it("flags names mixing alphabets", () => {
    // Cyrillic "е" (U+0435) in place of Latin "e"
    for (const ecosystem of ["npm", "pypi"] as const) {
      expect(normalizeName(ecosystem, "rеquests")).toMatchObject({
        ok: false,
        reason: expect.stringContaining("look-alike characters"),
      });
    }
  });

  it("dedupes a batch after normalization", () => {
    expect(normalizeBatch("pypi", ["Flask_Login", "requests", "flask-login", "FLASK.LOGIN", "bad name", "bad name"])).toEqual([
      { ok: true, name: "flask-login" },
      { ok: true, name: "requests" },
      { ok: false, name: "bad name", reason: expect.any(String) },
    ]);
  });
});
