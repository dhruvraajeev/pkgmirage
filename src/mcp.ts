import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { z } from "zod";
import { ecosystemInput, MAX_BODY_BYTES, nameInput, namesInput } from "./api";
import { checkPackages } from "./engine/check";
import type { Ecosystem } from "./engine/normalize";
import type { CheckResult } from "./engine/score";
import { watchFor } from "./engine/watch";

const VERDICT_TEXT = { safe: "SAFE", caution: "CAUTION.", block: "BLOCK, do not install." } as const;

// Tool output lands in an AI's context, so it carries only pkgMirage's own wording, never registry-supplied text.
const output = z.object({
  results: z.array(
    z.object({
      name: z.string(),
      ecosystem: ecosystemInput,
      verdict: z.enum(["safe", "caution", "block"]),
      reasons: z.array(z.string()),
      suggestions: z.array(z.string()),
      checkedAt: z.string(),
    }),
  ),
});
type Result = z.infer<typeof output>["results"][number];

const UNVERIFIED = "pkgMirage couldn't complete the check (internal error); treat these packages as unverified";

const annotations = { readOnlyHint: true, idempotentHint: true, openWorldHint: true };

const handler = createMcpHandler(
  ({ requestInfo }) => {
    // The tools never change, so no change notifications are offered (the SDK offers them by default).
    const server = new McpServer({ name: "pkgmirage", version: "0.1.0" }, { capabilities: { tools: { listChanged: false } } });
    server.registerTool(
      "check_package",
      {
        title: "Check a package",
        description:
          "Check an npm or PyPI package before you suggest it, add it to a dependency file or install it. pkgMirage " +
          "checks the registry, a malware database and the most popular package names, and opens risky npm packages " +
          "and reads their code (it never runs it). " +
          "safe: install as usual. " +
          "caution: it exists but looks risky (brand new, very few downloads, install scripts or one added in the " +
          "latest version, known vulnerabilities, a name close to a popular package, or something its code does, " +
          "such as running shell commands at install), or a check couldn't be completed. Tell the user the reasons " +
          "and let them decide before installing. " +
          "block: don't install it. It doesn't exist (likely invented), is known malware or was taken down, copies a " +
          "popular package's name, has look-alike or invisible characters, was registered after being seen as an " +
          "invented name, or its install script runs commands or reads secrets and sends data out. Offer the " +
          "suggested names instead, if there are any. " +
          "Check every package you haven't verified, especially ones you're not sure exist.",
        inputSchema: z.object({ ecosystem: ecosystemInput, name: nameInput }),
        outputSchema: output,
        annotations,
      },
      ({ ecosystem, name }) => check(ecosystem, [name], requestInfo),
    );
    server.registerTool(
      "check_packages",
      {
        title: "Check several packages",
        description: "Same as check_package for 1-50 packages in one call (e.g. a project's dependencies), before installing them.",
        inputSchema: z.object({ ecosystem: ecosystemInput, names: namesInput }),
        outputSchema: output,
        annotations,
      },
      ({ ecosystem, names }) => check(ecosystem, names, requestInfo),
    );
    return server;
  },
  {
    // Nothing is sent mid-call, so every answer is a single JSON body.
    responseMode: "json",
    // With no change notifications, a subscription stream would only sit open; refuse it at once.
    maxSubscriptions: 0,
    maxRequestBodySize: MAX_BODY_BYTES,
    onerror: (error) => console.warn("mcp request rejected", error),
  },
);

export const handleMcp = (request: Request) => handler.fetch(request);

async function check(ecosystem: Ecosystem, names: string[], request: Request | undefined) {
  let checked: CheckResult[];
  try {
    checked = await checkPackages(ecosystem, names, env.CACHE, watchFor(env, request, "mcp"));
  } catch (error) {
    // The SDK would put the error's message in the result; the AI only needs to know nothing was verified.
    console.error("mcp check failed", error);
    return { content: [{ type: "text" as const, text: UNVERIFIED }], isError: true };
  }
  const results: Result[] = checked.map((r) => ({
    name: shown(r.name),
    ecosystem: r.ecosystem,
    verdict: r.verdict,
    reasons: r.reasons,
    suggestions: r.suggestions,
    checkedAt: r.checkedAt,
  }));
  return { content: [{ type: "text" as const, text: results.map(summary).join("\n") }], structuredContent: { results } };
}

function summary({ name, ecosystem, verdict, reasons, suggestions }: Result): string {
  const didYouMean = suggestions.length ? `. Did you mean: ${suggestions.join(", ")}?` : "";
  return `${name} (${ecosystem}): ${[VERDICT_TEXT[verdict], reasons.join("; ")].filter(Boolean).join(" ")}${didYouMean}`;
}

// A rejected name can hold anything, including text written to look like instructions; outside the characters a
// package name may use, each one is shown as a \uXXXX code.
function shown(name: string): string {
  return name.replace(/[^\w@/.~-]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, "0")}`);
}
