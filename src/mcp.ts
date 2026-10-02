import { createMcpHandler, McpServer } from "@modelcontextprotocol/server";
import { env } from "cloudflare:workers";
import { z } from "zod";
import { ecosystemInput, nameInput, namesInput } from "./api";
import { checkPackages } from "./engine/check";
import type { Ecosystem } from "./engine/normalize";

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

const annotations = { readOnlyHint: true, idempotentHint: true, openWorldHint: true };

const handler = createMcpHandler(
  () => {
    const server = new McpServer({ name: "pkgmirage", version: "0.1.0" });
    server.registerTool(
      "check_package",
      {
        title: "Check a package",
        description:
          "Check a package before you suggest it or run an install. Returns safe; caution (it exists but looks risky, " +
          "or couldn't be fully checked; tell the user the reasons before installing); or block (it doesn't exist, " +
          "is known malware, or copies a popular package's name; don't install it, offer the suggested names " +
          "instead). Check every package you haven't verified, especially ones you're not sure exist.",
        inputSchema: z.object({ ecosystem: ecosystemInput, name: nameInput }),
        outputSchema: output,
        annotations,
      },
      ({ ecosystem, name }) => check(ecosystem, [name]),
    );
    server.registerTool(
      "check_packages",
      {
        title: "Check several packages",
        description: "Same as check_package for 1-50 packages in one call, e.g. a list of dependencies, before installing them.",
        inputSchema: z.object({ ecosystem: ecosystemInput, names: namesInput }),
        outputSchema: output,
        annotations,
      },
      ({ ecosystem, names }) => check(ecosystem, names),
    );
    return server;
  },
  // Nothing is sent mid-call, so every answer is a single JSON body.
  { responseMode: "json" },
);

export const handleMcp = (request: Request) => handler.fetch(request);

async function check(ecosystem: Ecosystem, names: string[]) {
  const results: Result[] = (await checkPackages(ecosystem, names, env.CACHE)).map((r) => ({
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
