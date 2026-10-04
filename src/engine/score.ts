import type { CodeCheck, Finding, FindingId } from "./code";
import type { Ecosystem } from "./normalize";
import type { OsvCheck } from "./osv";
import type { RegistryCheck } from "./registry";

export type Verdict = "safe" | "caution" | "block";

export interface Checks {
  registry: RegistryCheck;
  osv: OsvCheck;
  lookalike: string[];
  code: CodeCheck;
  // When callers first saw this name not exist, if it is watched and registered since.
  seenInvented?: string;
}

export interface CheckResult {
  name: string;
  ecosystem: Ecosystem;
  verdict: Verdict;
  reasons: string[];
  suggestions: string[];
  checks: Checks;
  checkedAt: string;
}

// Starting points, not tuned yet: loose enough that established small packages pass, tight enough to
// catch a freshly registered squat. Revisit once there is accuracy data.
export const RISK = {
  newPackageDays: 30,
  minWeeklyDownloads: 100,
};

const DAY_MS = 86_400_000;
const MAX_LISTED_ADVISORIES = 3;
// Advisory IDs come from OSV and end up in an AI's context through the MCP tools, so only ID-shaped ones are repeated.
const ADVISORY_ID = /^[A-Z]+(?:-[A-Za-z0-9.]+)+$/;
const REGISTRY_NAMES: Record<Ecosystem, string> = { npm: "npm", pypi: "PyPI" };

// Install-time code that runs shell commands or reads secrets and also sends data out is how install-time credential
// theft looks; none of 907 real packages read on 2026-10-03 has both (counting package code too, 5 would, yarn among
// them, so it isn't counted).
const SECRETS: readonly FindingId[] = ["ssh", "npmrc", "cloud", "env"];
export const OUTBOUND: readonly FindingId[] = ["raw-ip", "webhook", "paste"];
// pkgMirage's own words for each finding; nothing from the package ever reaches a reason.
const FINDING_WORDS: Record<FindingId, [verb: string, what: string]> = {
  shell: ["runs", "shell commands"],
  ssh: ["reads", "SSH keys"],
  npmrc: ["reads", "npm tokens"],
  cloud: ["reads", "cloud credentials"],
  env: ["reads", "all environment variables"],
  "raw-ip": ["sends data to", "a raw IP address"],
  webhook: ["sends data to", "a chat webhook"],
  paste: ["sends data to", "a paste site"],
  dynamic: ["runs", "code built from strings"],
  obfuscated: ["is", "obfuscated"],
};

export function score(ecosystem: Ecosystem, name: string, checks: Checks, now = Date.now()): CheckResult {
  const { registry, osv, lookalike, code } = checks;
  const result = (verdict: Verdict, reasons: string[]): CheckResult => ({
    name,
    ecosystem,
    verdict,
    reasons,
    suggestions: lookalike,
    checks,
    checkedAt: new Date(now).toISOString(),
  });

  switch (registry.status) {
    case "skipped":
      return result("block", [registry.reason]);
    case "not_found":
      return result("block", [`doesn't exist on ${REGISTRY_NAMES[ecosystem]} (likely hallucinated)`]);
    case "error":
      return result("caution", [`unverified: couldn't reach ${REGISTRY_NAMES[ecosystem]} (${registry.reason})`]);
  }

  const advisories = osv.status === "ok" ? osv.advisories : [];
  const malware = advisories.find((id) => id.startsWith("MAL-"));
  if (malware) return result("block", [`known malicious package (${shownId(malware)})`]);
  // npm swaps removed malware for a "0.0.1-security" placeholder so the name can't be reused.
  if (ecosystem === "npm" && registry.latestVersion?.endsWith("-security")) {
    return result("block", ["taken down by npm for security reasons"]);
  }

  const strong: string[] = [];
  if (registry.firstSeenAt !== null) {
    const ageDays = Math.floor((now - Date.parse(registry.firstSeenAt)) / DAY_MS);
    if (ageDays < RISK.newPackageDays) strong.push(`first seen ${ageDays} ${ageDays === 1 ? "day" : "days"} ago`);
  } else if (ecosystem === "pypi") {
    // npm age comes from download history, so its absence is already covered by the download reasons.
    strong.push("unverified: publish date unavailable");
  }
  if (registry.installScripts.length) strong.push(`runs install scripts (${registry.installScripts.join(", ")})`);
  // A package that suddenly gains an install script is the shape of a hijacked release.
  if (registry.installScriptAdded) strong.push("install script added in the latest version");
  const findings = code.status === "read" ? code.findings : [];
  const codeReasons = (["install", "package"] as const).flatMap((where) => findingReason(where, findings));
  strong.push(...codeReasons);
  if (registry.downloadsError) strong.push(`unverified: download count unavailable (${registry.downloadsError})`);
  if (registry.weeklyDownloads !== undefined && registry.weeklyDownloads < RISK.minWeeklyDownloads) {
    strong.push(`only ${registry.weeklyDownloads} downloads last week`);
  }
  if (osv.status === "error") strong.push(`unverified: malware check unavailable (${osv.reason})`);
  if (code.status === "error") strong.push(`unverified: code check unavailable (${code.reason})`);
  if (advisories.length) strong.push(vulnerabilityReason(advisories));
  // Plenty of established packages have one maintainer or no repo link (@types/node lists one maintainer),
  // so these only add context when something else already looks off.
  const weak: string[] = [];
  if (registry.maintainers === 1) weak.push("only one maintainer");
  if (!registry.hasRepo) weak.push("no source repository linked");

  if (checks.seenInvented) {
    // Some AI keeps inventing this name and somebody registered it: the slopsquatting pattern itself.
    return result("block", [`registered after being seen as an invented name on ${checks.seenInvented.slice(0, 10)}`, ...strong, ...weak]);
  }
  const copycat = lookalike.length ? [`looks like popular package "${lookalike[0]}"`] : [];
  if (codeBlocks(findings)) {
    return result("block", [...codeReasons, ...copycat, ...strong.filter((reason) => !codeReasons.includes(reason)), ...weak]);
  }
  if (lookalike.length) {
    // A copycat name on a package that is also new, unused or unverifiable is how slopsquats look.
    return strong.length
      ? result("block", [...copycat, ...strong, ...weak])
      : result("caution", [`name is close to popular package "${lookalike[0]}"`]);
  }
  const reasons = strong.length ? [...strong, ...weak] : [];
  return result(reasons.length ? "caution" : "safe", reasons);
}

function codeBlocks(findings: Finding[]): boolean {
  const install = new Set(findings.flatMap(({ id, where }) => (where === "install" ? [id] : [])));
  return (install.has("shell") || SECRETS.some((id) => install.has(id))) && OUTBOUND.some((id) => install.has(id));
}

// "install script runs shell commands, reads SSH keys and npm tokens, and sends data to a raw IP address": findings
// sharing a verb are listed under it.
function findingReason(where: Finding["where"], findings: Finding[]): string[] {
  const groups: [verb: string, what: string[]][] = [];
  for (const { id } of findings.filter((finding) => finding.where === where)) {
    const [verb, what] = FINDING_WORDS[id];
    const last = groups.at(-1);
    if (last?.[0] === verb) last[1].push(what);
    else groups.push([verb, [what]]);
  }
  if (!groups.length) return [];
  const phrases = groups.map(([verb, what]) => `${verb} ${listed(what, " and ")}`);
  return [`${where === "install" ? "install script" : "package code"} ${listed(phrases, phrases.length > 2 ? ", and " : " and ")}`];
}

const listed = (items: string[], last: string) => (items.length > 1 ? items.slice(0, -1).join(", ") + last + items.at(-1) : items[0]!);

function vulnerabilityReason(ids: string[]): string {
  const listed = ids.slice(0, MAX_LISTED_ADVISORIES).map(shownId).join(", ") + (ids.length > MAX_LISTED_ADVISORIES ? ", ..." : "");
  return `${ids.length} known ${ids.length === 1 ? "vulnerability" : "vulnerabilities"} in the latest version (${listed})`;
}

function shownId(id: string): string {
  return id.length <= 64 && ADVISORY_ID.test(id) ? id : "unrecognized id";
}
