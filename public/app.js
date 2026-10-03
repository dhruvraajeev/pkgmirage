// Everything that comes from the server or the user is set as text, never parsed as markup: a package name like
// `<img src=x onerror=...>` must show exactly as typed.
const form = document.getElementById("check");
const nameInput = document.getElementById("name");
const status = document.getElementById("status");
const result = document.getElementById("result");

const VERDICTS = { safe: "Safe", caution: "Caution", block: "Blocked: do not install" };

let inFlight = null;

form.addEventListener("submit", (event) => {
  event.preventDefault();
  check(form.elements.ecosystem.value, nameInput.value);
});

async function check(ecosystem, name) {
  // Only the newest check may draw: an older answer arriving late would show the wrong package.
  inFlight?.abort();
  const controller = (inFlight = new AbortController());
  result.replaceChildren();
  show(`Checking ${shown(name.trim())}…`);
  let res, body;
  try {
    res = await fetch("/api/check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ecosystem, names: [name] }),
      signal: controller.signal,
    });
    // A rate limit or error from in front of pkgMirage may not be JSON; the status still decides what to say.
    body = await res.json().catch(() => null);
  } catch {
    if (!controller.signal.aborted) couldNotCheck(name);
    return;
  }
  if (controller.signal.aborted) return;
  const verdict = res.ok ? body?.results?.[0] : undefined;
  if (verdict) {
    show(`${shown(verdict.name)}: ${label(verdict)}`);
    result.append(card(verdict));
  } else if (res.status === 429) {
    const wait = res.headers.get("retry-after");
    show(wait ? `Too many checks; try again in ${wait} seconds.` : "Too many checks; try again later.", true);
  } else if ((res.status === 400 || res.status === 413) && typeof body?.error === "string") {
    show(body.error, true);
  } else {
    couldNotCheck(name);
  }
}

// A failed check must never read as a pass.
function couldNotCheck(name) {
  show(`Couldn't check ${shown(name.trim())} right now. That is not a safe result.`, true);
}

function show(text, isError = false) {
  status.textContent = text;
  status.className = isError ? "error" : "";
}

// Valid npm and PyPI names are plain ASCII, so anything else is shown as a code: a zero-width space or a Cyrillic
// letter would otherwise make a blocked name look exactly like the popular one.
function shown(name) {
  return name.replace(/[^\x20-\x7e]/g, (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, "0")}`);
}

function label(verdict) {
  const unverified = verdict.reasons.some((reason) => reason.startsWith("unverified:"));
  return verdict.verdict === "caution" && unverified ? "Caution: couldn't fully verify" : VERDICTS[verdict.verdict];
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function card(verdict) {
  const article = el("article", undefined, `card ${verdict.verdict}`);
  const registry = verdict.checks.registry;
  article.append(el("h2", shown(verdict.name)), el("p", label(verdict), "verdict"));
  if (registry.latestVersion) article.append(el("p", `Latest version: ${registry.latestVersion}`));
  if (verdict.reasons.length) {
    const reasons = el("ul");
    for (const reason of verdict.reasons) reasons.append(el("li", reason));
    article.append(reasons);
  }
  if (verdict.suggestions.length) {
    const suggestions = el("p", "Did you mean: ", "suggestions");
    for (const name of verdict.suggestions) {
      const button = el("button", name);
      button.type = "button";
      button.addEventListener("click", () => {
        nameInput.value = name;
        nameInput.focus();
        check(verdict.ecosystem, name);
      });
      suggestions.append(button, " ");
    }
    article.append(suggestions);
  }
  const details = el("details");
  details.append(el("summary", "What was checked"), checksList(verdict));
  article.append(details, el("p", `Checked ${new Date(verdict.checkedAt).toLocaleString()}`, "checked-at"));
  return article;
}

function checksList({ checks }) {
  const list = el("dl");
  const add = (term, value) => list.append(el("dt", term), el("dd", value));
  const { registry, osv, lookalike, code, seenInvented } = checks;
  if (registry.status === "found") {
    add("Registry", "found");
    add("First seen", registry.firstSeenAt ? new Date(registry.firstSeenAt).toLocaleDateString() : "unknown");
    if (registry.weeklyDownloads !== undefined) add("Downloads last week", registry.weeklyDownloads.toLocaleString());
    if (registry.downloadsError) add("Downloads last week", `unavailable (${registry.downloadsError})`);
    add("Maintainers", String(registry.maintainers));
    add("Install scripts", registry.installScripts.length ? registry.installScripts.join(", ") : "none");
    add("Source repository", registry.hasRepo ? "linked" : "not linked");
  } else if (registry.status === "not_found") {
    add("Registry", "doesn't exist");
  } else if (registry.status === "error") {
    add("Registry", `couldn't check (${registry.reason})`);
  } else {
    add("Registry", `not looked up (${registry.reason})`);
  }
  const malware =
    osv.status === "ok" ? (osv.advisories.length ? osv.advisories.join(", ") : "none known")
    : osv.status === "error" ? `couldn't check (${osv.reason})`
    : "not checked";
  add("Malware and vulnerabilities", malware);
  add("Close to popular packages", lookalike.length ? lookalike.join(", ") : "none");
  add(
    "Code",
    code.status === "read" ? `read ${code.filesRead} of ${code.files} files${code.partial ? ", some only in part" : ""}`
    : code.status === "error" ? `couldn't check (${code.reason})`
    : "not opened",
  );
  if (seenInvented) add("Seen as an invented name", new Date(seenInvented).toLocaleDateString());
  return list;
}
