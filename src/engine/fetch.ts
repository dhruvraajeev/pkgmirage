export type FetchResult = { status: "ok"; data: unknown } | { status: "not_found" } | { status: "error"; reason: string };

const ALLOWED_HOSTS = new Set(["registry.npmjs.org", "api.npmjs.org", "pypi.org", "api.osv.dev"]);
const TIMEOUT_MS = 5_000;
const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
export const USER_AGENT = "pkgmirage/0.1";
export const TOO_LARGE = "response too large";

class TooLarge extends Error {}

// Only a definite 404 means "doesn't exist"; every other failure is an error so callers never mistake it for safe.
export async function fetchJson(
  url: string,
  { maxBytes = DEFAULT_MAX_BYTES, body }: { maxBytes?: number; body?: unknown } = {},
): Promise<FetchResult> {
  const { protocol, hostname, username } = new URL(url);
  if (protocol !== "https:" || username || !ALLOWED_HOSTS.has(hostname)) {
    throw new Error(`fetch to ${hostname} is not allowed`);
  }

  let res: Response;
  try {
    res = await fetch(url, {
      method: body === undefined ? "GET" : "POST",
      headers: {
        "user-agent": USER_AGENT,
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    return { status: "error", reason: isTimeout(err) ? "timed out" : "network error" };
  }

  if (res.status === 404) return { status: "not_found" };
  if (res.status !== 200) {
    await res.body?.cancel();
    return { status: "error", reason: statusReason(res.status) };
  }

  try {
    return { status: "ok", data: JSON.parse(await readCapped(res, maxBytes)) };
  } catch (err) {
    if (err instanceof TooLarge) return { status: "error", reason: TOO_LARGE };
    if (err instanceof SyntaxError) return { status: "error", reason: "invalid JSON" };
    return { status: "error", reason: isTimeout(err) ? "timed out" : "network error" };
  }
}

function statusReason(status: number): string {
  if (status === 429) return "rate limited";
  if (status >= 500) return `server error ${status}`;
  if (status >= 300 && status < 400) return "unexpected redirect";
  return `unexpected status ${status}`;
}

function isTimeout(err: unknown): boolean {
  return err instanceof DOMException && err.name === "TimeoutError";
}

// Content-Length can be missing or wrong, so the cap is enforced on the bytes actually read.
async function readCapped(res: Response, maxBytes: number): Promise<string> {
  if (Number(res.headers.get("content-length")) > maxBytes) {
    await res.body?.cancel();
    throw new TooLarge();
  }
  if (!res.body) return "";
  const decoder = new TextDecoder();
  const reader = res.body.getReader();
  let text = "";
  let bytes = 0;
  for (let chunk = await reader.read(); !chunk.done; chunk = await reader.read()) {
    bytes += chunk.value.byteLength;
    if (bytes > maxBytes) {
      await reader.cancel();
      throw new TooLarge();
    }
    text += decoder.decode(chunk.value, { stream: true });
  }
  return text + decoder.decode();
}
