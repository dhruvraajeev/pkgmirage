export type FetchResult = { status: "ok"; data: unknown } | { status: "not_found" } | { status: "error"; reason: string };
type Failure = Exclude<FetchResult, { status: "ok" }>;

const ALLOWED_HOSTS = new Set(["registry.npmjs.org", "api.npmjs.org", "pypi.org", "api.osv.dev"]);
export const TIMEOUT_MS = 5_000;
const DEFAULT_MAX_BYTES = 2 * 1024 * 1024;
export const USER_AGENT = "pkgmirage/0.1";
export const TOO_LARGE = "response too large";

// A body that failed while it was being read; the message is the reason callers report.
export class FetchFailed extends Error {}

// Only a definite 404 means "doesn't exist"; every other failure is an error so callers never mistake it for safe.
export async function fetchJson(
  url: string,
  { maxBytes = DEFAULT_MAX_BYTES, body }: { maxBytes?: number; body?: unknown } = {},
): Promise<FetchResult> {
  const res = await send(url, "application/json", maxBytes, body);
  if (res.status !== "ok") return res;
  try {
    const decoder = new TextDecoder();
    let text = "";
    for await (const chunk of res.body) text += decoder.decode(chunk, { stream: true });
    return { status: "ok", data: JSON.parse(text + decoder.decode()) };
  } catch (err) {
    if (err instanceof FetchFailed) return { status: "error", reason: err.message };
    return { status: "error", reason: err instanceof SyntaxError ? "invalid JSON" : "network error" };
  }
}

// The same rules as fetchJson, for a body read as it streams in; a read past maxBytes fails with FetchFailed.
export const fetchBytes = (url: string, maxBytes: number) => send(url, "application/octet-stream", maxBytes);

async function send(
  url: string,
  accept: string,
  maxBytes: number,
  body?: unknown,
): Promise<{ status: "ok"; body: ReadableStream<Uint8Array> } | Failure> {
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
        accept,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: "manual",
      // Also bounds reading the body, so a server that trickles bytes can't hold a check open.
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
  if (Number(res.headers.get("content-length")) > maxBytes) {
    await res.body?.cancel();
    return { status: "error", reason: TOO_LARGE };
  }
  return { status: "ok", body: capped(res.body ?? new Blob().stream(), maxBytes) };
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

// Content-Length can be missing or wrong, so the cap is enforced on the bytes actually read, and reading stops there.
function capped(body: ReadableStream<Uint8Array>, maxBytes: number): ReadableStream<Uint8Array> {
  const reader = body.getReader();
  let bytes = 0;
  return new ReadableStream({
    async pull(controller) {
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await reader.read();
      } catch (err) {
        throw new FetchFailed(isTimeout(err) ? "timed out" : "network error");
      }
      if (chunk.done) return controller.close();
      bytes += chunk.value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel();
        throw new FetchFailed(TOO_LARGE);
      }
      controller.enqueue(chunk.value);
    },
    cancel: (reason) => reader.cancel(reason),
  });
}
