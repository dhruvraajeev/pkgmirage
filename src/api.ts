import { z } from "zod";
import { checkPackages } from "./engine/check";

// The MCP tools take the same fields, so there is one set of input rules for every front door.
export const ecosystemInput = z.enum(["npm", "pypi"], { error: 'must be "npm" or "pypi"' });
export const nameInput = z.string().trim().min(1, "name is empty").max(214, "name is longer than 214 characters");
export const namesInput = z.array(nameInput).min(1, "need at least 1 name").max(50, "at most 50 names per request");
const checkRequest = z.object({ ecosystem: ecosystemInput, names: namesInput });
// The largest valid request (50 names of 214 three-byte characters) is about 32 KB.
export const MAX_BODY_BYTES = 64 * 1024;

export function jsonError(status: number, message: string, headers?: HeadersInit): Response {
  return Response.json({ error: message }, { status, headers });
}

// Stops as soon as a body is known to be too big (by its declared length or by counting what arrives), so an endless
// body is never read to the end.
export async function readBody(request: Request, maxBytes: number): Promise<Blob | null> {
  if (Number(request.headers.get("content-length")) > maxBytes) return null;
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of request.body ?? []) {
    size += chunk.byteLength;
    if (size > maxBytes) return null;
    chunks.push(chunk);
  }
  return new Blob(chunks);
}

export async function handleCheck(request: Request, cache: KVNamespace): Promise<Response> {
  const raw = await readBody(request, MAX_BODY_BYTES);
  if (!raw) return jsonError(413, "request body too large");
  let body: unknown;
  try {
    body = JSON.parse(await raw.text());
  } catch {
    return jsonError(400, "body must be JSON");
  }
  const parsed = checkRequest.safeParse(body);
  if (!parsed.success) {
    const issue = parsed.error.issues[0]!;
    return jsonError(400, `${issue.path.join(".") || "body"}: ${issue.message}`);
  }
  return Response.json({ results: await checkPackages(parsed.data.ecosystem, parsed.data.names, cache) });
}
