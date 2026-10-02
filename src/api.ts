import { z } from "zod";
import { checkPackages } from "./engine/check";

// The MCP tools take the same fields, so there is one set of input rules for every front door.
export const ecosystemInput = z.enum(["npm", "pypi"], { error: 'must be "npm" or "pypi"' });
export const nameInput = z.string().trim().min(1, "name is empty").max(214, "name is longer than 214 characters");
export const namesInput = z.array(nameInput).min(1, "need at least 1 name").max(50, "at most 50 names per request");
const checkRequest = z.object({ ecosystem: ecosystemInput, names: namesInput });

export function jsonError(status: number, message: string, headers?: HeadersInit): Response {
  return Response.json({ error: message }, { status, headers });
}

export async function handleCheck(request: Request, cache: KVNamespace): Promise<Response> {
  let body: unknown;
  try {
    body = await request.json();
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
