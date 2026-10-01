import { z } from "zod";
import { checkPackages } from "./engine/check";

const checkRequest = z.object({
  ecosystem: z.enum(["npm", "pypi"], { error: 'must be "npm" or "pypi"' }),
  names: z
    .array(z.string().trim().min(1, "name is empty").max(214, "name is longer than 214 characters"))
    .min(1, "need at least 1 name")
    .max(50, "at most 50 names per request"),
});

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
