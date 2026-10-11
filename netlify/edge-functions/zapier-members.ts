// Side door for Zapier: adds or removes one member without anyone signing in to /admin/.
// Zapier proves who it is with the ZAPIER_SECRET password, sent in the X-Webhook-Secret header.
// With no ZAPIER_SECRET set in Netlify, this door stays shut.
import { normalizeEmail } from "../lib/auth.ts";
import { updateMembers } from "../lib/members.ts";

const noStore = { "Cache-Control": "no-store" };
const encoder = new TextEncoder();

// Compares hashes rather than the raw strings so the time taken reveals nothing about the secret.
async function sameSecret(given: string, expected: string): Promise<boolean> {
  const [a, b] = await Promise.all(
    [given, expected].map(async (s) => new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(s)))),
  );
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Zapier can send either JSON or a regular form; accept both.
async function readFields(req: Request): Promise<Record<string, unknown>> {
  if (req.headers.get("content-type")?.includes("application/json")) return await req.json();
  return Object.fromEntries(await req.formData());
}

export default async (req: Request) => {
  const expected = Netlify.env.get("ZAPIER_SECRET");
  if (!expected) {
    return Response.json({ ok: false, error: "Zapier access is not set up." }, { status: 503, headers: noStore });
  }

  const given =
    req.headers.get("x-webhook-secret") ?? req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") ?? "";
  if (!(await sameSecret(given, expected))) {
    return Response.json({ ok: false, error: "Wrong or missing secret." }, { status: 401, headers: noStore });
  }

  let fields: Record<string, unknown>;
  try {
    fields = await readFields(req);
  } catch {
    return Response.json({ ok: false, error: "Invalid request." }, { status: 400, headers: noStore });
  }

  const email = normalizeEmail(fields.email);
  if (!email) return Response.json({ ok: false, error: "Missing or invalid email." }, { status: 400, headers: noStore });

  const action = fields.action ?? "add";
  if (action !== "add" && action !== "remove") {
    return Response.json({ ok: false, error: "Unknown action." }, { status: 400, headers: noStore });
  }

  const list = await updateMembers((current) =>
    action === "add" ? [...current, email] : current.filter((e) => e !== email),
  );
  return Response.json({ ok: true, action, email, members: list.emails.length }, { headers: noStore });
};

export const config = {
  path: "/api/zapier/members",
  method: "POST",
};
