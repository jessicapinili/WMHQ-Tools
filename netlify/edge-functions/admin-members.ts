// Admin API for the member list. Only signed-in admins can read or change it.
import { getSession, normalizeEmail } from "../lib/auth.ts";
import { getMembers, isAdmin, saveMembers } from "../lib/members.ts";

type Change =
  | { action: "add"; emails: string[] }
  | { action: "remove"; emails: string[] }
  | { action: "replace"; emails: string[] };

const noStore = { "Cache-Control": "no-store" };

export default async (req: Request) => {
  const session = await getSession(req);
  if (!session || !isAdmin(session.e)) {
    return Response.json({ ok: false, error: "Not signed in as an admin." }, { status: 401, headers: noStore });
  }

  if (req.method === "GET") {
    return Response.json({ ok: true, ...(await getMembers()) }, { headers: noStore });
  }

  // Requiring JSON means a cross-site form can't post here with the admin's cookie.
  if (!req.headers.get("content-type")?.includes("application/json")) {
    return Response.json({ ok: false, error: "Expected JSON." }, { status: 415, headers: noStore });
  }

  let change: Change;
  try {
    change = await req.json();
  } catch {
    return Response.json({ ok: false, error: "Invalid request." }, { status: 400, headers: noStore });
  }

  const incoming = Array.isArray(change?.emails)
    ? change.emails.map(normalizeEmail).filter((e): e is string => Boolean(e))
    : [];
  const current = (await getMembers()).emails;

  let next: string[];
  if (change.action === "add") next = [...current, ...incoming];
  else if (change.action === "remove") next = current.filter((e) => !incoming.includes(e));
  else if (change.action === "replace") next = incoming;
  else return Response.json({ ok: false, error: "Unknown action." }, { status: 400, headers: noStore });

  return Response.json({ ok: true, ...(await saveMembers(next)) }, { headers: noStore });
};

export const config = {
  path: "/api/admin/members",
  method: ["GET", "POST"],
};
