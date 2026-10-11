// Admin API for the member list. Only signed-in admins can read or change it.
import { getSession, normalizeEmail } from "../lib/auth.ts";
import { getMembers, isAdmin, saveMembers, updateMembers } from "../lib/members.ts";

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
  if (change.action === "add") {
    return Response.json({ ok: true, ...(await updateMembers((current) => [...current, ...incoming])) }, { headers: noStore });
  }
  if (change.action === "remove") {
    return Response.json(
      { ok: true, ...(await updateMembers((current) => current.filter((e) => !incoming.includes(e)))) },
      { headers: noStore },
    );
  }
  if (change.action === "replace") {
    return Response.json({ ok: true, ...(await saveMembers(incoming)) }, { headers: noStore });
  }
  return Response.json({ ok: false, error: "Unknown action." }, { status: 400, headers: noStore });
};

export const config = {
  path: "/api/admin/members",
  method: ["GET", "POST"],
};
