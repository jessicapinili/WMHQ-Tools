// Protects the dashboard home page and the admin page. Tool pages are intentionally left open.
import {
  clearedSessionCookie,
  getSession,
  RECHECK_MS,
  SESSION_TTL_MS,
  sessionCookie,
  signToken,
} from "../lib/auth.ts";
import { hasToolsAccess, isAdmin } from "../lib/members.ts";

function toLogin(req: Request, clearCookie = false): Response {
  const headers = new Headers({ Location: new URL("/login/", req.url).toString(), "Cache-Control": "no-store" });
  if (clearCookie) headers.append("Set-Cookie", clearedSessionCookie());
  return new Response(null, { status: 302, headers });
}

export default async (req: Request, context: { next: () => Promise<Response> }) => {
  const session = await getSession(req);
  if (!session) return toLogin(req, true);

  if (new URL(req.url).pathname.startsWith("/admin") && !isAdmin(session.e)) {
    return new Response(null, { status: 302, headers: { Location: new URL("/", req.url).toString() } });
  }

  const now = Date.now();
  let refreshedCookie: string | null = null;
  if (now - session.chk > RECHECK_MS) {
    try {
      if (!(await hasToolsAccess(session.e))) return toLogin(req, true);
      const token = await signToken("session", { e: session.e, iat: session.iat, chk: now });
      refreshedCookie = sessionCookie(token, SESSION_TTL_MS - (now - session.iat));
    } catch (err) {
      // Member list unreachable: keep the member in rather than locking everyone out. Retry next visit.
      console.error("Daily access re-check failed:", err);
    }
  }

  const response = await context.next();
  const headers = new Headers(response.headers);
  headers.set("Cache-Control", "private, no-store");
  if (refreshedCookie) headers.append("Set-Cookie", refreshedCookie);
  return new Response(response.body, { status: response.status, headers });
};

export const config = {
  path: ["/", "/index.html", "/admin", "/admin/", "/admin/index.html"],
};
