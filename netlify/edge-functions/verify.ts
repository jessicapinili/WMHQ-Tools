// The link in the email lands here: swaps a valid 15-minute token for a 60-day session cookie.
import { SESSION_TTL_MS, sessionCookie, signToken, verifyToken } from "../lib/auth.ts";

type LinkToken = { e: string; exp: number };

export default async (req: Request) => {
  const url = new URL(req.url);
  const link = await verifyToken<LinkToken>("link", url.searchParams.get("t"));

  if (!link || Date.now() > link.exp) {
    return Response.redirect(new URL("/login/?expired=1", url).toString(), 302);
  }

  const now = Date.now();
  const session = await signToken("session", { e: link.e, iat: now, chk: now });
  return new Response(null, {
    status: 302,
    headers: {
      Location: new URL("/", url).toString(),
      "Set-Cookie": sessionCookie(session, SESSION_TTL_MS),
      "Cache-Control": "no-store",
    },
  });
};

export const config = {
  path: "/api/verify",
};
