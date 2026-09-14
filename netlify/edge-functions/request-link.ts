// Login form submits here. Emails a 15-minute link only if the email has the Kajabi tag.
// The response is identical either way so the page never reveals who is a member.
import { env, hasToolsAccess, LINK_TTL_MS, normalizeEmail, signToken } from "../lib/auth.ts";

const DEFAULT_FROM = "Woman Mastery HQ <login@womanmasteryhqportal.com>";

function emailHtml(link: string): string {
  return `<!doctype html>
<html><body style="margin:0;padding:0;background:#f2f2f2;font-family:'DM Sans',Helvetica,Arial,sans-serif;color:#1a0a0a;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="padding:40px 16px;">
    <tr><td align="center">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:480px;background:#ffffff;border-radius:16px;overflow:hidden;">
        <tr><td style="background:#3D0D0C;padding:24px 32px;">
          <div style="font-size:17px;font-weight:800;color:#f1ebeb;">Woman Mastery HQ</div>
          <div style="font-size:10px;font-weight:700;letter-spacing:0.24em;text-transform:uppercase;color:#F2C6D0;margin-top:6px;">WMHQ Tools</div>
        </td></tr>
        <tr><td style="padding:32px;">
          <h1 style="margin:0 0 8px;font-size:22px;font-weight:800;">Your login link</h1>
          <p style="margin:0 0 24px;font-size:15px;line-height:1.6;color:#7a5a5a;">Your one-tap login link, valid for 15 minutes.</p>
          <a href="${link}" style="display:inline-block;background:#660810;color:#ffffff;text-decoration:none;font-weight:700;font-size:15px;padding:14px 28px;border-radius:999px;">Open Dashboard</a>
          <p style="margin:28px 0 0;font-size:13px;line-height:1.6;color:#7a5a5a;">Didn't ask for this? You can ignore this email.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;
}

async function sendLoginEmail(to: string, link: string): Promise<void> {
  const res = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${env("RESEND_API_KEY")}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      from: env("MAIL_FROM", DEFAULT_FROM),
      to: [to],
      subject: "Your login link",
      html: emailHtml(link),
      text: `Your one-tap login link, valid for 15 minutes:\n\n${link}\n\nDidn't ask for this? You can ignore this email.`,
    }),
  });
  if (!res.ok) throw new Error(`Resend send failed (HTTP ${res.status}): ${await res.text()}`);
}

export default async (req: Request) => {
  let rawEmail: unknown;
  try {
    rawEmail = (await req.json()).email;
  } catch {
    return Response.json({ ok: false, error: "Please enter your email." }, { status: 400 });
  }

  const email = normalizeEmail(rawEmail);
  if (!email) return Response.json({ ok: false, error: "Please enter a valid email." }, { status: 400 });

  try {
    if (await hasToolsAccess(email)) {
      const token = await signToken("link", { e: email, exp: Date.now() + LINK_TTL_MS });
      const link = new URL(`/api/verify?t=${encodeURIComponent(token)}`, req.url).toString();
      await sendLoginEmail(email, link);
    }
  } catch (err) {
    console.error("Login link request failed:", err);
    return Response.json({ ok: false, error: "Something went wrong. Please try again in a minute." }, { status: 502 });
  }

  return Response.json({ ok: true });
};

export const config = {
  path: "/api/request-link",
  method: "POST",
};
