// The list of emails allowed into the dashboard, kept in Netlify Blobs (never in the repo).
// Managed from /admin/ by the emails in ADMIN_EMAILS.
import { getStore } from "@netlify/blobs";
import { normalizeEmail } from "./auth.ts";

const DEFAULT_ADMIN_EMAILS = "jessicampinili@gmail.com";

type MemberList = { emails: string[]; updatedAt: string | null };

function store() {
  return getStore({ name: "wmhq-members", consistency: "strong" });
}

export function adminEmails(): string[] {
  const raw = Netlify.env.get("ADMIN_EMAILS") ?? DEFAULT_ADMIN_EMAILS;
  return raw.split(",").map(normalizeEmail).filter((e): e is string => Boolean(e));
}

export function isAdmin(email: string): boolean {
  return adminEmails().includes(email);
}

export async function getMembers(): Promise<MemberList> {
  const list = (await store().get("list", { type: "json" })) as MemberList | null;
  return list ?? { emails: [], updatedAt: null };
}

export async function saveMembers(emails: string[]): Promise<MemberList> {
  const unique = [...new Set(emails.map(normalizeEmail).filter((e): e is string => Boolean(e)))].sort();
  const list = { emails: unique, updatedAt: new Date().toISOString() };
  await store().setJSON("list", list);
  return list;
}

// Admins always get in, so you can never lock yourself out of /admin/.
export async function hasToolsAccess(email: string): Promise<boolean> {
  if (isAdmin(email)) return true;
  return (await getMembers()).emails.includes(email);
}
