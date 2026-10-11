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

function cleanList(emails: string[]): string[] {
  return [...new Set(emails.map(normalizeEmail).filter((e): e is string => Boolean(e)))].sort();
}

export async function saveMembers(emails: string[]): Promise<MemberList> {
  const list = { emails: cleanList(emails), updatedAt: new Date().toISOString() };
  await store().setJSON("list", list);
  return list;
}

// Read-change-write that can't lose a change when two happen at once (e.g. two sign-ups
// arriving from Zapier in the same second): the write only lands if the list is unchanged
// since it was read, otherwise it re-reads and tries again.
export async function updateMembers(change: (current: string[]) => string[]): Promise<MemberList> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const found = await store().getWithMetadata("list", { type: "json" });
    const current = ((found?.data as MemberList | null)?.emails) ?? [];
    const list = { emails: cleanList(change(current)), updatedAt: new Date().toISOString() };
    // No version tag on an existing list (not expected): fall back to a plain write.
    const condition = found?.etag ? { onlyIfMatch: found.etag } : found ? {} : { onlyIfNew: true };
    const { modified } = await store().setJSON("list", list, condition);
    if (modified) return list;
  }
  throw new Error("Member list was busy, could not save the change.");
}

// Admins always get in, so you can never lock yourself out of /admin/.
export async function hasToolsAccess(email: string): Promise<boolean> {
  if (isAdmin(email)) return true;
  return (await getMembers()).emails.includes(email);
}
