// Decides whether an email may register, from the Cloudflare Access groups named in ACCESS_GROUP_IDS.
// Fails closed: an unreadable group, an unsupported exclude or require rule, or any doubt means
// "not eligible via that group". Nothing is stored: every check fetches the groups live.

const API = "https://api.cloudflare.com/client/v4";
export const MAX_GROUP_IDS = 10;
const GROUP_ID = /^(?:[0-9a-f]{32}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;

type Rule = { kind: "email"; email: string } | { kind: "domain"; domain: string } | { kind: "other" };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function normalizeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  const parts = email.split("@");
  if (parts.length !== 2 || parts[0] === "" || parts[1] === "") return null;
  return email;
}

function normalizeDomain(value: unknown): string | null {
  if (typeof value !== "string") return null;
  let domain = value.trim().toLowerCase();
  if (domain.startsWith("@")) domain = domain.slice(1);
  if (domain === "" || domain.includes("@")) return null;
  return domain;
}

/**
 * Parses ACCESS_GROUP_IDS: ids separated by commas and/or whitespace, trimmed, lowercased, deduplicated.
 * Each id must be 32 hex digits or a hyphenated UUID; other entries are ignored, as are ids past the tenth.
 */
export function parseGroupIds(raw: unknown): string[] {
  if (typeof raw !== "string") return [];
  const ids: string[] = [];
  let invalid = 0;
  let extra = 0;
  for (const entry of raw.split(/[\s,]+/)) {
    const id = entry.trim().toLowerCase();
    if (id === "") continue;
    if (!GROUP_ID.test(id)) {
      invalid += 1;
      continue;
    }
    if (ids.includes(id)) continue;
    if (ids.length >= MAX_GROUP_IDS) {
      extra += 1;
      continue;
    }
    ids.push(id);
  }
  if (invalid > 0) console.warn(`eligibility: ignored ${invalid} malformed ACCESS_GROUP_IDS entr${invalid === 1 ? "y" : "ies"}`);
  if (extra > 0) console.warn(`eligibility: ACCESS_GROUP_IDS lists more than ${MAX_GROUP_IDS} groups; ignored ${extra}`);
  return ids;
}

/** A rule object with exactly one key and a well-formed value; anything else is "other". */
function parseRule(rule: unknown): Rule {
  if (!isRecord(rule)) return { kind: "other" };
  const keys = Object.keys(rule);
  if (keys.length !== 1) return { kind: "other" };
  const key = keys[0];
  const value = key === undefined ? undefined : rule[key];
  if (!isRecord(value) || Object.keys(value).length !== 1) return { kind: "other" };
  if (key === "email") {
    const email = normalizeEmail(value.email);
    return email ? { kind: "email", email } : { kind: "other" };
  }
  if (key === "email_domain") {
    const domain = normalizeDomain(value.domain);
    return domain ? { kind: "domain", domain } : { kind: "other" };
  }
  return { kind: "other" };
}

function ruleMatches(rule: Rule, email: string, domain: string): boolean {
  if (rule.kind === "email") return rule.email === email;
  if (rule.kind === "domain") return rule.domain === domain;
  return false;
}

/**
 * True only when the group is usable (empty `require`, every `exclude` rule an email or email-domain rule),
 * some email or email-domain `include` rule matches, and no `exclude` rule matches. Other include rules
 * (everyone, nested groups, IdP groups, ...) are ignored: they never match and never disable the group.
 */
export function groupAdmits(group: unknown, email: string, domain: string): boolean {
  if (!isRecord(group)) return false;
  const { include, exclude, require } = group;
  if (require !== undefined && require !== null && !(Array.isArray(require) && require.length === 0)) return false;
  if (!Array.isArray(include)) return false;
  if (exclude !== undefined && exclude !== null && !Array.isArray(exclude)) return false;

  const excludeRules = ((exclude as unknown[] | null | undefined) ?? []).map(parseRule);
  if (excludeRules.some((rule) => rule.kind === "other")) return false;
  if (excludeRules.some((rule) => ruleMatches(rule, email, domain))) return false;
  return include.some((rule) => ruleMatches(parseRule(rule), email, domain));
}

/** Fetches one Access group, or null on any failure (non-2xx, unsuccessful, bad JSON, network error). */
async function fetchGroup(env: Env, id: string): Promise<unknown | null> {
  try {
    const response = await fetch(
      `${API}/accounts/${encodeURIComponent(env.CLOUDFLARE_ACCOUNT_ID)}/access/groups/${encodeURIComponent(id)}`,
      { headers: { authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}` } },
    );
    if (!response.ok) {
      console.warn(`eligibility: skipped Access group ${id} (status ${response.status})`);
      return null;
    }
    const body: unknown = await response.json();
    if (!isRecord(body) || body.success !== true || !isRecord(body.result)) {
      console.warn(`eligibility: skipped Access group ${id} (unsuccessful response)`);
      return null;
    }
    return body.result;
  } catch (error) {
    console.warn(`eligibility: skipped Access group ${id} (${error instanceof Error ? error.name : "unknown error"})`);
    return null;
  }
}

/**
 * True only when one of the Access groups in ACCESS_GROUP_IDS admits the email. Groups are checked in
 * order and checking stops at the first match. Never throws.
 */
export async function isEmailEligible(env: Env, email: string): Promise<boolean> {
  try {
    const normalized = normalizeEmail(email);
    if (!normalized) return false;
    const domain = normalized.slice(normalized.lastIndexOf("@") + 1);
    for (const id of parseGroupIds(env.ACCESS_GROUP_IDS)) {
      const group = await fetchGroup(env, id);
      if (group !== null && groupAdmits(group, normalized, domain)) return true;
    }
    return false;
  } catch (error) {
    // Only the error class/message is logged; messages never contain tokens or addresses.
    console.warn(`eligibility: check failed closed (${error instanceof Error ? error.message : "unknown error"})`);
    return false;
  }
}
