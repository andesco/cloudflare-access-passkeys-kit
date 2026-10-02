const EMAIL_PATTERN = /^\S+@\S+\.\S+$/u;
const MAX_EMAIL_LENGTH = 254;

export function normalizeEmail(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const email = value.trim().toLowerCase();
  return email.length <= MAX_EMAIL_LENGTH && EMAIL_PATTERN.test(email) ? email : null;
}
