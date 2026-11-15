import { appName } from "./constants";

export type LinkMailKind = "invite" | "recovery";

export interface ComposedMail {
  subject: string;
  text: string;
  html: string;
}

const escapeHtml = (value: string) =>
  value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");

const days = (count: number) => `${count} ${count === 1 ? "day" : "days"}`;

/** Subject and bodies for a single-use invitation or recovery link. */
export function composeLinkMail(
  env: Env,
  kind: LinkMailKind,
  url: string,
  validDays: number,
): ComposedMail {
  const name = appName(env);
  const href = escapeHtml(url);
  const expiry = days(validDays);
  if (kind === "recovery") {
    return {
      subject: `Recover your ${name} account`,
      text: [
        `Someone asked to recover the ${name} account for this email address.`,
        `To register a new passkey, open this single-use link within ${expiry}:\n${url}`,
        "Completing recovery removes all of your existing passkeys and signs you out everywhere. Only the new passkey will work afterwards.",
        "If you did not ask for this, you can ignore this email. Nothing changes unless the link is used.",
      ].join("\n\n"),
      html: `<p>Someone asked to recover the ${escapeHtml(name)} account for this email address.</p>` +
        `<p><a href="${href}">Register a new passkey</a></p>` +
        `<p>This single-use link expires in ${expiry}. Completing recovery removes all of your existing passkeys and signs you out everywhere. Only the new passkey will work afterwards.</p>` +
        "<p>If you did not ask for this, you can ignore this email. Nothing changes unless the link is used.</p>",
    };
  }
  return {
    subject: `Your ${name} invitation`,
    text: [
      "You have been invited to register a passkey.",
      `Open this single-use link within ${expiry}:\n${url}`,
      "If you did not request this invitation, you can ignore this email.",
    ].join("\n\n"),
    html: "<p>You have been invited to register a passkey.</p>" +
      `<p><a href="${href}">Create your passkey</a></p>` +
      `<p>This single-use link expires in ${expiry}. If you did not request it, you can ignore this email.</p>`,
  };
}

/** Sends the link through the Email Sending binding. Throws when the message is rejected. */
export async function sendLinkMail(
  env: Env,
  kind: LinkMailKind,
  to: string,
  url: string,
  validDays: number,
): Promise<{ messageId?: string }> {
  const mail = composeLinkMail(env, kind, url, validDays);
  const result = await env.EMAIL.send({
    to,
    from: { name: appName(env), email: env.INVITATION_FROM },
    ...mail,
  });
  return { messageId: (result as { messageId?: string } | undefined)?.messageId };
}
