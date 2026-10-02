const INVITE_PATH = "/invite/";

// Invitation tokens are credentials carried in the URL path; keep them out of logs.
export function redactPath(pathname: string): string {
  return pathname.startsWith(INVITE_PATH) ? `${INVITE_PATH}[redacted]` : pathname;
}
