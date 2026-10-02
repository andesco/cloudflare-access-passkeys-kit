import { passkeyClient } from "@better-auth/passkey/client";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";
import { createAuthClient } from "better-auth/client";

const auth = createAuthClient({ plugins: [oauthProviderClient(), passkeyClient()] });

interface PublicConfig {
  appName: string;
  turnstileEnabled: boolean;
  turnstileSiteKey?: string;
}

interface PasskeyCredential {
  id: string;
  name?: string | null;
  credentialID: string;
  createdAt?: string;
  backedUp?: boolean;
}

type ActionResult = { error?: { message?: string } | null } | null | undefined;

// Must match RECENT_SIGN_IN_MESSAGE in src/passkey-management.ts.
const RECENT_SIGN_IN_MESSAGE = "Recent sign-in required";

let currentCredentialID: string | undefined;

let publicConfigPromise: Promise<PublicConfig> | undefined;

function getPublicConfig(): Promise<PublicConfig> {
  publicConfigPromise ??= fetch("/api/config").then(async (response) => {
    if (!response.ok) throw new Error("Unable to load public configuration");
    return await response.json() as PublicConfig;
  });
  return publicConfigPromise;
}

function element<T extends HTMLElement>(id: string): T {
  const value = document.getElementById(id);
  if (!value) throw new Error(`Missing element: ${id}`);
  return value as T;
}

async function loadTurnstile(): Promise<void> {
  if (window.turnstile) return;
  await new Promise<void>((resolve, reject) => {
    const script = document.createElement("script");
    script.src = "https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit";
    script.async = true;
    script.defer = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Turnstile failed to load"));
    document.head.appendChild(script);
  });
}

function setStatus(message: string, error = false): void {
  const status = element<HTMLOutputElement>("status");
  status.textContent = message;
  status.dataset.error = String(error);
}

function sharedApplicationName(): string | undefined {
  const query = new URLSearchParams(window.location.search);
  const name = query.get("application_name") ?? query.get("app_name");
  if (name?.trim()) return name.trim();

  const target = query.get("redirect_url") ?? query.get("return_to");
  if (!target) return undefined;
  try {
    return new URL(target).hostname;
  } catch {
    return undefined;
  }
}

async function listPasskeys(): Promise<PasskeyCredential[]> {
  try {
    const response = await fetch("/api/auth/passkey/list-user-passkeys");
    return response.ok ? await response.json() as PasskeyCredential[] : [];
  } catch {
    return [];
  }
}

function setPasskeyStatus(message: string, error = false): void {
  const status = element<HTMLOutputElement>("passkey-status");
  status.textContent = message;
  status.dataset.error = String(error);
}

/** Runs a passkey change; if the session is too old, asks for a passkey and retries once. */
async function withRecentSignIn(action: () => Promise<ActionResult>): Promise<ActionResult> {
  const result = await action();
  if (!result?.error?.message?.includes(RECENT_SIGN_IN_MESSAGE)) return result;
  setPasskeyStatus("Confirm it's you with a passkey…");
  const signedIn = await auth.signIn.passkey({ returnWebAuthnResponse: true });
  if (!signedIn || signedIn.error) return signedIn ?? result;
  if ("webauthn" in signedIn) currentCredentialID = signedIn.webauthn.response.id;
  return await action();
}

async function changePasskey(action: () => Promise<ActionResult>, success: string): Promise<void> {
  setPasskeyStatus("Waiting for your passkey…");
  const result = await withRecentSignIn(action);
  if (result?.error) {
    setPasskeyStatus(result.error.message ?? "That change could not be made.", true);
  } else {
    setPasskeyStatus(success);
  }
  await renderPasskeys();
}

function passkeyItem(passkey: PasskeyCredential, canRemove: boolean): HTMLLIElement {
  const item = document.createElement("li");
  const label = document.createElement("span");
  label.className = "passkey-name";
  label.textContent = passkey.name?.trim() || "Passkey";
  const meta = document.createElement("span");
  meta.className = "passkey-meta";
  meta.textContent = [
    isoDate(passkey.createdAt) ? `Added ${isoDate(passkey.createdAt)}` : undefined,
    passkey.backedUp ? "Synced" : "This device only",
    passkey.credentialID === currentCredentialID ? "Current" : undefined,
  ].filter(Boolean).join(" · ");
  label.appendChild(meta);

  const actions = document.createElement("span");
  const rename = document.createElement("button");
  rename.type = "button";
  rename.textContent = "Rename";
  rename.onclick = () => {
    const name = window.prompt("Passkey name", passkey.name ?? "")?.trim();
    if (name) {
      void changePasskey(() => auth.passkey.updatePasskey({ id: passkey.id, name }), "Passkey renamed.");
    }
  };
  const remove = document.createElement("button");
  remove.type = "button";
  remove.textContent = "Remove";
  remove.disabled = !canRemove;
  remove.title = canRemove ? "" : "You cannot remove your only passkey";
  remove.onclick = () => {
    if (window.confirm("Remove this passkey? You will no longer be able to sign in with it.")) {
      void changePasskey(() => auth.passkey.deletePasskey({ id: passkey.id }), "Passkey removed.");
    }
  };
  actions.appendChild(rename);
  actions.appendChild(document.createTextNode(" "));
  actions.appendChild(remove);
  item.appendChild(label);
  item.appendChild(actions);
  return item;
}

async function renderPasskeys(): Promise<void> {
  const passkeys = await listPasskeys();
  element<HTMLUListElement>("passkey-list").replaceChildren(
    ...passkeys.map((passkey) => passkeyItem(passkey, passkeys.length > 1)),
  );
}

async function addPasskey(): Promise<void> {
  await changePasskey(() => auth.passkey.addPasskey(), "Passkey added.");
}

function setSignedInDetail(name: string, value?: string): void {
  element<HTMLElement>(`signed-in-${name}-row`).hidden = !value;
  if (value) element<HTMLElement>(`signed-in-${name}`).textContent = value;
}

function isoDate(value?: string): string | undefined {
  if (!value) return undefined;
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? undefined : date.toISOString().slice(0, 10);
}

async function showSignedInState(credentialID?: string): Promise<void> {
  if (credentialID) currentCredentialID = credentialID;
  const [{ appName }, session, passkeys] = await Promise.all([
    getPublicConfig(),
    auth.getSession(),
    listPasskeys(),
  ]);
  const credential = passkeys.find((item) => item.credentialID === currentCredentialID);
  const email = session.data?.user.email;
  element<HTMLElement>("sign-in-title").textContent = `Signed in to ${appName}`;
  element<HTMLElement>("signed-in-email").textContent = email ?? "Unknown";
  setSignedInDetail("created-at", isoDate(credential?.createdAt));
  element<HTMLElement>("sign-in-options").hidden = true;
  element<HTMLElement>("signed-in-options").hidden = false;
  await renderPasskeys();
}

async function signOut(): Promise<void> {
  const button = element<HTMLButtonElement>("sign-out-action");
  button.disabled = true;
  try {
    await auth.signOut();
    window.location.replace("/");
  } finally {
    button.disabled = false;
  }
}

async function applyBranding(): Promise<void> {
  try {
    const { appName } = await getPublicConfig();
    document.querySelectorAll<HTMLElement>("[data-app-name]").forEach((node) => {
      node.textContent = appName;
    });
    document.querySelectorAll<HTMLElement>("[data-login-target]").forEach((node) => {
      node.textContent = sharedApplicationName() ?? appName;
    });
    const pageTitle = document.body.dataset.page === "invite" ? "Accept invitation" : "Sign in";
    document.title = `${pageTitle} — ${appName}`;
  } catch {
    // Keep the static fallback branding when public configuration is unavailable.
  }
}

declare global {
  interface Window {
    turnstile?: {
      render(target: string | HTMLElement, options: {
        sitekey: string;
        action: string;
        size?: "normal" | "compact" | "flexible";
        theme?: "light" | "dark" | "auto";
        callback?: (token: string) => void;
        "error-callback"?: () => void;
        "expired-callback"?: () => void;
      }): string;
      getResponse(widgetId?: string): string;
      reset(widgetId?: string): void;
    };
  }
}

async function setupInvitationRequest(): Promise<void> {
  const form = document.getElementById("invite-request-form") as HTMLFormElement | null;
  if (!form) return;
  const confirmation = element<HTMLDivElement>("invitation-confirmation");
  const confirmationEmail = element<HTMLElement>("invitation-confirmation-email");
  const status = element<HTMLOutputElement>("invite-request-status");
  const showConfirmation = (email: string): void => {
    status.textContent = "";
    confirmationEmail.textContent = email;
    form.classList.add("invite-request-form--hidden");
    form.setAttribute("aria-hidden", "true");
    form.setAttribute("inert", "");
    confirmation.hidden = false;
  };
  const config = await getPublicConfig();
  let widgetId: string | undefined;
  let pendingEmail = "";
  let submitting = false;
  const submitInvitation = async (turnstileToken: string): Promise<void> => {
    if (submitting) return;
    submitting = true;
    status.textContent = "Submitting…";
    try {
      await fetch("/api/invitations/request", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ email: pendingEmail, turnstileToken }),
      });
      showConfirmation(pendingEmail);
    } catch {
      showConfirmation(pendingEmail);
    } finally {
      submitting = false;
      if (widgetId) window.turnstile?.reset(widgetId);
    }
  };
  if (!config.turnstileEnabled || !config.turnstileSiteKey) {
    document.getElementById("turnstile-widget")?.remove();
  }
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    pendingEmail = element<HTMLInputElement>("invite-email").value.trim();
    if (!config.turnstileEnabled || !config.turnstileSiteKey) {
      await submitInvitation("");
      return;
    }
    const existingToken = widgetId ? window.turnstile?.getResponse(widgetId) ?? "" : "";
    if (existingToken) {
      await submitInvitation(existingToken);
      return;
    }
    if (widgetId) {
      status.textContent = "Complete the verification to request an invitation.";
      return;
    }
    status.textContent = "Loading verification…";
    try {
      await loadTurnstile();
      widgetId = window.turnstile?.render("#turnstile-widget", {
        sitekey: config.turnstileSiteKey,
        action: "turnstile-spin-v1",
        size: "flexible",
        theme: "light",
        callback: (token) => void submitInvitation(token),
        "error-callback": () => {
          status.textContent = "Verification failed. Try again or sign in with your passkey.";
        },
        "expired-callback": () => {
          status.textContent = "Verification expired. Complete it again to request an invitation.";
        },
      });
      status.textContent = "Complete the verification to request an invitation.";
    } catch {
      status.textContent = "Verification could not load. Try again or sign in with your passkey.";
    }
  });
}

async function signIn(): Promise<void> {
  setStatus("Waiting for your passkey…");
  const result = await auth.signIn.passkey({ returnWebAuthnResponse: true });
  if (!result || result.error) {
    setStatus(result.error.message ?? "Passkey sign-in failed.", true);
    return;
  }
  const credentialID = "webauthn" in result ? result.webauthn.response.id : undefined;
  await showSignedInState(credentialID);
}

function invitationTokenFromLocation(): string | null {
  // Current links keep the token in the fragment, which browsers never send to the server.
  // Older links carried it in the path; both are accepted.
  const fromFragment = window.location.hash.slice(1);
  const encoded = fromFragment || /^\/invite\/([^/]+)$/.exec(window.location.pathname)?.[1];
  if (!encoded) return null;
  try {
    return decodeURIComponent(encoded);
  } catch {
    return null;
  }
}

async function register(): Promise<void> {
  const token = invitationTokenFromLocation();
  if (!token) {
    setStatus("This invitation link is incomplete.", true);
    return;
  }
  // The token is sent as a header on every request, never in a URL.
  const inviteAuth = createAuthClient({
    plugins: [passkeyClient()],
    fetchOptions: { headers: { "x-invitation-token": token } },
  });
  const finish = (): void => {
    window.location.replace("/?registered=1");
  };
  const registrationComplete = async (): Promise<boolean> => {
    try {
      const response = await fetch("/api/invitations/status", {
        method: "POST",
        headers: { accept: "application/json", "content-type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const body = await response.json() as { complete?: boolean };
      return response.ok && body.complete === true;
    } catch {
      return false;
    }
  };
  if (await registrationComplete()) {
    finish();
    return;
  }
  setStatus("Creating your passkey…");
  const result = await inviteAuth.passkey.addPasskey();
  if (result?.error) {
    if (await registrationComplete()) {
      finish();
      return;
    }
    setStatus(result.error.message ?? "Passkey registration failed.", true);
    return;
  }
  finish();
}

const action = document.body.dataset.page;
const button = element<HTMLButtonElement>("primary-action");
void applyBranding();
button.onclick = () => void (action === "invite" ? register() : signIn());
if (action === "sign-in" && new URLSearchParams(window.location.search).get("registered") === "1") {
  setStatus("Passkey created. Sign in to continue.");
}
if (action === "sign-in") {
  element<HTMLButtonElement>("sign-out-action").onclick = () => void signOut();
  element<HTMLButtonElement>("add-passkey-action").onclick = () => void addPasskey();
  void setupInvitationRequest();
}
