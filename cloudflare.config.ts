import { bindings, defineConfig, triggers } from "cf/config";

/**
 * Deployment-specific values (Worker name, custom domain, D1 database, sender allowlist, vars) live in
 * the gitignored `cloudflare.local.ts` so this file stays reusable and free of account IDs.
 * Select it with `--mode personal`; see `cloudflare.local.example.ts`.
 */
export interface PersonalConfig {
  name?: string;
  domains?: string[];
  database?: { id?: string; name?: string };
  allowedSenderAddresses?: string[];
  vars?: { APP_NAME?: string; TURNSTILE_ENABLED?: string; PUBLIC_ORIGIN?: string };
}

async function loadPersonal(): Promise<PersonalConfig> {
  const path: string = "./cloudflare.local.ts";
  return (await import(path)).default as PersonalConfig;
}

export default defineConfig(async ({ mode }) => {
  const personal = mode === "personal" ? await loadPersonal() : {};
  return {
    worker: {
      name: personal.name ?? "cloudflare-access-passkeys-kit",
      compatibilityDate: "2026-07-16",
      compatibilityFlags: ["nodejs_compat"],
      entrypoint: "src/index.ts",
      triggers: [triggers.scheduled({ schedule: "17 4 * * *" })],
      ...(personal.domains ? { domains: personal.domains, workersDev: false, previewUrls: false } : {}),
      observability: {
        enabled: true,
        logs: { headSamplingRate: 1 },
        traces: { enabled: true, headSamplingRate: 0.05 },
      },
      assets: {
        htmlHandling: "none",
        notFoundHandling: "none",
        runWorkerFirst: true,
      },
      env: {
        APP_NAME: bindings.text(personal.vars?.APP_NAME ?? "Cloudflare Access Passkeys Kit"),
        TURNSTILE_ENABLED: bindings.text(personal.vars?.TURNSTILE_ENABLED ?? "true"),
        PUBLIC_ORIGIN: bindings.text(personal.vars?.PUBLIC_ORIGIN ?? ""),
        DB: bindings.d1(personal.database ?? {}),
        EMAIL: bindings.sendEmail(
          personal.allowedSenderAddresses ? { allowedSenderAddresses: personal.allowedSenderAddresses } : {},
        ),
        INVITE_RATE_LIMITER: bindings.rateLimit({
          namespace: "1001",
          simple: { limit: 5, period: 60 },
        }),
        ASSETS: bindings.assets(),
        // TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY are optional secrets (see src/env.d.ts), so they are
        // not declared here: declared secrets are required for a deploy to succeed.
        BETTER_AUTH_SECRET: bindings.secret(),
        ADMIN_TOKEN: bindings.secret(),
        CLOUDFLARE_ACCOUNT_ID: bindings.secret(),
        ACCESS_POLICY_ID: bindings.secret(),
        CLOUDFLARE_API_TOKEN: bindings.secret(),
        INVITATION_FROM: bindings.secret(),
      },
    },
  };
});
