// Copy to cloudflare.local.ts (gitignored) and use `--mode personal` (see the `*:local` scripts).
import type { PersonalConfig } from "./cloudflare.config";

export default {
  name: "my-passkey-idp",
  domains: ["auth.example.com"],
  database: { id: "00000000-0000-0000-0000-000000000000", name: "my-passkey-idp" },
  allowedSenderAddresses: ["auth@send.example.com"],
  vars: {
    APP_NAME: "Example",
    TURNSTILE_ENABLED: "true",
    PUBLIC_ORIGIN: "https://auth.example.com",
  },
} satisfies PersonalConfig;
