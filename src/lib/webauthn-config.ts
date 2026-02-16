import { env } from "@/server/config/env";

export function getWebAuthnConfig() {
  const appUrl = env.NEXT_PUBLIC_APP_URL ?? env.APP_URL;

  if (appUrl) {
    const url = new URL(appUrl);
    return {
      rpID: url.hostname,
      expectedOrigin: url.origin,
    };
  }

  // local fallback
  return {
    rpID: "localhost",
    expectedOrigin: "http://localhost:9002",
  };
}
