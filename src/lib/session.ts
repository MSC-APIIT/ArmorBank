import "server-only";
import { cookies } from "next/headers";
import type { SessionPayload, UserRole } from "./definitions";

const SESSION_COOKIE_NAME = "autharmor_session";
const SESSION_DURATION_SECONDS = 15 * 60; // 15 minutes

async function encrypt(payload: SessionPayload): Promise<string> {
  const payloadString = JSON.stringify(payload);
  return Buffer.from(payloadString).toString("base64");
}

async function decrypt(
  encryptedPayload: string,
): Promise<SessionPayload | null> {
  try {
    const payloadString = Buffer.from(encryptedPayload, "base64").toString(
      "utf-8",
    );
    return JSON.parse(payloadString);
  } catch (error) {
    console.error("Failed to decrypt session:", error);
    return null;
  }
}

// Accept user data directly instead of looking it up
export async function createSession(
  userId: string,
  role: string,
  name: string,
  isMfaPending: boolean = false,
  options?: { hasPasskey?: boolean; shouldPromptPasskey?: boolean },
) {
  const expires = Date.now() + SESSION_DURATION_SECONDS * 1000;
  const sessionPayload: SessionPayload = {
    user: {
      id: userId,
      role: role as UserRole,
      name: name,
    },
    isMfaPending,
    expires,
    hasPasskey: options?.hasPasskey ?? false,
    shouldPromptPasskey: options?.shouldPromptPasskey ?? false,
  };

  const encryptedSession = await encrypt(sessionPayload);

  (await cookies()).set(SESSION_COOKIE_NAME, encryptedSession, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    expires: new Date(expires),
    path: "/",
    sameSite: "lax",
  });
}

export async function getSession(): Promise<SessionPayload | null> {
  const cookie = (await cookies()).get(SESSION_COOKIE_NAME)?.value;
  if (!cookie) return null;
  return await decrypt(cookie);
}

export function isSessionTokenValid(session: SessionPayload): boolean {
  return session.expires > Date.now();
}

export async function deleteSession() {
  const store = await cookies();
  store.set(SESSION_COOKIE_NAME, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    expires: new Date(0),
    path: "/",
    sameSite: "lax",
  });
}

export async function updateSession(session: SessionPayload) {
  const encryptedSession = await encrypt(session);
  (await cookies()).set(SESSION_COOKIE_NAME, encryptedSession, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    expires: new Date(session.expires),
    path: "/",
    sameSite: "lax",
  });
}
