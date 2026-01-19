import 'server-only';
import { cookies } from 'next/headers';
import type { SessionPayload } from './definitions';
import { users } from './data';

// In a real app, use a secret from environment variables
const SECRET_KEY = process.env.SESSION_SECRET || 'a-very-secret-and-secure-key-for-demonstration';
const SESSION_COOKIE_NAME = 'autharmor_session';
const SESSION_DURATION_SECONDS = 5 * 60; // 5 minutes

// These are mock encryption/decryption functions.
// In a real app, use a library like 'jose' or 'iron-session' for robust JWT/JWE handling.
async function encrypt(payload: SessionPayload): Promise<string> {
  const payloadString = JSON.stringify(payload);
  return Buffer.from(payloadString).toString('base64');
}

async function decrypt(encryptedPayload: string): Promise<SessionPayload | null> {
  try {
    const payloadString = Buffer.from(encryptedPayload, 'base64').toString('utf-8');
    return JSON.parse(payloadString);
  } catch (error) {
    console.error('Failed to decrypt session:', error);
    return null;
  }
}

export async function createSession(userId: string, isMfaPending: boolean = false) {
  const user = users.find((u) => u.id === userId);
  if (!user) {
    throw new Error('User not found for session creation');
  }

  const expires = Date.now() + SESSION_DURATION_SECONDS * 1000;
  const sessionPayload: SessionPayload = {
    user: {
      id: user.id,
      role: user.role,
      name: user.name,
    },
    isMfaPending,
    expires,
  };

  const encryptedSession = await encrypt(sessionPayload);

  cookies().set(SESSION_COOKIE_NAME, encryptedSession, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    expires: new Date(expires),
    path: '/',
    sameSite: 'lax',
  });
}

export async function getSession(): Promise<SessionPayload | null> {
  const cookie = cookies().get(SESSION_COOKIE_NAME)?.value;
  if (!cookie) return null;
  return await decrypt(cookie);
}

export function isSessionTokenValid(session: SessionPayload): boolean {
  return session.expires > Date.now();
}

export async function deleteSession() {
  cookies().delete(SESSION_COOKIE_NAME);
}

export async function updateSession(session: SessionPayload) {
  const encryptedSession = await encrypt(session);
  cookies().set(SESSION_COOKIE_NAME, encryptedSession, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    expires: new Date(session.expires),
    path: '/',
    sameSite: 'lax',
  });
}
