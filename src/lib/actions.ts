'use server';

import { z } from 'zod';
import { users } from './data';
import { createSession, deleteSession, getSession, updateSession } from './session';
import { redirect } from 'next/navigation';
import { headers } from 'next/headers';

export type LoginState = {
  error?: string;
  success?: boolean;
};

const LoginSchema = z.object({
  email: z.string().email({ message: 'Please enter a valid email.' }),
  password: z.string().min(1, { message: 'Password is required.' }),
});

/**
 * A mock fraud and risk engine.
 * In a real-world scenario, this would be a sophisticated service using a rules engine,
 * machine learning models, and various data sources.
 * @param params - Signals for risk evaluation.
 * @returns A risk level.
 */
function calculateRiskScore(params: {
  ip: string | null;
  userAgent: string | null;
  failedLoginAttempts: number;
}): 'low' | 'medium' | 'high' {
  let score = 0;
  
  // Rule: High number of failed attempts increases risk
  score += params.failedLoginAttempts * 20;

  // In a real app, you would check against known malicious IPs or unusual user agents.
  // For demo purposes, we'll just check for their existence.
  if (!params.ip) score += 10;
  if (!params.userAgent) score += 10;
  
  if (score > 60) return 'high';
  if (score > 30) return 'medium';
  return 'low';
}

export async function login(prevState: LoginState, formData: FormData): Promise<LoginState> {
  const validatedFields = LoginSchema.safeParse(Object.fromEntries(formData.entries()));

  if (!validatedFields.success) {
    return {
      error: validatedFields.error.errors.map((e) => e.message).join(', '),
    };
  }
  const { email, password } = validatedFields.data;
  const user = users.find((u) => u.email === email);

  // Use generic error messages to avoid revealing user existence
  if (!user || user.password !== password) {
    // Note: In a real app, you'd increment a failed attempt counter in the database.
    return { error: 'Invalid credentials. Please try again.' };
  }

  // --- Fraud & Risk Engine Evaluation ---
  const headerMap = headers();
  const riskScore = calculateRiskScore({
    ip: headerMap.get('x-forwarded-for'),
    userAgent: headerMap.get('user-agent'),
    failedLoginAttempts: user.failedLoginAttempts,
  });

  // --- MFA Decision ---
  if (riskScore === 'medium' || riskScore === 'high') {
    // Require MFA. Create a pending session.
    await createSession(user.id, true);
    redirect('/mfa');
  }

  // Low risk, login successful
  await createSession(user.id, false);
  redirect(`/dashboard/${user.role}`);
}


export type MfaState = {
  error?: string;
};

const MfaSchema = z.object({
    mfaMethod: z.enum(['biometric', 'app', 'email']),
    mfaCode: z.string().optional(),
});


export async function verifyMfa(prevState: MfaState, formData: FormData) {
  const session = await getSession();
  if (!session || !session.isMfaPending) {
    redirect('/login');
  }
  
  const validatedFields = MfaSchema.safeParse(Object.fromEntries(formData.entries()));

  if (!validatedFields.success) {
    return {
      error: 'Invalid submission. Please try again.',
    };
  }

  const { mfaMethod, mfaCode } = validatedFields.data;

  // Mock verification logic. In a real app, this would involve WebAuthn challenges
  // or checking a TOTP/OTP code against a user's registered device/email.
  if (mfaMethod === 'biometric' || (mfaMethod && mfaCode === '123456')) {
    session.isMfaPending = false;
    await updateSession(session);
    redirect(`/dashboard/${session.user.role}`);
  }

  return { error: 'Invalid verification method or code.' };
}


export async function logout() {
  await deleteSession();
  redirect('/login');
}
