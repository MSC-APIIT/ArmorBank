"use server";

import { z } from "zod";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { createSession, deleteSession } from "@/lib/session";
import { loginWithPassword } from "@/server/domain/auth/auth.service";
import { rateLimit } from "@/server/security/rateLimit";
import crypto from "crypto";
import { revalidatePath } from "next/cache";

export type LoginState =
  | { status: "idle" }
  | { status: "error"; error: string; timestamp?: number }
  | { status: "success"; redirectTo: string }
  | {
      status: "mfa";
      mfaToken: string;
      riskScore: number;
      triggeredRules?: string[];
    };

const LoginSchema = z.object({
  email: z.string().email({ message: "Please enter a valid email." }),
  password: z.string().min(1, { message: "Password is required." }),
});

async function getBaseUrl() {
  const h = await headers();
  const host = h.get("host");
  const proto = h.get("x-forwarded-proto") ?? "http";
  return `${proto}://${host}`;
}

// login action
export async function login(_: any, formData: FormData) {
  const h = await headers();

  const parsed = LoginSchema.safeParse(Object.fromEntries(formData.entries()));

  if (!parsed.success) {
    return { status: "error", error: "Invalid input" } satisfies LoginState;
  }

  async function getClientIp() {
    const h = await headers();
    return h.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  }

  async function getUserAgent() {
    const h = await headers();
    return h.get("user-agent") ?? "";
  }

  async function getOrCreateDeviceId() {
    const store = await cookies();

    const existing = store.get("deviceId")?.value;
    if (existing) return existing;

    const id = crypto.randomUUID();
    store.set("deviceId", id, {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 365,
    });
    return id;
  }

  const email = parsed.data.email.toLowerCase();
  const ip = await getClientIp();
  const deviceId = await getOrCreateDeviceId();
  const userAgent = await getUserAgent();

  // 🔐 RATE LIMIT (SERVER SIDE)
  const checks = await Promise.all([
    rateLimit({ key: `ip:${ip}`, limit: 5, windowSeconds: 60 }),
    rateLimit({ key: `device:${deviceId}`, limit: 4, windowSeconds: 60 }),
    rateLimit({ key: `email:${email}`, limit: 3, windowSeconds: 60 }),
  ]);

  const blocked = checks.find((r) => r.ok === false);
  if (blocked) {
    revalidatePath("/login");
    return {
      status: "error",
      error: "Too many attempts. Try again later.",
      timestamp: Date.now(),
    } satisfies LoginState;
  }

  try {
    const result = await loginWithPassword({
      email,
      password: parsed.data.password,
      ip,
      deviceId,
      userAgent,
      roles: "customer",
    });
    console.log("------1", result);

    if (result.type === "MFA_REQUIRED") {
      return {
        status: "mfa",
        mfaToken: result.mfaToken,
        riskScore: result.riskScore,
        triggeredRules: result.triggeredRules,
      } satisfies LoginState;
    }

    if (result.type === "BLOCKED") {
      return {
        status: "error",
        error: "Login blocked due to security concerns.",
      } satisfies LoginState;
    }

    const userRole =
      Array.isArray(result.roles) && result.roles.length > 0
        ? result.roles[0]
        : "customer";

    await createSession(result.userId, userRole, result.userName, false);
    revalidatePath("/login");
    revalidatePath(`/dashboard/${userRole}`);

    return {
      status: "success",
      redirectTo: `/dashboard/${userRole}`,
    } satisfies LoginState;
  } catch {
    await deleteSession();
    revalidatePath("/login");
    return {
      status: "error",
      error: "Invalid email or password",
    } satisfies LoginState;
  }
}

//logout action
export async function logout() {
  const baseUrl = await getBaseUrl();

  await fetch(`${baseUrl}/api/auth/logout`, {
    method: "POST",
    credentials: "include",
  }).catch(() => {});

  redirect("/login");
}

export type RegisterState = {
  error?: string;
};

const RegisterSchema = z
  .object({
    email: z.string().email(),
    password: z.string().min(8, "Password must be at least 8 characters."),
    confirmPassword: z.string().min(1),
  })
  .refine((d) => d.password === d.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
  });

// register action
export async function register(
  _prev: RegisterState,
  formData: FormData,
): Promise<RegisterState> {
  const validated = RegisterSchema.safeParse(
    Object.fromEntries(formData.entries()),
  );
  if (!validated.success) {
    return { error: validated.error.errors.map((e) => e.message).join(", ") };
  }

  const baseUrl = await getBaseUrl();
  const res = await fetch(`${baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    credentials: "include",
    body: JSON.stringify({
      email: validated.data.email,
      password: validated.data.password,
    }),
    cache: "no-store",
  });

  const data = await res.json().catch(() => ({}) as any);
  if (!res.ok) return { error: data?.message ?? "Registration failed." };

  redirect("/login");
}

// MFA verification action
export type MfaState = { error?: string };

export async function verifyMfa(
  prev: MfaState,
  formData: FormData,
): Promise<MfaState> {
  const mfaToken = String(formData.get("mfaToken") ?? "");
  const method = String(formData.get("mfaMethod") ?? "");
  const code = String(formData.get("mfaCode") ?? "");

  const h = await headers();
  const proto = h.get("x-forwarded-proto") ?? "http";
  const host = h.get("host");
  const baseUrl = `${proto}://${host}`;

  try {
    if (method === "email") {
      // Ensure OTP requested (you can make a separate button too)
      if (!code) {
        await fetch(`${baseUrl}/api/mfa/email/request`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ mfaToken }),
          cache: "no-store",
        });
        return { error: "OTP sent. Please enter the code." };
      }

      const res = await fetch(`${baseUrl}/api/mfa/email/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mfaToken, code }),
        cache: "no-store",
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok)
        return { error: data?.message ?? "OTP verification failed." };

      // client will navigate after success (or you can return redirect instruction)
      return {};
    }

    if (method === "app") {
      return { error: "TOTP not implemented yet (use Email or Biometric)." };
    }

    return { error: "Use Biometric button for passkey verification." };
  } catch {
    return { error: "MFA failed. Try again." };
  }
}
