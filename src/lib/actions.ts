"use server";

import { z } from "zod";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { createSession, deleteSession } from "@/lib/session";
import { loginWithPassword } from "@/server/domain/auth/auth.service";
import { rateLimit } from "@/server/security/rateLimit";
import crypto from "crypto";
import { revalidatePath } from "next/cache";
import { getDb } from "@/server/db/mongo";

export type LoginState =
  | { status: "idle" }
  | { status: "error"; error: string; timestamp?: number }
  | { status: "success"; redirectTo: string }
  | {
      status: "mfa";
      mfaToken: string;
      riskScore: number;
      triggeredRules?: string[];
      hasPasskey: boolean;
      preferredMfa: "passkey" | "email";
    };

const LoginSchema = z.object({
  email: z.string().email({ message: "Please enter a valid email." }),
  password: z.string().min(1, { message: "Password is required." }),
  lat: z
    .string()
    .optional()
    .transform((v) => (v && v.trim() ? v.trim() : undefined)),
  lng: z
    .string()
    .optional()
    .transform((v) => (v && v.trim() ? v.trim() : undefined)),
});

function haversineMeters(
  a: { lat: number; lng: number },
  b: { lat: number; lng: number },
) {
  const R = 6371000;
  const toRad = (x: number) => (x * Math.PI) / 180;
  const dLat = toRad(b.lat - a.lat);
  const dLng = toRad(b.lng - a.lng);
  const lat1 = toRad(a.lat);
  const lat2 = toRad(b.lat);

  const s =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1) * Math.cos(lat2) * Math.sin(dLng / 2) * Math.sin(dLng / 2);

  return 2 * R * Math.asin(Math.min(1, Math.sqrt(s)));
}

function normalizeRole(role: any): string {
  return String(role ?? "").toLowerCase();
}

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

  // RATE LIMIT (SERVER SIDE)
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
    });

    if (result.type === "MFA_REQUIRED") {
      const mfaRoles = (process.env.MFA_ROLES ?? "")
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean);

      const roleFromResult =
        Array.isArray((result as any).roles) && (result as any).roles.length > 0
          ? (result as any).roles[0]
          : "customer";

      const roleNorm = normalizeRole(roleFromResult);

      // ✅ if role not in MFA_ROLES, block MFA flow and ask to login again (or treat as success if your service supports it)
      if (!mfaRoles.includes(roleNorm)) {
        return {
          status: "error",
          error: "MFA is not enabled for this account. Please contact support.",
          timestamp: Date.now(),
        } satisfies LoginState;
      }

      const db = await getDb();
      const mfaChallenges = db.collection("mfa_challenges");
      const webauthnCreds = db.collection("webauthn_credentials");

      const challenge = await mfaChallenges.findOne<any>({
        mfaTokenHash: crypto
          .createHash("sha256")
          .update(result.mfaToken)
          .digest("hex"),
        status: "pending",
        expiresAt: { $gt: new Date() },
      });

      if (!challenge?.userId) {
        return {
          status: "error",
          error: "MFA session expired. Please login again.",
        } satisfies LoginState;
      }

      const passkeyCount = await webauthnCreds.countDocuments({
        userId: challenge.userId,
      });

      const hasPasskey = passkeyCount > 0;
      const preferredMfa: "passkey" | "email" = hasPasskey
        ? "passkey"
        : "email";

      return {
        status: "mfa",
        mfaToken: result.mfaToken,
        riskScore: result.riskScore,
        triggeredRules: result.triggeredRules,
        hasPasskey,
        preferredMfa,
      } satisfies LoginState;
    }

    if (result.type === "BLOCKED") {
      return {
        status: "error",
        error: "Login blocked due to security concerns.",
      } satisfies LoginState;
    }

    const db = await getDb();
    const webauthnCreds = db.collection("webauthn_credentials");

    const passkeyCount = await webauthnCreds.countDocuments({
      userId: result.userId,
    });

    const hasPasskey = passkeyCount > 0;
    const shouldPromptPasskey = !hasPasskey;

    const userRole =
      Array.isArray(result.roles) && result.roles.length > 0
        ? result.roles[0]
        : "customer";

    const roleNorm = normalizeRole(userRole);

    const restrictedRoles = (process.env.LOCATION_RESTRICTED_ROLES ?? "")
      .split(",")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);

    const mustCheckLocation = restrictedRoles.includes(roleNorm);
    if (mustCheckLocation) {
      const latStr = (parsed.data as any).lat;
      const lngStr = (parsed.data as any).lng;

      if (!latStr || !lngStr) {
        return {
          status: "error",
          error: "Location access is required for this account.",
          timestamp: Date.now(),
        } satisfies LoginState;
      }

      const lat = Number(latStr);
      const lng = Number(lngStr);
      if (!Number.isFinite(lat) || !Number.isFinite(lng)) {
        return {
          status: "error",
          error: "Invalid location data. Please try again.",
          timestamp: Date.now(),
        } satisfies LoginState;
      }

      const db = await getDb();
      const policies = db.collection("role_access_policies");

      const policy = await policies.findOne<any>({
        userId: result.userId,
        enabled: true,
      });

      const allowedGeo = Array.isArray(policy?.allowedGeo)
        ? policy.allowedGeo
        : [];

      if (allowedGeo.length === 0) {
        return {
          status: "error",
          error: "Login blocked. Location policy not configured.",
          timestamp: Date.now(),
        } satisfies LoginState;
      }

      const current = { lat, lng };

      const ok = allowedGeo.some((g: any) => {
        const center = { lat: Number(g.lat), lng: Number(g.lng) };
        const radius = Number(g.radiusMeters);
        if (
          !Number.isFinite(center.lat) ||
          !Number.isFinite(center.lng) ||
          !Number.isFinite(radius)
        )
          return false;
        const d = haversineMeters(center, current);
        return d <= radius;
      });

      if (!ok) {
        return {
          status: "error",
          error: "Login failed. You are not in the allowed location.",
          timestamp: Date.now(),
        } satisfies LoginState;
      }
    }

    await createSession(result.userId, userRole, result.userName, false, {
      hasPasskey: hasPasskey,
      shouldPromptPasskey: shouldPromptPasskey,
    });
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
    cache: "no-store",
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

  if (method === "email") {
    // Ensure OTP requested
    if (!code) {
      try {
        await fetch(`${baseUrl}/api/mfa/email/request`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ mfaToken }),
          cache: "no-store",
        });
        return { error: "OTP sent. Please enter the code." };
      } catch {
        return { error: "Failed to send OTP. Try again." };
      }
    }

    const store = await cookies();
    const deviceId = store.get("deviceId")?.value ?? "unknown";
    const ip = h.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";

    try {
      const res = await fetch(`${baseUrl}/api/mfa/email/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mfaToken, code, deviceId, ip }),
        cache: "no-store",
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return { error: data?.message ?? "OTP verification failed." };
      }

      revalidatePath(`/dashboard/customer`);
      if (data.redirectTo) {
        redirect(data.redirectTo);
      }
    } catch (error) {
      // Re-throw if it's a redirect (Next.js redirects throw)
      if (error && typeof error === "object" && "digest" in error) {
        throw error;
      }
      // Otherwise it's a real error
      return { error: "MFA verification failed. Try again." };
    }
  }

  if (method === "app") {
    if (!code) {
      return { error: "Enter the 6-digit code from your Authenticator app." };
    }

    const store = await cookies();
    const deviceId = store.get("deviceId")?.value ?? "unknown";
    const ip = h.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";

    try {
      const res = await fetch(`${baseUrl}/api/mfa/totp/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ mfaToken, code, deviceId, ip }),
        cache: "no-store",
      });

      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        return { error: data?.message ?? "Authenticator verification failed." };
      }

      revalidatePath(`/dashboard/customer`);
      if (data.redirectTo) redirect(data.redirectTo);
    } catch (error) {
      if (error && typeof error === "object" && "digest" in error) throw error;
      return { error: "Authenticator verification failed. Try again." };
    }
  }

  return { error: "Use Biometric button for passkey verification." };
}
