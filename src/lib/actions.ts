"use server";

import { z } from "zod";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { createSession } from "@/lib/session";

export type LoginState = {
  error?: string;
  mfaRequired?: boolean;
  mfaToken?: string;
  riskScore?: number;
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

export async function login(
  _prevState: LoginState,
  formData: FormData,
): Promise<LoginState> {
  const validated = LoginSchema.safeParse(
    Object.fromEntries(formData.entries()),
  );

  if (!validated.success) {
    return { error: validated.error.errors.map((e) => e.message).join(", ") };
  }

  const baseUrl = await getBaseUrl();

  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    credentials: "include",
    body: JSON.stringify(validated.data),
    cache: "no-store",
  });

  const data = await res.json().catch(() => ({}) as any);

  if (!res.ok) {
    return { error: data?.message ?? "Login failed. Please try again." };
  }

  if (data?.mode === "MFA_REQUIRED") {
    return {
      mfaRequired: true,
      mfaToken: data.mfaToken,
      riskScore: data.riskScore,
      triggeredRules: data.triggeredRules,
    };
  }

  if (data?.mode === "ALLOW") {
    const role = (data?.roles?.[0] ?? "customer") as string;

    const userId = data.userId;
    const userName = data.userName;

    await createSession(userId, role, userName, false);

    redirect(`/dashboard/${role}`);
  }

  return { error: "Unexpected login response." };
}

export async function logout() {
  const baseUrl = (async () => {
    const h = await headers();
    const host = h.get("host");
    const proto = h.get("x-forwarded-proto") ?? "http";
    return `${proto}://${host}`;
  })();

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
