import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { loginWithPassword } from "@/server/domain/auth/auth.service";
import { rateLimit } from "@/server/security/rateLimit";
import { env } from "@/server/config/env";
import crypto from "crypto";

export const runtime = "nodejs";

const BodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
});

function getClientIp(req: NextRequest) {
  // Vercel: x-forwarded-for usually present
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0]!.trim();
  return req.headers.get("x-real-ip") ?? "0.0.0.0";
}

function getOrCreateDeviceId(req: NextRequest) {
  const existing = req.cookies.get("deviceId")?.value;
  if (existing) return existing;
  return crypto.randomUUID();
}

export async function POST(req: NextRequest) {
  const ip = getClientIp(req);
  const userAgent = req.headers.get("user-agent") ?? "unknown";
  const deviceId = getOrCreateDeviceId(req);

  const json = await req.json().catch(() => null);
  const parsed = BodySchema.safeParse(json);
  if (!parsed.success) {
    return NextResponse.json({ message: "Invalid payload" }, { status: 400 });
  }

  const emailKey = parsed.data.email.trim().toLowerCase();

  // Rate limits (IP + Device + Email)
  const checks = await Promise.all([
    rateLimit({ key: `ip:${ip}:login`, limit: 20, windowSeconds: 60 }),
    rateLimit({
      key: `device:${deviceId}:login`,
      limit: 12,
      windowSeconds: 60,
    }),
    rateLimit({ key: `email:${emailKey}:login`, limit: 8, windowSeconds: 60 }),
  ]);

  const blocked = checks.find((c) => c.ok === false) as
    | { ok: false; retryAfterSeconds: number }
    | undefined;
  if (blocked) {
    const res = NextResponse.json(
      {
        message: "Too many attempts",
        retryAfterSeconds: blocked.retryAfterSeconds,
      },
      { status: 429 },
    );
    res.headers.set("Retry-After", String(blocked.retryAfterSeconds));
    // keep deviceId cookie stable
    res.cookies.set("deviceId", deviceId, {
      httpOnly: true,
      secure: env.COOKIE_SECURE,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 365,
    });
    return res;
  }

  try {
    const outcome = await loginWithPassword({
      email: parsed.data.email,
      password: parsed.data.password,
      ip,
      userAgent,
      deviceId,
    });

    // Always set deviceId cookie (first time or refresh)
    if (outcome.type === "ALLOW") {
      const res = NextResponse.json(
        {
          ok: true,
          mode: "ALLOW",
          riskScore: outcome.riskScore,
          accessToken: outcome.accessToken,
        },
        { status: 200 },
      );

      // HttpOnly refresh cookie
      res.cookies.set("refreshToken", outcome.refreshToken, {
        httpOnly: true,
        secure: env.COOKIE_SECURE,
        sameSite: "lax",
        path: "/",
        maxAge: env.REFRESH_TOKEN_TTL_SECONDS,
      });

      res.cookies.set("deviceId", deviceId, {
        httpOnly: true,
        secure: env.COOKIE_SECURE,
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 60 * 24 * 365,
      });

      return res;
    }

    if (outcome.type === "MFA_REQUIRED") {
      const res = NextResponse.json(
        {
          ok: true,
          mode: "MFA_REQUIRED",
          riskScore: outcome.riskScore,
          mfaToken: outcome.mfaToken,
          triggeredRules: outcome.triggeredRules,
        },
        { status: 200 },
      );

      res.cookies.set("deviceId", deviceId, {
        httpOnly: true,
        secure: env.COOKIE_SECURE,
        sameSite: "lax",
        path: "/",
        maxAge: 60 * 60 * 24 * 365,
      });

      return res;
    }

    // BLOCKED
    const res = NextResponse.json(
      {
        ok: false,
        mode: "BLOCKED",
        riskScore: outcome.riskScore,
        triggeredRules: outcome.triggeredRules,
        message:
          "Login blocked due to high risk. Try later or request approval.",
      },
      { status: 403 },
    );

    res.cookies.set("deviceId", deviceId, {
      httpOnly: true,
      secure: env.COOKIE_SECURE,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 365,
    });

    return res;
  } catch (e: any) {
    // INVALID_CREDENTIALS or generic
    const res = NextResponse.json(
      { message: "Invalid email or password" },
      { status: 401 },
    );
    res.cookies.set("deviceId", deviceId, {
      httpOnly: true,
      secure: env.COOKIE_SECURE,
      sameSite: "lax",
      path: "/",
      maxAge: 60 * 60 * 24 * 365,
    });
    return res;
  }
}
