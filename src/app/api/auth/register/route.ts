import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import crypto from "crypto";
import bcrypt from "bcryptjs";
import { env } from "@/server/config/env";
import { getDb } from "@/server/db/mongo";
import { rateLimit } from "@/server/security/rateLimit";

export const runtime = "nodejs";

const BodySchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

function getClientIp(req: NextRequest) {
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

  const email = parsed.data.email.trim().toLowerCase();

  // Light rate limit for register
  const rl = await rateLimit({
    key: `ip:${ip}:register`,
    limit: 6,
    windowSeconds: 60,
  });
  if (!rl.ok) {
    const res = NextResponse.json(
      { message: "Too many attempts" },
      { status: 429 },
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

  const db = await getDb();
  const users = db.collection("users");

  const existing = await users.findOne({ email });
  if (existing) {
    const res = NextResponse.json(
      { message: "User already exists" },
      { status: 409 },
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

  const passwordHash = await bcrypt.hash(parsed.data.password, 10);
  const now = new Date();

  await users.insertOne({
    email,
    passwordHash,
    roles: ["customer"],
    status: "active",
    createdAt: now,
    updatedAt: now,
    registeredIp: ip,
    registeredUserAgent: userAgent,
    registeredDeviceId: deviceId,
  });

  const res = NextResponse.json({ ok: true }, { status: 201 });
  res.cookies.set("deviceId", deviceId, {
    httpOnly: true,
    secure: env.COOKIE_SECURE,
    sameSite: "lax",
    path: "/",
    maxAge: 60 * 60 * 24 * 365,
  });
  return res;
}
