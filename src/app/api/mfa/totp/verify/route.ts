import { NextResponse } from "next/server";
import { z } from "zod";
import crypto from "crypto";
import speakeasy from "speakeasy";
import { headers, cookies } from "next/headers";
import { getDb } from "@/server/db/mongo";
import { createSession } from "@/lib/session";
import { decryptSecret } from "@/server/security/secretVault";
import { env } from "@/server/config/env";

function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

const BodySchema = z.object({
  mfaToken: z.string().min(10),
  code: z.string().min(6).max(8),
  deviceId: z.string().optional(),
  ip: z.string().optional(),
});

export async function POST(req: Request) {
  try {
    const parsed = BodySchema.safeParse(await req.json().catch(() => ({})));
    if (!parsed.success) {
      return NextResponse.json({ message: "Invalid input" }, { status: 400 });
    }

    const { mfaToken, code, deviceId: bodyDeviceId, ip: bodyIp } = parsed.data;

    const h = await headers();
    const ip =
      bodyIp || h.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
    const deviceId =
      bodyDeviceId || (await cookies()).get("deviceId")?.value || "unknown";

    const db = await getDb();
    const mfaChallenges = db.collection("mfa_challenges");
    const users = db.collection("users");
    const sessions = db.collection("sessions");
    const devices = db.collection("devices");

    const authAttempts = db.collection("auth_attempts");
    const accountLocks = db.collection("account_locks");

    // First decode token hash to find challenge (without filtering status)
    const challengeRaw = await mfaChallenges.findOne<any>({
      mfaTokenHash: sha256(mfaToken),
    });

    if (challengeRaw) {
      const activeLock = await accountLocks.findOne({
        userId: String(challengeRaw.userId),
        lockedUntil: { $gt: new Date() },
      });

      if (activeLock) {
        return NextResponse.json(
          {
            message:
              "Your account is temporarily locked due to multiple failed verification attempts.",
          },
          { status: 423 },
        );
      }
    }

    const challenge = await mfaChallenges.findOne<any>({
      mfaTokenHash: sha256(mfaToken),
      status: "pending",
      expiresAt: { $gt: new Date() },
    });

    if (!challenge) {
      return NextResponse.json(
        { message: "Invalid or expired MFA token. Please sign in again." },
        { status: 401 },
      );
    }

    if (challenge.ip !== ip || challenge.deviceId !== deviceId) {
      return NextResponse.json(
        { message: "Token context mismatch" },
        { status: 401 },
      );
    }

    const user = await users.findOne<any>({ _id: challenge.userId });
    if (!user)
      return NextResponse.json({ message: "User not found" }, { status: 404 });

    const totp = user?.mfa?.totp;
    if (!totp?.enabled || !totp?.secretEnc) {
      return NextResponse.json(
        { message: "Authenticator app not enabled for this account." },
        { status: 400 },
      );
    }

    const secretBase32 = decryptSecret(totp.secretEnc);

    // Replay protection: reject same time-step token reuse
    const step = 30;
    const currentStep = Math.floor(Date.now() / 1000 / step);
    if (
      typeof totp.lastUsedStep === "number" &&
      totp.lastUsedStep === currentStep
    ) {
      return NextResponse.json(
        { message: "Code already used. Wait for the next code." },
        { status: 409 },
      );
    }

    const ok = speakeasy.totp.verify({
      secret: secretBase32,
      encoding: "base32",
      token: code.trim(),
      window: 1,
    });

    if (!ok) {
      const now = new Date();

      // NEW: record MFA failure
      await authAttempts.insertOne({
        createdAt: now,
        expiresAt: new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14),
        emailOrUsername: null,
        userId: challenge.userId,
        deviceId,
        ip,
        userAgentHash: sha256(h.get("user-agent") || "unknown"),
        result: "mfa_fail",
        failReason: "invalid_totp",
        riskScore: challenge.riskScore ?? null,
        triggeredRules: challenge.triggeredRules ?? [],
      });

      // lock if failures reached limit in window
      const windowAgo = new Date(
        now.getTime() - env.MFA_FAIL_WINDOW_SECONDS * 1000,
      );

      const failCount = await authAttempts.countDocuments({
        userId: challenge.userId,
        createdAt: { $gte: windowAgo },
        result: "mfa_fail",
      });

      if (failCount >= env.MFA_FAIL_LIMIT) {
        const lockedUntil = new Date(
          now.getTime() + env.ACCOUNT_LOCK_SECONDS * 1000,
        );

        await accountLocks.updateOne(
          { userId: String(challenge.userId) },
          {
            $set: {
              userId: String(challenge.userId),
              lockedUntil,
              reason: "mfa_failures_totp",
              riskScore: challenge.riskScore ?? null,
              triggeredRules: ["totp_mfa_failed_limit_reached"],
              updatedAt: now,
            },
            $setOnInsert: { createdAt: now },
          },
          { upsert: true },
        );

        await mfaChallenges.updateOne(
          { _id: challenge._id },
          { $set: { status: "failed", failedAt: now } },
        );

        return NextResponse.json(
          { message: "Account locked due to suspicious activity." },
          { status: 423 },
        );
      }

      return NextResponse.json({ message: "Invalid code" }, { status: 401 });
    }

    // Mark challenge passed
    await mfaChallenges.updateOne(
      { _id: challenge._id },
      { $set: { status: "passed", passedAt: new Date(), method: "totp" } },
    );

    // Save last used step
    await users.updateOne(
      { _id: user._id },
      {
        $set: {
          "mfa.totp.lastUsedStep": currentStep,
          "mfa.totp.updatedAt": new Date(),
        },
      },
    );

    // Trust device after successful MFA (same as email verify)
    const now = new Date();
    const existingDevice = await devices.findOne({
      deviceId: challenge.deviceId,
    });

    if (!existingDevice) {
      await devices.insertOne({
        deviceId: challenge.deviceId,
        userId: challenge.userId,
        fingerprintHash: sha256(h.get("user-agent") || "unknown"),
        userAgent: h.get("user-agent") || "unknown",
        platform: "web",
        trustLevel: "mfa_verified",
        firstSeenAt: now,
        lastSeenAt: now,
        lastSeenIp: challenge.ip,
        createdAt: now,
        updatedAt: now,
      });
    } else {
      await devices.updateOne(
        { deviceId: challenge.deviceId },
        {
          $set: {
            lastSeenAt: now,
            lastSeenIp: challenge.ip,
            updatedAt: now,
            userId: challenge.userId,
            trustLevel: "mfa_verified",
          },
        },
      );
    }

    // Single-session rule
    await sessions.updateMany(
      { userId: user._id, status: "active" },
      {
        $set: {
          status: "revoked",
          revokedAt: new Date(),
          revokedReason: "new_login_single_session",
        },
      },
    );

    const userRole =
      Array.isArray(user.roles) && user.roles.length > 0
        ? user.roles[0]
        : "customer";

    await createSession(
      String(user._id),
      userRole,
      user.name || user.email,
      false,
      {
        hasPasskey: false,
        shouldPromptPasskey: false,
      },
    );

    return NextResponse.json({
      ok: true,
      redirectTo: `/dashboard/${userRole}`,
    });
  } catch (e) {
    console.error("TOTP verify error:", e);
    return NextResponse.json(
      { message: "Verification failed" },
      { status: 500 },
    );
  }
}
