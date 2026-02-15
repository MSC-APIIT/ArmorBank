import { NextResponse } from "next/server";
import { headers, cookies } from "next/headers";
import crypto from "crypto";
import { getDb } from "@/server/db/mongo";
import { createSession } from "@/lib/session";
import { env } from "@/server/config/env";

function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export async function POST(req: Request) {
  try {
    const body = await req.json();
    const { mfaToken, code, deviceId: bodyDeviceId, ip: bodyIp } = body;

    const h = await headers();
    const ip =
      bodyIp || h.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
    const deviceId =
      bodyDeviceId || (await cookies()).get("deviceId")?.value || "unknown";

    if (!mfaToken || !code) {
      return NextResponse.json(
        { message: "Missing mfaToken or code" },
        { status: 400 },
      );
    }

    const db = await getDb();
    const mfaChallenges = db.collection("mfa_challenges");
    const users = db.collection("users");
    const sessions = db.collection("sessions");
    const devices = db.collection("devices");

    const authAttempts = db.collection("auth_attempts");
    const accountLocks = db.collection("account_locks");

    // Find challenge
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

    // Verify IP and device match
    if (challenge.ip !== ip || challenge.deviceId !== deviceId) {
      return NextResponse.json(
        { message: "Token context mismatch" },
        { status: 401 },
      );
    }

    // account lock check (block even before counting attempts)
    const nowLockCheck = new Date();
    const activeLock = await accountLocks.findOne({
      userId: String(challenge.userId),
      lockedUntil: { $gt: nowLockCheck },
    });

    if (activeLock) {
      return NextResponse.json(
        { message: "Account is locked. Try again later." },
        { status: 423 },
      );
    }

    // Check if OTP exists and not expired
    if (!challenge.emailOtpHash || !challenge.emailOtpExpiresAt) {
      return NextResponse.json(
        { message: "No OTP found. Request a new code." },
        { status: 400 },
      );
    }

    if (new Date() > challenge.emailOtpExpiresAt) {
      return NextResponse.json(
        { message: "OTP expired. Request a new code." },
        { status: 401 },
      );
    }

    // Check attempts (max 3)
    const attempts = challenge.emailOtpAttempts || 0;
    if (attempts >= 3) {
      const now = new Date();
      const lockedUntil = new Date(
        now.getTime() + env.ACCOUNT_LOCK_SECONDS * 1000,
      );

      await accountLocks.updateOne(
        { userId: String(challenge.userId) },
        {
          $set: {
            userId: String(challenge.userId),
            lockedUntil,
            reason: "mfa_failures_email",
            riskScore: challenge.riskScore ?? null,
            triggeredRules: ["email_mfa_failed_too_many_times"],
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

    // Verify OTP
    const codeHash = sha256(code.trim());

    if (codeHash !== challenge.emailOtpHash) {
      const now = new Date();

      // ✅ NEW: store MFA failure in auth_attempts
      await authAttempts.insertOne({
        createdAt: now,
        expiresAt: new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14),
        emailOrUsername: null,
        userId: challenge.userId,
        deviceId,
        ip,
        userAgentHash: sha256(h.get("user-agent") || "unknown"),
        result: "mfa_fail",
        failReason: "invalid_email_otp",
        riskScore: challenge.riskScore ?? null,
        triggeredRules: challenge.triggeredRules ?? [],
      });

      // Increment attempts
      await mfaChallenges.updateOne(
        { _id: challenge._id },
        { $inc: { emailOtpAttempts: 1 } },
      );

      // if failures reached limit in window, lock account
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
              reason: "mfa_failures_email",
              riskScore: challenge.riskScore ?? null,
              triggeredRules: ["email_mfa_failed_limit_reached"],
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

      return NextResponse.json(
        { message: `Invalid code. ${2 - attempts} attempts remaining.` },
        { status: 401 },
      );
    }

    // OTP verified! Mark challenge as passed
    await mfaChallenges.updateOne(
      { _id: challenge._id },
      { $set: { status: "passed", passedAt: new Date() } },
    );

    // 🔒 SECURITY FIX: Save/update device AFTER successful MFA
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

    // Get user
    const user = await users.findOne<any>({ _id: challenge.userId });
    if (!user) {
      return NextResponse.json({ message: "User not found" }, { status: 404 });
    }

    const userRole =
      Array.isArray(user.roles) && user.roles.length > 0
        ? user.roles[0]
        : "customer";

    // Revoke other sessions (single-session rule)
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

    const webauthnCreds = db.collection("webauthn_credentials");
    const passkeyCount = await webauthnCreds.countDocuments({
      userId: user._id,
    });

    const hasPasskey = passkeyCount > 0;
    const shouldPromptPasskey = !hasPasskey;

    // Create session
    await createSession(
      String(user._id),
      userRole,
      user.name || user.email,
      false,
      { hasPasskey, shouldPromptPasskey },
    );
    return NextResponse.json({
      ok: true,
      redirectTo: `/dashboard/${userRole}`,
    });
  } catch (error) {
    console.error("Email OTP verify error:", error);
    return NextResponse.json(
      { message: "Verification failed" },
      { status: 500 },
    );
  }
}
