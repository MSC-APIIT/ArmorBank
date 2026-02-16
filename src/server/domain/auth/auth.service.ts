import bcrypt from "bcryptjs";
import crypto from "crypto";
import { SignJWT } from "jose";
import { getDb } from "@/server/db/mongo";
import { env } from "@/server/config/env";
import { evaluateLoginRisk } from "../risk/risk.engine";

function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

async function signAccessToken(payload: Record<string, any>) {
  const secret = new TextEncoder().encode(env.JWT_ACCESS_SECRET);
  return new SignJWT(payload)
    .setProtectedHeader({ alg: "HS256", typ: "JWT" })
    .setIssuedAt()
    .setExpirationTime(
      Math.floor(Date.now() / 1000) + env.ACCESS_TOKEN_TTL_SECONDS,
    )
    .sign(secret);
}

export type LoginInput = {
  email: string;
  password: string;
  ip: string;
  userAgent: string;
  deviceId: string;
  roles?: string;
};

export type LoginOutcome =
  | {
      roles: any;
      type: "ALLOW";
      accessToken: string;
      refreshToken: string;
      sessionId: string;
      riskScore: number;
      userId: string;
      userName: string;
    }
  | {
      type: "MFA_REQUIRED";
      mfaToken: string;
      riskScore: number;
      triggeredRules: string[];
    }
  | { type: "BLOCKED"; riskScore: number; triggeredRules: string[] };

export async function loginWithPassword(
  input: LoginInput,
): Promise<LoginOutcome> {
  const db = await getDb();

  const users = db.collection("users");
  const devices = db.collection("devices");
  const sessions = db.collection("sessions");
  const attempts = db.collection("auth_attempts");
  const mfaChallenges = db.collection("mfa_challenges");

  const email = input.email.trim().toLowerCase();
  const user = await users.findOne<any>({ email });

  // Prevent enumeration: always do a bcrypt compare
  const hashToCheck = user?.passwordHash ?? env.DUMMY_BCRYPT_HASH;
  const passwordOk = await bcrypt.compare(input.password, hashToCheck);

  const now = new Date();

  const locks = db.collection("account_locks");

  if (user?._id) {
    const lock = await locks.findOne({
      userId: String(user._id),
      lockedUntil: { $gt: now },
    });

    if (lock) {
      await attempts.insertOne({
        createdAt: now,
        expiresAt: new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14),
        emailOrUsername: email,
        userId: user._id,
        deviceId: input.deviceId,
        ip: input.ip,
        userAgentHash: sha256(input.userAgent),
        result: "blocked",
        failReason: "account_locked",
        riskScore: lock.riskScore ?? null,
        triggeredRules: lock.triggeredRules ?? ["account_locked"],
      });

      return {
        type: "BLOCKED",
        riskScore: lock.riskScore ?? 100,
        triggeredRules: ["account_locked"],
      };
    }
  }

  // Track device
  const existingDevice = await devices.findOne<any>({
    deviceId: input.deviceId,
  });
  const isNewDevice = !existingDevice;

  // If device is new, don't double-penalise with NEW_IP too
  // If device exists, only flag IP change for untrusted devices
  const isNewIp = existingDevice
    ? existingDevice.lastSeenIp !== input.ip
    : false;

  // Compute recent failures (update query to be more comprehensive)
  const tenMinAgo = new Date(now.getTime() - 10 * 60 * 1000);
  const recentFailures = await attempts.countDocuments({
    $or: [
      { deviceId: input.deviceId },
      { ip: input.ip },
      { emailOrUsername: email },
    ],
    createdAt: { $gte: tenMinAgo },
    result: { $in: ["fail", "blocked", "mfa_fail"] },
  });

  const geoChanged = false;

  // Evaluate risk BEFORE device update
  const risk = evaluateLoginRisk({
    ip: input.ip,
    deviceId: input.deviceId,
    isNewDevice,
    isNewIp,
    deviceTrust: existingDevice?.trustLevel ?? "unknown",
    recentFailures,
    geoChanged,
  });

  console.log("🔍 Risk Detection:", {
    deviceId: input.deviceId,
    ip: input.ip,
    isNewDevice,
    isNewIp,
    lastSeenIp: existingDevice?.lastSeenIp,
    currentIp: input.ip,
  });

  console.log("Risk Score:", risk);

  // If bad password => record fail and return generic error upstream (caller decides message)
  if (!user || !passwordOk) {
    await attempts.insertOne({
      createdAt: now,
      expiresAt: new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14), // keep 14 days
      emailOrUsername: email,
      userId: user?._id ?? null,
      deviceId: input.deviceId,
      ip: input.ip,
      userAgentHash: sha256(input.userAgent),
      result: risk.tier === "high" ? "blocked" : "fail",
      failReason: "bad_creds",
      riskScore: risk.score,
      triggeredRules: risk.triggeredRules,
    });

    // Even if credentials wrong, don’t reveal anything. Return BLOCKED only if very high risk.
    if (risk.score >= env.HIGH_RISK_THRESHOLD) {
      return {
        type: "BLOCKED",
        riskScore: risk.score,
        triggeredRules: risk.triggeredRules,
      };
    }

    // Caller should respond 401 generic
    throw new Error("INVALID_CREDENTIALS");
  }

  // Credentials OK: apply decision gates
  if (risk.score >= env.HIGH_RISK_THRESHOLD) {
    const lockedUntil = new Date(
      now.getTime() + env.ACCOUNT_LOCK_SECONDS * 1000,
    );

    await db.collection("account_locks").updateOne(
      { userId: String(user._id) },
      {
        $set: {
          userId: String(user._id),
          email,
          lockedUntil,
          reason: "high_risk",
          riskScore: risk.score,
          triggeredRules: risk.triggeredRules,
          updatedAt: now,
        },
        $setOnInsert: { createdAt: now },
      },
      { upsert: true },
    );

    await attempts.insertOne({
      createdAt: now,
      expiresAt: new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14),
      emailOrUsername: email,
      userId: user._id,
      deviceId: input.deviceId,
      ip: input.ip,
      userAgentHash: sha256(input.userAgent),
      result: "blocked",
      failReason: "high_risk",
      riskScore: risk.score,
      triggeredRules: risk.triggeredRules,
    });

    return {
      type: "BLOCKED",
      riskScore: risk.score,
      triggeredRules: risk.triggeredRules,
    };
  }

  const roles = user.roles ?? ["customer"];
  const roleNorm = String(roles[0] ?? "").toLowerCase();
  const isFirstLogin = !user.lastLoginAt;

  const mfaRoles = (env.MFA_ROLES ?? "")
    .split(",")
    .map((r) => r.trim().toLowerCase())
    .filter(Boolean);

  const shouldRequireMfa =
    mfaRoles.includes(roleNorm) &&
    (isFirstLogin || risk.score >= env.MFA_REQUIRED_THRESHOLD);

  if (shouldRequireMfa) {
    // Create MFA token (short TTL) for step-up
    const mfaToken = randomToken(24);
    await mfaChallenges.insertOne({
      mfaTokenHash: sha256(mfaToken),
      userId: user._id,
      deviceId: input.deviceId,
      ip: input.ip,
      createdAt: now,
      expiresAt: new Date(now.getTime() + 1000 * 60 * 5), // 5 minutes
      status: "pending",
      riskScore: risk.score,
      triggeredRules: risk.triggeredRules,
    });

    await attempts.insertOne({
      createdAt: now,
      expiresAt: new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14),
      emailOrUsername: email,
      userId: user._id,
      deviceId: input.deviceId,
      ip: input.ip,
      userAgentHash: sha256(input.userAgent),
      result: "mfa_required",
      riskScore: risk.score,
      triggeredRules: risk.triggeredRules,
    });
    await users.updateOne(
      { _id: user._id },
      { $set: { lastLoginAt: now, lastLoginIp: input.ip, updatedAt: now } },
    );

    console.log("MFA REQUIRED - Medium risk:", risk.score);
    return {
      type: "MFA_REQUIRED",
      mfaToken,
      riskScore: risk.score,
      triggeredRules: risk.triggeredRules,
    };
  }

  // LOW RISK => create session + tokens
  const sessionId = crypto.randomUUID();
  const refreshToken = randomToken(48);
  const refreshTokenHash = sha256(refreshToken);

  const sessionExpiresAt = new Date(
    now.getTime() + env.REFRESH_TOKEN_TTL_SECONDS * 1000,
  );

  // Single-session rule: revoke all other sessions for user
  await sessions.updateMany(
    { userId: user._id, status: "active" },
    {
      $set: {
        status: "revoked",
        revokedAt: now,
        revokedReason: "new_login_single_session",
      },
    },
  );

  await sessions.insertOne({
    sessionId,
    userId: user._id,
    deviceId: input.deviceId,
    ip: input.ip,
    userAgentHash: sha256(input.userAgent),
    createdAt: now,
    lastSeenAt: now,
    expiresAt: sessionExpiresAt,
    status: "active",
    authLevel: "password_only",
    riskScore: risk.score,
    riskTier: risk.tier,
    refresh: {
      tokenHash: refreshTokenHash,
      rotatedAt: null,
      expiresAt: sessionExpiresAt,
      reuseDetected: false,
    },
  });

  await users.updateOne(
    { _id: user._id },
    { $set: { lastLoginAt: now, lastLoginIp: input.ip, updatedAt: now } },
  );

  await attempts.insertOne({
    createdAt: now,
    expiresAt: new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14),
    emailOrUsername: email,
    userId: user._id,
    deviceId: input.deviceId,
    ip: input.ip,
    userAgentHash: sha256(input.userAgent),
    result: "success",
    riskScore: risk.score,
    triggeredRules: risk.triggeredRules,
  });

  // Save/update device ONLY on successful low-risk login
  if (!existingDevice) {
    await devices.insertOne({
      deviceId: input.deviceId,
      userId: user._id,
      fingerprintHash: sha256(input.userAgent),
      userAgent: input.userAgent,
      platform: "web",
      trustLevel: "trusted",
      firstSeenAt: now,
      lastSeenAt: now,
      lastSeenIp: input.ip,
      createdAt: now,
      updatedAt: now,
    });
  } else {
    await devices.updateOne(
      { deviceId: input.deviceId },
      {
        $set: {
          lastSeenAt: now,
          lastSeenIp: input.ip,
          updatedAt: now,
          userId: user._id,
          trustLevel: "trusted",
        },
      },
    );
  }
  console.log("Login ALLOWED - Low risk:", risk.score);

  const accessToken = await signAccessToken({
    sub: String(user._id),
    sid: sessionId,
    roles: user.roles ?? ["customer"],
    scope: ["auth"],
  });

  return {
    type: "ALLOW",
    accessToken,
    refreshToken,
    sessionId,
    riskScore: risk.score,
    roles: user.roles,
    userId: String(user._id),
    userName: user.name || user.email,
  };
}
