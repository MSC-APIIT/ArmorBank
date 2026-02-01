import { NextResponse } from "next/server";
import { headers, cookies } from "next/headers";
import crypto from "crypto";
import { getDb } from "@/server/db/mongo";
import { env } from "@/server/config/env";
import { verifyAuthenticationResponse } from "@simplewebauthn/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/types";
import { createSession } from "@/lib/session";
import { SignJWT } from "jose";

function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
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

function getRpID(host: string) {
  return host.split(":")[0];
}

function toBuffer(v: any): Buffer {
  if (Buffer.isBuffer(v)) return v;
  if (typeof v === "string") return Buffer.from(v, "base64url");
  if (v?.buffer) return Buffer.from(v.buffer);
  throw new Error("Invalid buffer field");
}

function getExpectedOrigin(h: Headers) {
  const proto = h.get("x-forwarded-proto") ?? "http";
  const host = h.get("host") ?? "localhost";
  return `${proto}://${host}`;
}

export async function POST(req: Request) {
  const h = await headers();
  const ip = h.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const deviceId = (await cookies()).get("deviceId")?.value ?? "unknown";

  const { mfaToken, response } = (await req.json()) as {
    mfaToken: string;
    response: AuthenticationResponseJSON;
  };

  if (!mfaToken || !response) {
    return NextResponse.json({ message: "Missing payload" }, { status: 400 });
  }

  const db = await getDb();
  const mfaChallenges = db.collection("mfa_challenges");
  const webauthnCreds = db.collection("webauthn_credentials");
  const users = db.collection("users");
  const sessions = db.collection("sessions");

  const challengeDoc = await mfaChallenges.findOne<any>({
    mfaTokenHash: sha256(mfaToken),
    status: "pending",
    expiresAt: { $gt: new Date() },
  });

  if (!challengeDoc) {
    return NextResponse.json(
      { message: "Invalid/expired token" },
      { status: 401 },
    );
  }

  if (challengeDoc.ip !== ip || challengeDoc.deviceId !== deviceId) {
    return NextResponse.json(
      { message: "Token context mismatch" },
      { status: 401 },
    );
  }

  if (!challengeDoc.webauthnChallenge) {
    return NextResponse.json(
      { message: "No WebAuthn challenge" },
      { status: 400 },
    );
  }

  const host = h.get("host") ?? "localhost";
  const rpID = getRpID(host);
  const expectedOrigin = getExpectedOrigin(h);

  const credentialIdBuf = Buffer.from(response.rawId, "base64url");
  const credentialIdStr = response.rawId;

  const userIdObj = challengeDoc.userId;
  const userIdStr = String(challengeDoc.userId);

  const cred = await webauthnCreds.findOne<any>({
    $and: [
      { $or: [{ userId: userIdObj }, { userId: userIdStr }] },
      {
        $or: [
          { credentialId: credentialIdBuf },
          { credentialId: credentialIdStr },
        ],
      },
    ],
  });

  if (!cred) {
    return NextResponse.json(
      { message: "Unknown credential" },
      { status: 401 },
    );
  }

  const verification = await verifyAuthenticationResponse({
    response,
    expectedChallenge: challengeDoc.webauthnChallenge,
    expectedOrigin,
    expectedRPID: rpID,
    authenticator: {
      credentialID: toBuffer(cred.credentialId),
      credentialPublicKey: toBuffer(cred.publicKey),
      counter: cred.counter ?? 0,
    },
    requireUserVerification: true,
  } as any);

  if (!verification.verified) {
    return NextResponse.json(
      { message: "WebAuthn verification failed" },
      { status: 401 },
    );
  }

  // Update counter + last used
  await webauthnCreds.updateOne(
    { _id: cred._id },
    {
      $set: {
        counter: verification.authenticationInfo.newCounter,
        lastUsedAt: new Date(),
      },
    },
  );

  // Mark MFA passed
  await mfaChallenges.updateOne(
    { _id: challengeDoc._id },
    { $set: { status: "passed", passedAt: new Date() } },
  );

  // Save/update device AFTER successful passkey MFA
  const devices = db.collection("devices");
  const now = new Date();
  const existingDevice = await devices.findOne({
    deviceId: challengeDoc.deviceId,
  });

  if (!existingDevice) {
    await devices.insertOne({
      deviceId: challengeDoc.deviceId,
      userId: challengeDoc.userId,
      fingerprintHash: sha256(h.get("user-agent") || "unknown"),
      userAgent: h.get("user-agent") || "unknown",
      platform: "web",
      trustLevel: "passkey_verified",
      firstSeenAt: now,
      lastSeenAt: now,
      lastSeenIp: challengeDoc.ip,
      createdAt: now,
      updatedAt: now,
    });
  } else {
    await devices.updateOne(
      { deviceId: challengeDoc.deviceId },
      {
        $set: {
          lastSeenAt: now,
          lastSeenIp: challengeDoc.ip,
          updatedAt: now,
          userId: challengeDoc.userId,
          trustLevel: "passkey_verified",
        },
      },
    );
  }

  // create full session (same style as low-risk)
  const user = await users.findOne<any>({ _id: challengeDoc.userId });
  if (!user)
    return NextResponse.json({ message: "User not found" }, { status: 404 });

  const userRole =
    Array.isArray(user.roles) && user.roles.length ? user.roles[0] : "customer";

  // single-session rule
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

  await createSession(
    String(user._id),
    userRole,
    user.name || user.email,
    true,
  );

  return NextResponse.json({
    ok: true,
    redirectTo: `/dashboard/${userRole}`,
  });
}
