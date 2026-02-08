import { NextResponse } from "next/server";
import { getSession } from "@/lib/session";
import { getDb } from "@/server/db/mongo";
import { env } from "@/server/config/env";
import crypto from "crypto";
import speakeasy from "speakeasy";
import QRCode from "qrcode";
import { encryptSecret } from "@/server/security/secretVault";
import { ObjectId } from "mongodb";

function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export async function POST() {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ message: "Unauthorized" }, { status: 401 });
  }

  const db = await getDb();
  const users = db.collection("users");

  // ✅ FIX: convert session user id string -> ObjectId
  let userObjectId: ObjectId;
  try {
    userObjectId = new ObjectId(session.user.id);
  } catch {
    return NextResponse.json(
      { message: "Invalid session user id" },
      { status: 400 },
    );
  }

  const user = await users.findOne<any>({ _id: userObjectId });

  if (!user) {
    return NextResponse.json({ message: "User not found" }, { status: 404 });
  }

  // Already enabled?
  if (user?.mfa?.totp?.enabled) {
    return NextResponse.json(
      { message: "Authenticator app is already enabled." },
      { status: 400 },
    );
  }

  const secret = speakeasy.generateSecret({
    name: `${env.TOTP_ISSUER}:${user.email}`,
    issuer: env.TOTP_ISSUER,
    length: 20,
  });

  const enrollmentToken = crypto.randomBytes(24).toString("base64url");
  const enrollmentTokenHash = sha256(enrollmentToken);
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  const secretBase32 = secret.base32;
  const secretEnc = encryptSecret(secretBase32);

  await users.updateOne(
    { _id: userObjectId },
    {
      $set: {
        "mfa.totpPending": {
          tokenHash: enrollmentTokenHash,
          secretEnc,
          expiresAt,
          createdAt: new Date(),
        },
      },
    },
  );

  const qrDataUrl = await QRCode.toDataURL(secret.otpauth_url!);

  return NextResponse.json({
    ok: true,
    enrollmentToken,
    qrDataUrl,
    manualKey: secretBase32,
    issuer: env.TOTP_ISSUER,
  });
}
