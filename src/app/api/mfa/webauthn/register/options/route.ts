import { NextResponse } from "next/server";
import { headers } from "next/headers";
import crypto from "crypto";
import { getDb } from "@/server/db/mongo";
import { generateRegistrationOptions } from "@simplewebauthn/server";
import { getWebAuthnConfig } from "@/lib/webauthn-config";

function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function toUserIDBuffer(userId: string) {
  return Buffer.from(userId, "utf8");
}

function toCredentialIDBase64Url(id: any): string {
  // If it's already stored as base64url string
  if (typeof id === "string") return id;

  // If stored as Buffer
  if (Buffer.isBuffer(id)) return id.toString("base64url");

  // If stored as Mongo Binary (commonly has .buffer or is a Binary-like)
  if (id?.buffer) return Buffer.from(id.buffer).toString("base64url");

  throw new Error("Invalid credentialId type in DB");
}

export async function POST(req: Request) {
  const { userId } = await req.json();

  if (!userId) {
    return NextResponse.json({ message: "Missing userId" }, { status: 400 });
  }

  const { rpID } = getWebAuthnConfig();

  const db = await getDb();
  const webauthnCreds = db.collection("webauthn_credentials");
  const mfaChallenges = db.collection("mfa_challenges");

  // Exclude already-registered credentials
  const creds = await webauthnCreds
    .find({ $or: [{ userId }, { userId: String(userId) }] })
    .toArray();

  const options = await generateRegistrationOptions({
    rpName: "AuthArmor",
    rpID,
    userID: toUserIDBuffer(userId),
    userName: userId,
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "preferred",
      userVerification: "preferred",
    },
    excludeCredentials: creds.map((c: any) => ({
      id: toCredentialIDBase64Url(c.credentialId),
      type: "public-key",
      transports: c.transports ?? undefined,
    })),
  });

  await mfaChallenges.updateMany(
    {
      type: "webauthn-registration",
      userId,
      status: "pending",
    },
    { $set: { status: "superseded", supersededAt: new Date() } },
  );

  await mfaChallenges.insertOne({
    type: "webauthn-registration",
    userId,
    challenge: options.challenge,
    status: "pending",
    expiresAt: new Date(Date.now() + 5 * 60 * 1000),
    createdAt: new Date(),
  });

  return NextResponse.json(options);
}
