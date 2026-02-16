import { NextResponse } from "next/server";
import { headers } from "next/headers";
import { getDb } from "@/server/db/mongo";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/types";
import { getSession, updateSession } from "@/lib/session";
import { getWebAuthnConfig } from "@/lib/webauthn-config";

export async function POST(req: Request) {
  const { userId, registrationResponse } = (await req.json()) as {
    userId: string;
    registrationResponse: RegistrationResponseJSON;
  };

  if (!userId || !registrationResponse) {
    return NextResponse.json(
      { message: "Missing userId or registrationResponse" },
      { status: 400 },
    );
  }

  const h = await headers();
  const { rpID, expectedOrigin } = getWebAuthnConfig();

  const db = await getDb();
  const mfaChallenges = db.collection("mfa_challenges");
  const webauthnCreds = db.collection("webauthn_credentials");

  // Get latest pending registration challenge
  const challengeDoc = await mfaChallenges.findOne<any>(
    {
      type: "webauthn-registration",
      userId,
      status: "pending",
      expiresAt: { $gt: new Date() },
    },
    {
      sort: { createdAt: -1 },
    },
  );

  if (!challengeDoc?.challenge) {
    return NextResponse.json(
      { message: "Registration challenge not found/expired" },
      { status: 401 },
    );
  }

  const verification = await verifyRegistrationResponse({
    response: registrationResponse,
    expectedChallenge: challengeDoc.challenge,
    expectedOrigin,
    expectedRPID: rpID,
    requireUserVerification: false,
  });

  if (!verification.verified || !verification.registrationInfo) {
    return NextResponse.json(
      { message: "Passkey verification failed" },
      { status: 400 },
    );
  }

  const session = await getSession();
  if (session) {
    session.hasPasskey = true;
    session.shouldPromptPasskey = false;
    await updateSession(session);
  }

  const regInfo: any = verification.registrationInfo;

  // v10+ => regInfo.credential.id / regInfo.credential.publicKey
  // older => regInfo.credentialID / regInfo.credentialPublicKey
  const credentialID = regInfo.credentialID ?? regInfo.credential?.id;
  const credentialPublicKey =
    regInfo.credentialPublicKey ?? regInfo.credential?.publicKey;

  const counter = regInfo.counter ?? regInfo.credential?.counter;
  const credentialDeviceType =
    regInfo.credentialDeviceType ?? regInfo.credential?.deviceType;
  const credentialBackedUp =
    regInfo.credentialBackedUp ?? regInfo.credential?.backedUp;

  if (!credentialID || !credentialPublicKey) {
    return NextResponse.json(
      { message: "Missing credential id/publicKey from verification" },
      { status: 400 },
    );
  }

  const credentialIdB64 = registrationResponse.rawId;
  const publicKeyB64 = Buffer.from(credentialPublicKey).toString("base64url");

  const exists = await webauthnCreds.findOne({
    userId,
    credentialId: credentialIdB64,
  });

  if (!exists) {
    await webauthnCreds.insertOne({
      userId,
      credentialId: credentialIdB64,
      publicKey: publicKeyB64,
      counter,
      transports: registrationResponse.response.transports ?? [],
      deviceType: credentialDeviceType,
      backedUp: credentialBackedUp,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
  }

  // Mark challenge used
  await mfaChallenges.updateOne(
    { _id: challengeDoc._id },
    { $set: { status: "verified", verifiedAt: new Date() } },
  );

  return NextResponse.json({ ok: true });
}
