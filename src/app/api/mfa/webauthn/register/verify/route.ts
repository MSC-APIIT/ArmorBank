import { NextResponse } from "next/server";
import { headers } from "next/headers";
import { getDb } from "@/server/db/mongo";
import { verifyRegistrationResponse } from "@simplewebauthn/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/types";

function getRpID(host: string) {
  return host.split(":")[0];
}

function getOrigin(h: Headers) {
  const host = h.get("host") ?? "localhost";
  const proto = h.get("x-forwarded-proto") ?? "http";
  return `${proto}://${host}`;
}

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
  const host = h.get("host") ?? "localhost";
  const rpID = getRpID(host);
  const expectedOrigin = getOrigin(h);

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

  // IMPORTANT: store Buffer so your existing allowCredentials works (it uses c.credentialId directly)
  const credentialIdBuf = Buffer.from(credentialID);
  const publicKeyBuf = Buffer.from(credentialPublicKey);

  // Prevent duplicate insert
  const exists = await webauthnCreds.findOne({
    userId,
    credentialId: credentialIdBuf,
  });

  if (!exists) {
    await webauthnCreds.insertOne({
      userId,
      credentialId: credentialIdBuf,
      publicKey: publicKeyBuf,
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
