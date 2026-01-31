import { NextResponse } from "next/server";
import { headers, cookies } from "next/headers";
import crypto from "crypto";
import { getDb } from "@/server/db/mongo";
import { generateAuthenticationOptions } from "@simplewebauthn/server";

function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

function getRpID(host: string) {
  return host.split(":")[0];
}

export async function POST(req: Request) {
  const { mfaToken } = await req.json();

  if (!mfaToken) {
    return NextResponse.json({ message: "Missing mfaToken" }, { status: 400 });
  }

  const h = await headers();
  const host = h.get("host") ?? "localhost";
  const rpID = getRpID(host);

  const ip = h.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const deviceId = (await cookies()).get("deviceId")?.value ?? "unknown";

  const db = await getDb();
  const mfaChallenges = db.collection("mfa_challenges");
  const webauthnCreds = db.collection("webauthn_credentials");

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

  // Bind token to the environment that requested it (prevents token reuse from another device/ip)
  if (challengeDoc.ip !== ip || challengeDoc.deviceId !== deviceId) {
    return NextResponse.json(
      { message: "Token context mismatch" },
      { status: 401 },
    );
  }

  const creds = await webauthnCreds
    .find({ userId: challengeDoc.userId })
    .toArray();

  if (!creds.length) {
    return NextResponse.json(
      { message: "No passkey enrolled", code: "NO_PASSKEY" },
      { status: 409 },
    );
  }

  const options = generateAuthenticationOptions({
    rpID,
    userVerification: "required",
    allowCredentials: creds.map((c: any) => ({
      id: c.credentialId,
      transports: c.transports ?? undefined,
    })),
  });

  await mfaChallenges.updateOne(
    { _id: challengeDoc._id },
    { $set: { webauthnChallenge: (await options).challenge } },
  );

  return NextResponse.json(options);
}
