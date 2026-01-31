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

function toCredentialIDBase64Url(id: any): string {
  if (!id) throw new Error("Missing credentialId");

  // already base64url string
  if (typeof id === "string") return id;

  // Buffer
  if (Buffer.isBuffer(id)) return id.toString("base64url");

  // Uint8Array
  if (id instanceof Uint8Array) return Buffer.from(id).toString("base64url");

  // ArrayBuffer
  if (id instanceof ArrayBuffer)
    return Buffer.from(new Uint8Array(id)).toString("base64url");

  // Mongo/BSON Binary often has a `.buffer` (Buffer or ArrayBuffer/Uint8Array)
  const b = (id as any).buffer;
  if (b) {
    if (Buffer.isBuffer(b)) return b.toString("base64url");
    if (b instanceof Uint8Array) return Buffer.from(b).toString("base64url");
    if (b instanceof ArrayBuffer)
      return Buffer.from(new Uint8Array(b)).toString("base64url");
  }

  // Some drivers expose `.value()` for Binary
  if (typeof (id as any).value === "function") {
    const v = (id as any).value();
    if (Buffer.isBuffer(v)) return v.toString("base64url");
    if (v instanceof Uint8Array) return Buffer.from(v).toString("base64url");
  }

  // Last resort: print type info
  throw new Error(
    `Invalid credentialId type: ${Object.prototype.toString.call(id)}`,
  );
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

  const userIdObj = challengeDoc.userId;
  const userIdStr = String(challengeDoc.userId);

  const creds = await webauthnCreds
    .find({
      $or: [{ userId: userIdObj }, { userId: userIdStr }],
    })
    .toArray();

  if (!creds.length) {
    return NextResponse.json(
      { message: "No passkey enrolled", code: "NO_PASSKEY" },
      { status: 409 },
    );
  }

  const first = creds[0];
  const converted = toCredentialIDBase64Url(first.credentialId);

  const options = await generateAuthenticationOptions({
    rpID,
    userVerification: "required",
    allowCredentials: creds.map((c: any) => ({
      id: toCredentialIDBase64Url(c.credentialId),
      transports: c.transports ?? undefined,
    })),
  });

  await mfaChallenges.updateOne(
    { _id: challengeDoc._id },
    { $set: { webauthnChallenge: options.challenge } },
  );

  return NextResponse.json(options);
}
