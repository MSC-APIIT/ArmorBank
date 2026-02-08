import { NextResponse } from "next/server";
import { z } from "zod";
import { getSession } from "@/lib/session";
import { getDb } from "@/server/db/mongo";
import crypto from "crypto";
import speakeasy from "speakeasy";
import { decryptSecret } from "@/server/security/secretVault";
import { ObjectId } from "mongodb"; // ✅ ADD

function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

const BodySchema = z.object({
  enrollmentToken: z.string().min(10),
  code: z.string().min(6).max(8),
});

export async function POST(req: Request) {
  const session = await getSession();
  if (!session)
    return NextResponse.json({ message: "Unauthorized" }, { status: 401 });

  const parsed = BodySchema.safeParse(await req.json().catch(() => ({})));
  if (!parsed.success) {
    return NextResponse.json({ message: "Invalid input" }, { status: 400 });
  }

  const { enrollmentToken, code } = parsed.data;
  const tokenHash = sha256(enrollmentToken);

  const db = await getDb();
  const users = db.collection("users");

  // ✅ FIX: convert session id -> ObjectId
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
  if (!user)
    return NextResponse.json({ message: "User not found" }, { status: 404 });

  const pending = user?.mfa?.totpPending;
  if (!pending?.tokenHash || pending.tokenHash !== tokenHash) {
    return NextResponse.json(
      { message: "Invalid enrollment token" },
      { status: 401 },
    );
  }
  if (!pending.expiresAt || new Date() > new Date(pending.expiresAt)) {
    return NextResponse.json(
      { message: "Enrollment expired. Start again." },
      { status: 401 },
    );
  }

  const secretBase32 = decryptSecret(pending.secretEnc);

  const ok = speakeasy.totp.verify({
    secret: secretBase32,
    encoding: "base32",
    token: code.trim(),
    window: 1,
  });

  if (!ok) {
    return NextResponse.json({ message: "Invalid code" }, { status: 401 });
  }

  // Enable permanently
  await users.updateOne(
    { _id: userObjectId }, // ✅ use ObjectId (or user._id also ok)
    {
      $set: {
        "mfa.totp": {
          enabled: true,
          secretEnc: pending.secretEnc,
          createdAt: new Date(),
          updatedAt: new Date(),
          lastUsedStep: null,
        },
      },
      $unset: { "mfa.totpPending": "" },
    },
  );

  return NextResponse.json({ ok: true });
}
