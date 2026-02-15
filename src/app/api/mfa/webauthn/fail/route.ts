import { NextResponse } from "next/server";
import { headers, cookies } from "next/headers";
import crypto from "crypto";
import { getDb } from "@/server/db/mongo";
import { env } from "@/server/config/env";

function sha256(input: string) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

export async function POST(req: Request) {
  try {
    const { mfaToken } = await req.json().catch(() => ({}));

    if (!mfaToken) {
      return NextResponse.json({ message: "Missing token" }, { status: 400 });
    }

    const h = await headers();
    const ip = h.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
    const deviceId = (await cookies()).get("deviceId")?.value ?? "unknown";

    const db = await getDb();
    const mfaChallenges = db.collection("mfa_challenges");
    const attemptsCol = db.collection("auth_attempts");
    const locks = db.collection("account_locks");

    const challenge = await mfaChallenges.findOne<any>({
      mfaTokenHash: sha256(mfaToken),
      status: "pending",
      expiresAt: { $gt: new Date() },
    });

    if (!challenge) {
      return NextResponse.json({ ok: true });
    }

    const now = new Date();

    // 🔹 record failure
    await attemptsCol.insertOne({
      createdAt: now,
      expiresAt: new Date(now.getTime() + 1000 * 60 * 60 * 24 * 14),
      emailOrUsername: challenge.email ?? null,
      userId: challenge.userId,
      deviceId,
      ip,
      userAgentHash: sha256(h.get("user-agent") || "unknown"),
      result: "mfa_fail",
      failReason: "webauthn_client_fail",
    });

    // count recent MFA fails
    const tenMinAgo = new Date(
      now.getTime() - env.MFA_FAIL_WINDOW_SECONDS * 1000,
    );

    const failCount = await attemptsCol.countDocuments({
      userId: challenge.userId,
      createdAt: { $gte: tenMinAgo },
      result: { $in: ["mfa_fail"] },
    });

    const threshold = env.MFA_FAIL_LIMIT;

    if (failCount >= threshold) {
      const lockedUntil = new Date(
        now.getTime() + Number(env.ACCOUNT_LOCK_SECONDS) * 1000,
      );

      await locks.updateOne(
        { userId: String(challenge.userId) },
        {
          $set: {
            userId: String(challenge.userId),
            lockedUntil,
            reason: "mfa_failures",
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
    }

    return NextResponse.json({ ok: true });
  } catch (e) {
    console.error("WebAuthn fail tracking error:", e);
    return NextResponse.json({ ok: true });
  }
}
