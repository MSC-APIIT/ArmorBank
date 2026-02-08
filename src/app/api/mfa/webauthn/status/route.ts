import { NextResponse } from "next/server";
import { getSession } from "@/lib/session";
import { getDb } from "@/server/db/mongo";
import { ObjectId } from "mongodb";

export async function GET() {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ message: "Unauthorized" }, { status: 401 });
  }

  const userIdStr = String(session.user.id);

  let userIdObj: ObjectId | null = null;
  try {
    userIdObj = new ObjectId(userIdStr);
  } catch {
    userIdObj = null;
  }

  const db = await getDb();
  const webauthnCreds = db.collection("webauthn_credentials");

  const count = await webauthnCreds.countDocuments({
    $or: [
      { userId: userIdStr }, // ✅ if stored as string
      ...(userIdObj ? [{ userId: userIdObj }] : []), // ✅ if stored as ObjectId
    ],
  });

  return NextResponse.json({
    ok: true,
    count,
    hasPasskey: count > 0,
  });
}
