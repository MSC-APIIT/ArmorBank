import { NextResponse } from "next/server";
import { getSession } from "@/lib/session";
import { getDb } from "@/server/db/mongo";
import { ObjectId } from "mongodb";

export async function GET() {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ message: "Unauthorized" }, { status: 401 });
  }

  let userObjectId: ObjectId;
  try {
    userObjectId = new ObjectId(session.user.id);
  } catch {
    return NextResponse.json(
      { message: "Invalid session user id" },
      { status: 400 },
    );
  }

  const db = await getDb();
  const users = db.collection("users");

  const user = await users.findOne<any>(
    { _id: userObjectId },
    { projection: { "mfa.totp.enabled": 1 } },
  );

  if (!user) {
    return NextResponse.json({ message: "User not found" }, { status: 404 });
  }

  const enabled = !!user?.mfa?.totp?.enabled;
  return NextResponse.json({ ok: true, enabled });
}
