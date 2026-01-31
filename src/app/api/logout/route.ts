import { deleteSession } from "@/lib/session";
import { NextRequest, NextResponse } from "next/server";

async function handleLogout(request: NextRequest) {
  await deleteSession();

  const res = NextResponse.redirect(new URL("/login", request.url));
  res.headers.set("Cache-Control", "no-store");

  return res;
}

export async function POST(request: NextRequest) {
  return handleLogout(request);
}

export async function GET(request: NextRequest) {
  return handleLogout(request);
}
