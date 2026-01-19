import { deleteSession } from "@/lib/session";
import { redirect } from "next/navigation";
import { NextRequest, NextResponse } from "next/server";

export async function GET(request: NextRequest) {
    await deleteSession();
    return NextResponse.redirect(new URL('/login', request.url));
}
