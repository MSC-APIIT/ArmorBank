import { type NextRequest, NextResponse } from "next/server";
import type { SessionPayload } from "@/lib/definitions";

const SESSION_COOKIE_NAME = "autharmor_session";

function decodeSession(cookieValue: string): SessionPayload | null {
  try {
    // base64(JSON) In Edge, use atob
    const json = atob(cookieValue);
    return JSON.parse(json) as SessionPayload;
  } catch {
    return null;
  }
}

function isSessionTokenValid(session: SessionPayload): boolean {
  return session.expires > Date.now();
}

const PROTECTED_ROUTES = ["/dashboard"];
const AUTH_ROUTES = ["/login", "/access-denied"];
const MFA_ROUTE = "/mfa";

export default async function middleware(request: NextRequest) {
  // Skip middleware for Server Actions
  const isServerAction = request.headers.get("next-action") !== null;
  if (isServerAction) {
    return NextResponse.next();
  }

  const { pathname } = request.nextUrl;

  // Allow /mfa without a session (MFA token in URL is enough)
  if (pathname.startsWith("/mfa")) {
    const token = request.nextUrl.searchParams.get("token");
    if (!token) {
      const url = request.nextUrl.clone();
      url.pathname = "/login";
      return NextResponse.redirect(url);
    }
    return NextResponse.next();
  }

  // Skip middleware for internal Next.js paths
  if (pathname.startsWith("/_next") || pathname.startsWith("/api")) {
    return NextResponse.next();
  }

  const cookie = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  const session = cookie ? decodeSession(cookie) : null;

  const isProtectedRoute = PROTECTED_ROUTES.some((route) =>
    pathname.startsWith(route),
  );
  const isAuthRoute = AUTH_ROUTES.some((route) => pathname.startsWith(route));

  // 1. No session or expired session
  if (!session || !isSessionTokenValid(session)) {
    if (isProtectedRoute) {
      const url = request.nextUrl.clone();
      url.pathname = "/login";
      return NextResponse.redirect(url);
    }
    return NextResponse.next();
  }

  // 2. Session is valid, but MFA is pending
  if (session.isMfaPending) {
    if (pathname !== "/mfa") {
      const url = request.nextUrl.clone();
      url.pathname = "/mfa";
      return NextResponse.redirect(url);
    }
    return NextResponse.next();
  }

  // 3. Session is valid and MFA is complete
  const userDashboard = `/dashboard/${session.user.role}`;

  if (isProtectedRoute) {
    if (!pathname.startsWith(userDashboard)) {
      const url = request.nextUrl.clone();
      url.pathname = "/access-denied";
      return NextResponse.redirect(url);
    }
  }

  if (isAuthRoute || pathname === "/") {
    const url = request.nextUrl.clone();
    url.pathname = userDashboard;
    return NextResponse.redirect(url);
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api/|_next/|favicon.ico).*)"],
};
