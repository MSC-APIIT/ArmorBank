import { type NextRequest, NextResponse } from 'next/server';
import { getSession, isSessionTokenValid } from '@/lib/session';

const PROTECTED_ROUTES = ['/dashboard'];
const AUTH_ROUTES = ['/login', '/mfa', '/access-denied'];

export default async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const session = await getSession();

  const isProtectedRoute = PROTECTED_ROUTES.some((route) => pathname.startsWith(route));
  const isAuthRoute = AUTH_ROUTES.some((route) => pathname.startsWith(route));

  // 1. No session or expired session
  if (!session || !isSessionTokenValid(session)) {
    // If trying to access a protected route, redirect to login
    if (isProtectedRoute) {
      return NextResponse.redirect(new URL('/login', request.url));
    }
    // Otherwise, allow access to public/auth pages
    return NextResponse.next();
  }
  
  // 2. Session is valid, but MFA is pending
  if (session.isMfaPending) {
    // User must complete MFA. Redirect to MFA page if they are anywhere else.
    if (pathname !== '/mfa') {
      return NextResponse.redirect(new URL('/mfa', request.url));
    }
    return NextResponse.next();
  }

  // 3. Session is valid and MFA is complete
  const userDashboard = `/dashboard/${session.user.role}`;

  // If on a protected route, verify the role.
  if (isProtectedRoute) {
    if (!pathname.startsWith(userDashboard)) {
      // User is trying to access a dashboard for a different role. Deny it.
      return NextResponse.redirect(new URL('/access-denied', request.url));
    }
  }

  // If trying to access an auth route or the homepage, redirect to their dashboard.
  if (isAuthRoute || pathname === '/') {
    return NextResponse.redirect(new URL(userDashboard, request.url));
  }

  // 4. For all other cases, allow the request
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
