import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { verifySession } from "@/lib/auth/session";

// Paths that do not require authentication
const PUBLIC_PATHS = new Set(["/login", "/api/health"]);

// Static asset prefixes that should pass through unconditionally
const STATIC_PREFIXES = ["/_next/", "/favicon.ico", "/robots.txt"];

function isStaticAsset(pathname: string): boolean {
  return STATIC_PREFIXES.some((prefix) => pathname.startsWith(prefix));
}

function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.has(pathname);
}

export function middleware(request: NextRequest): NextResponse {
  const { pathname } = request.nextUrl;

  // Pass through static assets immediately
  if (isStaticAsset(pathname)) {
    return NextResponse.next();
  }

  const sessionToken = request.cookies.get("sb_session")?.value;

  // Read SESSION_SECRET from env directly — middleware runs in Edge runtime
  // context where we cannot use the full env.ts module (no zod at edge).
  const sessionSecret = process.env["SESSION_SECRET"] ?? "";

  const session =
    sessionToken !== undefined && sessionSecret.length >= 32
      ? verifySession(sessionToken, sessionSecret)
      : null;

  const isAuthenticated = session !== null;

  // Unauthenticated user trying to access protected route
  if (!isAuthenticated && !isPublicPath(pathname)) {
    const loginUrl = new URL("/login", request.url);
    return NextResponse.redirect(loginUrl);
  }

  // Authenticated user trying to access /login — redirect to dashboard
  if (isAuthenticated && pathname === "/login") {
    const dashboardUrl = new URL("/", request.url);
    return NextResponse.redirect(dashboardUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Match all request paths except those starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico
     */
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
