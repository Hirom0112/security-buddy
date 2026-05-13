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

  // Issue the single-use CSRF cookie when an unauthenticated visitor lands on
  // /login. Server components in Next 15 can't write cookies during render,
  // so middleware is the right place. Mutate the *request* cookies so the
  // server component sees the new value via cookies().get() on the same
  // request, and also set the Set-Cookie header on the response so the
  // browser stores it for the form POST.
  if (pathname === "/login" && !isAuthenticated) {
    const existing = request.cookies.get("sb_csrf")?.value;
    if (existing === undefined || existing.length < 32) {
      const bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      const token = Array.from(bytes, (b) =>
        b.toString(16).padStart(2, "0")
      ).join("");
      request.cookies.set("sb_csrf", token);
      const response = NextResponse.next({ request });
      response.cookies.set("sb_csrf", token, {
        httpOnly: true,
        secure: process.env["NODE_ENV"] === "production",
        sameSite: "strict",
        path: "/login",
        maxAge: 60 * 10,
      });
      return response;
    }
  }

  return NextResponse.next();
}

export const config = {
  runtime: "nodejs",
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
