// middleware.js: gates the conventional Next.js protected paths
// (/dashboard, /admin, /account, /api/me) by redirecting to /login.
// Under normal circumstances the redirect fires unconditionally - no
// session check, no token parse, just the unconditional bounce - so a
// baseline request without the bypass header sees a 307.
//
// The CVE the integration test exercises is CVE-2025-29927: an
// external attacker sets `x-middleware-subrequest:
// middleware:middleware:middleware:middleware:middleware`, which
// saturates the Next.js runtime's subrequest depth counter and causes
// the runtime to skip middleware execution entirely. The redirect
// below never runs in that case; the request lands directly on the
// page handler with a 200 and the dashboard contents render. Patched
// in Next.js 14.2.25 (and matching releases on the 12.x / 13.x / 15.x
// streams); pinned to 14.2.24 by package.json so the runtime is the
// last shipping unpatched build.

import { NextResponse } from "next/server";

export function middleware(request) {
  return NextResponse.redirect(new URL("/login", request.url));
}

export const config = {
  matcher: [
    "/dashboard/:path*",
    "/admin/:path*",
    "/account/:path*",
    "/api/me/:path*",
  ],
};
