# Next.js Middleware Bypass

{% embed url="https://zhero-web-sec.github.io/research-and-things/nextjs-and-the-corrupt-middleware" %}

**Brief**\
Published in March 2025 by zhero\_web\_security and inzo\_, this research uncovers a critical vulnerability (CVE-2025-29927, CVSS 9.1) in Next.js (11.1.4–15.2.2), allowing attackers to bypass middleware protections using the `x-middleware-subrequest` header. This enables unauthorized access to protected routes, CSP bypass, and cache-poisoning DoS. Fixed in 15.2.3 and 14.2.25; affects all versions with middleware.

**Testing Methodology**\
Test middleware bypass in Next.js (11.1.4–15.2.2) applications with Burp Suite, targeting authorization, CSP, or cache poisoning. Test cautiously on non-critical endpoints.

1. **Reconnaissance**
   * Confirm Next.js: Check `/api/`, `_next/`, or `X-Powered-By: Next.js`.
   * Verify Version: Inspect `<script id="__NEXT_DATA__">` for 11.1.4–15.2.2.
   * Identify Middleware: Look for redirects, CSP headers, or protected routes (e.g., `/dashboard/admin`).
   * Check Caching: Repeated requests show `Cache-Control` or CDN headers (e.g., `Server: cloudflare`).
2. **Test Middleware Bypass (Pre-12.2)**
   * Target: Protected route (e.g., `/dashboard/admin`).
   * Send: `GET /dashboard/admin` with `x-middleware-subrequest: pages/_middleware` or `pages/dashboard/_middleware`.
   * Verify: Access granted (e.g., no redirect to login).
   * Try nested paths: `pages/dashboard/panel/_middleware` for deeper routes.
3. **Test Middleware Bypass (12.2–15.2.2)**
   * Send: `GET /dashboard/admin` with `x-middleware-subrequest: middleware` or `src/middleware`.
   * For 15.x: Use `x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware` (5x to exceed `MAX_RECURSION_DEPTH`).
   * Verify: Access to protected route or bypassed CSP (e.g., missing headers).
4. **Test Cache-Poisoning DoS**
   * Target: Root (`/`) or rewritable route with no page (e.g., 404/500 on bypass).
   * Send: `GET /` with `x-middleware-subrequest: middleware` (or version-specific payload).
   * Check: Response is 404/500; re-request `/` to confirm cached error (DoS).
   * Safeguard: Use `Accept-Encoding: none` if in cache-key.
5. **Confirmation & Reporting**
   * Confirm: Access protected route, bypass CSP, or cache 404/500.
   * Impact: Unauthorized access (confidentiality/integrity), DoS (availability).
   * Mitigate: Test non-critical routes or get BBP permission.
   * Report: Include PoC (logs), version, endpoint, severity (critical, CVSS 9.1).
   * False Positives: No middleware, Vercel/Netlify (opt-in fix), 15.2.3+, 14.2.25+.

**References**

* Advisory: https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw
* Next.js Tweet: https://x.com/nextjs/status/1903522002431857063
* Related Next.js Research: https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir
