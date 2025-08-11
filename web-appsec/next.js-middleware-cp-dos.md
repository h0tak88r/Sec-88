# Next.js middleware CP - DOS

{% embed url="https://zhero-web-sec.github.io/research-and-things/nextjs-and-cache-poisoning-a-quest-for-the-black-hole" %}

**Overview**\
This 2024 blog post by zhero\_web\_security explores three cache-poisoning vulnerabilities in Next.js, a React-based JavaScript framework by Vercel with over 6 million weekly downloads. The research targets server-side behaviors to poison caches, enabling denial-of-service (DoS) attacks by serving empty or error pages. Vulnerabilities exploit HTTP headers and CDN misconfigurations, with real-world bounties from bug programs. Builds on prior DoS via cache poisoning research (e.g., on Mozilla).

**Key Concepts**

* **Cache Poisoning**: Manipulating cached responses to deliver unintended content (e.g., empty pages), causing DoS.
* **Next.js Features**: Middleware for request handling; server-side rendering (SSR) via `getServerSideProps`; React Server Components (RSC) for binary payloads with client DOM updates.
* **HTTP Headers**: `x-middleware-prefetch` for prefetching; `Rsc` for RSC; internal `x-invoke-status` and `x-invoke-error` for status/error control.
* **Vary Header**: Defines cache variance (e.g., by headers); often ignored by CDNs like Cloudflare (except `accept-encoding`/images), CloudFront (removes `Vary`), or Akamai (default removal in some products).
* **Prerequisites**: Caching system/CDN; vulnerabilities scored CVSS 7.5 (`CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/CR:X/IR:X/AR:X`).

**Findings**

1. **Middleware Prefetch (CVE-2023-46298)**: `x-middleware-prefetch` header during SSR prefetch returns empty JSON `{}`; cached, it blocks pages. Fixed in v13.4.20-canary.13 with cache-control headers.
2. **RSC Payload with CDNs**: RSC uses `_rsc=randomValue` cache-buster and `Vary: Rsc`; without buster, `Rsc: 1` poisons cache if CDNs ignore `Vary`. Exploitable on Cloudflare/CloudFront/Akamai.
3. **Internal Headers**: `x-invoke-status: 200` overwrites status to cacheable 200, invoking error page; `x-invoke-error` injects custom JSON (e.g., `{"message":"<>"}`). Requires non-minimal/non-edge mode and valid `invokePath`.

**Exploits**

* **First**: Request with `x-middleware-prefetch` caches empty response for DoS.
* **Second**: `Rsc: 1` without cache-buster poisons root pages with RSC payload; mass-scanned for vulnerable assets, yielding $2000 bounty.
* **Third**: `x-invoke-status: 200` caches error page; customize with `x-invoke-error`. Confirmed locally and on targets ($3000 bounty)

**Testing Methodology**\
As a bug hunter, focus on identifying and exploiting these in Next.js applications with CDNs. Use proxies like Burp Suite for header manipulation.

1. **Reconnaissance**:
   * Scan for Next.js indicators (e.g., `/api/` routes, `_next/` paths) via source code or headers.
   * Check CDN (e.g., Cloudflare via `Server: cloudflare` header) and caching (send repeated requests; observe `Cache-Control`).
2. **Test First Vulnerability (Middleware Prefetch)**:
   * Target SSR pages (e.g., using `getServerSideProps`).
   * Add `x-middleware-prefetch: 1` header to a GET request.
   * Verify empty `{}` response; re-request without header—if empty, cache poisoned (DoS confirmed).
3. **Test Second Vulnerability (RSC Payload)**:
   * Identify RSC-enabled pages (e.g., App Router in v13+).
   * Send GET with `Rsc: 1` header (omit `_rsc` param).
   * Check if response is RSC binary; re-request without header—if RSC served, poison successful.
   * Validate CDN ignores `Vary: Rsc` by testing cache persistence.
4. **Test Third Vulnerability (Internal Headers)**:
   * Ensure non-edge runtime (check via errors or docs).
   * Send GET with `x-invoke-status: 200` and optional `x-invoke-error: {"message":"test"}`.
   * Verify error page with 200 status; re-request—if error cached, DoS achieved.
   * Bypass Strips: Test if headers pass through CDN/proxy.

**Takeaways**\
Internal headers create attack surfaces if not stripped/varied; CDNs amplify flaws, with vendors deflecting responsibility. Widespread Next.js use demands user awareness.

**References**

* Next.js Source: https://github.com/vercel/next.js/blob/f412c5e72a068d3667e0005f33a9ac7802634b61/packages/next/src/server/base-server.ts
* Header Constants: https://github.com/vercel/next.js/blob/f412c5e72a068d3667e0005f33a9ac7802634b61/packages/next/src/shared/lib/constants.ts
* Fix Commit: https://github.com/vercel/next.js/commit/61ee393fb4cdf10e8b3dd1eca54c31360a73c559
* Other: NPM Stats (https://www.npmjs.com/package/next); Mozilla Write-up (https://zhero-web-sec.github.io/dos-via-cache-poisoning/); GitHub Issues/Commits as cited.

#### Automation

{% embed url="https://github.com/h0tak88r/nuclei_templates/blob/main/cves/CVE-2025-29927.yaml" %}
