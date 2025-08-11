# Nuxt CP - DOS

{% embed url="https://zhero-web-sec.github.io/research-and-things/nuxt-show-me-your-payload/" %}

**Brief**\
A 2025 research by zhero\_web\_security uncovers a cache-poisoning vulnerability (CVE-2025-27415) in Nuxt (3.0.0–3.15.2), a Vue.js framework. A lax URL regex allows query (`?poc=/_payload.json`) or hash (`#/_payload.json`) to force JSON payload rendering on main routes, causing DoS when cached. Affects all non-Nitro pages; patched in 3.16.0.

**Testing Methodology**\
Test cache poisoning in Nuxt (3.0.0–3.15.2) with CDNs on non-critical endpoints to avoid unintended DoS. Use Burp Suite.

1. **Reconnaissance**
   * Confirm Nuxt via `/api/`, `_nuxt/`, or `<script id="__NUXT_DATA__">`.
   * Verify version 3.0.0–3.15.2.
   * Check caching: Repeated requests show `Cache-Control` or CDN headers (e.g., `Server: cloudflare`).
   * Test cache-key: `GET /?test=1` vs. `GET /` returns same response if params ignored.
2. **Query-Based DoS**
   * Send: `GET /?poc=/_payload.json`
   * Verify: JSON payload, status 200.
   * Check: Re-request `/`; JSON served = cache poisoned (DoS).
   * Safeguard: Use `Accept-Encoding: none` if in cache-key.
   * Automate: Script requests \~1s post-cache expiry.
3. **Hash-Based DoS**
   * Send via proxy: `GET /#/_payload.json`
   * Verify: JSON payload, status 200.
   * Check: Re-request `/`; JSON served = DoS.
   * Note: Fails if CDN encodes hash (e.g., `%23/_payload.json` → 404).
4. **Confirmation & Reporting**
   * Confirm: JSON persists on main route; page unusable.
   * Impact: DoS (CVSS 7.5).
   * Mitigate: Test `/test` or get BBP permission.
   * Report: PoC (logs), routes, CDN details.
   * False Positives: Nitro `/api`, 3.16.0+, no CDN, params in cache-key.

**References**

* Advisory: https://github.com/nuxt/nuxt/security/advisories/GHSA-jvhm-gjrh-3h93
* PortSwigger Cache Poisoning: https://portswigger.net/web-security/web-cache-poisoning
* Related Next.js Research: https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir
