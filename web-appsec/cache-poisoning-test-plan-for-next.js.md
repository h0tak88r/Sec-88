# Cache Poisoning Test Plan for Next.js

{% embed url="https://zhero-web-sec.github.io/research-and-things/nextjs-cache-and-chains-the-stale-elixir" %}

### 1. Reconnaissance

* **Identify Next.js**: Check for `/api/`, `_next/` paths, or `X-Powered-By: Next.js` header.
* **Verify Version**: Review source (e.g., `<script id="__NEXT_DATA__">`) for `buildID` or version clues (13.5.1–14.2.9).
* **Detect SSR**: Target pages using `getServerSideProps` (dynamic data, e.g., `/dashboard`). Avoid dynamic routes (e.g., `/blog/[slug]`).
* **Check Caching**: Send repeated requests; look for `Cache-Control` or CDN headers (e.g., `Server: cloudflare`).

### 2. Test DoS via Cache Poisoning

* **Setup**: Use Burp Repeater/Intruder; identify SSR page (e.g., `/poc`).
* **Test 1: `__nextDataReq` Parameter**
  * Send: `GET /poc?__nextDataReq=1`
  * Check: JSON `pageProps` response (e.g., `{"userAgent":"..."}`).
  * Re-request `/poc` without param; if JSON served, cache poisoned (DoS).
* **Test 2: `x-now-route-matches` Header**
  * Send: `GET /poc?__nextDataReq=1` with `x-now-route-matches: 1`.
  * Verify: `Cache-Control: s-maxage=1, stale-while-revalidate`; re-request `/poc` for JSON.
* **Test 3: Data Route**
  * Extract `buildID` from `<script id="__NEXT_DATA__">`.
  * Send: `GET /_next/data/{buildID}/poc.json` with `x-now-route-matches: 1`.
  * Confirm: JSON cached; `/poc` serves JSON.
* **Safeguard**: Test with `Accept-Encoding: none` if header is in cache-key to avoid impacting users.

### 3. Test Stored XSS

* **Identify Reflection**: Check if SSR page reflects request data (e.g., user-agent, cookies, CSRF token).
* **Craft Payload**:
  * Send: `GET /poc?__nextDataReq=1` with `User-Agent: <img src=x onerror=alert('test')>` and `x-now-route-matches: 1`.
  * Verify: Cached `/poc` response is `text/html` with payload.
  * Access `/poc` in browser; confirm alert triggers.
* **Common Reflections**: User-agent, locale cookies, session IDs, CSRF headers, theme preferences.

### 4. Test Cache Deception

* **Target Sensitive Data**: Check if SSR reflects user-specific data (e.g., session cookies).
* **Send Payload**: Use above methods to cache victim’s response.
* **Verify**: Access `/poc` to see if sensitive data is served.
* **References**:
  * Advisory: https://github.com/advisories/GHSA-gp8f-8m3g-qvj9
  * PortSwigger Cache Poisoning: https://portswigger.net/web-security/web-cache-poisoning

#### Automation

{% embed url="https://github.com/h0tak88r/nuclei_templates/blob/ffabf2473eb510b71c07091ec03a4fdf0e07f557/cves/CVE-2024-46982.yaml" %}
